"""Thread-safe, bounded graph built only from observed packet metadata."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import ipaddress
import math
from threading import RLock
import time
from typing import Any


PROTOCOLS = ("TCP", "UDP", "DNS", "HTTP", "ICMP", "Other")
STATUS_RANK = {"NORMAL": 0, "WARNING": 1, "CRITICAL": 2}
LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def classify_ip(address: str) -> str:
    """Classify an IP as LOCAL, EXTERNAL, or SPECIAL using stdlib rules."""
    ip = ipaddress.ip_address(address)
    if ip.is_loopback or ip.is_link_local or any(ip in network for network in LOCAL_NETWORKS if ip.version == network.version):
        return "LOCAL"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or not ip.is_global:
        return "SPECIAL"
    if ip.is_global:
        return "EXTERNAL"
    return "SPECIAL"


class GraphManager:
    """Aggregate endpoints and bidirectional communications from observed traffic."""

    def __init__(
        self,
        edge_ttl_seconds: int = 300,
        node_ttl_seconds: int = 600,
        max_nodes: int = 250,
        max_edges: int = 500,
    ) -> None:
        if edge_ttl_seconds < 1 or node_ttl_seconds < edge_ttl_seconds:
            raise ValueError("Node TTL must be at least as large as edge TTL")
        if max_nodes < 2 or max_edges < 1:
            raise ValueError("Graph limits must allow at least two nodes and one edge")
        self.edge_ttl_seconds = edge_ttl_seconds
        self.node_ttl_seconds = node_ttl_seconds
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = RLock()

    def observe_packet(
        self,
        packet: dict[str, Any],
        observed_at: float | None = None,
        is_demo: bool = False,
    ) -> bool:
        """Add one parsed packet to the graph; return False when it has no valid IP pair."""
        source = packet.get("source_ip")
        destination = packet.get("destination_ip")
        if not source or not destination or source == destination:
            return False
        try:
            ipaddress.ip_address(str(source))
            ipaddress.ip_address(str(destination))
        except ValueError:
            return False
        try:
            packet_size = max(0, int(packet.get("size", 0)))
        except (TypeError, ValueError):
            packet_size = 0
        self.observe_flow(
            str(source),
            str(destination),
            str(packet.get("protocol", "Other")),
            packet_count=1,
            total_bytes=packet_size,
            observed_at=observed_at,
            is_demo=is_demo,
        )
        return True

    def observe_flow(
        self,
        source: str,
        destination: str,
        protocol: str,
        packet_count: int,
        total_bytes: int,
        observed_at: float | None = None,
        is_demo: bool = False,
    ) -> None:
        """Aggregate a flow. Bulk counts are used only by synthetic demo input."""
        try:
            ipaddress.ip_address(source)
            ipaddress.ip_address(destination)
        except ValueError:
            return
        if source == destination:
            return
        now = float(observed_at if observed_at is not None else time.time())
        count = max(1, int(packet_count))
        byte_count = max(0, int(total_bytes))
        protocol = protocol if protocol in PROTOCOLS else "Other"

        with self._lock:
            self._cleanup_locked(now)
            self._ensure_node_capacity_locked(source)
            self._ensure_node_capacity_locked(destination, protected={source})
            source_node = self._nodes.setdefault(source, self._new_node(source, now))
            destination_node = self._nodes.setdefault(destination, self._new_node(destination, now))
            self._update_node(source_node, protocol, count, byte_count, now, sent=True, is_demo=is_demo)
            self._update_node(destination_node, protocol, count, byte_count, now, sent=False, is_demo=is_demo)

            edge_key = tuple(sorted((source, destination)))
            if edge_key not in self._edges and len(self._edges) >= self.max_edges:
                oldest = min(self._edges, key=lambda key: self._edges[key]["_last_seen_epoch"])
                del self._edges[oldest]
            edge = self._edges.setdefault(edge_key, self._new_edge(*edge_key, now))
            edge["packet_count"] += count
            edge["bytes"] += byte_count
            edge["protocols"][protocol] += count
            edge["_last_seen_epoch"] = now
            if is_demo:
                edge["_demo_packet_count"] += count
                edge["_demo_bytes"] += byte_count
                edge["_demo_protocols"][protocol] += count

    def apply_alert(self, alert: dict[str, Any]) -> None:
        """Apply an existing Part 2 alert to observed nodes without creating nodes."""
        severity = str(alert.get("severity", "INFO")).upper()
        if severity not in {"WARNING", "CRITICAL"}:
            return
        addresses = [alert.get("source_ip")]
        if not addresses[0]:
            addresses.append(alert.get("destination_ip"))
        with self._lock:
            for address in {str(item) for item in addresses if item}:
                node = self._nodes.get(address)
                if not node:
                    continue
                node["alert_count"] += 1
                alert_kind = "_demo_alert_severities" if alert.get("is_demo", False) else "_real_alert_severities"
                node[alert_kind][severity] += 1
                if STATUS_RANK[severity] > STATUS_RANK[node["status"]]:
                    node["status"] = severity

    def clear_demo_data(self) -> dict[str, int]:
        """Subtract synthetic graph contributions while preserving captured observations."""
        with self._lock:
            removed_edges = 0
            for key, edge in list(self._edges.items()):
                edge["packet_count"] -= edge["_demo_packet_count"]
                edge["bytes"] -= edge["_demo_bytes"]
                for protocol, count in edge["_demo_protocols"].items():
                    edge["protocols"][protocol] -= count
                    if edge["protocols"][protocol] <= 0:
                        del edge["protocols"][protocol]
                edge["_demo_packet_count"] = 0
                edge["_demo_bytes"] = 0
                edge["_demo_protocols"].clear()
                if edge["packet_count"] <= 0:
                    del self._edges[key]
                    removed_edges += 1

            removed_nodes = 0
            connected = {address for key in self._edges for address in key}
            for address, node in list(self._nodes.items()):
                node["packet_count"] -= node["_demo_packet_count"]
                node["sent_packets"] -= node["_demo_sent_packets"]
                node["received_packets"] -= node["_demo_received_packets"]
                node["bytes"] -= node["_demo_bytes"]
                for protocol, count in node["_demo_protocols"].items():
                    node["protocols"][protocol] -= count
                    if node["protocols"][protocol] <= 0:
                        del node["protocols"][protocol]
                demo_alerts = sum(node["_demo_alert_severities"].values())
                node["alert_count"] = max(0, node["alert_count"] - demo_alerts)
                node["_demo_packet_count"] = 0
                node["_demo_sent_packets"] = 0
                node["_demo_received_packets"] = 0
                node["_demo_bytes"] = 0
                node["_demo_protocols"].clear()
                node["_demo_alert_severities"].clear()
                node["status"] = self._highest_alert_status(node["_real_alert_severities"])
                if node["packet_count"] <= 0 and address not in connected:
                    del self._nodes[address]
                    removed_nodes += 1
            return {"nodes": removed_nodes, "edges": removed_edges}

    def snapshot(self, now: float | None = None) -> dict[str, Any]:
        """Return the complete bounded graph in frontend-ready form."""
        current_time = float(now if now is not None else time.time())
        with self._lock:
            self._cleanup_locked(current_time)
            nodes = [self._serialize_node(node) for node in self._nodes.values()]
            edges = [self._serialize_edge(edge) for edge in self._edges.values()]
        nodes.sort(key=lambda item: (-STATUS_RANK[item["status"]], -item["packet_count"], item["id"]))
        edges.sort(key=lambda item: (-item["packet_count"], item["id"]))
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "observed_devices": len(nodes),
                "active_connections": len(edges),
                "local_devices": sum(node["node_type"] == "LOCAL" for node in nodes),
                "external_devices": sum(node["node_type"] == "EXTERNAL" for node in nodes),
                "special_devices": sum(node["node_type"] == "SPECIAL" for node in nodes),
                "suspicious_devices": sum(node["status"] != "NORMAL" for node in nodes),
            },
            "limits": {
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "edge_ttl_seconds": self.edge_ttl_seconds,
                "node_ttl_seconds": self.node_ttl_seconds,
            },
        }

    def clear_alert_state(self) -> None:
        with self._lock:
            for node in self._nodes.values():
                node["alert_count"] = 0
                node["status"] = "NORMAL"

    def reset(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()

    def _new_node(self, address: str, timestamp: float) -> dict[str, Any]:
        return {
            "id": address,
            "ip": address,
            "node_type": classify_ip(address),
            "packet_count": 0,
            "sent_packets": 0,
            "received_packets": 0,
            "bytes": 0,
            "protocols": Counter(),
            "alert_count": 0,
            "status": "NORMAL",
            "_first_seen_epoch": timestamp,
            "_last_seen_epoch": timestamp,
            "_demo_packet_count": 0,
            "_demo_sent_packets": 0,
            "_demo_received_packets": 0,
            "_demo_bytes": 0,
            "_demo_protocols": Counter(),
            "_real_alert_severities": Counter(),
            "_demo_alert_severities": Counter(),
        }

    @staticmethod
    def _new_edge(source: str, target: str, timestamp: float) -> dict[str, Any]:
        return {
            "id": f"{source}|{target}",
            "source": source,
            "target": target,
            "packet_count": 0,
            "bytes": 0,
            "protocols": Counter(),
            "_first_seen_epoch": timestamp,
            "_last_seen_epoch": timestamp,
            "_demo_packet_count": 0,
            "_demo_bytes": 0,
            "_demo_protocols": Counter(),
        }

    @staticmethod
    def _update_node(
        node: dict[str, Any],
        protocol: str,
        packet_count: int,
        byte_count: int,
        timestamp: float,
        sent: bool,
        is_demo: bool,
    ) -> None:
        node["packet_count"] += packet_count
        node["sent_packets" if sent else "received_packets"] += packet_count
        node["bytes"] += byte_count
        node["protocols"][protocol] += packet_count
        node["_last_seen_epoch"] = timestamp
        if is_demo:
            node["_demo_packet_count"] += packet_count
            node["_demo_sent_packets" if sent else "_demo_received_packets"] += packet_count
            node["_demo_bytes"] += byte_count
            node["_demo_protocols"][protocol] += packet_count

    @staticmethod
    def _highest_alert_status(severities: Counter[str]) -> str:
        if severities["CRITICAL"]:
            return "CRITICAL"
        if severities["WARNING"]:
            return "WARNING"
        return "NORMAL"

    def _ensure_node_capacity_locked(self, address: str, protected: set[str] | None = None) -> None:
        if address in self._nodes or len(self._nodes) < self.max_nodes:
            return
        protected = protected or set()
        candidates = [node for node in self._nodes if node not in protected]
        if not candidates:
            return
        oldest = min(candidates, key=lambda node: self._nodes[node]["_last_seen_epoch"])
        self._remove_node_locked(oldest)

    def _remove_node_locked(self, address: str) -> None:
        self._nodes.pop(address, None)
        for edge_key in [key for key in self._edges if address in key]:
            del self._edges[edge_key]

    def _cleanup_locked(self, now: float) -> None:
        edge_cutoff = now - self.edge_ttl_seconds
        for key in [key for key, edge in self._edges.items() if edge["_last_seen_epoch"] < edge_cutoff]:
            del self._edges[key]

        connected = {address for key in self._edges for address in key}
        node_cutoff = now - self.node_ttl_seconds
        for address in [
            address for address, node in self._nodes.items()
            if address not in connected and node["_last_seen_epoch"] < node_cutoff
        ]:
            del self._nodes[address]

    @staticmethod
    def _format_timestamp(timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp).astimezone().isoformat(timespec="seconds")

    def _serialize_node(self, node: dict[str, Any]) -> dict[str, Any]:
        return {
            key: (dict(value) if key == "protocols" else value)
            for key, value in node.items()
            if not key.startswith("_")
        } | {
            "label": node["ip"],
            "first_seen": self._format_timestamp(node["_first_seen_epoch"]),
            "last_seen": self._format_timestamp(node["_last_seen_epoch"]),
            "protocol_names": list(node["protocols"].keys()),
        }

    def _serialize_edge(self, edge: dict[str, Any]) -> dict[str, Any]:
        return {
            key: (dict(value) if key == "protocols" else value)
            for key, value in edge.items()
            if not key.startswith("_")
        } | {
            "first_seen": self._format_timestamp(edge["_first_seen_epoch"]),
            "last_seen": self._format_timestamp(edge["_last_seen_epoch"]),
            "protocol_names": list(edge["protocols"].keys()),
            "edge_width": round(min(8.0, 1.0 + math.log10(edge["packet_count"] + 1) * 1.8), 2),
        }
