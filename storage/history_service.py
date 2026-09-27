"""Background aggregate sampling, analytics composition, and report generation."""

from __future__ import annotations

import atexit
from collections import Counter
import csv
from io import StringIO
import logging
from threading import Event, Lock, RLock, Thread, current_thread
import time
from typing import Any
from uuid import uuid4

from detection.alert_store import AlertStore
from detection.traffic_spike_detector import TrafficSpikeDetector
from storage.repositories import HistoryRepository, RANGE_SECONDS


logger = logging.getLogger(__name__)


PROTOCOL_COLUMNS = {
    "TCP": "tcp_packets",
    "UDP": "udp_packets",
    "DNS": "dns_packets",
    "HTTP": "http_packets",
    "ICMP": "icmp_packets",
    "Other": "other_packets",
}


class HistoryAccumulator:
    """Collect one interval of packet metadata without any database I/O."""

    def __init__(self, started_at: float | None = None) -> None:
        self._lock = RLock()
        self._started_at = float(started_at if started_at is not None else time.time())
        self._reset_bucket()

    def _reset_bucket(self) -> None:
        self._packets = 0
        self._bytes = 0
        self._protocols: Counter[str] = Counter()
        self._source_ips: set[str] = set()
        self._destination_ips: set[str] = set()
        self._ips: dict[str, dict[str, int]] = {}
        self._connections: dict[tuple[str, str], dict[str, Any]] = {}

    def observe_packet(self, packet: dict[str, Any]) -> None:
        protocol = str(packet.get("protocol", "Other"))
        if protocol not in PROTOCOL_COLUMNS:
            protocol = "Other"
        try:
            packet_size = max(0, int(packet.get("size", 0)))
        except (TypeError, ValueError):
            packet_size = 0
        source = str(packet["source_ip"]) if packet.get("source_ip") else None
        destination = str(packet["destination_ip"]) if packet.get("destination_ip") else None

        with self._lock:
            self._packets += 1
            self._bytes += packet_size
            self._protocols[protocol] += 1
            if source:
                self._source_ips.add(source)
                stats = self._ips.setdefault(source, self._new_ip_stats())
                stats["packets"] += 1
                stats["bytes"] += packet_size
                stats["sent_packets"] += 1
            if destination:
                self._destination_ips.add(destination)
                stats = self._ips.setdefault(destination, self._new_ip_stats())
                stats["packets"] += 1
                stats["bytes"] += packet_size
                stats["received_packets"] += 1
            if source and destination and source != destination:
                key = tuple(sorted((source, destination)))
                connection = self._connections.setdefault(key, {
                    "packets": 0,
                    "bytes": 0,
                    "protocols": Counter(),
                })
                connection["packets"] += 1
                connection["bytes"] += packet_size
                connection["protocols"][protocol] += 1

    def observe_alert(self, alert: dict[str, Any]) -> None:
        address = alert.get("source_ip") or alert.get("destination_ip")
        if not address:
            return
        with self._lock:
            self._ips.setdefault(str(address), self._new_ip_stats())["alert_count"] += 1

    @staticmethod
    def _new_ip_stats() -> dict[str, int]:
        return {"packets": 0, "bytes": 0, "sent_packets": 0, "received_packets": 0, "alert_count": 0}

    def drain(self, timestamp: float | None = None) -> dict[str, Any]:
        now = float(timestamp if timestamp is not None else time.time())
        with self._lock:
            elapsed = max(0.001, now - self._started_at)
            result = {
                "started_at": self._started_at,
                "timestamp": now,
                "interval_seconds": elapsed,
                "total_packets": self._packets,
                "total_bytes": self._bytes,
                "protocols": dict(self._protocols),
                "unique_source_ips": len(self._source_ips),
                "unique_destination_ips": len(self._destination_ips),
                "ips": {key: value.copy() for key, value in self._ips.items()},
                "connections": {
                    key: {**value, "protocols": dict(value["protocols"])}
                    for key, value in self._connections.items()
                },
            }
            self._started_at = now
            self._reset_bucket()
            return result


class HistoryService:
    """Coordinate periodic samples, persistence, analytics, and safe demo history."""

    def __init__(
        self,
        repository: HistoryRepository,
        alert_store: AlertStore,
        traffic_detector: TrafficSpikeDetector,
        sample_interval_seconds: int = 10,
        history_retention_days: int = 7,
        alert_retention_days: int = 30,
        cleanup_interval_seconds: int = 3600,
        status_window_seconds: int = 120,
    ) -> None:
        self.repository = repository
        self.alert_store = alert_store
        self.traffic_detector = traffic_detector
        self.sample_interval_seconds = sample_interval_seconds
        self.history_retention_days = history_retention_days
        self.alert_retention_days = alert_retention_days
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self.status_window_seconds = status_window_seconds
        self.accumulator = HistoryAccumulator()
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._start_lock = Lock()
        self._last_cleanup = 0.0
        self._atexit_registered = False

    def start(self) -> None:
        """Start one daemon sampler; repeated calls are harmless."""
        with self._start_lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = Thread(target=self._run, name="history-sampler", daemon=True)
            self._thread.start()
            if not self._atexit_registered:
                atexit.register(self.stop)
                self._atexit_registered = True

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not current_thread():
            thread.join(timeout=min(2, self.sample_interval_seconds + 0.5))

    def _run(self) -> None:
        while not self._stop_event.wait(self.sample_interval_seconds):
            try:
                self.sample_once()
                self.cleanup_if_due()
            except Exception:
                # Capture and Flask must remain available if a transient database
                # error occurs; the next interval will retry with a new connection.
                logger.exception("Historical sampler failed; retrying next interval")
                continue

    def observe_packet(self, packet: dict[str, Any]) -> None:
        self.accumulator.observe_packet(packet)

    def record_alert(self, alert: dict[str, Any]) -> None:
        self.repository.insert_alert(alert)
        # Synthetic alert counts must never leak into the next real IP bucket
        # after Clear Demo Data. Demo history supplies its own marked IP rows.
        if not alert.get("is_demo", False):
            self.accumulator.observe_alert(alert)

    def sample_once(self, timestamp: float | None = None) -> dict[str, Any]:
        bucket = self.accumulator.drain(timestamp)
        elapsed = bucket["interval_seconds"]
        total_packets = bucket["total_packets"]
        total_bytes = bucket["total_bytes"]
        baseline = self.traffic_detector.snapshot()["baseline_pps"]
        status = self.alert_store.network_status(bucket["timestamp"], self.status_window_seconds)
        sample = {
            "timestamp": bucket["timestamp"],
            "interval_seconds": elapsed,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "packets_per_second": round(total_packets / elapsed, 2),
            "bytes_per_second": round(total_bytes / elapsed, 2),
            "throughput_bps": round(total_bytes * 8 / elapsed, 2),
            "unique_source_ips": bucket["unique_source_ips"],
            "unique_destination_ips": bucket["unique_destination_ips"],
            "baseline_packets_per_second": baseline,
            "network_status": status,
            "is_demo": False,
        }
        for protocol, column in PROTOCOL_COLUMNS.items():
            sample[column] = bucket["protocols"].get(protocol, 0)
        ip_rows = [
            {"timestamp": bucket["timestamp"], "ip_address": address, **stats, "is_demo": False}
            for address, stats in bucket["ips"].items()
        ]
        connection_rows = [
            {
                "timestamp": bucket["timestamp"],
                "source_ip": key[0],
                "destination_ip": key[1],
                **stats,
                "is_demo": False,
            }
            for key, stats in bucket["connections"].items()
        ]
        self.repository.insert_sample(sample, ip_rows, connection_rows)
        logger.debug(
            "Stored history sample: packets=%s bytes=%s ips=%s connections=%s",
            total_packets, total_bytes, len(ip_rows), len(connection_rows),
        )
        return sample

    def cleanup_if_due(self, now: float | None = None, force: bool = False) -> dict[str, int] | None:
        current = float(now if now is not None else time.time())
        if not force and current - self._last_cleanup < self.cleanup_interval_seconds:
            return None
        self._last_cleanup = current
        deleted = self.repository.cleanup(
            current - self.history_retention_days * 86400,
            current - self.alert_retention_days * 86400,
        )
        if any(deleted.values()):
            logger.info("Historical retention cleanup removed rows: %s", deleted)
        return deleted

    def restore_alerts(self, limit: int = 500) -> int:
        restored = self.repository.load_recent_alerts(limit)
        for alert in restored:
            self.alert_store.add(alert, timestamp=alert["timestamp_epoch"], alert_id=alert["id"])
        return len(restored)

    def analytics(self, range_key: str, now: float | None = None) -> dict[str, Any]:
        traffic = self.repository.traffic(range_key, now)
        return {
            "range": range_key,
            "range_seconds": RANGE_SECONDS[range_key],
            "summary": self.repository.summary(range_key, now),
            "traffic": self.downsample(traffic),
            "protocols": self.repository.protocols(range_key, now),
            "alerts": self.repository.alert_analytics(range_key, now),
            "comparison": self.repository.comparison(range_key, now),
            "top_talkers": self.repository.top_talkers(range_key, now),
            "top_connections": self.repository.top_connections(range_key, now),
        }

    @staticmethod
    def downsample(rows: list[dict[str, Any]], max_points: int = 720) -> list[dict[str, Any]]:
        if len(rows) <= max_points:
            return rows
        chunk_size = (len(rows) + max_points - 1) // max_points
        result = []
        status_rank = {"NORMAL": 0, "UNUSUAL ACTIVITY": 1, "WARNING": 2, "CRITICAL": 3}
        for start in range(0, len(rows), chunk_size):
            chunk = rows[start:start + chunk_size]
            representative = dict(chunk[-1])
            representative["packets_per_second"] = round(max(row["packets_per_second"] for row in chunk), 2)
            representative["baseline_packets_per_second"] = round(
                sum(row["baseline_packets_per_second"] for row in chunk) / len(chunk), 2
            )
            representative["throughput_bps"] = round(max(row["throughput_bps"] for row in chunk), 2)
            representative["network_status"] = max(chunk, key=lambda row: status_rank.get(row["network_status"], 0))["network_status"]
            result.append(representative)
        return result

    def generate_demo_history(self, now: float | None = None) -> dict[str, int]:
        """Insert a repeatable 30-minute synthetic timeline without network traffic."""
        current = float(now if now is not None else time.time())
        self.clear_demo_data()
        interval = 10
        points = 180
        start = current - (points - 1) * interval
        samples: list[dict[str, Any]] = []
        ip_rows: list[dict[str, Any]] = []
        connection_rows: list[dict[str, Any]] = []
        baseline = 30.0

        for index in range(points):
            timestamp = start + index * interval
            if index < 75:
                pps = 27 + index % 7
                status = "NORMAL"
            elif index < 100:
                pps = 35 + (index - 75) * 2.2
                status = "NORMAL"
            elif index == 100:
                pps = 240
                status = "CRITICAL"
            elif index < 113:
                pps = 82 - (index - 101) * 2.5
                status = "CRITICAL"
            elif index < 126:
                pps = 48 - (index - 113) * 1.2
                status = "WARNING"
            else:
                pps = 29 + index % 5
                status = "NORMAL"
            packet_count = max(0, round(pps * interval))
            total_bytes = packet_count * (420 + index % 9 * 20)
            tcp = round(packet_count * .48)
            udp = round(packet_count * .17)
            dns = round(packet_count * .14)
            http = round(packet_count * .15)
            icmp = round(packet_count * .03)
            other = packet_count - tcp - udp - dns - http - icmp
            samples.append({
                "timestamp": timestamp,
                "interval_seconds": interval,
                "total_packets": packet_count,
                "total_bytes": total_bytes,
                "packets_per_second": round(pps, 2),
                "bytes_per_second": round(total_bytes / interval, 2),
                "throughput_bps": round(total_bytes * 8 / interval, 2),
                "tcp_packets": tcp,
                "udp_packets": udp,
                "dns_packets": dns,
                "http_packets": http,
                "icmp_packets": icmp,
                "other_packets": other,
                "unique_source_ips": 3,
                "unique_destination_ips": 3,
                "baseline_packets_per_second": baseline,
                "network_status": status,
                "is_demo": True,
            })
            shares = (("192.168.1.10", .46), ("192.168.1.20", .34), ("8.8.8.8", .20))
            allocated_packets = 0
            allocated_bytes = 0
            for position, (address, share) in enumerate(shares):
                packets = packet_count - allocated_packets if position == 2 else round(packet_count * share)
                byte_count = total_bytes - allocated_bytes if position == 2 else round(total_bytes * share)
                allocated_packets += packets
                allocated_bytes += byte_count
                ip_rows.append({
                    "timestamp": timestamp,
                    "ip_address": address,
                    "packets": packets,
                    "bytes": byte_count,
                    "sent_packets": round(packets * (.7 if address != "8.8.8.8" else .25)),
                    "received_packets": packets - round(packets * (.7 if address != "8.8.8.8" else .25)),
                    "alert_count": 1 if address == "192.168.1.20" and index == 108 else 0,
                    "is_demo": True,
                })
            first_packets = round(packet_count * .62)
            first_bytes = round(total_bytes * .62)
            connection_rows.extend([
                {
                    "timestamp": timestamp, "source_ip": "192.168.1.10", "destination_ip": "8.8.8.8",
                    "packets": first_packets, "bytes": first_bytes, "protocols": {"DNS": dns, "TCP": max(0, first_packets - dns)}, "is_demo": True,
                },
                {
                    "timestamp": timestamp, "source_ip": "192.168.1.10", "destination_ip": "192.168.1.20",
                    "packets": packet_count - first_packets, "bytes": total_bytes - first_bytes,
                    "protocols": {"TCP": max(0, packet_count - first_packets)}, "is_demo": True,
                },
            ])

        alerts = [
            {
                "id": str(uuid4()), "timestamp_epoch": start + 100 * interval,
                "type": "TRAFFIC_SPIKE", "severity": "CRITICAL", "title": "Synthetic Traffic Spike",
                "description": "Demo traffic reached 240.0 packets/sec compared with a 30.0 packets/sec baseline (8.0x increase).",
                "source_ip": None, "destination_ip": None, "metric": 240.0, "threshold": 90.0,
                "metadata": {"baseline_pps": 30.0, "increase_ratio": 8.0}, "is_demo": True,
            },
            {
                "id": str(uuid4()), "timestamp_epoch": start + 108 * interval,
                "type": "PORT_SCAN", "severity": "WARNING", "title": "Synthetic Port-Scan Pattern",
                "description": "Demo source contacted 18 unique destination ports within 10 seconds.",
                "source_ip": "192.168.1.20", "destination_ip": "192.168.1.10", "metric": 18, "threshold": 15,
                "metadata": {"window_seconds": 10, "unique_ports": 18}, "is_demo": True,
            },
        ]
        self.repository.insert_dataset(samples, ip_rows, connection_rows, alerts)
        for alert in alerts:
            self.alert_store.add(alert, timestamp=alert["timestamp_epoch"], alert_id=alert["id"])
        result = {"samples": len(samples), "ip_rows": len(ip_rows), "connections": len(connection_rows), "alerts": len(alerts)}
        logger.info("Generated synthetic history: %s", result)
        return result

    def clear_demo_data(self) -> dict[str, int]:
        deleted = self.repository.clear_demo_data()
        deleted["memory_alerts"] = self.alert_store.clear_demo()
        logger.info("Cleared synthetic historical data: %s", deleted)
        return deleted

    def csv_report(self, range_key: str, now: float | None = None) -> str:
        data = self.analytics(range_key, now)
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["SMART NETWORK TRAFFIC ANALYZER"])
        writer.writerow(["Historical Traffic Report", range_key])
        writer.writerow([])
        if not data["summary"]["has_data"]:
            writer.writerow(["No historical data available for the selected period."])
            return output.getvalue()

        writer.writerow(["TRAFFIC SUMMARY"])
        for key in ("total_packets", "total_bytes", "average_pps", "peak_pps", "average_throughput_bps", "total_alerts", "critical_alerts"):
            writer.writerow([key, data["summary"][key]])
        writer.writerow([])
        writer.writerow(["PROTOCOL STATISTICS"])
        writer.writerow(["protocol", "packets"])
        for protocol, count in data["protocols"].items():
            writer.writerow([protocol, count])
        writer.writerow([])
        writer.writerow(["NORMAL VS ABNORMAL"])
        writer.writerow(["classification", "intervals", "percentage", "average_pps", "peak_pps"])
        writer.writerow(["Normal", data["comparison"]["normal"]["intervals"], data["comparison"]["normal_percent"], data["comparison"]["normal"]["average_pps"], data["comparison"]["normal"]["peak_pps"]])
        writer.writerow(["Abnormal", data["comparison"]["abnormal"]["intervals"], data["comparison"]["abnormal_percent"], data["comparison"]["abnormal"]["average_pps"], data["comparison"]["abnormal"]["peak_pps"]])
        writer.writerow([])
        writer.writerow(["ALERT SUMMARY"])
        writer.writerow(["category", "count"])
        writer.writerow(["Total", data["alerts"]["total"]])
        for alert_type, count in data["alerts"]["by_type"].items():
            writer.writerow([alert_type, count])
        for severity, count in data["alerts"]["by_severity"].items():
            writer.writerow([severity, count])
        writer.writerow(["Most frequently alerted source", data["alerts"]["most_frequently_alerted_source"] or ""])
        writer.writerow([])
        writer.writerow(["TOP TALKERS"])
        writer.writerow(["ip_address", "packets", "bytes", "sent_packets", "received_packets", "alert_count"])
        for row in data["top_talkers"]:
            writer.writerow([row["ip_address"], row["packets"], row["bytes"], row["sent_packets"], row["received_packets"], row["alert_count"]])
        writer.writerow([])
        writer.writerow(["TOP CONNECTIONS"])
        writer.writerow(["source_ip", "destination_ip", "packets", "bytes"])
        for row in data["top_connections"]:
            writer.writerow([row["source_ip"], row["destination_ip"], row["packets"], row["bytes"]])
        writer.writerow([])
        writer.writerow(["ALERT HISTORY"])
        writer.writerow(["timestamp", "severity", "type", "source_ip", "destination_ip", "title", "description", "is_demo"])
        for alert in data["alerts"]["timeline"]:
            writer.writerow([alert["timestamp_iso"], alert["severity"], alert["type"], alert.get("source_ip") or "", alert.get("destination_ip") or "", alert["title"], alert["description"], int(alert["is_demo"])])
        return output.getvalue()
