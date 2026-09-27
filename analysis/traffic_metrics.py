"""Thread-safe, bounded storage and basic traffic metrics."""

from __future__ import annotations

from collections import Counter, deque
from copy import deepcopy
from threading import RLock
import time
from typing import Any


PROTOCOLS = ("TCP", "UDP", "DNS", "HTTP", "ICMP", "Other")


class TrafficMetrics:
    """Store recent packet rows and calculate dashboard values."""

    def __init__(self, max_packets: int = 1000, history_seconds: int = 120) -> None:
        self.max_packets = max_packets
        self.history_seconds = history_seconds
        self._packets: deque[dict[str, Any]] = deque(maxlen=max_packets)
        self._protocol_counts: Counter[str] = Counter()
        self._second_buckets: dict[int, dict[str, int]] = {}
        self._total_packets = 0
        self._first_packet_second: int | None = None
        self._lock = RLock()

    def add_packet(self, packet: dict[str, Any], received_at: float | None = None) -> None:
        """Add a parsed packet and update counters atomically."""
        now_second = int(received_at if received_at is not None else time.time())
        protocol = packet.get("protocol", "Other")
        if protocol not in PROTOCOLS:
            protocol = "Other"
            packet = {**packet, "protocol": protocol}

        try:
            packet_size = max(0, int(packet.get("size", 0)))
        except (TypeError, ValueError):
            packet_size = 0

        with self._lock:
            self._packets.append(packet)
            self._total_packets += 1
            self._protocol_counts[protocol] += 1
            if self._first_packet_second is None:
                self._first_packet_second = now_second

            bucket = self._second_buckets.setdefault(now_second, {
                "packets": 0,
                "bytes": 0,
                "source_ips": set(),
                "destination_ips": set(),
            })
            bucket["packets"] += 1
            bucket["bytes"] += packet_size
            if packet.get("source_ip"):
                bucket["source_ips"].add(str(packet["source_ip"]))
            if packet.get("destination_ip"):
                bucket["destination_ips"].add(str(packet["destination_ip"]))
            cutoff = now_second - self.history_seconds
            for second in [key for key in self._second_buckets if key < cutoff]:
                del self._second_buckets[second]

    def recent_packets(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return newest packets first, with a safe upper limit."""
        safe_limit = max(1, min(int(limit), self.max_packets))
        with self._lock:
            packets = list(self._packets)[-safe_limit:]
            return deepcopy(list(reversed(packets)))

    def snapshot(self, now: float | None = None, chart_seconds: int = 60) -> dict[str, Any]:
        """Return a consistent statistics snapshot.

        Current rate and throughput use a rolling window of up to five seconds.
        Throughput is the bytes captured in that window multiplied by eight and
        divided by the window duration.
        """
        now_second = int(now if now is not None else time.time())
        chart_seconds = max(10, min(chart_seconds, self.history_seconds))

        with self._lock:
            rate_duration = 5
            if self._first_packet_second is not None:
                rate_duration = min(5, max(1, now_second - self._first_packet_second + 1))
            recent_buckets = [
                values
                for second, values in self._second_buckets.items()
                if now_second - rate_duration + 1 <= second <= now_second
            ]
            recent_packet_count = sum(item["packets"] for item in recent_buckets)
            recent_bytes = sum(item["bytes"] for item in recent_buckets)

            history = []
            for second in range(now_second - chart_seconds + 1, now_second + 1):
                bucket = self._second_buckets.get(second, {"packets": 0, "bytes": 0})
                history.append({
                    "timestamp": second,
                    "time": time.strftime("%H:%M:%S", time.localtime(second)),
                    "packets": bucket["packets"],
                })

            protocols = {name: self._protocol_counts[name] for name in PROTOCOLS}
            recent_ip_buckets = [
                values for second, values in self._second_buckets.items()
                if now_second - 59 <= second <= now_second
            ]
            source_ips = set().union(*(item["source_ips"] for item in recent_ip_buckets)) if recent_ip_buckets else set()
            destination_ips = set().union(*(item["destination_ips"] for item in recent_ip_buckets)) if recent_ip_buckets else set()
            return {
                "total_packets": self._total_packets,
                "protocols": protocols,
                "packets_per_second": round(recent_packet_count / rate_duration, 2),
                "throughput_bps": round((recent_bytes * 8) / rate_duration, 2),
                "history": history,
                "stored_packets": len(self._packets),
                "unique_source_ips": len(source_ips),
                "unique_destination_ips": len(destination_ips),
            }

    def reset(self) -> None:
        """Clear all collected traffic data."""
        with self._lock:
            self._packets.clear()
            self._protocol_counts.clear()
            self._second_buckets.clear()
            self._total_packets = 0
            self._first_packet_second = None
