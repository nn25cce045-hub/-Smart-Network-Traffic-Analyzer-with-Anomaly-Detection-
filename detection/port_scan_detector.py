"""Passive detector for port-scan-like connection patterns."""

from __future__ import annotations

from threading import RLock
import time
from typing import Any


class PortScanDetector:
    """Track unique destination ports per source/destination pair."""

    def __init__(
        self,
        port_threshold: int = 15,
        window_seconds: int = 10,
        cooldown_seconds: int = 60,
        critical_multiplier: float = 2.0,
        max_tracked_pairs: int = 5000,
    ) -> None:
        self.port_threshold = port_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.critical_multiplier = critical_multiplier
        self.max_tracked_pairs = max_tracked_pairs
        self._activity: dict[tuple[str, str], dict[int, float]] = {}
        self._last_alert: dict[tuple[str, str], float] = {}
        self._last_severity: dict[tuple[str, str], str] = {}
        self._observations = 0
        self._lock = RLock()

    def observe(self, packet: dict[str, Any], observed_at: float | None = None) -> dict[str, Any] | None:
        """Return an alert payload when a pair crosses the unique-port threshold."""
        source = packet.get("source_ip")
        destination = packet.get("destination_ip")
        destination_port = packet.get("destination_port")
        if not source or not destination or destination_port is None:
            return None
        try:
            port = int(destination_port)
        except (TypeError, ValueError):
            return None
        if not 0 <= port <= 65535:
            return None

        # When TCP flags are available, count connection attempts (SYN without
        # ACK), not established response/data packets aimed at ephemeral ports.
        if packet.get("transport_protocol") == "TCP" and packet.get("tcp_flags") is not None:
            flags = str(packet["tcp_flags"])
            if "S" not in flags or "A" in flags:
                return None

        now = float(observed_at if observed_at is not None else time.time())
        cutoff = now - self.window_seconds
        key = (str(source), str(destination))
        with self._lock:
            self._observations += 1
            if self._observations % 256 == 0:
                self._remove_stale_pairs(cutoff)
            if key not in self._activity and len(self._activity) >= self.max_tracked_pairs:
                oldest_key = min(
                    self._activity,
                    key=lambda item: max(self._activity[item].values(), default=float("-inf")),
                )
                self._activity.pop(oldest_key, None)
                self._last_alert.pop(oldest_key, None)
                self._last_severity.pop(oldest_key, None)
            ports = self._activity.setdefault(key, {})
            for old_port in [item for item, seen_at in ports.items() if seen_at < cutoff]:
                del ports[old_port]
            ports[port] = now

            unique_count = len(ports)
            last_alert = self._last_alert.get(key, float("-inf"))
            severity = self.severity_for_count(unique_count)
            previous_severity = self._last_severity.get(key)
            severity_escalated = previous_severity == "WARNING" and severity == "CRITICAL"
            if unique_count < self.port_threshold or (
                now - last_alert < self.cooldown_seconds and not severity_escalated
            ):
                return None
            self._last_alert[key] = now
            self._last_severity[key] = severity

            return {
                "type": "PORT_SCAN",
                "severity": severity,
                "title": "Possible Port Scan",
                "description": (
                    f"Source {source} contacted {unique_count} unique destination ports on "
                    f"{destination} within {self.window_seconds} seconds."
                ),
                "source_ip": str(source),
                "destination_ip": str(destination),
                "metric": unique_count,
                "threshold": self.port_threshold,
                "metadata": {
                    "window_seconds": self.window_seconds,
                    "unique_ports": unique_count,
                },
            }

    def severity_for_count(self, unique_port_count: int) -> str:
        critical_at = self.port_threshold * self.critical_multiplier
        return "CRITICAL" if unique_port_count >= critical_at else "WARNING"

    def _remove_stale_pairs(self, cutoff: float) -> None:
        stale_keys = [
            key for key, ports in self._activity.items()
            if not ports or max(ports.values()) < cutoff
        ]
        for key in stale_keys:
            self._activity.pop(key, None)
            if cutoff - self._last_alert.get(key, cutoff) >= self.cooldown_seconds:
                self._last_alert.pop(key, None)
                self._last_severity.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._activity.clear()
            self._last_alert.clear()
            self._last_severity.clear()
            self._observations = 0
