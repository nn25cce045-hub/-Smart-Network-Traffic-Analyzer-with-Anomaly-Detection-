"""Thread-safe bounded in-memory alert storage."""

from __future__ import annotations

from collections import Counter, deque
from copy import deepcopy
from datetime import datetime
from threading import RLock
import time
from typing import Any
from uuid import uuid4


SEVERITIES = ("INFO", "WARNING", "CRITICAL")


class AlertStore:
    """Keep recent structured alerts without unbounded memory growth."""

    def __init__(self, max_alerts: int = 500) -> None:
        self.max_alerts = max_alerts
        self._alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self._total_created = 0
        self._lock = RLock()

    def add(
        self,
        alert: dict[str, Any],
        timestamp: float | None = None,
        alert_id: str | None = None,
    ) -> dict[str, Any]:
        event_time = float(timestamp if timestamp is not None else time.time())
        severity = str(alert.get("severity", "INFO")).upper()
        if severity not in SEVERITIES:
            severity = "INFO"
        event_datetime = datetime.fromtimestamp(event_time).astimezone()
        stored = {
            "id": alert_id or str(alert.get("id") or uuid4()),
            "timestamp": event_datetime.isoformat(timespec="seconds"),
            "time": event_datetime.strftime("%H:%M:%S"),
            "timestamp_epoch": event_time,
            "type": str(alert.get("type", "GENERAL")).upper(),
            "severity": severity,
            "title": str(alert.get("title", "Traffic Notice")),
            "description": str(alert.get("description", "")),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "metric": alert.get("metric"),
            "threshold": alert.get("threshold"),
            "metadata": deepcopy(alert.get("metadata", {})),
            "is_demo": bool(alert.get("is_demo", False)),
        }
        with self._lock:
            self._alerts.append(stored)
            self._total_created += 1
        return deepcopy(stored)

    def recent(self, limit: int = 500) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), self.max_alerts))
        with self._lock:
            return deepcopy(list(reversed(list(self._alerts)[-safe_limit:])))

    def summary(self) -> dict[str, int]:
        with self._lock:
            counts = Counter(alert["severity"] for alert in self._alerts)
            return {
                "total": len(self._alerts),
                "total_created": self._total_created,
                "info": counts["INFO"],
                "warning": counts["WARNING"],
                "critical": counts["CRITICAL"],
            }

    def network_status(self, now: float | None = None, recent_seconds: int = 120) -> str:
        cutoff = float(now if now is not None else time.time()) - recent_seconds
        with self._lock:
            severities = {
                alert["severity"] for alert in self._alerts
                if alert["timestamp_epoch"] >= cutoff
            }
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "WARNING" in severities:
            return "WARNING"
        if "INFO" in severities:
            return "UNUSUAL ACTIVITY"
        return "NORMAL"

    def clear(self) -> None:
        with self._lock:
            self._alerts.clear()

    def clear_demo(self) -> int:
        """Remove only synthetic alerts, preserving real captured history."""
        with self._lock:
            retained = [alert for alert in self._alerts if not alert.get("is_demo", False)]
            removed = len(self._alerts) - len(retained)
            self._alerts = deque(retained, maxlen=self.max_alerts)
            return removed
