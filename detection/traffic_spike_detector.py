"""Moving-average traffic spike detector."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from threading import RLock
import time
from typing import Any

from detection.baseline import RollingBaseline


class TrafficSpikeDetector:
    """Compare completed one-second packet counts with a rolling baseline."""

    def __init__(
        self,
        baseline_window: int = 30,
        minimum_samples: int = 10,
        spike_multiplier: float = 3.0,
        critical_multiplier: float = 6.0,
        minimum_baseline_pps: float = 5.0,
        cooldown_seconds: int = 60,
        history_size: int = 120,
    ) -> None:
        self.spike_multiplier = spike_multiplier
        self.critical_multiplier = critical_multiplier
        self.minimum_baseline_pps = minimum_baseline_pps
        self.cooldown_seconds = cooldown_seconds
        self._baseline = RollingBaseline(baseline_window, minimum_samples)
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._current_second: int | None = None
        self._current_packets = 0
        self._current_bytes = 0
        self._last_alert = float("-inf")
        self._lock = RLock()

    def observe_packet(self, packet_size: int, observed_at: float | None = None) -> list[dict[str, Any]]:
        """Add one packet and evaluate the previous completed second if needed."""
        now_second = int(observed_at if observed_at is not None else time.time())
        alerts: list[dict[str, Any]] = []
        with self._lock:
            if self._current_second is None:
                self._current_second = now_second
            elif now_second > self._current_second:
                alert = self._evaluate_sample_locked(
                    self._current_packets,
                    self._current_bytes,
                    self._current_second,
                )
                if alert:
                    alerts.append(alert)
                # A gap longer than the baseline window means the earlier traffic
                # is no longer representative of the current session.
                if now_second - self._current_second > self._baseline.window_size:
                    self._baseline.reset()
                self._current_second = now_second
                self._current_packets = 0
                self._current_bytes = 0
            elif now_second < self._current_second:
                return alerts

            self._current_packets += 1
            try:
                self._current_bytes += max(0, int(packet_size))
            except (TypeError, ValueError):
                pass
        return alerts

    def evaluate_sample(
        self,
        packets_per_second: float,
        bytes_per_second: float = 0,
        observed_at: float | None = None,
    ) -> dict[str, Any] | None:
        """Evaluate an already aggregated sample, primarily for tests and demo mode."""
        timestamp = float(observed_at if observed_at is not None else time.time())
        with self._lock:
            return self._evaluate_sample_locked(packets_per_second, bytes_per_second, timestamp)

    def _evaluate_sample_locked(
        self,
        packets_per_second: float,
        bytes_per_second: float,
        timestamp: float,
    ) -> dict[str, Any] | None:
        current = max(0.0, float(packets_per_second))
        baseline = self._baseline.average
        ready = self._baseline.ready and baseline >= self.minimum_baseline_pps
        ratio = current / baseline if baseline > 0 else 0.0
        is_spike = ready and ratio >= self.spike_multiplier

        self._history.append({
            "timestamp": int(timestamp),
            "time": time.strftime("%H:%M:%S", time.localtime(timestamp)),
            "current_pps": round(current, 2),
            "baseline_pps": round(baseline, 2),
        })

        # Do not teach the baseline that a detected anomalous spike is normal.
        if not is_spike:
            self._baseline.add(current)

        if not is_spike or timestamp - self._last_alert < self.cooldown_seconds:
            return None
        self._last_alert = timestamp
        severity = self.severity_for_ratio(ratio)
        return {
            "type": "TRAFFIC_SPIKE",
            "severity": severity,
            "title": "Traffic Spike Detected",
            "description": (
                f"Traffic reached {current:.1f} packets/sec compared with a "
                f"{baseline:.1f} packets/sec baseline ({ratio:.1f}x increase)."
            ),
            "source_ip": None,
            "destination_ip": None,
            "metric": round(current, 2),
            "threshold": round(baseline * self.spike_multiplier, 2),
            "metadata": {
                "baseline_pps": round(baseline, 2),
                "increase_ratio": round(ratio, 2),
                "bytes_per_second": round(float(bytes_per_second), 2),
                "baseline_samples": self._baseline.sample_count,
                "minimum_samples_required": self._baseline.minimum_samples,
            },
        }

    def severity_for_ratio(self, ratio: float) -> str:
        return "CRITICAL" if ratio >= self.critical_multiplier else "WARNING"

    @property
    def minimum_samples(self) -> int:
        return self._baseline.minimum_samples

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            baseline = self._baseline.average
            current = float(self._current_packets)
            return {
                "baseline_pps": round(baseline, 2),
                "baseline_samples": self._baseline.sample_count,
                "baseline_ready": self._baseline.ready,
                "minimum_samples_required": self._baseline.minimum_samples,
                "current_second_packets": round(current, 2),
                "deviation_ratio": round(current / baseline, 2) if baseline > 0 else 0.0,
                "spike_multiplier": self.spike_multiplier,
                "history": deepcopy(list(self._history)),
            }

    def reset(self) -> None:
        with self._lock:
            self._baseline.reset()
            self._history.clear()
            self._current_second = None
            self._current_packets = 0
            self._current_bytes = 0
            self._last_alert = float("-inf")
