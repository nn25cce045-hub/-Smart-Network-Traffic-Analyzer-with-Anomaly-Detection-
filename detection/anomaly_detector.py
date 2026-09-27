"""Coordinator connecting parsed packet metadata to detectors and alerts."""

from __future__ import annotations

import logging
import time
from typing import Any, TYPE_CHECKING

from analysis.traffic_metrics import TrafficMetrics
from detection.alert_store import AlertStore
from detection.port_scan_detector import PortScanDetector
from detection.traffic_spike_detector import TrafficSpikeDetector
from network.graph_manager import GraphManager

if TYPE_CHECKING:
    from storage.history_service import HistoryService


logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Run independent detectors and publish their structured alerts."""

    def __init__(
        self,
        metrics: TrafficMetrics,
        alert_store: AlertStore,
        port_scan_detector: PortScanDetector,
        traffic_spike_detector: TrafficSpikeDetector,
        graph_manager: GraphManager,
        history_service: HistoryService | None = None,
        status_window_seconds: int = 120,
    ) -> None:
        self.metrics = metrics
        self.alert_store = alert_store
        self.port_scan_detector = port_scan_detector
        self.traffic_spike_detector = traffic_spike_detector
        self.graph_manager = graph_manager
        self.history_service = history_service
        self.status_window_seconds = status_window_seconds

    def process_packet(self, packet: dict[str, Any], received_at: float | None = None) -> None:
        """Update metrics and the graph, then evaluate all anomaly detectors."""
        now = float(received_at if received_at is not None else time.time())
        self.metrics.add_packet(packet, received_at=now)
        self.graph_manager.observe_packet(packet, observed_at=now)
        if self.history_service:
            self.history_service.observe_packet(packet)

        port_alert = self.port_scan_detector.observe(packet, observed_at=now)
        if port_alert:
            self._record_alert(port_alert, now)

        for spike_alert in self.traffic_spike_detector.observe_packet(packet.get("size", 0), observed_at=now):
            self._record_alert(spike_alert, now)

    def _record_alert(self, alert: dict[str, Any], timestamp: float) -> dict[str, Any]:
        stored = self.alert_store.add(alert, timestamp=timestamp)
        logger.warning(
            "%s alert detected: %s (source=%s destination=%s)",
            stored["severity"], stored["type"], stored.get("source_ip"), stored.get("destination_ip"),
        )
        self.graph_manager.apply_alert(stored)
        if self.history_service:
            self.history_service.record_alert(stored)
        return stored

    def status(self, now: float | None = None) -> dict[str, Any]:
        return {
            "network_status": self.alert_store.network_status(now, self.status_window_seconds),
            "summary": self.alert_store.summary(),
            "recent_alerts": self.alert_store.recent(5),
            "traffic": self.traffic_spike_detector.snapshot(),
        }

    def simulate(self, scenario: str, now: float | None = None) -> dict[str, Any]:
        """Feed synthetic metadata to detectors without creating network traffic."""
        event_time = float(now if now is not None else time.time())
        scenario = scenario.lower().strip()

        if scenario == "normal":
            self.traffic_spike_detector.reset()
            start = event_time - 14
            for index in range(15):
                self.traffic_spike_detector.evaluate_sample(
                    24 + (index % 3),
                    bytes_per_second=(24 + (index % 3)) * 500,
                    observed_at=start + index,
                )
            self._populate_demo_graph(event_time)
            return {"scenario": scenario, "alerts_created": 0, "message": "Stable synthetic traffic established a normal baseline."}

        if scenario == "network":
            self._populate_demo_graph(event_time)
            return {"scenario": scenario, "alerts_created": 0, "message": "Synthetic network-map metadata was generated."}

        if scenario == "port_scan":
            self.port_scan_detector.reset()
            before = self.alert_store.summary()["total_created"]
            threshold = self.port_scan_detector.port_threshold
            for offset, port in enumerate(range(20000, 20000 + threshold)):
                packet = {
                    "source_ip": "198.51.100.25",
                    "destination_ip": "192.0.2.10",
                    "source_port": 45000 + offset,
                    "destination_port": port,
                    "transport_protocol": "TCP",
                    "tcp_flags": "S",
                    "protocol": "TCP",
                    "size": 60,
                }
                self.graph_manager.observe_packet(packet, observed_at=event_time + offset / 100, is_demo=True)
                alert = self.port_scan_detector.observe(packet, observed_at=event_time + offset / 100)
                if alert:
                    self._record_alert({**alert, "is_demo": True}, event_time)
            created = self.alert_store.summary()["total_created"] - before
            return {"scenario": scenario, "alerts_created": created, "message": "Synthetic port-scan-like metadata was evaluated."}

        if scenario == "traffic_spike":
            self.traffic_spike_detector.reset()
            before = self.alert_store.summary()["total_created"]
            minimum = self.traffic_spike_detector.minimum_samples
            start = event_time - minimum
            for index in range(minimum):
                self.traffic_spike_detector.evaluate_sample(40, 20000, start + index)
            alert = self.traffic_spike_detector.evaluate_sample(160, 80000, event_time)
            self.graph_manager.observe_flow("192.168.1.10", "8.8.8.8", "TCP", 160, 80000, event_time, is_demo=True)
            if alert:
                self._record_alert({**alert, "is_demo": True}, event_time)
            created = self.alert_store.summary()["total_created"] - before
            return {"scenario": scenario, "alerts_created": created, "message": "Synthetic traffic-spike samples were evaluated."}

        raise ValueError("Unknown demo scenario.")

    def _populate_demo_graph(self, event_time: float) -> None:
        self.graph_manager.observe_flow("192.168.1.10", "8.8.8.8", "DNS", 36, 26640, event_time, is_demo=True)
        self.graph_manager.observe_flow("192.168.1.20", "203.0.113.10", "HTTP", 22, 41800, event_time, is_demo=True)
        self.graph_manager.observe_flow("192.168.1.30", "192.168.1.10", "TCP", 18, 12600, event_time, is_demo=True)

    def reset_demo_state(self) -> dict[str, Any]:
        if self.history_service:
            history_deleted = self.history_service.clear_demo_data()
        else:
            history_deleted = {"memory_alerts": self.alert_store.clear_demo()}
        self.port_scan_detector.reset()
        self.traffic_spike_detector.reset()
        graph_deleted = self.graph_manager.clear_demo_data()
        return {"history": history_deleted, "graph": graph_deleted}
