"""Synthetic unit tests for explainable anomaly detection."""

from detection.alert_store import AlertStore
from detection.port_scan_detector import PortScanDetector
from detection.traffic_spike_detector import TrafficSpikeDetector


def connection(port: int, source: str = "198.51.100.2", destination: str = "192.0.2.5"):
    return {
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        "size": 60,
    }


def test_normal_connections_do_not_trigger_port_scan_alert():
    detector = PortScanDetector(port_threshold=5, window_seconds=10)

    alerts = [detector.observe(connection(port), observed_at=port) for port in range(4)]

    assert all(alert is None for alert in alerts)


def test_many_unique_ports_inside_window_trigger_port_scan_alert():
    detector = PortScanDetector(port_threshold=5, window_seconds=10)

    alert = None
    for index, port in enumerate((21, 22, 23, 25, 80)):
        alert = detector.observe(connection(port), observed_at=100 + index)

    assert alert is not None
    assert alert["type"] == "PORT_SCAN"
    assert alert["metric"] == 5
    assert alert["severity"] == "WARNING"


def test_established_tcp_responses_are_not_counted_as_scan_attempts():
    detector = PortScanDetector(port_threshold=2, window_seconds=10)
    first = {**connection(50000), "transport_protocol": "TCP", "tcp_flags": "SA"}
    second = {**connection(50001), "transport_protocol": "TCP", "tcp_flags": "A"}

    assert detector.observe(first, observed_at=0) is None
    assert detector.observe(second, observed_at=1) is None


def test_ports_outside_rolling_window_do_not_trigger_alert():
    detector = PortScanDetector(port_threshold=3, window_seconds=5)
    detector.observe(connection(21), observed_at=0)
    detector.observe(connection(22), observed_at=1)

    assert detector.observe(connection(23), observed_at=20) is None
    assert detector.observe(connection(24), observed_at=21) is None


def test_port_scan_duplicate_alerts_respect_cooldown_but_allow_escalation():
    detector = PortScanDetector(
        port_threshold=3,
        window_seconds=10,
        cooldown_seconds=60,
        critical_multiplier=2,
    )
    alerts = [detector.observe(connection(1000 + index), observed_at=index) for index in range(7)]

    assert alerts[2]["severity"] == "WARNING"
    assert alerts[3] is None
    assert alerts[4] is None
    assert alerts[5]["severity"] == "CRITICAL"
    assert alerts[6] is None


def make_spike_detector(cooldown=60):
    return TrafficSpikeDetector(
        baseline_window=10,
        minimum_samples=5,
        spike_multiplier=3,
        critical_multiplier=6,
        minimum_baseline_pps=5,
        cooldown_seconds=cooldown,
    )


def test_stable_traffic_does_not_trigger_spike_alert():
    detector = make_spike_detector()

    alerts = [detector.evaluate_sample(20 + index % 2, observed_at=index) for index in range(20)]

    assert all(alert is None for alert in alerts)
    assert detector.snapshot()["baseline_ready"] is True


def test_sudden_synthetic_increase_triggers_spike_alert():
    detector = make_spike_detector()
    for index in range(5):
        detector.evaluate_sample(20, observed_at=index)

    alert = detector.evaluate_sample(80, observed_at=6)

    assert alert is not None
    assert alert["type"] == "TRAFFIC_SPIKE"
    assert alert["metadata"]["increase_ratio"] == 4.0
    assert alert["severity"] == "WARNING"


def test_warmup_does_not_create_false_spike_alert():
    detector = make_spike_detector()

    assert detector.evaluate_sample(20, observed_at=0) is None
    assert detector.evaluate_sample(500, observed_at=1) is None
    assert detector.snapshot()["baseline_ready"] is False


def test_spike_cooldown_and_severity_rules():
    detector = make_spike_detector(cooldown=60)
    for index in range(5):
        detector.evaluate_sample(20, observed_at=index)

    first = detector.evaluate_sample(140, observed_at=10)
    duplicate = detector.evaluate_sample(160, observed_at=11)

    assert first["severity"] == "CRITICAL"
    assert duplicate is None
    assert detector.severity_for_ratio(3.5) == "WARNING"
    assert detector.severity_for_ratio(6.0) == "CRITICAL"


def test_alert_storage_remains_bounded_and_counts_severity():
    store = AlertStore(max_alerts=3)
    for index in range(5):
        store.add({
            "type": "TEST",
            "severity": "CRITICAL" if index == 4 else "INFO",
            "title": f"Alert {index}",
            "description": "Synthetic test alert",
        }, timestamp=index)

    assert len(store.recent(100)) == 3
    assert store.summary()["total"] == 3
    assert store.summary()["total_created"] == 5
    assert store.summary()["critical"] == 1
