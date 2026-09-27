"""Tests for bounded storage, counters, and rolling metrics."""

from analysis.traffic_metrics import TrafficMetrics


def packet(protocol="TCP", size=100, marker=0):
    return {"protocol": protocol, "size": size, "marker": marker}


def test_counts_protocols_and_calculates_five_second_rates():
    metrics = TrafficMetrics()
    metrics.add_packet(packet("TCP", 100), received_at=100)
    metrics.add_packet(packet("DNS", 150), received_at=102)
    metrics.add_packet(packet("TCP", 50), received_at=104)

    snapshot = metrics.snapshot(now=104)

    assert snapshot["total_packets"] == 3
    assert snapshot["protocols"]["TCP"] == 2
    assert snapshot["protocols"]["DNS"] == 1
    assert snapshot["packets_per_second"] == 0.6
    assert snapshot["throughput_bps"] == 480.0


def test_recent_packet_storage_is_bounded_and_newest_first():
    metrics = TrafficMetrics(max_packets=3)
    for marker in range(5):
        metrics.add_packet(packet(marker=marker), received_at=marker)

    recent = metrics.recent_packets(limit=100)

    assert [item["marker"] for item in recent] == [4, 3, 2]
    assert metrics.snapshot(now=4)["total_packets"] == 5
    assert metrics.snapshot(now=4)["stored_packets"] == 3


def test_unknown_protocol_is_safely_classified_as_other():
    metrics = TrafficMetrics()
    metrics.add_packet(packet("SCTP", 80), received_at=10)

    assert metrics.snapshot(now=10)["protocols"]["Other"] == 1
    assert metrics.recent_packets()[0]["protocol"] == "Other"


def test_history_contains_rolling_zero_filled_seconds():
    metrics = TrafficMetrics(history_seconds=20)
    metrics.add_packet(packet(), received_at=98)
    metrics.add_packet(packet(), received_at=100)

    history = metrics.snapshot(now=100, chart_seconds=10)["history"]

    assert len(history) == 10
    assert history[-1]["packets"] == 1
    assert history[-3]["packets"] == 1
    assert history[-2]["packets"] == 0

