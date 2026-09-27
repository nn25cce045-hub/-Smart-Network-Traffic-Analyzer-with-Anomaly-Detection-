"""Part 4 persistence, analytics, retention, and report tests."""

from __future__ import annotations

import sqlite3

import pytest

from detection.alert_store import AlertStore
from detection.traffic_spike_detector import TrafficSpikeDetector
from storage.database import Database
from storage.history_service import HistoryService
from storage.repositories import HistoryRepository, range_cutoff


NOW = 2_000_000_000.0


@pytest.fixture()
def history(tmp_path):
    database = Database(tmp_path / "history.db")
    database.initialize()
    repository = HistoryRepository(database)
    alerts = AlertStore()
    service = HistoryService(repository, alerts, TrafficSpikeDetector())
    return database, repository, alerts, service


def sample(timestamp, pps=20, status="NORMAL", demo=False):
    packets = int(pps * 10)
    return {
        "timestamp": timestamp,
        "interval_seconds": 10,
        "total_packets": packets,
        "total_bytes": packets * 100,
        "packets_per_second": pps,
        "bytes_per_second": pps * 100,
        "throughput_bps": pps * 800,
        "tcp_packets": packets // 2,
        "udp_packets": packets // 5,
        "dns_packets": packets // 10,
        "http_packets": packets // 10,
        "icmp_packets": packets // 20,
        "other_packets": packets - (packets // 2 + packets // 5 + packets // 10 + packets // 10 + packets // 20),
        "unique_source_ips": 2,
        "unique_destination_ips": 2,
        "baseline_packets_per_second": 20,
        "network_status": status,
        "is_demo": demo,
    }


def alert(alert_id, timestamp, demo=False):
    return {
        "id": alert_id,
        "timestamp_epoch": timestamp,
        "type": "PORT_SCAN",
        "severity": "WARNING",
        "title": "Port pattern",
        "description": "A source contacted many ports.",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "metric": 18,
        "threshold": 15,
        "metadata": {"unique_ports": 18},
        "is_demo": demo,
    }


def insert_complete_sample(repository, timestamp, pps=20, status="NORMAL", demo=False):
    repository.insert_sample(
        sample(timestamp, pps, status, demo),
        [{
            "timestamp": timestamp,
            "ip_address": "192.0.2.10",
            "packets": int(pps * 10),
            "bytes": int(pps * 1000),
            "sent_packets": int(pps * 6),
            "received_packets": int(pps * 4),
            "alert_count": int(status != "NORMAL"),
            "is_demo": demo,
        }],
        [{
            "timestamp": timestamp,
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.5",
            "packets": int(pps * 10),
            "bytes": int(pps * 1000),
            "protocols": {"TCP": int(pps * 10)},
            "is_demo": demo,
        }],
    )


def test_database_initializes_only_aggregate_tables(history):
    database, _, _, _ = history
    with sqlite3.connect(database.path) as connection:
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {"traffic_history", "ip_history", "connection_history", "alert_history"} <= tables
    assert not any("raw" in name or "payload" in name for name in tables)


def test_range_validation_and_time_filtering(history):
    _, repository, _, _ = history
    insert_complete_sample(repository, NOW - 100)
    insert_complete_sample(repository, NOW - 4000)

    assert len(repository.traffic("1h", NOW)) == 1
    assert len(repository.traffic("6h", NOW)) == 2
    with pytest.raises(ValueError):
        range_cutoff("all", NOW)


def test_summary_protocols_comparison_and_rankings(history):
    _, repository, _, _ = history
    insert_complete_sample(repository, NOW - 20, pps=20, status="NORMAL")
    insert_complete_sample(repository, NOW - 10, pps=60, status="CRITICAL")
    repository.insert_alert(alert("real-alert", NOW - 10))

    summary = repository.summary("1h", NOW)
    protocols = repository.protocols("1h", NOW)
    comparison = repository.comparison("1h", NOW)
    talkers = repository.top_talkers("1h", NOW)
    connections = repository.top_connections("1h", NOW)

    assert summary["sample_count"] == 2
    assert summary["average_pps"] == 40
    assert summary["peak_pps"] == 60
    assert summary["total_alerts"] == 1
    assert sum(protocols.values()) == summary["total_packets"]
    assert comparison["normal_percent"] == 50
    assert comparison["abnormal_percent"] == 50
    assert comparison["anomaly_events"] == 1
    assert talkers[0]["ip_address"] == "192.0.2.10"
    assert talkers[0]["packets"] == 800
    assert connections[0]["source_ip"] == "192.0.2.10"
    assert connections[0]["packets"] == 800


def test_alerts_persist_and_restore_after_restart(history):
    database, repository, _, _ = history
    repository.insert_alert(alert("persisted-alert", NOW))

    restored_store = AlertStore()
    restored_service = HistoryService(
        HistoryRepository(Database(database.path)),
        restored_store,
        TrafficSpikeDetector(),
    )

    assert restored_service.restore_alerts() == 1
    assert restored_store.recent()[0]["id"] == "persisted-alert"
    assert restored_store.recent()[0]["metadata"]["unique_ports"] == 18


def test_accumulator_persists_one_aggregate_interval(history):
    database, repository, _, service = history
    service.accumulator = service.accumulator.__class__(started_at=NOW - 10)
    service.observe_packet({
        "protocol": "TCP", "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1", "size": 100,
    })
    service.observe_packet({
        "protocol": "DNS", "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.1", "size": 60,
    })

    stored = service.sample_once(NOW)
    rows = repository.traffic("15m", NOW)
    with sqlite3.connect(database.path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}

    assert stored["total_packets"] == 2
    assert stored["total_bytes"] == 160
    assert rows[0]["tcp_packets"] == 1
    assert rows[0]["dns_packets"] == 1
    assert "packets" not in tables and "raw_packets" not in tables


def test_retention_removes_old_rows_but_keeps_recent(history):
    _, repository, _, _ = history
    insert_complete_sample(repository, NOW - 100_000)
    insert_complete_sample(repository, NOW - 100)
    repository.insert_alert(alert("old", NOW - 200_000))
    repository.insert_alert(alert("new", NOW - 50))

    deleted = repository.cleanup(NOW - 86_400, NOW - 86_400)

    assert deleted == {"traffic": 1, "ips": 1, "connections": 1, "alerts": 1}
    assert len(repository.traffic("7d", NOW)) == 1
    assert [item["id"] for item in repository.alerts("7d", NOW)] == ["new"]


def test_demo_history_is_repeatable_and_clear_preserves_real_data(history):
    _, repository, alert_store, service = history
    insert_complete_sample(repository, NOW - 30, pps=12)
    real = alert_store.add(alert("real", NOW - 20), timestamp=NOW - 20, alert_id="real")
    repository.insert_alert(real)

    result = service.generate_demo_history(NOW)
    first_count = repository.summary("1h", NOW)["sample_count"]
    service.generate_demo_history(NOW)
    second_count = repository.summary("1h", NOW)["sample_count"]

    assert result == {"samples": 180, "ip_rows": 540, "connections": 360, "alerts": 2}
    assert first_count == second_count == 181
    assert repository.summary("1h", NOW)["critical_alerts"] == 1
    assert all(row["is_demo"] for row in repository.traffic("1h", NOW) if row["timestamp"] != NOW - 30)
    assert all(item["is_demo"] for item in repository.alerts("1h", NOW) if item["id"] != "real")
    deleted = service.clear_demo_data()
    assert deleted["traffic"] == 180
    assert repository.summary("1h", NOW)["sample_count"] == 1
    assert [item["id"] for item in repository.alerts("1h", NOW)] == ["real"]
    assert [item["id"] for item in alert_store.recent()] == ["real"]


def test_demo_alert_does_not_leak_into_real_ip_bucket(history):
    _, repository, _, service = history
    demo_alert = alert("demo-alert", NOW - 1, demo=True)

    service.record_alert(demo_alert)
    service.sample_once(NOW)
    service.clear_demo_data()

    assert repository.top_talkers("1h", NOW) == []
    assert repository.alerts("1h", NOW) == []


def test_csv_report_contains_stored_values_and_empty_message(history):
    _, repository, _, service = history
    assert "No historical data available" in service.csv_report("1h", NOW)

    insert_complete_sample(repository, NOW - 10, pps=42)
    repository.insert_alert(alert("csv-alert", NOW - 5))
    report = service.csv_report("1h", NOW)

    assert "TRAFFIC SUMMARY" in report
    assert "ALERT SUMMARY" in report
    assert "average_pps,42.0" in report
    assert "TOP TALKERS" in report
    assert "192.0.2.10" in report
    assert "csv-alert" not in report  # IDs are intentionally omitted from human reports.
    assert "A source contacted many ports." in report
