"""Small API and page smoke tests that do not capture live traffic."""

import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": tmp_path / "app-test.db"})
    return app.test_client()


@pytest.mark.parametrize("path", ["/", "/packets", "/traffic", "/alerts", "/network", "/history"])
def test_pages_load(client, path):
    assert client.get(path).status_code == 200


def test_stats_has_expected_empty_shape(client):
    response = client.get("/api/stats")
    data = response.get_json()

    assert response.status_code == 200
    assert data["total_packets"] == 0
    assert data["capturing"] is False
    assert set(data["protocols"]) == {"TCP", "UDP", "DNS", "HTTP", "ICMP", "Other"}
    assert len(data["history"]) == 60


def test_packet_limit_validation(client):
    response = client.get("/api/packets?limit=invalid")

    assert response.status_code == 400
    assert "error" in response.get_json()
    assert response.get_json()["success"] is False


def test_capture_start_requires_interface(client):
    response = client.post("/api/capture/start", json={})

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_anomaly_apis_have_empty_initial_state(client):
    alerts = client.get("/api/alerts").get_json()
    status = client.get("/api/anomaly/status").get_json()
    baseline = client.get("/api/traffic/baseline").get_json()

    assert alerts["summary"]["total"] == 0
    assert status["network_status"] == "NORMAL"
    assert baseline["baseline_ready"] is False
    assert baseline["minimum_samples_required"] == 10
    assert baseline["unique_source_ips"] == 0


def test_synthetic_demo_creates_alert_without_capture(client):
    response = client.post("/api/demo/simulate", json={"scenario": "port_scan"})
    alerts = client.get("/api/alerts").get_json()

    assert response.status_code == 200
    assert response.get_json()["alerts_created"] == 1
    assert alerts["alerts"][0]["type"] == "PORT_SCAN"
    assert alerts["alerts"][0]["source_ip"] == "198.51.100.25"


def test_demo_network_and_unified_clear_preserve_real_graph(client):
    graph = client.application.extensions["graph_manager"]
    now = __import__("time").time()
    graph.observe_flow("10.0.0.1", "8.8.8.8", "TCP", 2, 200, observed_at=now)

    generated = client.post("/api/demo/simulate", json={"scenario": "network"})
    before_clear = client.get("/api/network/graph").get_json()
    cleared = client.post("/api/demo/reset")
    after_clear = client.get("/api/network/graph").get_json()

    assert generated.status_code == 200
    assert before_clear["stats"]["observed_devices"] > 2
    assert cleared.status_code == 200
    assert cleared.get_json()["deleted"]["graph"]["nodes"] > 0
    assert after_clear["stats"]["observed_devices"] == 2
    assert after_clear["edges"][0]["packet_count"] == 2


def test_demo_mode_can_be_disabled(tmp_path):
    disabled_app = create_app({"TESTING": True, "DEMO_MODE": False, "DATABASE_PATH": tmp_path / "disabled.db"})
    response = disabled_app.test_client().post("/api/demo/simulate", json={"scenario": "traffic_spike"})

    assert response.status_code == 403


def test_history_endpoints_and_demo_report(client):
    empty = client.get("/api/history?range=1h")
    invalid = client.get("/api/history?range=forever")
    generated = client.post("/api/history/demo/generate")
    data = client.get("/api/history?range=1h").get_json()
    csv_report = client.get("/api/history/export?range=1h")
    print_report = client.get("/history/report?range=1h")

    assert empty.status_code == 200
    assert empty.get_json()["summary"]["has_data"] is False
    assert invalid.status_code == 400
    assert generated.status_code == 200
    assert generated.get_json()["samples"] == 180
    assert data["summary"]["sample_count"] == 180
    assert data["comparison"]["abnormal"]["intervals"] > 0
    assert csv_report.status_code == 200
    assert csv_report.mimetype == "text/csv"
    assert b"NORMAL VS ABNORMAL" in csv_report.data
    assert print_report.status_code == 200
    assert b"Network Traffic Report" in print_report.data


def test_demo_history_can_be_cleared_without_touching_real_rows(client):
    repository = client.application.extensions["history_repository"]
    now = __import__("time").time()
    repository.insert_sample(sample={
        "timestamp": now, "interval_seconds": 10, "total_packets": 10, "total_bytes": 500,
        "packets_per_second": 1, "bytes_per_second": 50, "throughput_bps": 400,
        "network_status": "NORMAL", "is_demo": False,
    }, ip_rows=[], connection_rows=[])
    client.post("/api/history/demo/generate")

    response = client.post("/api/history/demo/clear")
    summary = client.get("/api/history/summary?range=1h").get_json()

    assert response.status_code == 200
    assert response.get_json()["deleted"]["traffic"] == 180
    assert summary["sample_count"] == 1


def test_parsed_packet_pipeline_keeps_metrics_and_adds_detection(tmp_path):
    app = create_app({
        "TESTING": True,
        "PORT_SCAN_PORT_THRESHOLD": 3,
        "PORT_SCAN_CRITICAL_MULTIPLIER": 2,
        "DATABASE_PATH": tmp_path / "pipeline.db",
    })
    detector = app.extensions["anomaly_detector"]
    for index, port in enumerate((21, 22, 23)):
        detector.process_packet({
            "protocol": "TCP",
            "transport_protocol": "TCP",
            "tcp_flags": "S",
            "source_ip": "198.51.100.8",
            "destination_ip": "192.0.2.8",
            "source_port": 45000,
            "destination_port": port,
            "size": 60,
        }, received_at=100 + index)

    metrics = app.extensions["traffic_metrics"].snapshot(now=102)
    alerts = app.extensions["alert_store"].recent()
    assert metrics["total_packets"] == 3
    assert metrics["protocols"]["TCP"] == 3
    assert metrics["unique_source_ips"] == 1
    assert alerts[0]["type"] == "PORT_SCAN"
    graph = app.extensions["graph_manager"].snapshot(now=102)
    assert graph["stats"]["observed_devices"] == 2
    assert graph["stats"]["active_connections"] == 1
    assert next(node for node in graph["nodes"] if node["id"] == "198.51.100.8")["status"] == "WARNING"
