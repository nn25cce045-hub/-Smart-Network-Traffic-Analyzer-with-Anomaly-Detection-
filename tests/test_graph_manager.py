"""Non-networked tests for passive communication graph aggregation."""

from app import create_app
from network.graph_manager import GraphManager, classify_ip


def packet(source="192.168.1.10", destination="8.8.8.8", protocol="TCP", size=100):
    return {
        "source_ip": source,
        "destination_ip": destination,
        "protocol": protocol,
        "size": size,
    }


def test_new_packet_creates_nodes_and_bidirectional_edge():
    graph = GraphManager()

    assert graph.observe_packet(packet(), observed_at=100) is True
    snapshot = graph.snapshot(now=100)

    assert {node["id"] for node in snapshot["nodes"]} == {"192.168.1.10", "8.8.8.8"}
    assert len(snapshot["edges"]) == 1
    assert snapshot["edges"][0]["packet_count"] == 1


def test_repeated_and_reverse_traffic_updates_without_duplicates():
    graph = GraphManager()
    graph.observe_packet(packet(protocol="TCP", size=100), observed_at=100)
    graph.observe_packet(packet(protocol="DNS", size=60), observed_at=101)
    graph.observe_packet(packet(source="8.8.8.8", destination="192.168.1.10", protocol="DNS", size=70), observed_at=102)

    snapshot = graph.snapshot(now=102)
    edge = snapshot["edges"][0]
    local = next(node for node in snapshot["nodes"] if node["id"] == "192.168.1.10")

    assert len(snapshot["nodes"]) == 2
    assert len(snapshot["edges"]) == 1
    assert edge["packet_count"] == 3
    assert edge["bytes"] == 230
    assert edge["protocols"] == {"TCP": 1, "DNS": 2}
    assert local["packet_count"] == 3
    assert local["sent_packets"] == 2
    assert local["received_packets"] == 1


def test_local_external_and_special_ip_classification():
    assert classify_ip("192.168.1.1") == "LOCAL"
    assert classify_ip("10.0.0.1") == "LOCAL"
    assert classify_ip("127.0.0.1") == "LOCAL"
    assert classify_ip("8.8.8.8") == "EXTERNAL"
    assert classify_ip("224.0.0.1") == "SPECIAL"
    assert classify_ip("203.0.113.10") == "SPECIAL"


def test_warning_and_critical_alerts_update_observed_node_status():
    graph = GraphManager()
    graph.observe_packet(packet(), observed_at=100)
    graph.apply_alert({"severity": "WARNING", "source_ip": "192.168.1.10"})
    warning = next(node for node in graph.snapshot(now=100)["nodes"] if node["id"] == "192.168.1.10")
    graph.apply_alert({"severity": "CRITICAL", "source_ip": "192.168.1.10"})
    critical = next(node for node in graph.snapshot(now=100)["nodes"] if node["id"] == "192.168.1.10")

    assert warning["status"] == "WARNING"
    assert warning["alert_count"] == 1
    assert critical["status"] == "CRITICAL"
    assert critical["alert_count"] == 2


def test_alerts_do_not_create_unobserved_nodes():
    graph = GraphManager()
    graph.apply_alert({"severity": "CRITICAL", "source_ip": "192.0.2.99"})

    assert graph.snapshot()["nodes"] == []


def test_stale_edges_then_disconnected_nodes_are_removed():
    graph = GraphManager(edge_ttl_seconds=5, node_ttl_seconds=10)
    graph.observe_packet(packet(), observed_at=100)

    after_edge_ttl = graph.snapshot(now=106)
    after_node_ttl = graph.snapshot(now=111)

    assert after_edge_ttl["edges"] == []
    assert len(after_edge_ttl["nodes"]) == 2
    assert after_node_ttl["nodes"] == []


def test_graph_node_and_edge_limits_are_respected():
    graph = GraphManager(max_nodes=3, max_edges=2)
    graph.observe_packet(packet("10.0.0.1", "10.0.0.2"), observed_at=1)
    graph.observe_packet(packet("10.0.0.2", "10.0.0.3"), observed_at=2)
    graph.observe_packet(packet("10.0.0.3", "10.0.0.4"), observed_at=3)
    graph.observe_packet(packet("10.0.0.4", "10.0.0.5"), observed_at=4)
    snapshot = graph.snapshot(now=4)

    assert len(snapshot["nodes"]) <= 3
    assert len(snapshot["edges"]) <= 2
    assert all(edge["source"] in {node["id"] for node in snapshot["nodes"]} for edge in snapshot["edges"])


def test_invalid_or_same_address_packet_is_ignored():
    graph = GraphManager()

    assert graph.observe_packet(packet("not-an-ip", "8.8.8.8")) is False
    assert graph.observe_packet(packet("10.0.0.1", "10.0.0.1")) is False
    assert graph.snapshot()["stats"]["observed_devices"] == 0


def test_synthetic_demo_builds_graph_and_marks_scan_source(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": tmp_path / "graph-demo.db"})
    client = app.test_client()

    normal = client.post("/api/demo/simulate", json={"scenario": "normal"})
    normal_graph = client.get("/api/network/graph").get_json()
    scan = client.post("/api/demo/simulate", json={"scenario": "port_scan"})
    scan_graph = client.get("/api/network/graph").get_json()
    scan_source = next(node for node in scan_graph["nodes"] if node["id"] == "198.51.100.25")

    assert normal.status_code == 200
    assert normal_graph["stats"]["observed_devices"] == 5
    assert normal_graph["stats"]["active_connections"] == 3
    assert scan.status_code == 200
    assert scan_source["status"] == "WARNING"
    assert scan_source["alert_count"] == 1
    assert scan_graph["stats"]["suspicious_devices"] == 1
