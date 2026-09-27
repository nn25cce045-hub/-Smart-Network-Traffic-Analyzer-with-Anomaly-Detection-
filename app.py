"""Flask entry point for Smart Network Traffic Analyzer."""

from __future__ import annotations

from flask import Flask, Response, jsonify, render_template, request

import config
from analysis.traffic_metrics import TrafficMetrics
from capture.packet_capture import PacketCapture
from detection.alert_store import AlertStore
from detection.anomaly_detector import AnomalyDetector
from detection.port_scan_detector import PortScanDetector
from detection.traffic_spike_detector import TrafficSpikeDetector
from network.graph_manager import GraphManager
from storage.database import Database
from storage.history_service import HistoryService
from storage.repositories import HistoryRepository, RANGE_SECONDS


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config)
    if test_config:
        app.config.update(test_config)

    metrics = TrafficMetrics(max_packets=app.config["MAX_PACKET_RESULTS"])
    alerts = AlertStore(max_alerts=app.config["MAX_ALERTS"])
    port_scan_detector = PortScanDetector(
        port_threshold=app.config["PORT_SCAN_PORT_THRESHOLD"],
        window_seconds=app.config["PORT_SCAN_WINDOW_SECONDS"],
        cooldown_seconds=app.config["PORT_SCAN_ALERT_COOLDOWN"],
        critical_multiplier=app.config["PORT_SCAN_CRITICAL_MULTIPLIER"],
        max_tracked_pairs=app.config["PORT_SCAN_MAX_TRACKED_PAIRS"],
    )
    traffic_spike_detector = TrafficSpikeDetector(
        baseline_window=app.config["TRAFFIC_BASELINE_WINDOW"],
        minimum_samples=app.config["TRAFFIC_MIN_BASELINE_SAMPLES"],
        spike_multiplier=app.config["TRAFFIC_SPIKE_MULTIPLIER"],
        critical_multiplier=app.config["TRAFFIC_SPIKE_CRITICAL_MULTIPLIER"],
        minimum_baseline_pps=app.config["TRAFFIC_MIN_BASELINE_PPS"],
        cooldown_seconds=app.config["TRAFFIC_SPIKE_ALERT_COOLDOWN"],
    )
    database = Database(app.config["DATABASE_PATH"])
    database.initialize()
    history_repository = HistoryRepository(database)
    graph_manager = GraphManager(
        edge_ttl_seconds=app.config["GRAPH_EDGE_TTL_SECONDS"],
        node_ttl_seconds=app.config["GRAPH_NODE_TTL_SECONDS"],
        max_nodes=app.config["GRAPH_MAX_NODES"],
        max_edges=app.config["GRAPH_MAX_EDGES"],
    )
    history_service = HistoryService(
        history_repository,
        alerts,
        traffic_spike_detector,
        sample_interval_seconds=app.config["HISTORY_SAMPLE_INTERVAL_SECONDS"],
        history_retention_days=app.config["HISTORY_RETENTION_DAYS"],
        alert_retention_days=app.config["ALERT_RETENTION_DAYS"],
        cleanup_interval_seconds=app.config["HISTORY_CLEANUP_INTERVAL_SECONDS"],
        status_window_seconds=app.config["NETWORK_STATUS_WINDOW_SECONDS"],
    )
    history_service.restore_alerts(app.config["MAX_ALERTS"])
    anomaly_detector = AnomalyDetector(
        metrics,
        alerts,
        port_scan_detector,
        traffic_spike_detector,
        graph_manager,
        history_service,
        status_window_seconds=app.config["NETWORK_STATUS_WINDOW_SECONDS"],
    )
    capture = PacketCapture(anomaly_detector.process_packet)
    app.extensions["traffic_metrics"] = metrics
    app.extensions["packet_capture"] = capture
    app.extensions["alert_store"] = alerts
    app.extensions["anomaly_detector"] = anomaly_detector
    app.extensions["graph_manager"] = graph_manager
    app.extensions["history_service"] = history_service
    app.extensions["history_repository"] = history_repository

    @app.before_request
    def ensure_history_sampler():
        if app.config["HISTORY_SAMPLER_ENABLED"] and not app.config.get("TESTING", False):
            history_service.start()

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", active_page="dashboard")

    @app.get("/packets")
    def packets_page():
        return render_template("packets.html", active_page="packets")

    @app.get("/traffic")
    def traffic_page():
        return render_template("traffic.html", active_page="traffic")

    @app.get("/alerts")
    def alerts_page():
        return render_template(
            "alerts.html",
            active_page="alerts",
            demo_mode=app.config["DEMO_MODE"],
        )

    @app.get("/network")
    def network_page():
        return render_template("network.html", active_page="network")

    @app.get("/history")
    def history_page():
        return render_template("history.html", active_page="history", demo_mode=app.config["DEMO_MODE"])

    def requested_range() -> str:
        range_key = request.args.get("range", "1h")
        if range_key not in RANGE_SECONDS:
            raise ValueError("Invalid time range. Use 15m, 1h, 6h, 24h, or 7d.")
        return range_key

    @app.get("/history/report")
    def history_report():
        try:
            range_key = requested_range()
        except ValueError as exc:
            return render_template("history_report.html", error=str(exc), data=None, range_key=None), 400
        return render_template(
            "history_report.html",
            error=None,
            data=history_service.analytics(range_key),
            range_key=range_key,
        )

    @app.get("/api/stats")
    def api_stats():
        return jsonify({**metrics.snapshot(), **capture.status()})

    @app.get("/api/packets")
    def api_packets():
        raw_limit = request.args.get("limit", "500")
        try:
            limit = int(raw_limit)
        except ValueError:
            return jsonify({"error": "The limit parameter must be an integer."}), 400
        if limit < 1:
            return jsonify({"error": "The limit parameter must be at least 1."}), 400
        return jsonify({"packets": metrics.recent_packets(limit), "count": min(limit, metrics.max_packets)})

    @app.get("/api/interfaces")
    def api_interfaces():
        try:
            return jsonify({"interfaces": capture.available_interfaces()})
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503

    @app.get("/api/alerts")
    def api_alerts():
        raw_limit = request.args.get("limit", "500")
        try:
            limit = int(raw_limit)
        except ValueError:
            return jsonify({"error": "The limit parameter must be an integer."}), 400
        if limit < 1:
            return jsonify({"error": "The limit parameter must be at least 1."}), 400
        return jsonify({"alerts": alerts.recent(limit), "summary": alerts.summary()})

    @app.get("/api/anomaly/status")
    def api_anomaly_status():
        return jsonify(anomaly_detector.status())

    @app.get("/api/traffic/baseline")
    def api_traffic_baseline():
        traffic = anomaly_detector.status()["traffic"]
        current = metrics.snapshot()
        baseline = traffic["baseline_pps"]
        current_rate = current["packets_per_second"]
        return jsonify({
            **traffic,
            "current_pps": current_rate,
            "throughput_bps": current["throughput_bps"],
            "deviation_ratio": round(current_rate / baseline, 2) if baseline > 0 else 0.0,
            "unique_source_ips": current["unique_source_ips"],
            "unique_destination_ips": current["unique_destination_ips"],
        })

    @app.get("/api/network/graph")
    def api_network_graph():
        return jsonify(graph_manager.snapshot())

    @app.get("/api/history")
    def api_history():
        try:
            return jsonify(history_service.analytics(requested_range()))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/summary")
    def api_history_summary():
        try:
            return jsonify(history_repository.summary(requested_range()))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/traffic")
    def api_history_traffic():
        try:
            rows = history_repository.traffic(requested_range())
            return jsonify({"traffic": history_service.downsample(rows), "count": len(rows)})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/protocols")
    def api_history_protocols():
        try:
            return jsonify({"protocols": history_repository.protocols(requested_range())})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/alerts")
    def api_history_alerts():
        try:
            return jsonify(history_repository.alert_analytics(requested_range()))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/top-talkers")
    def api_history_top_talkers():
        try:
            return jsonify({"top_talkers": history_repository.top_talkers(requested_range())})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/top-connections")
    def api_history_top_connections():
        try:
            return jsonify({"top_connections": history_repository.top_connections(requested_range())})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/comparison")
    def api_history_comparison():
        try:
            return jsonify(history_repository.comparison(requested_range()))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history/export")
    def api_history_export():
        try:
            range_key = requested_range()
            csv_data = history_service.csv_report(range_key)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=network-report-{range_key}.csv"},
        )

    @app.post("/api/history/demo/generate")
    def api_history_demo_generate():
        if not app.config["DEMO_MODE"]:
            return jsonify({"error": "Synthetic demo mode is disabled."}), 403
        if capture.status()["capturing"]:
            return jsonify({"error": "Stop live capture before generating demo history."}), 409
        result = history_service.generate_demo_history()
        return jsonify({"message": "Synthetic historical timeline generated.", **result})

    @app.post("/api/history/demo/clear")
    def api_history_demo_clear():
        if not app.config["DEMO_MODE"]:
            return jsonify({"error": "Synthetic demo mode is disabled."}), 403
        result = history_service.clear_demo_data()
        return jsonify({"message": "Only synthetic historical data was removed.", "deleted": result})

    @app.post("/api/demo/simulate")
    def api_demo_simulate():
        if not app.config["DEMO_MODE"]:
            return jsonify({"error": "Synthetic demo mode is disabled."}), 403
        if capture.status()["capturing"]:
            return jsonify({"error": "Stop live capture before running a synthetic demonstration."}), 409
        data = request.get_json(silent=True) or {}
        try:
            result = anomaly_detector.simulate(str(data.get("scenario", "")))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(result)

    @app.post("/api/demo/reset")
    def api_demo_reset():
        if not app.config["DEMO_MODE"]:
            return jsonify({"error": "Synthetic demo mode is disabled."}), 403
        if capture.status()["capturing"]:
            return jsonify({"error": "Stop live capture before resetting demo data."}), 409
        anomaly_detector.reset_demo_state()
        return jsonify({"message": "Alerts, detector state, and synthetic graph data were cleared."})

    @app.post("/api/capture/start")
    def api_capture_start():
        data = request.get_json(silent=True) or {}
        interface = data.get("interface")
        if not isinstance(interface, str) or not interface.strip():
            return jsonify({"error": "Select a network interface before starting capture."}), 400
        started, message = capture.start(interface.strip())
        status_code = 200 if started else 409
        return jsonify({"message" if started else "error": message, **capture.status()}), status_code

    @app.post("/api/capture/stop")
    def api_capture_stop():
        stopped, message = capture.stop()
        status_code = 200 if stopped else 409
        return jsonify({"message" if stopped else "error": message, **capture.status()}), status_code

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "API endpoint not found."}), 404
        return render_template("404.html", active_page=""), 404

    @app.errorhandler(500)
    def server_error(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "An unexpected server error occurred."}), 500
        return render_template("500.html", active_page=""), 500

    return app


app = create_app()


if __name__ == "__main__":
    # The reloader is disabled so it cannot create a duplicate capture controller.
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
