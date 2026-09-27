"""Parameterized SQLite queries for history, alerts, analytics, and retention."""

from __future__ import annotations

from datetime import datetime
import json
import time
from typing import Any

from storage.database import Database


RANGE_SECONDS = {
    "15m": 15 * 60,
    "1h": 60 * 60,
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
}


def range_cutoff(range_key: str, now: float | None = None) -> float:
    if range_key not in RANGE_SECONDS:
        raise ValueError("Invalid time range. Use 15m, 1h, 6h, 24h, or 7d.")
    return float(now if now is not None else time.time()) - RANGE_SECONDS[range_key]


class HistoryRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def insert_sample(
        self,
        sample: dict[str, Any],
        ip_rows: list[dict[str, Any]],
        connection_rows: list[dict[str, Any]],
    ) -> None:
        with self.database.connection() as connection:
            self._insert_sample(connection, sample)
            self._insert_ip_rows(connection, ip_rows)
            self._insert_connection_rows(connection, connection_rows)

    def insert_dataset(
        self,
        samples: list[dict[str, Any]],
        ip_rows: list[dict[str, Any]],
        connection_rows: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
    ) -> None:
        with self.database.connection() as connection:
            for sample in samples:
                self._insert_sample(connection, sample)
            self._insert_ip_rows(connection, ip_rows)
            self._insert_connection_rows(connection, connection_rows)
            for alert in alerts:
                self._insert_alert(connection, alert)

    @staticmethod
    def _insert_sample(connection, sample: dict[str, Any]) -> None:
        connection.execute(
            """INSERT INTO traffic_history (
                timestamp, interval_seconds, total_packets, total_bytes,
                packets_per_second, bytes_per_second, throughput_bps,
                tcp_packets, udp_packets, dns_packets, http_packets,
                icmp_packets, other_packets, unique_source_ips,
                unique_destination_ips, baseline_packets_per_second,
                network_status, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sample["timestamp"], sample["interval_seconds"], sample["total_packets"],
                sample["total_bytes"], sample["packets_per_second"], sample["bytes_per_second"],
                sample["throughput_bps"], sample.get("tcp_packets", 0), sample.get("udp_packets", 0),
                sample.get("dns_packets", 0), sample.get("http_packets", 0),
                sample.get("icmp_packets", 0), sample.get("other_packets", 0),
                sample.get("unique_source_ips", 0), sample.get("unique_destination_ips", 0),
                sample.get("baseline_packets_per_second", 0), sample.get("network_status", "NORMAL"),
                int(bool(sample.get("is_demo", False))),
            ),
        )

    @staticmethod
    def _insert_ip_rows(connection, rows: list[dict[str, Any]]) -> None:
        connection.executemany(
            """INSERT INTO ip_history (
                timestamp, ip_address, packets, bytes, sent_packets,
                received_packets, alert_count, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [(
                row["timestamp"], row["ip_address"], row["packets"], row["bytes"],
                row["sent_packets"], row["received_packets"], row.get("alert_count", 0),
                int(bool(row.get("is_demo", False))),
            ) for row in rows],
        )

    @staticmethod
    def _insert_connection_rows(connection, rows: list[dict[str, Any]]) -> None:
        connection.executemany(
            """INSERT INTO connection_history (
                timestamp, source_ip, destination_ip, packets, bytes,
                protocols_json, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(
                row["timestamp"], row["source_ip"], row["destination_ip"],
                row["packets"], row["bytes"], json.dumps(row.get("protocols", {}), sort_keys=True),
                int(bool(row.get("is_demo", False))),
            ) for row in rows],
        )

    def insert_alert(self, alert: dict[str, Any]) -> None:
        with self.database.connection() as connection:
            self._insert_alert(connection, alert)

    @staticmethod
    def _insert_alert(connection, alert: dict[str, Any]) -> None:
        connection.execute(
            """INSERT OR IGNORE INTO alert_history (
                id, timestamp, alert_type, severity, title, description,
                source_ip, destination_ip, measured_value, threshold_value,
                metadata_json, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert["id"], alert["timestamp_epoch"], alert["type"], alert["severity"],
                alert["title"], alert["description"], alert.get("source_ip"),
                alert.get("destination_ip"), alert.get("metric"), alert.get("threshold"),
                json.dumps(alert.get("metadata", {}), sort_keys=True),
                int(bool(alert.get("is_demo", False))),
            ),
        )

    def load_recent_alerts(self, limit: int = 500) -> list[dict[str, Any]]:
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM alert_history ORDER BY timestamp DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [self._alert_from_row(row) for row in reversed(rows)]

    @staticmethod
    def _alert_from_row(row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp_epoch": row["timestamp"],
            "type": row["alert_type"],
            "severity": row["severity"],
            "title": row["title"],
            "description": row["description"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "metric": row["measured_value"],
            "threshold": row["threshold_value"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
            "is_demo": bool(row["is_demo"]),
        }

    def traffic(self, range_key: str, now: float | None = None) -> list[dict[str, Any]]:
        cutoff = range_cutoff(range_key, now)
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM traffic_history WHERE timestamp >= ? ORDER BY timestamp", (cutoff,)
            ).fetchall()
        return [dict(row) | {
            "timestamp_iso": datetime.fromtimestamp(row["timestamp"]).astimezone().isoformat(timespec="seconds"),
            "is_demo": bool(row["is_demo"]),
        } for row in rows]

    def alerts(self, range_key: str, now: float | None = None) -> list[dict[str, Any]]:
        cutoff = range_cutoff(range_key, now)
        with self.database.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM alert_history WHERE timestamp >= ? ORDER BY timestamp", (cutoff,)
            ).fetchall()
        return [self._alert_from_row(row) | {
            "timestamp_iso": datetime.fromtimestamp(row["timestamp"]).astimezone().isoformat(timespec="seconds")
        } for row in rows]

    def summary(self, range_key: str, now: float | None = None) -> dict[str, Any]:
        cutoff = range_cutoff(range_key, now)
        with self.database.connection() as connection:
            traffic = connection.execute(
                """SELECT COUNT(*) sample_count, COALESCE(SUM(total_packets), 0) total_packets,
                    COALESCE(SUM(total_bytes), 0) total_bytes,
                    COALESCE(AVG(packets_per_second), 0) average_pps,
                    COALESCE(MAX(packets_per_second), 0) peak_pps,
                    COALESCE(AVG(throughput_bps), 0) average_throughput_bps
                FROM traffic_history WHERE timestamp >= ?""", (cutoff,)
            ).fetchone()
            alerts = connection.execute(
                """SELECT COUNT(*) total_alerts,
                    COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) critical_alerts
                FROM alert_history WHERE timestamp >= ?""", (cutoff,)
            ).fetchone()
        result = dict(traffic) | dict(alerts)
        result["has_data"] = result["sample_count"] > 0
        return result

    def protocols(self, range_key: str, now: float | None = None) -> dict[str, int]:
        cutoff = range_cutoff(range_key, now)
        with self.database.connection() as connection:
            row = connection.execute(
                """SELECT COALESCE(SUM(tcp_packets), 0) TCP,
                    COALESCE(SUM(udp_packets), 0) UDP,
                    COALESCE(SUM(dns_packets), 0) DNS,
                    COALESCE(SUM(http_packets), 0) HTTP,
                    COALESCE(SUM(icmp_packets), 0) ICMP,
                    COALESCE(SUM(other_packets), 0) Other
                FROM traffic_history WHERE timestamp >= ?""", (cutoff,)
            ).fetchone()
        return {key: int(row[key]) for key in row.keys()}

    def top_talkers(self, range_key: str, now: float | None = None, limit: int = 10) -> list[dict[str, Any]]:
        cutoff = range_cutoff(range_key, now)
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT ip_address, SUM(packets) packets, SUM(bytes) bytes,
                    SUM(sent_packets) sent_packets, SUM(received_packets) received_packets,
                    SUM(alert_count) alert_count
                FROM ip_history WHERE timestamp >= ? GROUP BY ip_address
                ORDER BY bytes DESC, packets DESC LIMIT ?""", (cutoff, int(limit))
            ).fetchall()
        return [dict(row) for row in rows]

    def top_connections(self, range_key: str, now: float | None = None, limit: int = 10) -> list[dict[str, Any]]:
        cutoff = range_cutoff(range_key, now)
        with self.database.connection() as connection:
            rows = connection.execute(
                """SELECT source_ip, destination_ip, SUM(packets) packets, SUM(bytes) bytes
                FROM connection_history WHERE timestamp >= ?
                GROUP BY source_ip, destination_ip ORDER BY bytes DESC, packets DESC LIMIT ?""",
                (cutoff, int(limit)),
            ).fetchall()
        return [dict(row) for row in rows]

    def alert_analytics(self, range_key: str, now: float | None = None) -> dict[str, Any]:
        alerts = self.alerts(range_key, now)
        by_type = {"PORT_SCAN": 0, "TRAFFIC_SPIKE": 0}
        by_severity = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
        sources: dict[str, int] = {}
        for alert in alerts:
            by_type[alert["type"]] = by_type.get(alert["type"], 0) + 1
            by_severity[alert["severity"]] = by_severity.get(alert["severity"], 0) + 1
            if alert.get("source_ip"):
                sources[alert["source_ip"]] = sources.get(alert["source_ip"], 0) + 1
        frequent_source = max(sources, key=sources.get) if sources else None
        return {
            "total": len(alerts),
            "by_type": by_type,
            "by_severity": by_severity,
            "most_frequently_alerted_source": frequent_source,
            "recent": list(reversed(alerts[-20:])),
            # Keep the browser/API payload bounded while counts still cover
            # every retained alert in the selected period.
            "timeline": alerts[-500:],
        }

    def comparison(self, range_key: str, now: float | None = None) -> dict[str, Any]:
        samples = self.traffic(range_key, now)
        normal = [row for row in samples if row["network_status"] == "NORMAL"]
        abnormal = [row for row in samples if row["network_status"] != "NORMAL"]
        total = len(samples)

        def stats(rows: list[dict[str, Any]]) -> dict[str, float | int]:
            return {
                "intervals": len(rows),
                "average_pps": round(sum(row["packets_per_second"] for row in rows) / len(rows), 2) if rows else 0,
                "peak_pps": round(max((row["packets_per_second"] for row in rows), default=0), 2),
            }

        return {
            "normal": stats(normal),
            "abnormal": stats(abnormal),
            "normal_percent": round(len(normal) / total * 100, 2) if total else 0,
            "abnormal_percent": round(len(abnormal) / total * 100, 2) if total else 0,
            "anomaly_events": len(self.alerts(range_key, now)),
            "total_intervals": total,
        }

    def cleanup(self, history_cutoff: float, alert_cutoff: float) -> dict[str, int]:
        with self.database.connection() as connection:
            traffic = connection.execute("DELETE FROM traffic_history WHERE timestamp < ?", (history_cutoff,)).rowcount
            ips = connection.execute("DELETE FROM ip_history WHERE timestamp < ?", (history_cutoff,)).rowcount
            connections = connection.execute("DELETE FROM connection_history WHERE timestamp < ?", (history_cutoff,)).rowcount
            alerts = connection.execute("DELETE FROM alert_history WHERE timestamp < ?", (alert_cutoff,)).rowcount
        return {"traffic": traffic, "ips": ips, "connections": connections, "alerts": alerts}

    def clear_demo_data(self) -> dict[str, int]:
        with self.database.connection() as connection:
            traffic = connection.execute("DELETE FROM traffic_history WHERE is_demo = 1").rowcount
            ips = connection.execute("DELETE FROM ip_history WHERE is_demo = 1").rowcount
            connections = connection.execute("DELETE FROM connection_history WHERE is_demo = 1").rowcount
            alerts = connection.execute("DELETE FROM alert_history WHERE is_demo = 1").rowcount
        return {"traffic": traffic, "ips": ips, "connections": connections, "alerts": alerts}
