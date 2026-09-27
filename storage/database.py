"""SQLite initialization and safe short-lived connection handling."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    interval_seconds REAL NOT NULL,
    total_packets INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    packets_per_second REAL NOT NULL,
    bytes_per_second REAL NOT NULL,
    throughput_bps REAL NOT NULL,
    tcp_packets INTEGER NOT NULL DEFAULT 0,
    udp_packets INTEGER NOT NULL DEFAULT 0,
    dns_packets INTEGER NOT NULL DEFAULT 0,
    http_packets INTEGER NOT NULL DEFAULT 0,
    icmp_packets INTEGER NOT NULL DEFAULT 0,
    other_packets INTEGER NOT NULL DEFAULT 0,
    unique_source_ips INTEGER NOT NULL DEFAULT 0,
    unique_destination_ips INTEGER NOT NULL DEFAULT 0,
    baseline_packets_per_second REAL NOT NULL DEFAULT 0,
    network_status TEXT NOT NULL DEFAULT 'NORMAL',
    is_demo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    ip_address TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    sent_packets INTEGER NOT NULL,
    received_packets INTEGER NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    is_demo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    protocols_json TEXT NOT NULL DEFAULT '{}',
    is_demo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alert_history (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    measured_value REAL,
    threshold_value REAL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    is_demo INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_history_timestamp ON traffic_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_ip_history_timestamp ON ip_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_ip_history_address ON ip_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_connection_history_timestamp ON connection_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_history_timestamp ON alert_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_history_type ON alert_history(alert_type);
CREATE INDEX IF NOT EXISTS idx_alert_history_severity ON alert_history(severity);
"""


class Database:
    """Own the database path while opening one connection per operation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

