"""Central configuration for capture, detection, alerts, and demo mode."""

from __future__ import annotations

import os
from pathlib import Path


MAX_PACKET_RESULTS = 1000
MAX_ALERTS = 500
NETWORK_STATUS_WINDOW_SECONDS = 120

# A source contacting this many unique ports on one destination inside the
# rolling window is considered port-scan-like behavior.
PORT_SCAN_PORT_THRESHOLD = 15
PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_ALERT_COOLDOWN = 60
PORT_SCAN_CRITICAL_MULTIPLIER = 2.0
PORT_SCAN_MAX_TRACKED_PAIRS = 5000

# Completed one-second packet counts form the moving baseline. A sample must be
# both this multiple of baseline and at least the minimum rate to be anomalous.
TRAFFIC_BASELINE_WINDOW = 30
TRAFFIC_MIN_BASELINE_SAMPLES = 10
TRAFFIC_SPIKE_MULTIPLIER = 3.0
TRAFFIC_SPIKE_CRITICAL_MULTIPLIER = 6.0
TRAFFIC_MIN_BASELINE_PPS = 5.0
TRAFFIC_SPIKE_ALERT_COOLDOWN = 60

# Demo mode only submits documentation-range IP metadata and numeric traffic
# samples to detectors. It never opens a socket or sends a packet.
DEMO_MODE = os.getenv("NETRA_DEMO_MODE", "1").strip().lower() not in {"0", "false", "no", "off"}

# Passive graph retention and hard limits protect both server and browser memory.
GRAPH_EDGE_TTL_SECONDS = 300
GRAPH_NODE_TTL_SECONDS = 600
GRAPH_MAX_NODES = 250
GRAPH_MAX_EDGES = 500

# Historical storage contains aggregate metadata only—never raw packets or payloads.
DATABASE_PATH = os.getenv(
    "NETRA_DATABASE_PATH",
    str(Path(__file__).resolve().parent / "data" / "network_analyzer.db"),
)
HISTORY_SAMPLE_INTERVAL_SECONDS = 10
HISTORY_RETENTION_DAYS = 7
ALERT_RETENTION_DAYS = 30
HISTORY_CLEANUP_INTERVAL_SECONDS = 3600
HISTORY_SAMPLER_ENABLED = True
