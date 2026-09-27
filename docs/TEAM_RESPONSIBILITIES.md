# Three-Person Team Responsibilities

The ownership below divides presentation and maintenance work without treating the application as separate projects. All members should understand the shared pipeline and be able to run the complete demonstration.

## Member 1 — network monitoring

Primary topics:

- Scapy and passive packet capture.
- Interface selection, privileges, start/stop lifecycle and error handling.
- IPv4/IPv6 parsing and TCP, UDP, DNS, clear-text HTTP, ICMP and Other classification.
- Packet size, packets/sec and approximate throughput calculations.
- Bounded recent-packet memory.
- Dashboard and Live Packets page.

Code ownership:

- `capture/packet_capture.py`
- `capture/packet_parser.py`
- `analysis/traffic_metrics.py`
- Packet-capture and metrics portions of `app.py`
- `dashboard.html/js` and `packets.html/js`

Member 1 should explain why HTTPS appears as TCP, why root/administrator privileges may be needed and why capture visibility depends on the selected interface.

## Member 2 — anomaly detection

Primary topics:

- Rolling non-anomalous traffic baseline and warm-up.
- Traffic-spike ratios, minimum baseline, severity and cooldown.
- Port-scan-like unique-port window, TCP SYN filtering, deduplication and escalation.
- INFO, WARNING and CRITICAL levels and current network status.
- False positives and why alerts are evidence for review rather than proof of attack.
- Safe synthetic demo inputs.

Code ownership:

- `detection/baseline.py`
- `detection/port_scan_detector.py`
- `detection/traffic_spike_detector.py`
- `detection/alert_store.py`
- `detection/anomaly_detector.py`
- `alerts.html/js`

Member 2 should be ready to calculate an example spike ratio and explain why detected spikes are excluded from the baseline.

## Member 3 — visualization and analytics

Primary topics:

- Passive graph nodes, bidirectional edges and local/external/special classification.
- Graph limits, expiration, filtering, selection details and suspicious-node styling.
- SQLite aggregate schema, parameterized queries and short-lived connections.
- Ten-second history sampling, retention and alert persistence.
- Normal versus abnormal comparison, top talkers/connections and reports.

Code ownership:

- `network/graph_manager.py`
- `storage/database.py`, `storage/repositories.py`, `storage/history_service.py`
- `network.html/js`, `history.html/js`, `history_report.html`
- Historical/report routes in `app.py`

Member 3 should explain why raw packets are not persisted and why SQLite is suitable for this mini-project but not a large distributed deployment.

## Shared integration knowledge

Every member should understand:

1. `PacketCapture` sends each Scapy packet to `parse_packet`.
2. Parsed metadata is distributed to live metrics, anomaly detection, graph aggregation and the history accumulator.
3. Detectors create structured alerts; alerts update the UI, graph status and SQLite history.
4. Flask APIs provide bounded snapshots to JavaScript polling clients.
5. Locks protect shared in-memory structures. SQLite connections are opened per operation.
6. Demo actions create only internal synthetic metadata and are rejected while live capture is running.
7. The project never actively scans, injects packets, extracts credentials or decrypts traffic.

## Joint responsibilities before submission

- Run `python -m pytest -q` and record the actual result.
- Complete `docs/MANUAL_TEST_CHECKLIST.md` on the presentation laptop.
- Verify the selected capture interface and privilege method.
- Confirm Chart.js/Cytoscape.js load on the presentation network.
- Rehearse the six scenes in `docs/DEMO_GUIDE.md`.
- Agree on honest limitations and avoid calling every anomaly an attack.
