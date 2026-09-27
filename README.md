# Smart Network Traffic Analyzer

A passive, real-time network monitoring, explainable anomaly-detection, communication-visualization, and historical analytics dashboard built as a three-student college mini-project. Part 1 captures traffic, Part 2 analyzes suspicious patterns, Part 3 maps observed communication, and Part 4 stores aggregate history for review and reporting.

> Use this application only on networks and devices you own or are authorized to monitor. It does not inject, modify, or generate network traffic.

## Part 1 features

- Select from network interfaces discovered by Scapy.
- Start and stop capture without blocking the Flask server.
- View capture state and permission/capture errors in the dashboard.
- Parse IPv4, IPv6, TCP, UDP, DNS, clear-text HTTP, ICMP, and other packets.
- Track total packets, protocol counts, packets per second, and approximate throughput.
- Display a live 60-second line chart and actual protocol-distribution doughnut chart.
- Browse the newest packets with protocol filters and an IP-address search.
- Bound memory usage to the latest 1,000 packet rows and 120 per-second buckets.
- Provide responsive Dashboard, Live Packets, Traffic Analysis, Alerts, and Network Map pages.
- Expose JSON APIs for use by the frontend or later project modules.

## Part 2 — anomaly detection

Part 2 extends the working Part 1 pipeline rather than replacing it:

```text
Network Traffic
      ↓
Packet Capture
      ↓
Packet Parser
      ↓
Traffic Metrics
      ↓
Anomaly Detection
   ↙             ↘
Port Scan       Traffic Spike
Detector         Detector
   ↘             ↙
        Alerts
          ↓
    Web Dashboard
```

### Port-scan-like behavior

The detector groups already-observed connection attempts by `(source IP, destination IP)`. Within a rolling **10-second** window, it counts unique destination ports. TCP packets are counted only when they are SYN attempts without ACK; UDP metadata can also contribute. It never sends probes.

- **Warning:** at least 15 unique destination ports in 10 seconds.
- **Critical:** at least 30 unique ports (2× the warning threshold).
- **Deduplication:** the same source/destination pair cannot repeat the same severity for 60 seconds. Escalation from Warning to Critical is allowed immediately.
- **Memory bound:** at most 5,000 source/destination pairs are tracked, and expired activity is pruned.

### Traffic-spike detection and rolling baseline

Packets are aggregated into completed one-second samples. A moving average of the latest **30 non-anomalous samples** is the baseline. Detection is disabled until at least **10 samples** exist and the baseline is at least **5 packets/sec**.

A spike is detected when:

```text
current packets/sec >= baseline packets/sec × 3.0
```

- A 3× to less than 6× increase is **Warning**.
- A 6× or larger increase is **Critical**.
- Spike alerts have a 60-second cooldown.
- Detected spike samples are excluded from the moving baseline so a short anomaly does not immediately become “normal.”
- A long observation gap resets the old baseline because it no longer represents the current traffic session.

These rules indicate suspicious patterns, not proof of an attack. Legitimate service discovery, software updates, backups, or bursty applications can produce false positives.

### Alert storage and status

The newest 500 structured alerts are kept in a thread-safe in-memory deque for fast live display. Part 4 also persists alerts to SQLite, so recent findings can be restored after the Python process restarts. The deque remains bounded while database retention is configured separately.

`NORMAL`, `UNUSUAL ACTIVITY`, `WARNING`, and `CRITICAL` status values are based on the highest-severity alert generated during the latest 120 seconds. The alert center supports severity/type filters and IP/description search.

### Safe demo mode

The Alerts page includes controls for stable traffic, a port-scan-like pattern, and a traffic spike. Demo mode passes numeric samples and documentation-range IP metadata (`192.0.2.0/24` and `198.51.100.0/24`) directly to detectors. It does **not** open sockets, send packets, scan hosts, or flood a network. Stop live capture before using demo actions.

Demo mode is enabled by default for presentations. Disable it before starting the app with:

```bash
NETRA_DEMO_MODE=0 python app.py
```

## Part 3 — network communication map

Part 3 adds an interactive Cytoscape.js graph without changing the Part 1 capture or Part 2 detector responsibilities:

```text
                    NETWORK
                       ↓
                PACKET CAPTURE
                       ↓
                 PACKET PARSER
                       ↓
             ┌─────────┴─────────┐
             ↓                   ↓
       TRAFFIC METRICS      GRAPH MANAGER
             ↓                   ↓
     ANOMALY DETECTION      NETWORK MAP
             ↓                   ↑
           ALERTS ────────────────┘
             ↓
          DASHBOARD
```

### Passive nodes and edges

Every valid source and destination IP already present in parsed packets becomes a node. The application never performs ARP discovery, ping sweeps, reverse probing, or port scans. Therefore, the map represents **observed communication**, not a complete inventory of devices connected to the network.

Traffic in both directions is combined into one bidirectional edge. For example, `A → B` and `B → A` update the same edge. This reduces clutter while retaining total packets, bytes, protocols, and first/last-seen times. Nodes separately retain sent and received packet counts.

Node type is determined with Python's `ipaddress` module and explicit private ranges:

- **Local:** RFC 1918 IPv4, IPv6 unique-local, loopback, or link-local.
- **External:** globally routable addresses.
- **Special:** multicast, unspecified, reserved, and documentation ranges.

No physical device type is inferred from an IP address.

### Visualization and filtering

- Local, External, and Special nodes use distinct shapes and text labels.
- Warning nodes gain an orange dashed border; Critical nodes gain a wider red double border, so status is not communicated by color alone.
- Edge width uses `min(8, 1 + 1.8 × log10(packet_count + 1))`, keeping very busy links readable.
- Selecting a node shows type, sent/received packets, bytes, protocols, alerts, timestamps, and security status.
- Selecting an edge shows its endpoints, total packets, traffic, protocols, and timestamps.
- Controls pause/resume polling, fit the graph, reset the view, filter protocol/device type, and hide links below 1, 5, 10, 50, or 100 packets.

### Alert and demo integration

The graph does not run another detector. When Part 2 creates a Warning or Critical alert associated with an observed source IP, the existing alert coordinator updates that node's status and alert count. Critical status takes precedence over Warning.

Safe demo actions now also submit synthetic flows to the graph manager. **Simulate Normal Traffic** starts a small synthetic topology, **Simulate Port-Scan Pattern** adds a source node that becomes Warning through the real Part 2 detector, and **Simulate Traffic Spike** increases a synthetic edge's traffic. No packets are sent. **Reset Demo Data** clears alerts, detector state, and the in-memory graph while capture is stopped.

### Expiration and performance limits

- Edges expire after 300 seconds without observed communication.
- Disconnected nodes expire after 600 seconds without traffic.
- At most 250 nodes and 500 edges are retained.
- When a hard limit is reached, the least-recently-observed data is evicted.
- The API sends only current aggregated nodes and edges—never raw historical packet objects.
- The browser updates existing Cytoscape elements every two seconds instead of recreating the graph.

## Part 4 — historical analytics & reporting

Part 4 records one aggregate sample every **10 seconds** while the application is running. Capture and detection threads only update a lock-protected accumulator; the sampler performs database writes separately so SQLite work does not block packet handling.

```text
Parsed packet metadata ──→ in-memory accumulator ──→ 10-second sampler
Anomaly alert ────────────→ immediate persistence          │
                                                          ↓
                                                    SQLite history
                                                          │
                         History page / CSV / print report ←┘
```

### Privacy-conscious SQLite schema

The application creates `data/network_analyzer.db` automatically and uses short-lived, parameterized SQLite connections with WAL enabled. It stores only aggregate metadata—never raw packet objects or payload content.

| Table | Stored aggregate data |
|---|---|
| `traffic_history` | Interval totals, rates, protocol counts, baseline, status, demo marker |
| `ip_history` | Per-interval IP packet/byte totals, direction counts, alert count |
| `connection_history` | Per-interval source/destination totals and protocol-count JSON |
| `alert_history` | Structured anomaly details, source/destination, measurements, demo marker |

Traffic, IP, and connection rows are retained for **7 days** by default. Alerts are retained for **30 days**. Cleanup runs at most once per hour and removes rows older than their configured cutoffs.

### History page and reports

Open **History / Analytics** in the sidebar to select 15 minutes, 1 hour, 6 hours, 24 hours, or 7 days. The page provides:

- Total traffic, average and peak packets/sec, average throughput, and alert totals.
- Actual traffic versus the stored rolling baseline, throughput history, protocol distribution, and alert timeline.
- Normal versus abnormal interval percentages, averages, and peaks. “Abnormal” means baseline deviation or an anomaly-related status—not proof of malicious activity.
- Top talkers and bidirectional connections calculated from stored aggregates.
- Persisted alert counts, types, severities, recent details, and most frequently alerted source.
- CSV download and a print-friendly report that can be saved as PDF from the browser.

### Safe historical demo

With demo mode enabled, **Generate Demo History** creates a repeatable 30-minute aggregate timeline with normal traffic, growth, a critical spike, a warning port pattern, and recovery. It inserts database rows directly and sends no network packets. All synthetic rows and alerts are marked `is_demo=1`; **Clear Demo Data** deletes only those marked rows and preserves real captured history.

## Technology stack

- Python 3
- Flask
- Scapy
- SQLite (Python standard library)
- HTML, CSS, and vanilla JavaScript
- Chart.js (loaded from the jsDelivr CDN)
- Cytoscape.js (loaded from the jsDelivr CDN)
- Pytest

## Project structure

```text
.
├── app.py                         # Flask app factory, pages, and JSON API routes
├── config.py                      # Central detection, storage, and demo thresholds
├── analysis/
│   ├── __init__.py
│   └── traffic_metrics.py         # Thread-safe bounded storage and rate calculations
├── capture/
│   ├── __init__.py
│   ├── packet_capture.py          # Background Scapy capture lifecycle
│   └── packet_parser.py           # Safe field extraction and protocol classification
├── detection/
│   ├── __init__.py
│   ├── alert_store.py             # Bounded, thread-safe structured alert storage
│   ├── anomaly_detector.py        # Detection pipeline coordinator and safe demo input
│   ├── baseline.py                # Rolling moving-average helper
│   ├── port_scan_detector.py      # Unique-port rolling-window detector
│   └── traffic_spike_detector.py  # Per-second baseline and spike detector
├── network/
│   ├── __init__.py
│   └── graph_manager.py           # Bounded passive node/edge aggregation
├── storage/
│   ├── database.py                # SQLite schema and connection lifecycle
│   ├── repositories.py            # Parameterized history/analytics queries
│   └── history_service.py         # Sampler, retention, demo data, and CSV reports
├── static/
│   ├── css/style.css              # Responsive dark monitoring-dashboard design
│   └── js/
│       ├── common.js              # Shared formatting, API, header, and toast helpers
│       ├── alerts.js              # Alert filters, polling, status, and safe demo controls
│       ├── dashboard.js           # Capture controls, charts, status, and recent alerts
│       ├── history.js             # Historical charts, tables, filters, and demo controls
│       ├── network.js             # Cytoscape updates, filters, controls, and details
│       ├── packets.js             # Live table polling, filtering, and IP search
│       └── traffic.js             # Traffic Analysis page charts
├── templates/
│   ├── base.html                  # Shared navigation and page shell
│   ├── dashboard.html
│   ├── packets.html
│   ├── traffic.html
│   ├── alerts.html
│   ├── network.html
│   ├── history.html               # Historical analytics dashboard
│   ├── history_report.html        # Printable stored-data report
│   ├── 404.html
│   └── 500.html
├── tests/
│   ├── test_app.py
│   ├── test_detection.py
│   ├── test_graph_manager.py
│   ├── test_history.py
│   ├── test_packet_parser.py
│   └── test_traffic_metrics.py
├── requirements.txt
└── README.md
```

## Installation

Python 3.10 or newer is recommended. From the project directory:

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the application

Start the development server:

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in a browser. Select an interface on the Dashboard, then choose **Start Capture**.

For a development-only alternative, use:

```bash
flask --app app run --no-reload
```

The reloader should remain disabled while capturing because it launches an extra process and can create duplicate capture controllers.

## Packet-capture privileges

Opening a raw capture socket commonly requires elevated privileges.

On Linux, the simplest test is:

```bash
sudo .venv/bin/python app.py
```

For a less broad Linux setup, an administrator can grant the Python interpreter the `cap_net_raw` and `cap_net_admin` capabilities. Capabilities should be applied only after understanding the security implications and may need to be reapplied after Python upgrades. On Windows, install Npcap and run the terminal as Administrator. On macOS, run with `sudo` when the selected interface cannot be opened normally.

Never expose this development server publicly or run untrusted code with elevated privileges.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/stats` | Counters, protocol totals, rolling rates, chart history, and capture state |
| `GET` | `/api/packets?limit=500` | Newest parsed packet rows (maximum 1,000) |
| `GET` | `/api/interfaces` | Available capture interfaces and discovered IPv4 addresses |
| `POST` | `/api/capture/start` | Start capture with JSON such as `{"interface": "eth0"}` |
| `POST` | `/api/capture/stop` | Stop the current capture worker |
| `GET` | `/api/alerts?limit=500` | Recent structured alerts and severity totals |
| `GET` | `/api/anomaly/status` | Current network status, alert summary, and detector state |
| `GET` | `/api/traffic/baseline` | Current rate, baseline, deviation, IP counts, and comparison history |
| `GET` | `/api/network/graph` | Current bounded graph, topology statistics, and configured limits |
| `GET` | `/api/history?range=1h` | Combined summary, charts, comparison, talkers, connections, and alerts |
| `GET` | `/api/history/summary` | Stored totals, averages, peaks, and alert totals |
| `GET` | `/api/history/traffic` | Time-ordered, display-downsampled traffic intervals |
| `GET` | `/api/history/protocols` | Aggregate protocol packet counts |
| `GET` | `/api/history/alerts` | Persisted alert analytics and recent findings |
| `GET` | `/api/history/top-talkers` | Highest-volume stored IP aggregates |
| `GET` | `/api/history/top-connections` | Highest-volume stored endpoint pairs |
| `GET` | `/api/history/comparison` | Normal versus abnormal interval statistics |
| `GET` | `/api/history/export` | CSV report generated from stored data |
| `POST` | `/api/history/demo/generate` | Insert a safe 30-minute synthetic aggregate timeline |
| `POST` | `/api/history/demo/clear` | Delete only rows and alerts marked as demo data |
| `POST` | `/api/demo/simulate` | Submit a safe synthetic `normal`, `port_scan`, or `traffic_spike` scenario |
| `POST` | `/api/demo/reset` | Clear alert, detector, and synthetic graph state while capture is stopped |

Errors are returned as JSON with an `error` field and an appropriate 4xx/5xx status.

## How the measurements work

**Packets per second** is a rolling average. The application totals packets observed in the current second and preceding four seconds, then divides by the active window duration (up to five seconds).

**Approximate throughput** uses the same window:

```text
throughput (bits/second) = captured packet bytes × 8 ÷ window duration in seconds
```

This is an approximation of observed traffic. It uses Scapy packet lengths and does not compensate for every physical-layer framing overhead, packets dropped before capture, interface offloading, or traffic hidden by capture permissions.

Protocol totals are cumulative for the running Python process. Recent table rows are bounded separately, so the total can be greater than the number of stored rows.

## Detection configuration

All tunable values are together in `config.py`:

| Setting | Default | Meaning |
|---|---:|---|
| `PORT_SCAN_PORT_THRESHOLD` | 15 | Unique ports needed for a warning |
| `PORT_SCAN_WINDOW_SECONDS` | 10 | Rolling port observation window |
| `PORT_SCAN_ALERT_COOLDOWN` | 60 | Duplicate alert suppression period |
| `PORT_SCAN_CRITICAL_MULTIPLIER` | 2.0 | Critical threshold relative to warning |
| `TRAFFIC_BASELINE_WINDOW` | 30 | Maximum one-second baseline samples |
| `TRAFFIC_MIN_BASELINE_SAMPLES` | 10 | Warm-up samples required |
| `TRAFFIC_SPIKE_MULTIPLIER` | 3.0 | Warning ratio against baseline |
| `TRAFFIC_SPIKE_CRITICAL_MULTIPLIER` | 6.0 | Critical ratio against baseline |
| `TRAFFIC_MIN_BASELINE_PPS` | 5.0 | Minimum meaningful baseline |
| `TRAFFIC_SPIKE_ALERT_COOLDOWN` | 60 | Repeated spike suppression period |
| `NETWORK_STATUS_WINDOW_SECONDS` | 120 | How long alerts affect current status |
| `MAX_ALERTS` | 500 | In-memory alert retention limit |
| `GRAPH_EDGE_TTL_SECONDS` | 300 | Idle time before a connection expires |
| `GRAPH_NODE_TTL_SECONDS` | 600 | Idle time before a disconnected node expires |
| `GRAPH_MAX_NODES` | 250 | Maximum nodes retained and sent to the browser |
| `GRAPH_MAX_EDGES` | 500 | Maximum aggregated connections retained |
| `DATABASE_PATH` | `data/network_analyzer.db` | SQLite history file; override with `NETRA_DATABASE_PATH` |
| `HISTORY_SAMPLE_INTERVAL_SECONDS` | 10 | Aggregate persistence interval |
| `HISTORY_RETENTION_DAYS` | 7 | Traffic/IP/connection retention |
| `ALERT_RETENTION_DAYS` | 30 | Persisted alert retention |
| `HISTORY_CLEANUP_INTERVAL_SECONDS` | 3600 | Minimum interval between cleanup runs |

Restart the Flask process after changing these values.

## Run the tests

The included tests construct packets in memory and do not require root access or live capture:

```bash
python -m pytest -q
```

To perform a syntax/import check:

```bash
python -m compileall app.py config.py analysis capture detection network storage tests
python -c "from app import create_app; print(create_app().url_map)"
```

## Troubleshooting

- **Permission denied:** Run in an elevated terminal or configure packet-capture capabilities as described above.
- **No interfaces appear:** Verify that Scapy can access the operating system's networking APIs and that a network adapter is enabled.
- **Npcap/WinPcap error on Windows:** Install current Npcap with WinPcap API compatibility, then restart the terminal.
- **Capture starts but no packets appear:** Generate ordinary authorized traffic (for example, load a web page) and confirm the correct active interface was selected.
- **Docker, WSL, or a VM shows limited traffic:** These environments expose virtual interfaces and may not provide the host's full traffic. Run on the host or select the correct bridged interface.
- **Charts are blank while counters work:** Chart.js and the dashboard font are CDN assets; verify internet access or vendor those assets locally for an offline deployment.
- **Port 5000 is busy:** Use `flask --app app run --port 5050 --no-reload` and open the matching port.
- **Demo button is rejected:** Stop live capture first. Demo and live inputs are deliberately not mixed.
- **Baseline says “Warming up”:** Allow at least 10 completed one-second traffic samples.

## Known limitations

- Capture availability and visibility depend on the OS, driver, privileges, and interface mode.
- HTTPS payloads are encrypted and are counted as TCP; the application does not decrypt traffic.
- HTTP recognition is intentionally limited to common clear-text ports and recognizable request/response payloads.
- DNS over HTTPS/TLS cannot be identified as ordinary DNS from packet headers.
- Raw live packet rows, detector windows, and the current graph remain in memory and reset when the process restarts; Part 4 aggregate samples and alerts persist in SQLite.
- Detection observes only traffic visible to the selected interface; switched networks normally do not expose other devices' unicast traffic.
- Statistical and rule-based alerts are explainable indicators, not definitive proof of malicious activity.
- The network map is based only on captured IP traffic and is not a complete device inventory.
- Cytoscape.js, like Chart.js and the fonts, is loaded from a CDN and requires internet access unless vendored locally.
- The frontend polls the APIs; it does not yet use WebSockets.
- Counts describe captured packets, not necessarily every packet that crossed the physical interface.

## Future Part 5

Part 5 is intentionally not implemented in this version. Possible future work includes authenticated multi-user access, configurable dashboards, and production deployment hardening.
