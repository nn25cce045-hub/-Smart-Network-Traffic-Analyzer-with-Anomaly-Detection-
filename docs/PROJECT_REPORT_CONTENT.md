# Project Report Content

This document is structured material for the final college report. Replace bracketed placeholders with institution details, team names, screenshots and results measured on the final presentation computer.

## Title

**Smart Network Traffic Analyzer with Anomaly Detection**

College mini-project submitted by: [INSERT TEAM MEMBER NAMES AND ROLL NUMBERS]

Guide: [INSERT GUIDE NAME]  
Department/Institution: [INSERT DETAILS]  
Academic year: [INSERT YEAR]

## Abstract

Smart Network Traffic Analyzer is a passive, host-based monitoring application that combines live packet visibility, explainable anomaly detection, an observed communication graph and aggregate historical analytics. Scapy captures authorized traffic, a parser extracts limited metadata, and thread-safe Python components calculate packet rates, throughput and protocol counts. Two rule/statistical detectors identify port-scan-like patterns and sudden traffic-volume spikes. Flask exposes the results to a consistent browser dashboard using Chart.js and Cytoscape.js. SQLite stores ten-second aggregate summaries and structured alerts rather than permanent raw packet payloads. Safe internal demo controls make the project repeatable without generating attack traffic. The system is designed as an understandable three-person college project, not an enterprise intrusion-detection platform.

## Introduction

Networks continuously carry traffic from browsers, operating-system services, DNS clients and many other applications. Raw traffic is difficult to interpret manually, while full commercial monitoring platforms can be too complex for a small educational environment. This project demonstrates how packet metadata can be captured, summarized, visualized and checked for explainable abnormal patterns in one application.

The application focuses on visibility and learning: what protocols are present, which IP addresses communicate, how current traffic compares with recent behavior and when simple anomaly rules are triggered.

## Problem statement

Students and small lab users need an accessible method to observe traffic behavior and understand basic anomalies without deploying enterprise infrastructure or storing sensitive payload data. Separate packet sniffers, graph tools and reports make the workflow fragmented. The problem is to integrate these functions safely in a local web application with bounded resource usage and understandable outputs.

## Objectives

- Capture traffic passively from a user-selected authorized interface.
- Classify common traffic as TCP, UDP, DNS, clear-text HTTP, ICMP or Other.
- Present packet counts, packets/sec, throughput, protocols and recent packet metadata.
- Detect explainable port-scan-like and traffic-spike behavior.
- Visualize IP communication without actively discovering devices.
- Persist aggregate history and alerts without saving every packet or payload.
- Compare normal and abnormal intervals and produce CSV/print reports.
- Provide safe, repeatable synthetic demonstrations.
- Remain testable, bounded and understandable by a three-person team.

## Scope

The project is a single-host passive monitoring and educational anomaly-analysis tool. It observes only traffic visible to the selected interface. It is intended for authorized local demonstrations and small environments. It does not perform active scanning, exploitation, packet injection, decryption, credential extraction or attack automation.

## Existing system / motivation

Basic packet sniffers expose detailed packets but may not provide an integrated high-level dashboard, anomaly explanations, communication graph and history. Enterprise SIEM/NDR products provide extensive capabilities but require infrastructure, specialist administration and larger resources. The motivation was to implement a smaller transparent system in which each calculation and rule can be understood and tested.

## Proposed system

The proposed system uses Scapy for passive capture, Python classes for parsing and analysis, Flask for local APIs/pages, Chart.js for charts, Cytoscape.js for the graph and SQLite for aggregate persistence. Each packet becomes a small metadata dictionary that is shared with independent bounded components. The browser polls snapshots and updates existing visual objects.

## System architecture

See `docs/ARCHITECTURE.md` for the full diagram. The main flow is:

```text
Network → Capture → Parser → Metrics / Detectors / Graph / History Accumulator
                              ↓          ↓              ↓
                            Alerts    Network Map     SQLite
                              └──────────┬──────────────┘
                                         ↓
                               Flask APIs and Dashboard
```

## Modules

### Module 1 — packet capture

The user selects an interface listed by Scapy. A daemon thread calls `sniff` with `store=False`, preventing Scapy from accumulating packets internally. One-second timeouts allow responsive stopping. The controller validates interfaces, prevents duplicate capture workers and reports permission/interface failures.

### Module 2 — traffic analysis

The parser extracts timestamp, source/destination IP, ports, TCP flags, transport protocol, classified protocol and packet size. A bounded deque stores recent display rows. Short second buckets calculate live packet rate, approximate throughput and a 60-second chart. Protocol and recent unique-IP totals are exposed through APIs.

### Module 3 — anomaly detection

The port-pattern detector counts unique destination ports per source/destination pair in a rolling time window. The traffic-spike detector compares completed one-second samples with a rolling average of non-anomalous traffic. Warm-up, minimum baseline, cooldown and severity escalation rules reduce noisy output. Alerts contain human-readable evidence and thresholds.

### Module 4 — network visualization

Valid source and destination addresses become graph nodes. A sorted pair forms one bidirectional edge, preventing duplicate forward/reverse links. Nodes and edges aggregate counts, bytes, protocols and timestamps. The graph marks alert-associated nodes, supports filters and expires stale elements. It never scans the network.

### Module 5 — historical analytics

A lock-protected accumulator gathers ten-second packet metadata. The sampler writes one traffic row plus per-IP and per-connection aggregates. Alert records are persisted immediately. The History page calculates summary cards, time series, protocols, normal/abnormal comparison, rankings and alert analytics for predefined ranges. Retention cleanup bounds database growth.

## Technologies used

| Technology | Role |
|---|---|
| Python 3 | Core implementation |
| Flask | Local web server, routes and JSON APIs |
| Scapy | Interface discovery, capture and packet layers |
| SQLite | Aggregate history and persistent alerts |
| HTML/CSS/JavaScript | Responsive user interface |
| Chart.js | Traffic, protocol and comparison charts |
| Cytoscape.js | Interactive communication graph |
| Pytest | Unit and integration testing |

## Algorithms / methods

### Live rate and throughput

```text
packets/sec = packets observed in rolling window ÷ active window seconds
throughput bps = observed bytes × 8 ÷ active window seconds
```

### Moving baseline

The baseline is the arithmetic mean of up to 30 recent non-anomalous completed one-second packet counts. Detection starts after the configured warm-up and minimum meaningful rate.

### Traffic spike

```text
ratio = current packets/sec ÷ baseline packets/sec
warning when ratio ≥ configured warning multiplier
critical when ratio ≥ configured critical multiplier
```

### Port-scan-like pattern

The detector maintains destination-port timestamps for each `(source IP, destination IP)` pair, removes observations outside the rolling window and compares the unique-port count with warning/critical thresholds.

### Graph aggregation

An edge key is `sorted(source IP, destination IP)`, so traffic in both directions updates the same link. Edge width grows logarithmically to avoid an unreadable difference between low and high counts.

### Normal versus abnormal

Stored intervals with `network_status = NORMAL` are normal. `UNUSUAL ACTIVITY`, `WARNING` and `CRITICAL` are grouped as abnormal. Percentages are interval counts divided by all stored intervals in the selected range.

## Database design

| Table | Important fields |
|---|---|
| `traffic_history` | timestamp, interval, totals, rates, protocols, unique IP counts, baseline, status, is_demo |
| `ip_history` | timestamp, IP, packets, bytes, sent/received, alert count, is_demo |
| `connection_history` | timestamp, source, destination, packets, bytes, protocol JSON, is_demo |
| `alert_history` | ID, timestamp, type, severity, explanation, endpoints, measured/threshold values, metadata JSON, is_demo |

Timestamp and common alert/IP query columns are indexed. SQL values are parameterized. Traffic/IP/connection retention defaults to seven days; alerts default to thirty days.

## Testing

Automated tests cover:

- TCP, UDP/DNS, HTTP, ICMP, IPv6 and non-IP parsing.
- Packet/protocol/byte counts, rate, throughput and bounded storage.
- Baseline warm-up, stable traffic, spikes, cooldown and severity.
- Port-pattern thresholds, rolling window, TCP flags, cooldown and escalation.
- Graph aggregation, classification, alert status, limits, expiration and safe demo clearing.
- SQLite initialization, queries, analytics, retention, persistence, reports and demo separation.
- Flask pages, APIs, validation, demos and end-to-end parsed metadata flow.

Actual final automated result: [INSERT OUTPUT FROM `python -m pytest -q` HERE]

Manual environment result: [INSERT COMPLETED CHECKLIST/SUMMARY HERE]

## Results

The implemented application provides one integrated interface for live monitoring, explainable alerting, communication visualization and aggregate history. Insert only results measured during final validation:

- Tests passed/failed/skipped: [INSERT ACTUAL RESULT]
- Interfaces detected: [INSERT ACTUAL RESULT]
- Selected interface and capture result: [INSERT ACTUAL RESULT]
- Example observed protocols: [INSERT ACTUAL RESULT]
- Example demo alerts: [INSERT ACTUAL RESULT]
- History/report validation: [INSERT ACTUAL RESULT]
- Screenshots: [INSERT DASHBOARD, ALERT, MAP AND HISTORY SCREENSHOTS]

## Advantages

- Integrates four monitoring perspectives in one consistent application.
- Explainable thresholds and evidence rather than opaque predictions.
- Bounded in-memory structures and aggregate database writes.
- Persistent alerts/history with low setup overhead.
- Safe deterministic demos that require no attack traffic.
- Privacy-conscious avoidance of permanent payload storage.
- Automated tests cover core behavior without requiring root access.

## Limitations

- Raw capture may require administrator/root privileges.
- Only traffic visible to the host/interface is observed.
- HTTPS and encrypted DNS contents are not inspected.
- Rule/statistical anomalies can produce false positives or miss novel behavior.
- Thresholds may need tuning for different networks.
- The graph is observed communication, not a complete device inventory.
- Live packets, current baseline and graph state are process memory and reset on restart.
- SQLite and Flask's development server are appropriate for this mini-project, not a high-volume distributed production deployment.
- Frontend libraries/fonts currently depend on public CDNs.

## Future enhancements

Possible future work—not implemented in this version—includes offline PCAP import, configurable thresholds, authentication, email notifications, a server database, distributed sensors, richer protocol metadata, cautious device-identification methods and evaluated machine-learning techniques such as Isolation Forest.

## Ethical considerations

Packet capture can expose sensitive metadata and must be performed only with permission. The application listens locally, stores aggregate history rather than payloads, avoids credential collection and labels synthetic records. Alerts must be interpreted carefully: an unusual pattern is not proof of malicious intent. Stored databases and exported reports should be protected and deleted according to institutional policy.

## Conclusion

The project demonstrates that passive capture, basic statistics, explainable anomaly rules, graph visualization and historical reporting can be combined in a small, testable Python application. Its design emphasizes transparency, bounded resources, privacy-aware storage and safe demonstration. It meets the educational goal while clearly acknowledging that a production network-security platform would require greater scale, tuning, access control and operational hardening.
