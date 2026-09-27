# System Architecture

## End-to-end flow

```text
                         AUTHORIZED NETWORK
                                │
                                ▼
                       PACKET CAPTURE (Scapy)
                      background daemon thread
                                │
                                ▼
                          PACKET PARSER
                 small metadata record; no decryption
                                │
              ┌─────────────────┼──────────────────┐
              ▼                 ▼                  ▼
       TRAFFIC METRICS    ANOMALY DETECTOR    GRAPH MANAGER
       bounded packets    ┌──────┴──────┐      bounded nodes/
       and rate buckets   ▼             ▼      bidirectional edges
                     PORT PATTERN   TRAFFIC SPIKE       │
                          │             │               ▼
                          └──────┬──────┘          NETWORK MAP API
                                 ▼
                         STRUCTURED ALERTS
                       memory + SQLite history
                                 │
              ┌──────────────────┴──────────────────┐
              ▼                                     ▼
       HISTORY ACCUMULATOR                  LIVE JSON APIs
       lock-protected metadata                       │
              │                                      │
              ▼                                      │
       10-SECOND SAMPLER                              │
              │                                      │
              ▼                                      │
     SQLITE AGGREGATE STORAGE                         │
       traffic / IP / connection / alerts             │
              │                                      │
       ┌──────┼──────────┐                           │
       ▼      ▼          ▼                           │
    HISTORY  ANALYTICS  CSV/PRINT REPORTS             │
       └──────────────┬───────────────────────────────┘
                      ▼
              FLASK + HTML/CSS/JS
             Chart.js and Cytoscape.js
```

## Component responsibilities

### Capture and parsing

`PacketCapture` owns one background Scapy worker. It validates the selected interface, uses short sniff timeouts so Stop remains responsive, and prevents a second worker from starting. `parse_packet` converts a Scapy object into JSON-friendly metadata: timestamp, addresses, ports, flags, protocol and size. Malformed packets are ignored without terminating capture.

### Live metrics

`TrafficMetrics` uses a re-entrant lock. A deque retains only the configured latest packet rows, while second buckets retain a short rolling time window. It calculates five-second packets/sec and approximate bits/sec. Protocol counters describe the current process lifetime.

### Anomaly detection

`AnomalyDetector` coordinates two explainable rules:

- `PortScanDetector` tracks unique destination ports for a source/destination pair inside a rolling window. TCP packets count only when they look like SYN attempts without ACK.
- `TrafficSpikeDetector` compares completed one-second counts with a moving average of recent non-anomalous samples.

Alert cooldowns reduce duplicates. The coordinator stores each alert, applies it to an existing graph node and persists it. Neither detector sends traffic.

### Network graph

`GraphManager` receives the same already-parsed metadata. Each IP is a node, and each sorted endpoint pair is one bidirectional edge. Counts, bytes, protocols and timestamps are aggregated under a lock. TTL cleanup and hard node/edge limits bound memory. Synthetic contributions are tracked separately so Clear Demo Data can subtract them without deleting genuine observations.

### Historical storage

`HistoryAccumulator` gathers packet metadata per interval without performing SQL in the packet callback. `HistoryService` drains it every ten seconds and uses `HistoryRepository` to insert one traffic sample plus lightweight per-IP and per-connection aggregates in a transaction. Alerts are persisted immediately.

`Database` opens short-lived SQLite connections, enables foreign-key checking and a busy timeout, and configures WAL once during initialization. No connection is shared between capture, Flask or sampler threads.

### Flask APIs and frontend

`create_app` constructs and connects the components. API routes validate interface, limit, demo scenario and history range inputs. API errors use `{"success": false, "error": "..."}` and appropriate status codes. HTML pages use a shared base template and visual system. Browser code polls bounded endpoints and updates existing Chart.js/Cytoscape.js objects rather than continually creating new objects.

## Threading and locks

```text
Flask request threads ─┐
Capture worker ────────┼─→ independently locked metrics/detector/graph/accumulator
History sampler ───────┘

SQLite operation → new connection → transaction → close
```

Locks are held only while copying or updating in-memory structures. Database work occurs after the accumulator has produced a detached snapshot. The Flask reloader is disabled for `python app.py`, preventing duplicate capture and history workers. `HistoryService.start()` is idempotent and guarded by a lock.

## Storage schema

- `traffic_history`: interval totals, rates, protocol counts, IP counts, baseline, status and demo flag.
- `ip_history`: time-bucketed IP packets, bytes, sent/received counts, alert count and demo flag.
- `connection_history`: time-bucketed normalized endpoints, packets, bytes, protocol JSON and demo flag.
- `alert_history`: stable alert ID, time, type, severity, explanation, endpoints, measurements, metadata JSON and demo flag.

Indexes cover timestamps, IP address, alert type and severity. All user-selectable time ranges map to predefined durations before parameterized queries are executed.

## Privacy and trust boundaries

- Live packet rows are bounded in memory and disappear on restart.
- Historical storage contains aggregate metadata, not raw packet payloads.
- HTTPS is not decrypted; credentials and form contents are not extracted.
- The graph shows only communication observed by the selected host/interface.
- Synthetic demonstrations use documentation/private example addresses and internal numeric data only.
- The development server listens only on `127.0.0.1` by default.
