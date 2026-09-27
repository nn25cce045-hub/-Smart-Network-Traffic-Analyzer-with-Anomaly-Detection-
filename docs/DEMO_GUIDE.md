# Demonstration Guide

This guide lets any of the three team members present Smart Network Traffic Analyzer v1.0.0. Use only a network and computer you are authorized to monitor.

## Preparation

1. Use a laptop with Python 3.10 or newer and a current Chrome or Firefox browser.
2. Confirm internet access for the Chart.js, Cytoscape.js, and font CDN files.
3. From the project directory, prepare the environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   python -m pytest -q
   ```

4. Start normally with `python app.py`. If Linux reports capture permission denied, stop with `Ctrl+C` and use `sudo .venv/bin/python app.py`.
5. Open `http://127.0.0.1:5000`. Keep the terminal visible enough to confirm clean startup and logging.
6. Close unrelated traffic-heavy applications. Make sure **Demo mode: Enabled** appears at startup.

## Scene 1 — normal monitoring

1. Open **Dashboard**.
2. Select the active Wi-Fi/Ethernet interface. The displayed address helps identify it; `lo` is loopback only.
3. Select **Start Capture**. The state should become **CAPTURING** and show the interface name.
4. Generate authorized ordinary traffic by loading a website.
5. Point out increasing total packets, packets/sec, throughput, protocol counts, the traffic chart, and recent packet rows.
6. Open **Live Packets**. Demonstrate a protocol filter and search for a visible IP address.
7. Open **Traffic Analysis**. Explain current traffic, throughput, baseline warm-up, deviation, protocol mix, and unique IP totals.

Expected result: counters and tables update without reloading the page. HTTPS normally appears as TCP because encrypted application contents are not decrypted.

## Scene 2 — network map

1. Open **Network Map**.
2. Show observed IP nodes and bidirectional communication edges.
3. Select a node, then an edge, to show details.
4. Demonstrate protocol/device/minimum-packet filters, **Pause Live Update**, **Resume**, **Fit Graph**, and **Reset View**.
5. Explain the legend: Local, External, Special, Warning and Critical.

Expected result: the graph updates existing elements without recreating the view or resetting zoom for every poll.

## Scene 3 — port-scan-like detection

1. Stop live capture before using synthetic controls.
2. Open **Alerts** and locate **DEMO MODE — SYNTHETIC DATA ONLY**.
3. Select **Simulate Port-Scan-Like Pattern**.
4. Show the Warning alert, explanation, source/destination, changed network status, and highlighted source on Network Map.

Explain that internal metadata is passed through the real detector. No host is contacted and no ports are scanned.

## Scene 4 — traffic spike

1. In the same Demo Mode panel, select **Simulate Traffic Spike**.
2. Show the new alert and severity.
3. Open **Traffic Analysis** to explain the moving baseline and configured spike ratio.
4. Return to Dashboard/Alerts to show the status change.

## Scene 5 — historical analytics

1. In Alerts, select **Generate Demo History**.
2. Open **History / Analytics** and keep **Last 1 Hour** selected.
3. Show the 30-minute normal → growth → spike → warning → recovery timeline.
4. Explain actual traffic versus baseline, throughput, protocols, normal/abnormal percentages, top talkers, top connections and persisted alerts.
5. Emphasize that abnormal means deviation or a triggered rule, not proof of malicious activity.

## Scene 6 — reporting

1. Select **Download CSV** and show its traffic, protocol, alert, comparison and top-talker sections.
2. Select **Print Report** and demonstrate the browser's Print/Save as PDF dialog.
3. Explain that history stores aggregated metadata rather than permanent raw packets or payloads.

## Fallback presentation without capture privileges

If capture cannot start, keep it stopped and use the centralized Alerts demo controls in this order:

1. **Simulate Normal Traffic**
2. **Generate Demo Network**
3. **Simulate Port-Scan-Like Pattern**
4. **Simulate Traffic Spike**
5. **Generate Demo History**

This fallback is deterministic and does not generate network traffic.

## Resetting the demonstration

Stop live capture and select **Clear Demo Data** in Alerts. It removes demo-marked alerts, history and graph contributions while preserving real stored history and real graph observations. Detector working state is reset so the next demonstration begins cleanly.

If a full local reset is ever required for development, stop Flask and back up/remove `data/network_analyzer.db`. This deletes real history too and is therefore not part of the presentation workflow.

## Presenter handoff

- Member 1 presents Scene 1.
- Member 3 presents Scene 2.
- Member 2 presents Scenes 3 and 4.
- Member 3 presents Scenes 5 and 6.
- All members should be able to explain passive capture, the data pipeline, false positives, aggregate storage and ethical limitations.
