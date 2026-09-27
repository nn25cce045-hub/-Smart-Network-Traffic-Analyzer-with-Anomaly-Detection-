# Manual Test Checklist

Record the date, tester, operating system and browser before completing this checklist.

- Date: ____________________
- Tester: __________________
- OS: ______________________
- Browser: __________________
- Selected interface: __________________

## Startup and dashboard

- [ ] Virtual environment activates and dependencies install without errors.
- [ ] Application starts and prints version, database, demo-mode and local-address information.
- [ ] Dashboard loads without a server error.
- [ ] Browser developer console shows no major JavaScript errors.
- [ ] Interface list loads.
- [ ] No-interface selection is rejected with a readable message.
- [ ] Capture starts on an authorized interface.
- [ ] Capture state and selected interface are clearly displayed.
- [ ] Starting capture twice is rejected safely.
- [ ] Capture stops.
- [ ] Stopping capture twice is rejected safely.
- [ ] Permission/interface errors appear in the UI without crashing Flask.

## Live traffic

- [ ] Packet count increases while authorized traffic is generated.
- [ ] Packets appear on Dashboard and Live Packets.
- [ ] Packet time, source/destination IP, ports, protocol and size appear correctly.
- [ ] TCP filter works.
- [ ] UDP/DNS/HTTP/ICMP filters work when matching traffic is available.
- [ ] IP search works.
- [ ] No-match and waiting-for-packets states are readable.
- [ ] Protocol chart updates.
- [ ] Traffic chart updates.
- [ ] Throughput updates with sensible bps/Kbps/Mbps units.
- [ ] Live packet table remains bounded and usable.

## Analysis and alerts

- [ ] Traffic Analysis page loads.
- [ ] Current packets/sec and throughput match the active traffic trend.
- [ ] Baseline warm-up count progresses.
- [ ] Baseline and deviation display after warm-up.
- [ ] Unique source and destination counts update.
- [ ] Alerts page loads and empty state is clear.
- [ ] Severity/type filters and search work.
- [ ] Port-scan-like demo creates an alert.
- [ ] Traffic-spike demo creates an alert.
- [ ] Network status changes appropriately.
- [ ] Demo controls are rejected while capture is running.

## Network map

- [ ] Network Map loads.
- [ ] Nodes appear for observed or demo IPs.
- [ ] Edges appear for observed communication.
- [ ] Local, External and Special styles match the legend.
- [ ] Node details work.
- [ ] Edge details work.
- [ ] Protocol filter works.
- [ ] Device filter works.
- [ ] Minimum-packet filter works.
- [ ] Pause and Resume Live Update work.
- [ ] Fit Graph and Reset View work.
- [ ] New polling data does not constantly reset user zoom.
- [ ] Suspicious node highlighting works.
- [ ] Stale graph cleanup works after configured TTLs or via automated tests.

## History and reports

- [ ] History / Analytics page loads.
- [ ] Empty-history message appears for an empty selected period.
- [ ] 15-minute, 1-hour, 6-hour, 24-hour and 7-day filters work.
- [ ] Historical traffic and baseline chart works.
- [ ] Throughput and protocol charts work.
- [ ] Alert timeline works.
- [ ] Normal versus abnormal comparison works.
- [ ] Top Talkers works.
- [ ] Top Connections works.
- [ ] Alert History works.
- [ ] CSV export downloads and contains actual stored values.
- [ ] Printable report loads and browser Print/Save as PDF works.
- [ ] Demo history creates the documented timeline.

## Safe reset and persistence

- [ ] Generate Demo Network works without network traffic.
- [ ] Clear Demo Data removes synthetic alerts/history/graph contributions.
- [ ] Clear Demo Data preserves genuine history and graph observations.
- [ ] Restarting Flask restores persisted alerts/history.
- [ ] No payload or raw-packet table exists in SQLite.

## Final regression

- [ ] `python -m pytest -q` passes.
- [ ] Python compile/import check passes.
- [ ] JavaScript syntax checks pass.
- [ ] Dashboard, packets, traffic, alerts, map and history pages remain visually consistent.
- [ ] Laptop/tablet widths do not cause severe chart or table overflow.
- [ ] No active scan, packet injection or attack traffic was generated.

## Notes and actual results

[INSERT ACTUAL MANUAL TEST NOTES HERE]
