# Viva Questions and Concise Answers

## Project and networking

1. **What problem does the project solve?**  
   It gives a host user one passive dashboard for live traffic visibility, explainable anomaly indicators, observed communication mapping and aggregate historical reports.

2. **Why did you choose Scapy?**  
   Scapy exposes packet layers and fields directly in Python, supports multiple protocols and integrates cleanly with our Flask-side processing pipeline.

3. **What is packet sniffing?**  
   It is observing packets visible to a network interface. Our application captures passively and does not modify or inject them.

4. **What is the difference between TCP and UDP?**  
   TCP is connection-oriented and provides ordered, reliable delivery. UDP is connectionless with lower overhead and no built-in delivery guarantee.

5. **How do you identify DNS traffic?**  
   We check for Scapy's DNS layer and also whether the source or destination port is 53.

6. **How do you identify HTTP?**  
   We recognize common clear-text HTTP ports or standard request/response prefixes in an available Raw layer. We do not store the payload.

7. **Why might HTTPS appear as TCP instead of HTTP?**  
   HTTPS encrypts application data with TLS. Without decryption, the visible transport is TCP, commonly on port 443.

8. **How is throughput calculated?**  
   Captured bytes in the rolling window are multiplied by eight and divided by the window duration to produce approximate bits per second.

9. **What is packets per second?**  
   It is the number of observed packets divided by elapsed time. The live dashboard uses a rolling window of up to five seconds.

10. **Why is captured traffic not necessarily all network traffic?**  
    A normal switched network exposes mainly traffic addressed to/from the host plus broadcast/multicast traffic. Interface choice, permissions, offloading and dropped packets also affect visibility.

## Anomaly detection

11. **What is anomaly detection?**  
    It identifies activity that differs from expected behavior or crosses an explainable rule. An anomaly is a reason to investigate, not automatic proof of attack.

12. **What is a baseline?**  
    It is a moving average representing recent normal traffic volume. Our baseline uses bounded, completed one-second non-anomalous samples.

13. **How does the traffic-spike detector work?**  
    After warm-up, it compares a completed second's packets/sec with the baseline. A sample at least three times a meaningful baseline creates a warning; a larger configured ratio creates a critical alert.

14. **Why exclude anomalous samples from the baseline?**  
    Including a spike would quickly increase the baseline and make the same abnormal burst appear normal.

15. **How does the port-scan-like detector work?**  
    It counts unique destination ports contacted by one source toward one destination inside a ten-second rolling window. For TCP it counts SYN attempts without ACK when flags are available.

16. **Why call it port-scan-like rather than an attack?**  
    Legitimate discovery, monitoring or applications can contact many ports. The observed pattern alone cannot prove intent.

17. **What is a false positive?**  
    It is legitimate activity that satisfies an anomaly rule and is incorrectly interpreted as suspicious.

18. **How do you reduce false positives?**  
    We use baseline warm-up, minimum activity, rolling windows, TCP flag checks, cooldowns, severity escalation rules and exclude detected spikes from baseline learning.

19. **What is an alert cooldown?**  
    It suppresses repeated equivalent alerts for a configured time so one event does not flood the alert list. A warning may still escalate immediately to critical.

20. **Why did you not use deep learning?**  
    Explainable statistical rules fit the small project scope, need no training dataset, use fewer resources and are easier to test and defend in a viva.

## Graph and history

21. **How does the network graph work?**  
    Parsed source and destination IPs update nodes and a normalized bidirectional edge. Counts, bytes, protocols and times are aggregated without active discovery.

22. **What does a node represent?**  
    A node represents an IP address observed in captured communication, not a verified person or device type.

23. **What does an edge represent?**  
    It represents observed communication between two IPs in either direction, with aggregate packets, bytes and protocols.

24. **How do you distinguish private and public IP addresses?**  
    Python's `ipaddress` module plus explicit RFC 1918/IPv6 unique-local networks classify addresses as Local, External or Special.

25. **Does the application actively scan devices?**  
    No. The map includes only addresses from already-observed packets or clearly marked internal demo metadata.

26. **Why not permanently store every packet?**  
    Packet-by-packet storage grows quickly and creates privacy risk. Aggregate time buckets provide useful trends with lower storage and no saved payload content.

27. **Why SQLite?**  
    It is serverless, included with Python, reliable for a single-host mini-project and supports transactions, indexes and parameterized queries.

28. **What is the difference between normal and abnormal history?**  
    A stored interval is normal when its existing network status is `NORMAL`; unusual, warning or critical statuses are grouped as abnormal. Abnormal does not automatically mean malicious.

29. **How are Top Talkers calculated?**  
    Per-IP aggregate rows inside the selected range are grouped by IP and summed, then ordered by bytes and packets.

30. **How do alerts survive restart?**  
    Structured alerts are written immediately to `alert_history`. At startup, recent persisted alerts are loaded into the bounded in-memory alert store.

## Engineering, limitations and ethics

31. **How do you ensure thread safety?**  
    Metrics, alerts, detectors, graph and history accumulator protect shared structures with locks. SQLite uses a new connection per operation rather than sharing one across threads.

32. **How do you prevent duplicate background workers?**  
    Capture checks its running state under a lock, HistoryService starts idempotently under a start lock, and the Flask reloader is disabled in the normal startup command.

33. **What happens when traffic becomes very high?**  
    Recent packets use a fixed deque, graph nodes/edges have hard limits and TTLs, detector windows are bounded, APIs return bounded histories, and SQLite receives interval aggregates rather than one row per packet. Extremely high production rates can still exceed this mini-project's capacity.

34. **How are SQL injection risks reduced?**  
    Time ranges are selected from a fixed mapping and all query values use SQLite parameters rather than string-concatenated user input.

35. **How does demo mode remain safe?**  
    It passes numbers and example metadata directly to internal components. It opens no sockets, sends no packets and performs no scan or flood.

36. **What are the project's main limitations?**  
    Visibility is host/interface dependent, encrypted traffic is not inspected, thresholds require tuning, rules may produce false positives, the graph is not a full inventory and SQLite/Flask development server are not enterprise infrastructure.

37. **How could the project be improved?**  
    Future work could add offline PCAP analysis, authentication, notifications, configurable thresholds, richer protocol metadata, a server database or carefully evaluated machine-learning detection.

38. **What ethical considerations apply?**  
    Capture only with authorization, minimize stored information, avoid payload/credential collection, protect access to history, label synthetic data and never interpret an alert as guilt without investigation.

39. **How was the application tested?**  
    Pytest covers parsing, metrics, detectors, cooldowns, graph behavior, SQLite, retention, demos and APIs. Syntax checks and browser-level smoke tests complement unit/integration tests; privileged live capture still requires manual testing.

40. **Why is this a single integrated system rather than four separate parts?**  
    One parsed metadata event feeds shared metrics, detectors, graph and history components; alerts flow back into graph status and persistence; all pages use the same Flask APIs, navigation and visual system.
