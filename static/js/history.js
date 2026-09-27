"use strict";

let selectedHistoryRange = "1h";
let trafficChart;
let throughputChart;
let protocolChart;
let alertChart;
let comparisonChart;

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function shortTime(value) {
  const date = new Date(value);
  return selectedHistoryRange === "7d" || selectedHistoryRange === "24h"
    ? date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function initializeHistoryCharts() {
  if (typeof Chart === "undefined") {
    Netra.showToast("Charts could not load. Check the internet connection for Chart.js.", true);
    return;
  }
  Chart.defaults.color = "#68778b";
  Chart.defaults.font.family = "DM Sans";
  const axis = { grid: { color: "rgba(125,139,157,.10)" }, border: { display: false }, ticks: { font: { family: "JetBrains Mono", size: 8 } } };
  trafficChart = new Chart(document.getElementById("historyTrafficChart"), {
    type: "line", data: { labels: [], datasets: [
      { label: "Actual traffic", data: [], borderColor: "#36e3c1", backgroundColor: "rgba(54,227,193,.07)", fill: true, pointRadius: 0, tension: .28, borderWidth: 1.5 },
      { label: "Rolling baseline", data: [], borderColor: "#f5a65b", borderDash: [5, 5], pointRadius: 0, tension: .2, borderWidth: 1.2 }
    ] }, options: { responsive: true, maintainAspectRatio: false, animation: false, interaction: { intersect: false, mode: "index" }, plugins: { legend: { labels: { boxWidth: 8, boxHeight: 8 } } }, scales: { x: { ...axis, grid: { display: false }, ticks: { ...axis.ticks, maxTicksLimit: 10 } }, y: { ...axis, beginAtZero: true } } }
  });
  throughputChart = new Chart(document.getElementById("historyThroughputChart"), {
    type: "line", data: { labels: [], datasets: [{ data: [], borderColor: "#4e8cff", backgroundColor: "rgba(78,140,255,.08)", fill: true, pointRadius: 0, tension: .3, borderWidth: 1.4 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false }, tooltip: { callbacks: { label: context => Netra.formatThroughput(context.raw) } } }, scales: { x: { ...axis, grid: { display: false }, ticks: { ...axis.ticks, maxTicksLimit: 6 } }, y: { ...axis, beginAtZero: true, ticks: { ...axis.ticks, callback: value => Netra.formatThroughput(value) } } } }
  });
  protocolChart = new Chart(document.getElementById("historyProtocolChart"), {
    type: "doughnut", data: { labels: Object.keys(Netra.protocolColors), datasets: [{ data: [], backgroundColor: Object.values(Netra.protocolColors), borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { display: false } } }
  });
  alertChart = new Chart(document.getElementById("historyAlertChart"), {
    type: "bar", data: { labels: [], datasets: [
      { label: "Info", data: [], backgroundColor: "#4e8cff" },
      { label: "Warning", data: [], backgroundColor: "#f5a65b" },
      { label: "Critical", data: [], backgroundColor: "#ff6278" }
    ] }, options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { labels: { boxWidth: 8, boxHeight: 8 } } }, scales: { x: { stacked: true, grid: { display: false }, ticks: { ...axis.ticks, maxTicksLimit: 6 } }, y: { ...axis, stacked: true, beginAtZero: true, ticks: { ...axis.ticks, precision: 0 } } } }
  });
  comparisonChart = new Chart(document.getElementById("historyComparisonChart"), {
    type: "doughnut", data: { labels: ["Normal", "Abnormal"], datasets: [{ data: [0, 0], backgroundColor: ["#36e3c1", "#f5a65b"], borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "70%", plugins: { legend: { display: false } } }
  });
}

function renderTables(data) {
  const talkers = document.getElementById("topTalkers");
  talkers.innerHTML = data.top_talkers.length ? data.top_talkers.map(row => `<tr><td>${Netra.escapeHtml(row.ip_address)}</td><td>${Netra.formatNumber(row.packets)}</td><td>${formatBytes(row.bytes)}</td><td>${Netra.formatNumber(row.sent_packets)} / ${Netra.formatNumber(row.received_packets)}</td></tr>`).join("") : '<tr class="empty-row"><td colspan="4">No historical talker data.</td></tr>';

  const connections = document.getElementById("topConnections");
  connections.innerHTML = data.top_connections.length ? data.top_connections.map(row => `<tr><td>${Netra.escapeHtml(row.source_ip)} <span class="connection-arrow">↔</span> ${Netra.escapeHtml(row.destination_ip)}</td><td>${Netra.formatNumber(row.packets)}</td><td>${formatBytes(row.bytes)}</td></tr>`).join("") : '<tr class="empty-row"><td colspan="3">No historical connection data.</td></tr>';

  const alerts = data.alerts.recent;
  document.getElementById("historyAlertRows").innerHTML = alerts.length ? alerts.map(alert => `<tr><td>${Netra.escapeHtml(shortTime(alert.timestamp_iso))}${alert.is_demo ? '<span class="demo-tag">DEMO</span>' : ""}</td><td><span class="severity-badge ${alert.severity.toLowerCase()}">${Netra.escapeHtml(alert.severity)}</span></td><td>${Netra.escapeHtml(alert.type.replaceAll("_", " "))}</td><td>${Netra.escapeHtml(alert.source_ip)}</td><td class="history-alert-description">${Netra.escapeHtml(alert.description)}</td></tr>`).join("") : '<tr class="empty-row"><td colspan="5">No persisted alerts in this period.</td></tr>';
}

function updateHistoryCharts(data) {
  const labels = data.traffic.map(row => shortTime(row.timestamp_iso));
  if (trafficChart) {
    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = data.traffic.map(row => row.packets_per_second);
    trafficChart.data.datasets[1].data = data.traffic.map(row => row.baseline_packets_per_second);
    trafficChart.update("none");
  }
  if (throughputChart) {
    throughputChart.data.labels = labels;
    throughputChart.data.datasets[0].data = data.traffic.map(row => row.throughput_bps);
    throughputChart.update("none");
  }
  const protocols = Object.keys(Netra.protocolColors);
  const protocolTotal = Object.values(data.protocols).reduce((sum, value) => sum + value, 0);
  if (protocolChart) { protocolChart.data.datasets[0].data = protocols.map(name => data.protocols[name] || 0); protocolChart.update("none"); }
  document.getElementById("historyProtocolLegend").innerHTML = protocols.map(name => `<span><i style="background:${Netra.protocolColors[name]}"></i>${name} ${protocolTotal ? Math.round((data.protocols[name] || 0) / protocolTotal * 100) : 0}%</span>`).join("");

  const alertTimeline = data.alerts.timeline.slice(-200);
  if (alertChart) {
    alertChart.data.labels = alertTimeline.map(alert => shortTime(alert.timestamp_iso));
    alertChart.data.datasets[0].data = alertTimeline.map(alert => alert.severity === "INFO" ? 1 : 0);
    alertChart.data.datasets[1].data = alertTimeline.map(alert => alert.severity === "WARNING" ? 1 : 0);
    alertChart.data.datasets[2].data = alertTimeline.map(alert => alert.severity === "CRITICAL" ? 1 : 0);
    alertChart.update("none");
  }
  if (comparisonChart) {
    comparisonChart.data.datasets[0].data = [data.comparison.normal.intervals, data.comparison.abnormal.intervals];
    comparisonChart.update("none");
  }
}

function updateHistoryValues(data) {
  const summary = data.summary;
  document.getElementById("historyNoData").classList.toggle("hidden", summary.has_data);
  document.getElementById("historyTraffic").textContent = formatBytes(summary.total_bytes);
  document.getElementById("historyPackets").textContent = `${Netra.formatNumber(summary.total_packets)} packets`;
  document.getElementById("historyAvgPps").textContent = Number(summary.average_pps).toFixed(1);
  document.getElementById("historyPeakPps").textContent = Number(summary.peak_pps).toFixed(1);
  document.getElementById("historyAvgThroughput").textContent = Netra.formatThroughput(summary.average_throughput_bps);
  document.getElementById("historyAlerts").textContent = Netra.formatNumber(summary.total_alerts);
  document.getElementById("historyCritical").textContent = Netra.formatNumber(summary.critical_alerts);

  const comparison = data.comparison;
  document.getElementById("normalPercent").textContent = `${Number(comparison.normal_percent).toFixed(1)}%`;
  document.getElementById("abnormalPercent").textContent = `${Number(comparison.abnormal_percent).toFixed(1)}%`;
  document.getElementById("normalAverage").textContent = Number(comparison.normal.average_pps).toFixed(1);
  document.getElementById("normalPeak").textContent = Number(comparison.normal.peak_pps).toFixed(1);
  document.getElementById("abnormalAverage").textContent = Number(comparison.abnormal.average_pps).toFixed(1);
  document.getElementById("abnormalPeak").textContent = Number(comparison.abnormal.peak_pps).toFixed(1);
  document.getElementById("anomalyEvents").textContent = Netra.formatNumber(comparison.anomaly_events);
  document.getElementById("historyPortScans").textContent = Netra.formatNumber(data.alerts.by_type.PORT_SCAN || 0);
  document.getElementById("historySpikes").textContent = Netra.formatNumber(data.alerts.by_type.TRAFFIC_SPIKE || 0);
  document.getElementById("historyAlertedSource").textContent = data.alerts.most_frequently_alerted_source || "—";
  renderTables(data);
  updateHistoryCharts(data);
}

async function refreshHistory() {
  try {
    const [data, stats] = await Promise.all([
      Netra.request(`/api/history?range=${selectedHistoryRange}`),
      Netra.request("/api/stats")
    ]);
    updateHistoryValues(data);
    Netra.updateGlobalState(stats.capturing);
    document.getElementById("csvReport").href = `/api/history/export?range=${selectedHistoryRange}`;
    document.getElementById("printReport").href = `/history/report?range=${selectedHistoryRange}`;
  } catch (error) { Netra.showToast(error.message, true); }
}

document.getElementById("historyRanges").addEventListener("click", event => {
  const button = event.target.closest("button[data-range]");
  if (!button) return;
  selectedHistoryRange = button.dataset.range;
  document.querySelectorAll("#historyRanges button").forEach(item => item.classList.toggle("active", item === button));
  refreshHistory();
});

initializeHistoryCharts();
refreshHistory();
window.setInterval(refreshHistory, 10000);
