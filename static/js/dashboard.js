"use strict";

const chartFont = { family: "JetBrains Mono", size: 9 };
const chartGridColor = "rgba(125,139,157,.10)";
let trafficChart;
let protocolChart;

function buildCharts() {
  if (typeof Chart === "undefined") {
    Netra.showToast("Charts could not load. Check the internet connection for Chart.js.", true);
    return;
  }
  Chart.defaults.color = "#68778b";
  Chart.defaults.font.family = "DM Sans";
  trafficChart = new Chart(document.getElementById("trafficChart"), {
    type: "line",
    data: { labels: [], datasets: [{ data: [], borderColor: "#36e3c1", backgroundColor: "rgba(54,227,193,.08)", fill: true, tension: .35, pointRadius: 0, borderWidth: 1.5 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false, interaction: { intersect: false, mode: "index" }, plugins: { legend: { display: false }, tooltip: { displayColors: false } }, scales: { x: { grid: { display: false }, ticks: { font: chartFont, maxTicksLimit: 8 } }, y: { beginAtZero: true, grid: { color: chartGridColor }, border: { display: false }, ticks: { font: chartFont, precision: 0 } } } }
  });
  protocolChart = new Chart(document.getElementById("protocolChart"), {
    type: "doughnut",
    data: { labels: Object.keys(Netra.protocolColors), datasets: [{ data: [0, 0, 0, 0, 0, 0], backgroundColor: Object.values(Netra.protocolColors), borderWidth: 0, hoverOffset: 3 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "75%", animation: { duration: 250 }, plugins: { legend: { display: false } } }
  });
}

function updateLegend(protocols, elementId = "protocolLegend") {
  const total = Object.values(protocols).reduce((sum, value) => sum + value, 0);
  document.getElementById(elementId).innerHTML = Object.entries(protocols).map(([name, count]) => {
    const percent = total ? Math.round((count / total) * 100) : 0;
    return `<span><i style="background:${Netra.protocolColors[name]}"></i>${name} ${percent}%</span>`;
  }).join("");
}

function updateCaptureControls(stats) {
  Netra.updateGlobalState(stats.capturing);
  const startButton = document.getElementById("startCapture");
  const stopButton = document.getElementById("stopCapture");
  const interfaceSelect = document.getElementById("interfaceSelect");
  startButton.disabled = stats.capturing;
  stopButton.disabled = !stats.capturing;
  interfaceSelect.disabled = stats.capturing;
  const state = document.getElementById("captureState");
  state.textContent = stats.capturing ? "CAPTURING" : "STOPPED";
  state.classList.toggle("capturing", stats.capturing);
  document.getElementById("activeInterface").textContent = stats.interface || "No interface selected";
  const error = document.getElementById("captureError");
  if (stats.last_error) error.textContent = stats.last_error;
}

async function loadInterfaces() {
  const select = document.getElementById("interfaceSelect");
  try {
    const data = await Netra.request("/api/interfaces");
    select.replaceChildren();
    if (!data.interfaces.length) {
      select.add(new Option("No interfaces found", ""));
      return;
    }
    data.interfaces.forEach(item => select.add(new Option(`${item.name}${item.address ? ` · ${item.address}` : ""}`, item.name)));
  } catch (error) {
    select.replaceChildren(new Option("Could not load interfaces", ""));
    document.getElementById("captureError").textContent = error.message;
  }
}

async function refreshStats() {
  try {
    const stats = await Netra.request("/api/stats");
    document.getElementById("totalPackets").textContent = Netra.formatNumber(stats.total_packets);
    document.getElementById("chartTotal").textContent = Netra.formatNumber(stats.total_packets);
    document.getElementById("packetsPerSecond").textContent = Number(stats.packets_per_second).toFixed(1);
    document.getElementById("throughput").textContent = Netra.formatThroughput(stats.throughput_bps);
    Object.entries(stats.protocols).forEach(([name, count]) => {
      const target = document.getElementById(`count${name}`);
      if (target) target.textContent = Netra.formatNumber(count);
    });
    updateCaptureControls(stats);
    updateLegend(stats.protocols);
    if (trafficChart) {
      trafficChart.data.labels = stats.history.map(item => item.time);
      trafficChart.data.datasets[0].data = stats.history.map(item => item.packets);
      trafficChart.update("none");
    }
    if (protocolChart) {
      protocolChart.data.datasets[0].data = Object.keys(Netra.protocolColors).map(name => stats.protocols[name] || 0);
      protocolChart.update("none");
    }
  } catch (error) { Netra.showToast(error.message, true); }
}

async function refreshRecentPackets() {
  try {
    const data = await Netra.request("/api/packets?limit=6");
    const body = document.getElementById("recentPackets");
    if (!data.packets.length) {
      body.innerHTML = '<tr class="empty-row"><td colspan="5">No packets captured yet. Select an interface to begin.</td></tr>';
      return;
    }
    body.innerHTML = data.packets.map(packet => `<tr><td>${Netra.escapeHtml(packet.time)}</td><td>${Netra.escapeHtml(packet.source_ip)}</td><td>${Netra.escapeHtml(packet.destination_ip)}</td><td><span class="protocol-badge protocol-${packet.protocol.toLowerCase()}">${Netra.escapeHtml(packet.protocol)}</span></td><td>${Netra.formatNumber(packet.size)} B</td></tr>`).join("");
  } catch { /* Stats refresh reports connectivity problems. */ }
}

async function refreshAnomalyStatus() {
  try {
    const data = await Netra.request("/api/anomaly/status");
    const status = document.getElementById("networkStatus");
    const statusClass = data.network_status.toLowerCase().replaceAll(" ", "-");
    status.className = `network-status ${statusClass}`;
    status.innerHTML = `<i></i>${Netra.escapeHtml(data.network_status)}`;
    document.getElementById("networkStatusDetail").textContent = data.summary.total
      ? `${data.summary.warning} warning · ${data.summary.critical} critical retained`
      : "No recent anomaly alerts";
    document.getElementById("dashboardAlertCount").textContent = `${data.summary.total} ALERT${data.summary.total === 1 ? "" : "S"}`;

    const list = document.getElementById("dashboardAlertList");
    if (!data.recent_alerts.length) {
      list.innerHTML = '<p class="alert-empty">No anomalies detected. Monitoring rules are active.</p>';
      return;
    }
    list.innerHTML = data.recent_alerts.slice(0, 3).map(alert => `<a href="/alerts" class="dashboard-alert-item">
      <span class="severity-dot ${alert.severity.toLowerCase()}"></span>
      <time>${Netra.escapeHtml(alert.time)}</time>
      <strong>${Netra.escapeHtml(alert.title)}</strong>
      <em class="severity-badge ${alert.severity.toLowerCase()}">${Netra.escapeHtml(alert.severity)}</em>
    </a>`).join("");
  } catch { /* The primary stats request already reports connectivity issues. */ }
}

async function refreshNetworkOverview() {
  try {
    const data = await Netra.request("/api/network/graph");
    document.getElementById("dashboardDevices").textContent = Netra.formatNumber(data.stats.observed_devices);
    document.getElementById("dashboardConnections").textContent = Netra.formatNumber(data.stats.active_connections);
    document.getElementById("dashboardSuspicious").textContent = Netra.formatNumber(data.stats.suspicious_devices);
  } catch { /* Other dashboard requests report server connectivity problems. */ }
}

document.getElementById("startCapture").addEventListener("click", async () => {
  const interfaceName = document.getElementById("interfaceSelect").value;
  document.getElementById("captureError").textContent = "";
  try {
    const data = await Netra.request("/api/capture/start", { method: "POST", body: JSON.stringify({ interface: interfaceName }) });
    Netra.showToast(data.message);
    await refreshStats();
  } catch (error) { document.getElementById("captureError").textContent = error.message; Netra.showToast(error.message, true); }
});

document.getElementById("stopCapture").addEventListener("click", async () => {
  try {
    const data = await Netra.request("/api/capture/stop", { method: "POST", body: "{}" });
    Netra.showToast(data.message);
    window.setTimeout(refreshStats, 1100);
  } catch (error) { Netra.showToast(error.message, true); }
});

buildCharts();
loadInterfaces();
refreshStats();
refreshRecentPackets();
refreshAnomalyStatus();
refreshNetworkOverview();
window.setInterval(refreshStats, 1000);
window.setInterval(refreshRecentPackets, 1500);
window.setInterval(refreshAnomalyStatus, 2000);
window.setInterval(refreshNetworkOverview, 3000);
