"use strict";

let alerts = [];
let selectedAlertFilter = "ALL";

function renderAlerts() {
  const query = document.getElementById("alertSearch").value.trim().toLowerCase();
  const visible = alerts.filter(alert => {
    const categoryMatch = selectedAlertFilter === "ALL" || alert.severity === selectedAlertFilter || alert.type === selectedAlertFilter;
    const haystack = [alert.source_ip, alert.destination_ip, alert.title, alert.description, alert.type].filter(Boolean).join(" ").toLowerCase();
    return categoryMatch && (!query || haystack.includes(query));
  });
  document.getElementById("visibleAlertCount").textContent = visible.length;
  const body = document.getElementById("alertRows");
  if (!visible.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">${alerts.length ? "No alerts match the current filters." : "No anomaly alerts have been generated."}</td></tr>`;
    return;
  }
  body.innerHTML = visible.map(alert => `<tr>
    <td>${Netra.escapeHtml(alert.time)}</td>
    <td><span class="severity-badge ${alert.severity.toLowerCase()}">${Netra.escapeHtml(alert.severity)}</span></td>
    <td><span class="alert-type">${Netra.escapeHtml(alert.type.replaceAll("_", " "))}</span></td>
    <td>${Netra.escapeHtml(alert.source_ip)}</td>
    <td>${Netra.escapeHtml(alert.destination_ip)}</td>
    <td class="alert-description"><strong>${Netra.escapeHtml(alert.title)}</strong><span>${Netra.escapeHtml(alert.description)}</span></td>
  </tr>`).join("");
}

function updateStatus(status) {
  const banner = document.getElementById("alertNetworkStatus");
  const statusClass = status.toLowerCase().replaceAll(" ", "-");
  banner.className = `status-banner ${statusClass}`;
  banner.innerHTML = `<small>NETWORK STATUS</small><strong>${Netra.escapeHtml(status)}</strong>`;
}

async function refreshAlerts() {
  try {
    const [alertData, anomalyData] = await Promise.all([
      Netra.request("/api/alerts?limit=500"),
      Netra.request("/api/anomaly/status")
    ]);
    alerts = alertData.alerts.slice(0, 500);
    const summary = alertData.summary;
    document.getElementById("totalAlerts").textContent = Netra.formatNumber(summary.total);
    document.getElementById("infoAlerts").textContent = Netra.formatNumber(summary.info);
    document.getElementById("warningAlerts").textContent = Netra.formatNumber(summary.warning);
    document.getElementById("criticalAlerts").textContent = Netra.formatNumber(summary.critical);
    updateStatus(anomalyData.network_status);
    renderAlerts();
  } catch (error) { Netra.showToast(error.message, true); }
}

document.getElementById("alertFilters").addEventListener("click", event => {
  const button = event.target.closest("button[data-filter]");
  if (!button) return;
  selectedAlertFilter = button.dataset.filter;
  document.querySelectorAll("#alertFilters .filter-btn").forEach(item => item.classList.toggle("active", item === button));
  renderAlerts();
});
document.getElementById("alertSearch").addEventListener("input", renderAlerts);

document.querySelectorAll("button[data-scenario]").forEach(button => button.addEventListener("click", async () => {
  button.disabled = true;
  try {
    const result = await Netra.request("/api/demo/simulate", {
      method: "POST",
      body: JSON.stringify({ scenario: button.dataset.scenario })
    });
    await refreshAlerts();
    const newLabel = result.alerts_created === 1 ? "alert" : "alerts";
    const retainedLabel = alerts.length === 1 ? "alert" : "alerts";
    Netra.showToast(`${result.message} This run added ${result.alerts_created} new ${newLabel}; ${alerts.length} ${retainedLabel} retained total.`);
  } catch (error) { Netra.showToast(error.message, true); }
  finally { button.disabled = false; }
}));

document.getElementById("generateDemoHistory")?.addEventListener("click", async event => {
  event.currentTarget.disabled = true;
  try {
    const result = await Netra.request("/api/history/demo/generate", { method: "POST", body: "{}" });
    Netra.showToast(`${result.message} ${result.samples} samples created.`);
    await refreshAlerts();
  } catch (error) { Netra.showToast(error.message, true); }
  finally { event.currentTarget.disabled = false; }
});

document.getElementById("resetDemo")?.addEventListener("click", async () => {
  try {
    const result = await Netra.request("/api/demo/reset", { method: "POST", body: "{}" });
    Netra.showToast(result.message);
    await refreshAlerts();
  } catch (error) { Netra.showToast(error.message, true); }
});

refreshAlerts();
window.setInterval(refreshAlerts, 2000);
