"use strict";

window.Netra = (() => {
  const THEME_KEY = "netra-theme";
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const protocolColors = {
    TCP: "#36e3c1", UDP: "#4e8cff", DNS: "#a879ff",
    HTTP: "#f5a65b", ICMP: "#ff6278", Other: "#738196"
  };

  function getThemePreference() {
    const saved = localStorage.getItem(THEME_KEY);
    return ["light", "dark", "system"].includes(saved) ? saved : "dark";
  }

  function resolveTheme(preference = getThemePreference()) {
    return preference === "system" ? (systemTheme.matches ? "dark" : "light") : preference;
  }

  function getThemeColors() {
    const styles = getComputedStyle(document.documentElement);
    const value = name => styles.getPropertyValue(name).trim();
    return {
      textColor: value("--chart-text"),
      mutedTextColor: value("--chart-muted"),
      gridColor: value("--chart-grid"),
      tooltipBackground: value("--chart-tooltip-bg"),
      tooltipText: value("--chart-tooltip-text")
    };
  }

  function applyChartTheme(chart) {
    if (!chart?.options) return;
    const colors = getThemeColors();
    chart.options.color = colors.mutedTextColor;
    if (chart.options.plugins?.legend?.labels) chart.options.plugins.legend.labels.color = colors.mutedTextColor;
    if (chart.options.plugins?.tooltip) {
      chart.options.plugins.tooltip.backgroundColor = colors.tooltipBackground;
      chart.options.plugins.tooltip.titleColor = colors.tooltipText;
      chart.options.plugins.tooltip.bodyColor = colors.tooltipText;
      chart.options.plugins.tooltip.borderColor = colors.gridColor;
      chart.options.plugins.tooltip.borderWidth = 1;
    }
    Object.values(chart.options.scales || {}).forEach(scale => {
      if (scale.ticks) scale.ticks.color = colors.mutedTextColor;
      if (scale.grid && scale.grid.display !== false) scale.grid.color = colors.gridColor;
    });
    chart.update("none");
  }

  function updateCharts() {
    if (typeof Chart === "undefined" || !Chart.instances) return;
    const charts = typeof Chart.instances.values === "function"
      ? [...Chart.instances.values()]
      : Object.values(Chart.instances);
    charts.forEach(applyChartTheme);
  }

  function applyTheme(preference, persist = true) {
    const safePreference = ["light", "dark", "system"].includes(preference) ? preference : "dark";
    const resolved = resolveTheme(safePreference);
    if (persist) localStorage.setItem(THEME_KEY, safePreference);
    document.documentElement.dataset.theme = resolved;
    document.documentElement.dataset.themePreference = safePreference;
    const selector = document.getElementById("themeSelector");
    const icon = document.getElementById("themeIcon");
    if (selector) selector.value = safePreference;
    if (icon) icon.textContent = resolved === "dark" ? "☾" : "☀";
    updateCharts();
    window.dispatchEvent(new CustomEvent("netra:themechange", { detail: { preference: safePreference, theme: resolved } }));
  }

  function escapeHtml(value) {
    const node = document.createElement("div");
    node.textContent = value ?? "—";
    return node.innerHTML;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat().format(Number(value) || 0);
  }

  function formatThroughput(bitsPerSecond) {
    const value = Number(bitsPerSecond) || 0;
    if (value >= 1e9) return `${(value / 1e9).toFixed(2)} Gbps`;
    if (value >= 1e6) return `${(value / 1e6).toFixed(2)} Mbps`;
    if (value >= 1e3) return `${(value / 1e3).toFixed(1)} Kbps`;
    return `${value.toFixed(0)} bps`;
  }

  async function request(url, options = {}) {
    const response = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options
    });
    let data;
    try { data = await response.json(); } catch { data = { error: "The server returned an invalid response." }; }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }

  function showToast(message, isError = false) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast show${isError ? " error" : ""}`;
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => { toast.className = "toast"; }, 3500);
  }

  function updateGlobalState(capturing) {
    const chip = document.getElementById("globalCaptureState");
    if (!chip) return;
    chip.className = `capture-chip ${capturing ? "capturing" : "stopped"}`;
    chip.innerHTML = `<i></i> ${capturing ? "CAPTURING" : "STOPPED"}`;
  }

  return { protocolColors, escapeHtml, formatNumber, formatThroughput, request, showToast, updateGlobalState, getThemeColors, applyChartTheme, applyTheme };
})();

const themeSelector = document.getElementById("themeSelector");
themeSelector?.addEventListener("change", event => Netra.applyTheme(event.target.value));
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (document.documentElement.dataset.themePreference === "system") Netra.applyTheme("system", false);
});
Netra.applyTheme(document.documentElement.dataset.themePreference || "dark", false);
window.addEventListener("DOMContentLoaded", () => window.setTimeout(() => {
  Netra.applyTheme(document.documentElement.dataset.themePreference || "dark", false);
}, 0));

document.getElementById("menuButton")?.addEventListener("click", () => {
  document.getElementById("sidebar")?.classList.toggle("open");
});

function tickClock() {
  const clock = document.getElementById("liveClock");
  if (clock) clock.textContent = new Date().toLocaleTimeString([], { hour12: false });
}
tickClock();
window.setInterval(tickClock, 1000);

// Pages without their own stats polling still keep the header status current.
if (!document.body.querySelector("canvas")) {
  const refreshHeaderState = async () => {
    try {
      const stats = await Netra.request("/api/stats");
      Netra.updateGlobalState(stats.capturing);
    } catch { /* A temporary server error will be retried on the next interval. */ }
  };
  refreshHeaderState();
  window.setInterval(refreshHeaderState, 2500);
}
