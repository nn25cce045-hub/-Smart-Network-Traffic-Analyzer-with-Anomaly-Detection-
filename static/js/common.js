"use strict";

window.Netra = (() => {
  const protocolColors = {
    TCP: "#36e3c1", UDP: "#4e8cff", DNS: "#a879ff",
    HTTP: "#f5a65b", ICMP: "#ff6278", Other: "#738196"
  };

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

  return { protocolColors, escapeHtml, formatNumber, formatThroughput, request, showToast, updateGlobalState };
})();

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

