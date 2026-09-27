"use strict";

let recentPackets = [];
let selectedProtocol = "All";

function renderPackets() {
  const query = document.getElementById("ipSearch").value.trim().toLowerCase();
  const visible = recentPackets.filter(packet => {
    const protocolMatch = selectedProtocol === "All" || packet.protocol === selectedProtocol;
    const ipMatch = !query || String(packet.source_ip || "").toLowerCase().includes(query) || String(packet.destination_ip || "").toLowerCase().includes(query);
    return protocolMatch && ipMatch;
  });
  document.getElementById("visibleCount").textContent = visible.length;
  const body = document.getElementById("packetRows");
  if (!visible.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="7">${recentPackets.length ? "No packets match the current filters." : "No packets captured yet."}</td></tr>`;
    return;
  }
  body.innerHTML = visible.map(packet => `<tr>
    <td>${Netra.escapeHtml(packet.time)}</td>
    <td>${Netra.escapeHtml(packet.source_ip)}</td>
    <td>${Netra.escapeHtml(packet.source_port)}</td>
    <td>${Netra.escapeHtml(packet.destination_ip)}</td>
    <td>${Netra.escapeHtml(packet.destination_port)}</td>
    <td><span class="protocol-badge protocol-${packet.protocol.toLowerCase()}">${Netra.escapeHtml(packet.protocol)}</span></td>
    <td>${Netra.formatNumber(packet.size)} B</td>
  </tr>`).join("");
}

async function refreshPackets() {
  try {
    const [packetData, stats] = await Promise.all([
      Netra.request("/api/packets?limit=500"), Netra.request("/api/stats")
    ]);
    recentPackets = packetData.packets.slice(0, 500);
    renderPackets();
    Netra.updateGlobalState(stats.capturing);
    const indicator = document.querySelector(".stream-indicator");
    indicator.classList.toggle("active", stats.capturing);
    document.getElementById("streamStatus").textContent = stats.capturing ? "STREAMING LIVE" : "WAITING FOR CAPTURE";
  } catch (error) { Netra.showToast(error.message, true); }
}

document.getElementById("protocolFilters").addEventListener("click", event => {
  const button = event.target.closest("button[data-protocol]");
  if (!button) return;
  selectedProtocol = button.dataset.protocol;
  document.querySelectorAll(".filter-btn").forEach(item => item.classList.toggle("active", item === button));
  renderPackets();
});
document.getElementById("ipSearch").addEventListener("input", renderPackets);

refreshPackets();
window.setInterval(refreshPackets, 1500);

