"use strict";

let graph;
let liveUpdates = true;
let graphHasLayout = false;
let latestGraphData = { nodes: [], edges: [], stats: {} };

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatSeen(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function protocolMarkup(protocols, total) {
  const entries = Object.entries(protocols || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return '<p class="details-muted">No protocol data</p>';
  return entries.map(([name, count]) => {
    const percent = total ? Math.round(count / total * 100) : 0;
    return `<div class="protocol-detail"><span>${Netra.escapeHtml(name)}</span><b>${Netra.formatNumber(count)}</b><em>${percent}%</em></div>`;
  }).join("");
}

function showNodeDetails(node) {
  const data = node.data();
  document.getElementById("graphDetails").innerHTML = `
    <div class="details-header"><p class="eyebrow">IP ADDRESS</p><h2>${Netra.escapeHtml(data.ip)}</h2><span class="node-status ${data.status.toLowerCase()}">${Netra.escapeHtml(data.status)}</span></div>
    <div class="details-grid">
      <div><small>TYPE</small><strong>${Netra.escapeHtml(data.node_type)}</strong></div>
      <div><small>PACKETS OBSERVED</small><strong>${Netra.formatNumber(data.packet_count)}</strong></div>
      <div><small>SENT / RECEIVED</small><strong>${Netra.formatNumber(data.sent_packets)} / ${Netra.formatNumber(data.received_packets)}</strong></div>
      <div><small>TRAFFIC OBSERVED</small><strong>${formatBytes(data.bytes)}</strong></div>
      <div><small>FIRST SEEN</small><strong>${Netra.escapeHtml(formatSeen(data.first_seen))}</strong></div>
      <div><small>LAST SEEN</small><strong>${Netra.escapeHtml(formatSeen(data.last_seen))}</strong></div>
      <div><small>ASSOCIATED ALERTS</small><strong>${Netra.formatNumber(data.alert_count)}</strong></div>
    </div>
    <div class="details-protocols"><small>PROTOCOLS</small>${protocolMarkup(data.protocols, data.packet_count)}</div>`;
}

function showEdgeDetails(edge) {
  const data = edge.data();
  document.getElementById("graphDetails").innerHTML = `
    <div class="details-header"><p class="eyebrow">BIDIRECTIONAL CONNECTION</p><h2 class="edge-title">${Netra.escapeHtml(data.source)} <span>↔</span> ${Netra.escapeHtml(data.target)}</h2></div>
    <div class="details-grid">
      <div><small>TOTAL PACKETS</small><strong>${Netra.formatNumber(data.packet_count)}</strong></div>
      <div><small>TRAFFIC</small><strong>${formatBytes(data.bytes)}</strong></div>
      <div><small>FIRST SEEN</small><strong>${Netra.escapeHtml(formatSeen(data.first_seen))}</strong></div>
      <div><small>LAST SEEN</small><strong>${Netra.escapeHtml(formatSeen(data.last_seen))}</strong></div>
    </div>
    <div class="details-protocols"><small>PROTOCOLS</small>${protocolMarkup(data.protocols, data.packet_count)}</div>`;
}

function showDetailsPlaceholder() {
  document.getElementById("graphDetails").innerHTML = '<div class="details-placeholder"><span>⌘</span><h2>Select a node or connection</h2><p>Details about observed traffic and security status will appear here.</p></div>';
}

function initializeGraph() {
  if (typeof cytoscape === "undefined") {
    document.getElementById("graphEmpty").innerHTML = "<strong>GRAPH LIBRARY COULD NOT LOAD</strong><span>Check the internet connection for Cytoscape.js.</span>";
    Netra.showToast("Cytoscape.js could not load.", true);
    return;
  }
  graph = cytoscape({
    container: document.getElementById("networkGraph"),
    elements: [],
    minZoom: .2,
    maxZoom: 3,
    wheelSensitivity: .18,
    style: [
      { selector: "node", style: { "label": "data(label)", "font-family": "JetBrains Mono", "font-size": 9, "color": "#c8d2dd", "text-valign": "bottom", "text-halign": "center", "text-margin-y": 8, "text-wrap": "none", "text-max-width": 220, "background-color": "#738196", "width": 31, "height": 31, "border-width": 2, "border-color": "#9aa7b6", "overlay-opacity": 0 } },
      { selector: 'node[node_type = "LOCAL"]', style: { "shape": "round-rectangle", "background-color": "#36e3c1", "border-color": "#197a68" } },
      { selector: 'node[node_type = "EXTERNAL"]', style: { "shape": "diamond", "background-color": "#4e8cff", "border-color": "#28518e" } },
      { selector: 'node[node_type = "SPECIAL"]', style: { "shape": "hexagon", "background-color": "#a879ff", "border-color": "#604595" } },
      { selector: 'node[status = "WARNING"]', style: { "border-color": "#f5a65b", "border-width": 5, "border-style": "dashed", "width": 37, "height": 37 } },
      { selector: 'node[status = "CRITICAL"]', style: { "border-color": "#ff6278", "border-width": 7, "border-style": "double", "width": 41, "height": 41 } },
      { selector: "edge", style: { "curve-style": "bezier", "line-color": "#3c4b5e", "width": "data(edge_width)", "opacity": .68, "overlay-opacity": 0 } },
      { selector: ":selected", style: { "border-color": "#ffffff", "line-color": "#36e3c1", "opacity": 1 } }
    ],
    layout: { name: "cose", animate: false, fit: true, padding: 60, randomize: true }
  });
  graph.on("tap", "node", event => showNodeDetails(event.target));
  graph.on("tap", "edge", event => showEdgeDetails(event.target));
  graph.on("tap", event => { if (event.target === graph) showDetailsPlaceholder(); });
}

function updateGraphElements(data) {
  if (!graph) return;
  const incomingIds = new Set([...data.nodes.map(node => node.id), ...data.edges.map(edge => edge.id)]);
  let addedNodes = 0;
  graph.batch(() => {
    graph.elements().forEach(element => { if (!incomingIds.has(element.id())) element.remove(); });
    data.nodes.forEach(node => {
      const existing = graph.getElementById(node.id);
      if (existing.length) existing.data(node);
      else { graph.add({ group: "nodes", data: node }); addedNodes += 1; }
    });
    data.edges.forEach(edge => {
      const existing = graph.getElementById(edge.id);
      if (existing.length) existing.data(edge);
      else graph.add({ group: "edges", data: edge });
    });
  });
  if (addedNodes) {
    graph.layout({
      name: "cose", animate: false, fit: !graphHasLayout, padding: 55,
      randomize: !graphHasLayout
    }).run();
    graphHasLayout = true;
  }
  applyGraphFilters();
}

function applyGraphFilters() {
  if (!graph) return;
  const protocol = document.getElementById("graphProtocol").value;
  const deviceType = document.getElementById("graphDeviceType").value;
  const minimumPackets = Number(document.getElementById("graphMinPackets").value);
  const visibleNodeIds = new Set();
  const visibleEdges = [];

  graph.edges().forEach(edge => {
    const source = edge.source().data();
    const target = edge.target().data();
    const protocolMatch = protocol === "ALL" || (edge.data("protocol_names") || []).includes(protocol);
    const volumeMatch = Number(edge.data("packet_count")) >= minimumPackets;
    let deviceMatch = true;
    if (deviceType === "LOCAL") deviceMatch = source.node_type === "LOCAL" && target.node_type === "LOCAL";
    if (deviceType === "EXTERNAL") deviceMatch = source.node_type === "EXTERNAL" && target.node_type === "EXTERNAL";
    if (deviceType === "SUSPICIOUS") deviceMatch = source.status !== "NORMAL" || target.status !== "NORMAL";
    if (protocolMatch && volumeMatch && deviceMatch) {
      visibleEdges.push(edge);
      visibleNodeIds.add(source.id);
      visibleNodeIds.add(target.id);
    }
  });

  if (deviceType === "SUSPICIOUS") {
    graph.nodes().forEach(node => { if (node.data("status") !== "NORMAL") visibleNodeIds.add(node.id()); });
  }
  graph.elements().style("display", "none");
  visibleEdges.forEach(edge => edge.style("display", "element"));
  visibleNodeIds.forEach(id => graph.getElementById(id).style("display", "element"));
  const visibleCount = visibleNodeIds.size;
  const empty = document.getElementById("graphEmpty");
  empty.classList.toggle("hidden", visibleCount > 0);
  if (!visibleCount && latestGraphData.nodes.length) {
    empty.innerHTML = "<strong>NO GRAPH DATA MATCHES THESE FILTERS</strong><span>Lower the packet threshold or change a filter.</span>";
  } else if (!latestGraphData.nodes.length) {
    empty.innerHTML = "<strong>NO OBSERVED COMMUNICATION YET</strong><span>Start packet capture or use safe demo mode on the Alerts page.</span>";
  }
}

function updateGraphStats(stats) {
  document.getElementById("graphDevices").textContent = Netra.formatNumber(stats.observed_devices);
  document.getElementById("graphConnections").textContent = Netra.formatNumber(stats.active_connections);
  document.getElementById("graphLocal").textContent = Netra.formatNumber(stats.local_devices);
  document.getElementById("graphExternal").textContent = Netra.formatNumber(stats.external_devices);
  document.getElementById("graphSuspicious").textContent = Netra.formatNumber(stats.suspicious_devices);
}

async function refreshGraph() {
  if (!liveUpdates) return;
  try {
    latestGraphData = await Netra.request("/api/network/graph");
    updateGraphStats(latestGraphData.stats);
    updateGraphElements(latestGraphData);
  } catch (error) { Netra.showToast(error.message, true); }
}

document.querySelectorAll(".graph-filter-set select").forEach(select => select.addEventListener("change", applyGraphFilters));
document.getElementById("toggleGraphLive").addEventListener("click", async event => {
  liveUpdates = !liveUpdates;
  event.currentTarget.textContent = liveUpdates ? "PAUSE LIVE UPDATE" : "RESUME LIVE UPDATE";
  const status = document.getElementById("mapLiveStatus");
  status.classList.toggle("paused", !liveUpdates);
  status.querySelector("span").textContent = liveUpdates ? "LIVE UPDATE ON" : "LIVE UPDATE PAUSED";
  if (liveUpdates) await refreshGraph();
});
document.getElementById("fitGraph").addEventListener("click", () => {
  if (graph) graph.fit(graph.elements().filter(element => element.visible()), 55);
});
document.getElementById("resetGraphView").addEventListener("click", () => {
  if (!graph) return;
  const visible = graph.elements().filter(element => element.visible());
  graph.zoom(1);
  graph.center(visible);
});

async function startNetworkMap() {
  // Cytoscape measures labels during initialization, so wait for web fonts to
  // prevent long IP labels from being clipped using fallback-font dimensions.
  if (document.fonts?.ready) await document.fonts.ready;
  initializeGraph();
  await refreshGraph();
  window.setInterval(refreshGraph, 2000);
}

startNetworkMap();
