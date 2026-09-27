"use strict";

let protocolChart;
let comparisonChart;

if (typeof Chart !== "undefined") {
  Chart.defaults.color = "#68778b";
  Chart.defaults.font.family = "DM Sans";
  protocolChart = new Chart(document.getElementById("analysisProtocolChart"), {
    type: "doughnut",
    data: { labels: Object.keys(Netra.protocolColors), datasets: [{ data: [0, 0, 0, 0, 0, 0], backgroundColor: Object.values(Netra.protocolColors), borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { display: false } } }
  });
  comparisonChart = new Chart(document.getElementById("analysisTrafficChart"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "Current traffic", data: [], borderColor: "#36e3c1", backgroundColor: "rgba(54,227,193,.07)", fill: true, tension: .3, pointRadius: 0, borderWidth: 1.5 },
      { label: "Rolling baseline", data: [], borderColor: "#f5a65b", borderDash: [5, 5], tension: .25, pointRadius: 0, borderWidth: 1.3 }
    ] },
    options: { responsive: true, maintainAspectRatio: false, animation: false, interaction: { intersect: false, mode: "index" }, plugins: { legend: { labels: { boxWidth: 8, boxHeight: 8, font: { family: "JetBrains Mono", size: 9 } } } }, scales: { x: { grid: { display: false }, ticks: { font: { family: "JetBrains Mono", size: 9 }, maxTicksLimit: 8 } }, y: { beginAtZero: true, border: { display: false }, grid: { color: "rgba(125,139,157,.10)" }, ticks: { precision: 0, font: { family: "JetBrains Mono", size: 9 } } } } }
  });
} else {
  Netra.showToast("Charts could not load. Check the internet connection for Chart.js.", true);
}

async function refreshAnalysis() {
  try {
    const [stats, baseline] = await Promise.all([
      Netra.request("/api/stats"), Netra.request("/api/traffic/baseline")
    ]);
    Netra.updateGlobalState(stats.capturing);
    document.getElementById("analysisCurrentPps").textContent = Number(baseline.current_pps).toFixed(1);
    document.getElementById("analysisThroughput").textContent = Netra.formatThroughput(baseline.throughput_bps);
    document.getElementById("analysisBaseline").textContent = Number(baseline.baseline_pps).toFixed(1);
    document.getElementById("analysisDeviation").textContent = `${Number(baseline.deviation_ratio).toFixed(1)}×`;
    document.getElementById("analysisSources").textContent = Netra.formatNumber(baseline.unique_source_ips);
    document.getElementById("analysisDestinations").textContent = Netra.formatNumber(baseline.unique_destination_ips);
    document.getElementById("baselineReadiness").textContent = baseline.baseline_ready
      ? `${baseline.baseline_samples} samples · Ready`
      : `${baseline.baseline_samples} / ${baseline.minimum_samples_required} samples · Warming up`;

    const names = Object.keys(Netra.protocolColors);
    const total = Object.values(stats.protocols).reduce((sum, value) => sum + value, 0);
    document.getElementById("analysisLegend").innerHTML = names.map(name => {
      const count = stats.protocols[name] || 0;
      const percent = total ? Math.round(count / total * 100) : 0;
      return `<span><i style="background:${Netra.protocolColors[name]}"></i>${name} · ${Netra.formatNumber(count)} (${percent}%)</span>`;
    }).join("");
    if (protocolChart) {
      protocolChart.data.datasets[0].data = names.map(name => stats.protocols[name] || 0);
      protocolChart.update("none");
    }
    if (comparisonChart) {
      comparisonChart.data.labels = baseline.history.map(item => item.time);
      comparisonChart.data.datasets[0].data = baseline.history.map(item => item.current_pps);
      comparisonChart.data.datasets[1].data = baseline.history.map(item => item.baseline_pps);
      comparisonChart.update("none");
    }
  } catch (error) { Netra.showToast(error.message, true); }
}

refreshAnalysis();
window.setInterval(refreshAnalysis, 1000);
