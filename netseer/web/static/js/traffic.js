// Traffic Volume chart (Home + Network), one shared implementation.
"use strict";

/**
 * Render the Traffic Volume chart into #traffic-chart. No-op when the canvas is absent.
 * `traffic` is the /api/analyses/<id>/traffic series; `dataUnit` is "packet", "bit" or "byte".
 */
window.trafficChart = function (traffic, dataUnit, analysisId) {
  const canvas = document.getElementById("traffic-chart");
  if (!canvas) return;
  const unitWord = dataUnit === "packet" ? "packets" : (dataUnit === "bit" ? "bits" : "bytes");
  let seconds = traffic.seconds;

  function fmt(v) {
    const a = Math.abs(v);
    if (dataUnit === "packet") return a.toLocaleString() + " pkt";
    const units = dataUnit === "bit" ? ["b", "kb", "Mb", "Gb"] : ["B", "KB", "MB", "GB"];
    if (a === 0) return "0 " + units[0];
    let x = a, i = 0;
    while (x >= 1000 && i < units.length - 1) { x /= 1000; i += 1; }
    const digits = x >= 100 ? 0 : (x >= 10 ? 1 : 2);
    return x.toFixed(digits) + " " + units[i];
  }

  const value = p => {
    const key = dataUnit === "packet" ? "packets" : "bytes";
    const mult = dataUnit === "bit" ? 8 : 1;
    return { ii: p["ii_" + key] * mult, ie: p["ie_" + key] * mult, ei: p["ei_" + key] * mult };
  };

  const binLabel = s => s < 60 ? s + " s" : (Math.round(s / 60 * 100) / 100) + " min";

  const INGRESS = "#f97316", EGRESS = "#2563eb", INTERNAL = "#7c3aed";
  const datasets = mode => mode === "total" ? [
    { label: "INT>INT", data: traffic.points.map(p => value(p).ii), borderColor: INTERNAL,
      backgroundColor: INTERNAL, fill: false, tension: 0.2, pointRadius: traffic.points.length <= 60 ? 3 : 0 },
    { label: "INT>EXT", data: traffic.points.map(p => value(p).ie), borderColor: EGRESS,
      backgroundColor: EGRESS, fill: false, tension: 0.2, pointRadius: traffic.points.length <= 60 ? 3 : 0 },
    { label: "EXT>INT", data: traffic.points.map(p => value(p).ei), borderColor: INGRESS,
      backgroundColor: INGRESS, fill: false, tension: 0.2, pointRadius: traffic.points.length <= 60 ? 3 : 0 },
  ] : [
    { label: "Ingress (EXT>INT)", data: traffic.points.map(p => value(p).ei), borderColor: INGRESS,
      backgroundColor: INGRESS, fill: false, tension: 0.2, pointRadius: traffic.points.length <= 60 ? 3 : 0 },
    { label: "Egress (INT>EXT)", data: traffic.points.map(p => -value(p).ie), borderColor: EGRESS,
      backgroundColor: EGRESS, fill: false, tension: 0.2, pointRadius: traffic.points.length <= 60 ? 3 : 0 },
  ];

  const chart = new Chart(canvas, {
    type: "line",
    data: { labels: traffic.points.map(p => p.t), datasets: datasets("total") },
    options: { maintainAspectRatio: false,
               interaction: { mode: "index", intersect: false },
               plugins: { legend: { display: true },
                          tooltip: { callbacks: { label: c => ` ${c.dataset.label}: ${fmt(c.parsed.y)}` } } },
               scales: { x: { title: { display: true, text: `Time (UTC), ${binLabel(seconds)} bins` },
                              ticks: { maxRotation: 0, autoSkipPadding: 24, callback(v) {   // full date stays in the tooltip
                                const t = this.getLabelForValue(v), all = this.chart.data.labels;
                                const time = seconds % 60 === 0 ? t.slice(11, 16) : t.slice(11);
                                return all[0].slice(0, 10) === all[all.length - 1].slice(0, 10)
                                  ? time : `${t.slice(5, 10)} ${time}`;
                              } } },
                          y: { stacked: true, title: { display: true, text: `${unitWord} per ${binLabel(seconds)}` },
                              ticks: { precision: 0, callback: fmt } } } },
  });

  let mode = "total";
  const buttons = { ie: document.getElementById("traffic-mode-ie"),
                    total: document.getElementById("traffic-mode-total") };
  const setMode = m => {
    mode = m;
    chart.data.datasets = datasets(m);
    chart.options.scales.y.stacked = m === "total";
    for (const key in buttons) {
      buttons[key].classList.toggle("primary", key === m);
      buttons[key].setAttribute("aria-pressed", String(key === m));
    }
    chart.update();
  };
  buttons.ie.addEventListener("click", () => setMode("ie"));
  buttons.total.addEventListener("click", () => setMode("total"));

  const binInput = document.getElementById("traffic-bin");
  const binNote = document.getElementById("traffic-bin-note");
  const clamped = s => Math.min(3600, Math.max(5, s));
  let requestId = 0;
  let debounce = null;

  const applyFresh = fresh => {
    seconds = fresh.seconds;
    traffic.points = fresh.points;
    binInput.value = fresh.seconds;
    chart.data.labels = fresh.points.map(p => p.t);
    chart.data.datasets = datasets(mode);
    chart.options.scales.x.title.text = `Time (UTC), ${binLabel(seconds)} bins`;
    chart.options.scales.y.title.text = `${unitWord} per ${binLabel(seconds)}`;
    binNote.textContent = fresh.raised ? `Raised to ${fresh.seconds} s to keep the chart readable.` : "";
    chart.update();
  };

  const fetchTraffic = url => {
    clearTimeout(debounce);
    const id = ++requestId;
    getJSON(url).then(fresh => { if (id === requestId) applyFresh(fresh); })
                .catch(() => { /* leave the chart unchanged on error */ });
  };

  binInput.addEventListener("change", () => {
    const raw = parseInt(binInput.value, 10);
    const s = clamped(Number.isNaN(raw) ? seconds : Math.round(raw / 5) * 5);
    binInput.value = s;
    fetchTraffic(`/api/analyses/${analysisId}/traffic?seconds=${s}`);
  });

  binInput.addEventListener("wheel", e => {
    if (document.activeElement !== binInput) return;
    e.preventDefault();
    const s = clamped((Number(binInput.value) || seconds) + (e.deltaY < 0 ? 5 : -5));
    binInput.value = s;
    clearTimeout(debounce);
    debounce = setTimeout(() => fetchTraffic(`/api/analyses/${analysisId}/traffic?seconds=${s}`), 250);
  }, { passive: false });

  document.getElementById("traffic-bin-reset").addEventListener("click", () => {
    fetchTraffic(`/api/analyses/${analysisId}/traffic`);
  });
};
