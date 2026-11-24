// Protocol / App protocol pie charts (Devices pop-up + Network "Protocols" card), one shared implementation.
"use strict";

/**
 * Render two pie charts (transport protocol and app protocol) into `container`.
 * `analysisId` scopes the query; `ip` is '' for the whole network; `dataUnit` is "packet", "bit" or "byte".
 * Returns { destroy() } to tear the charts down.
 */
window.protoPies = function (container, analysisId, ip, dataUnit) {
  const COLOURS = ["#2563eb", "#f97316", "#7c3aed", "#16a34a", "#dc2626", "#0891b2", "#ca8a04", "#64748b"];
  const charts = [];
  let destroyed = false;

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

  const value = row => dataUnit === "packet" ? row.packets : row.bytes * (dataUnit === "bit" ? 8 : 1);

  // Keep the 7 largest slices; merge the rest into "Other" (the 8th colour).
  function slices(list) {
    const sorted = [...list].sort((a, b) => value(b) - value(a));
    if (sorted.length <= 7) {
      return sorted.map((r, i) => ({ name: r.name, value: value(r), flows: r.flows, color: COLOURS[i] }));
    }
    const top = sorted.slice(0, 7), rest = sorted.slice(7);
    const other = rest.reduce((acc, r) => ({ flows: acc.flows + r.flows, value: acc.value + value(r) }),
                              { flows: 0, value: 0 });
    return top.map((r, i) => ({ name: r.name, value: value(r), flows: r.flows, color: COLOURS[i] }))
      .concat({ name: "Other", value: other.value, flows: other.flows, color: COLOURS[7] });
  }

  function makeChart(canvas, data) {
    const total = data.reduce((s, r) => s + r.value, 0);
    return new Chart(canvas, {
      type: "pie",
      data: { labels: data.map(r => r.name),
              datasets: [{ data: data.map(r => r.value), backgroundColor: data.map(r => r.color) }] },
      options: { maintainAspectRatio: false,
                 plugins: { legend: { position: "right" },
                            tooltip: { callbacks: { label: ctx => {
                              const pct = total ? (ctx.parsed / total * 100).toFixed(1) : "0.0";
                              return ` ${ctx.label}: ${fmt(ctx.parsed)} (${pct}%) · ${data[ctx.dataIndex].flows} flows`;
                            } } } } },
    });
  }

  function render(proto, app) {
    const grid = document.createElement("div");
    grid.className = "grid";
    container.replaceChildren(grid);   // attach first so Chart.js can size the canvases
    for (const [title, list] of [["Protocol", proto], ["App protocol", app]]) {
      const part = document.createElement("div");
      const h = document.createElement("h3");
      h.textContent = title;
      const box = document.createElement("div");
      box.className = "chart-box";
      box.style.height = "220px";
      const canvas = document.createElement("canvas");
      box.appendChild(canvas);
      part.append(h, box);
      grid.appendChild(part);
      charts.push(makeChart(canvas, slices(list)));
    }
  }

  getJSON(`/api/analyses/${analysisId}/protocols?ip=${encodeURIComponent(ip)}`).then(res => {
    if (destroyed) return;
    if (!res.proto.length && !res.app.length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "No protocol data. Re-analyse this analysis to see it.";
      container.replaceChildren(p);
      return;
    }
    render(res.proto, res.app);
  }).catch(e => {
    if (destroyed) return;
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = `Could not load protocols: ${e.message}`;
    container.replaceChildren(p);
  });

  return { destroy() { destroyed = true; charts.forEach(c => c.destroy()); } };
};
