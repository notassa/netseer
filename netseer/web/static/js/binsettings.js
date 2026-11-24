// Time-axis bin settings: a gear button on a chart box and a pop-up to set the x-axis bin.
"use strict";

/**
 * Add a gear button to `box` (a .chart-box) that opens a pop-up for the x-axis bin.
 * `unit` is the API's storage unit ("s" seconds, "min" minutes); `unitMin` is the
 * smallest step in that unit (5 for traffic's 5 s buckets, 1 for per-minute series).
 * `current` is the bin in `unit`. `onApply(value)` gets the rounded bin in `unit`;
 * `onReset()` restores the server default. Returns a handle with `setCurrent`.
 */
window.binSettings = function (box, opts) {
  const unit = opts.unit, unitMin = opts.unitMin;
  let current = opts.current;
  const unitWord = unit === "s" ? "s" : "min";
  const stepNote = unit === "s" ? `stored in ${unitMin} s steps.` : "stored per minute.";
  let uid = "bin-settings-" + Math.random().toString(36).slice(2, 8);

  const gear = document.createElement("button");
  gear.type = "button";
  gear.className = "btn small chart-settings";
  gear.setAttribute("aria-label", "Time axis settings");
  gear.setAttribute("aria-haspopup", "dialog");
  gear.title = "Time axis settings";
  gear.innerHTML = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">' +
    '<path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/><circle cx="12" cy="12" r="3"/></svg>';
  box.appendChild(gear);

  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.setAttribute("role", "dialog");
  backdrop.setAttribute("aria-modal", "true");
  backdrop.setAttribute("aria-labelledby", uid + "-title");
  backdrop.innerHTML =
    '<div class="modal">' +
      '<header style="display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:1rem">' +
        '<h2 id="' + uid + '-title" style="margin:0">Time axis settings</h2>' +
        '<button class="btn small js-close" type="button">Close</button>' +
      '</header>' +
      '<label for="' + uid + '-num" style="margin-top:0">Bin size</label>' +
      '<div class="row-actions">' +
        '<input id="' + uid + '-num" type="number" min="1" max="1000" step="1" style="width:7rem">' +
        '<select id="' + uid + '-unit" aria-label="Bin unit">' +
          '<option value="seconds">seconds</option>' +
          '<option value="minutes">minutes</option>' +
          '<option value="hours">hours</option>' +
        '</select>' +
      '</div>' +
      '<p class="muted" role="status"></p>' +
      '<div class="row-actions">' +
        '<button class="btn small primary js-apply" type="button">Apply</button>' +
        '<button class="btn small js-reset" type="button">Reset</button>' +
        '<button class="btn small js-close" type="button">Close</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(backdrop);

  const numInput = backdrop.querySelector("input");
  const select = backdrop.querySelector("select");
  const note = backdrop.querySelector("[role=status]");
  const applyBtn = backdrop.querySelector(".js-apply");
  const resetBtn = backdrop.querySelector(".js-reset");

  const split = value => {
    if (unit === "s") {
      if (value % 3600 === 0) return [value / 3600, "hours"];
      if (value % 60 === 0) return [value / 60, "minutes"];
      return [value, "seconds"];
    }
    if (value % 60 === 0) return [value / 60, "hours"];
    return [value, "minutes"];
  };

  const open = () => {
    const [num, sel] = split(current);
    numInput.value = num;
    select.value = sel;
    refresh();
    backdrop.classList.add("open");
    backdrop.querySelector(".js-close").focus();
  };
  const close = () => { backdrop.classList.remove("open"); gear.focus(); };

  const read = () => {
    const num = Math.min(1000, Math.max(1, Math.round(parseInt(numInput.value, 10) || 1)));
    const sel = select.value;
    const secs = sel === "hours" ? num * 3600 : sel === "minutes" ? num * 60 : num;
    const raw = unit === "s" ? secs : secs / 60;
    const value = Math.ceil(raw / unitMin) * unitMin;
    return { num, value, raised: value !== raw };
  };

  const refresh = () => {
    const r = read();
    numInput.value = r.num;
    note.textContent = r.raised ? `Raised to ${r.value} ${unitWord}: ${stepNote}` : "";
  };

  numInput.addEventListener("input", refresh);
  select.addEventListener("change", refresh);
  applyBtn.addEventListener("click", () => {
    const r = read();
    current = r.value;
    opts.onApply(r.value);
    close();
  });
  resetBtn.addEventListener("click", () => { opts.onReset(); close(); });
  backdrop.querySelectorAll(".js-close").forEach(b => b.addEventListener("click", close));
  backdrop.addEventListener("click", e => { if (e.target === backdrop) close(); });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && backdrop.classList.contains("open")) close();
  });
  gear.addEventListener("click", open);

  return { setCurrent: value => { current = value; } };
};
