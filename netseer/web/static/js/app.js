// NetSeer shared helpers (vanilla JS, no build step).
"use strict";

/** CSRF token of the current page (from the logout form, present on every signed-in page). */
function csrfToken() {
  const el = document.querySelector('input[name="csrf_token"]');
  return el ? el.value : "";
}

/** Escape text for safe insertion into HTML. */
function esc(value) {
  const d = document.createElement("div");
  d.textContent = value == null ? "" : String(value);
  return d.innerHTML;
}

/** Fetch JSON or throw with the server's message. */
async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// Sidebar: toggle the narrow icon rail and remember it per browser.
(function () {
  const btn = document.getElementById("sidebar-toggle");
  if (!btn) return;
  const sync = () => btn.setAttribute("aria-expanded", String(!document.documentElement.classList.contains("sidebar-collapsed")));
  sync();
  btn.addEventListener("click", () => {
    const collapsed = document.documentElement.classList.toggle("sidebar-collapsed");
    sync();
    try { localStorage.setItem("netseer.sidebar", collapsed ? "collapsed" : "open"); } catch (e) { /* private mode */ }
  });
})();

// Session countdown (10 minutes from sign-in); only the Extend button adds time.
(function () {
  const timer = document.getElementById("session-timer");
  if (!timer) return;
  const left = document.getElementById("session-left");
  // Count from the server's remaining seconds, so a wrong browser clock cannot cause early sign-outs.
  let expires = Date.now() + Number(timer.dataset.remaining) * 1000;
  const tick = () => {
    const secs = Math.max(0, Math.round((expires - Date.now()) / 1000));
    left.textContent = `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
    timer.classList.toggle("low", secs < 60);
    if (Date.now() > expires + 1500) location.href = "/login";
  };
  const set = data => { expires = Date.now() + data.remaining_s * 1000; tick(); };
  document.getElementById("session-extend").addEventListener("click", async () => {
    const r = await fetch("/api/session/extend", { method: "POST", headers: { "X-CSRF-Token": csrfToken() } });
    if (r.ok) set(await r.json()); else location.href = "/login";
  });
  // Another tab may have extended the session: re-read it when this tab comes back into view.
  document.addEventListener("visibilitychange", async () => {
    if (document.visibilityState !== "visible") return;
    const r = await fetch("/api/session", { headers: { Accept: "application/json" } });
    if (r.ok) set(await r.json()); else location.href = "/login";
  });
  tick();
  setInterval(tick, 1000);
})();

// Sortable tables: click a column head (th[data-key]) to sort, again to reverse; "Reset order" restores.
// Client mode sorts the rows in place (cell data-sort value, else text; digit runs compare as numbers, so IPs
// sort naturally). Server mode (data-server-sort, paginated tables) reloads with ?sort=&dir=.
(function () {
  const natural = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
  document.querySelectorAll("table.sortable").forEach(table => {
    const server = table.hasAttribute("data-server-sort");
    const tbody = table.tBodies[0], heads = [...table.tHead.rows[0].cells];
    const original = [...tbody.rows];
    // A tr.child-row (e.g. an analysis's Info) belongs to the row above it and moves with it.
    const children = row => { const out = []; let n = row.nextElementSibling;
                              while (n && n.classList.contains("child-row")) { out.push(n); n = n.nextElementSibling; }
                              return out; };
    const url = new URL(location.href);
    let key = server ? url.searchParams.get("sort") : null;
    let dir = server && url.searchParams.get("dir") === "desc" ? "desc" : "asc";
    const mark = () => heads.forEach(th => { th.dataset.dir = th.dataset.key && th.dataset.key === key ? dir : ""; });
    const value = (row, i) => { const c = row.cells[i]; return c ? (c.dataset.sort ?? c.textContent.trim()) : ""; };
    heads.forEach((th, i) => {
      if (!th.dataset.key) return;
      th.classList.add("sort-head");
      th.tabIndex = 0;
      th.title = "Sort by this column";
      const sort = () => {
        dir = key === th.dataset.key && dir === "asc" ? "desc" : "asc";
        key = th.dataset.key;
        if (server) {
          url.searchParams.set("sort", key);
          url.searchParams.set("dir", dir);
          url.searchParams.delete("page");
          location.href = url;
          return;
        }
        const rows = [...tbody.rows].filter(r => r.cells.length === heads.length);
        rows.sort((a, b) => (dir === "asc" ? 1 : -1) * natural(value(a, i), value(b, i)));
        tbody.append(...rows.flatMap(r => [r, ...children(r)]));
        mark();
        table.dispatchEvent(new Event("rows-changed"));
      };
      th.addEventListener("click", sort);
      th.addEventListener("keydown", e => { if (e.key === "Enter") sort(); });
    });
    document.querySelectorAll(`[data-reset-sort="${table.id}"]`).forEach(btn => btn.addEventListener("click", () => {
      if (server) {
        url.searchParams.delete("sort");
        url.searchParams.delete("dir");
        location.href = url;
        return;
      }
      key = null;
      tbody.append(...original);
      mark();
      table.dispatchEvent(new Event("rows-changed"));
    }));
    mark();
  });
})();

// Table rows that open a page (tr[data-href]); links inside the row keep working on their own.
document.querySelectorAll("tr[data-href]").forEach(row => row.addEventListener("click", e => {
  if (!e.target.closest("a, button, input, select")) location.href = row.dataset.href;
}));

// Long tables show their first 20 rows with "Show all" / "Hide". Server-paged tables (data-server-sort)
// page on the server instead (20 per page, ?all=1 for everything).
(function () {
  const LIMIT = 20;
  document.querySelectorAll("table.data").forEach(table => {
    const tbody = table.tBodies[0];
    if (!tbody || table.hasAttribute("data-server-sort") ||
        [...tbody.rows].filter(r => !r.classList.contains("child-row")).length <= LIMIT) return;
    let open = false;
    const bar = document.createElement("div");
    bar.className = "table-more";
    const info = document.createElement("span");
    info.className = "muted";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn small";
    bar.append(info, btn);
    (table.closest(".table-wrap") || table).after(bar);
    const apply = () => {
      const rows = [...tbody.rows].filter(r => !r.classList.contains("child-row"));
      rows.forEach((r, i) => {
        r.hidden = !open && i >= LIMIT;
        for (let n = r.nextElementSibling; n && n.classList.contains("child-row"); n = n.nextElementSibling) n.hidden = r.hidden;
      });
      info.textContent = open ? `Showing all ${rows.length} rows` : `Showing ${LIMIT} of ${rows.length} rows`;
      btn.textContent = open ? "Hide" : "Show all";
    };
    btn.addEventListener("click", () => { open = !open; apply(); });
    table.addEventListener("rows-changed", apply);
    apply();
  });
})();

