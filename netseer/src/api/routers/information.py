"""Information page (CONCEPTS A10): system logs for the administrator (account activity, process log) and
NetSeer Details (the machine NetSeer runs on)."""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, Form, Request

from netseer.src.api.client import who
from netseer.src.api.deps import (distinct_values, get_db, layout_context, order_by, page_qs, paging, redirect, render,
                                  require_admin, verify_csrf)
from netseer.src.database.db import audit
from netseer.src.config import app_config
from netseer.src.engine import sysinfo
from netseer.src.engine.events import EVENTS, actions
from netseer.src.engine.oui import vendor_for

router = APIRouter(dependencies=[Depends(require_admin)])

TABS = ("account", "process")
LEVELS = ("info", "warning", "error")
LOG_SORT = {"time": "l.id", "event": "l.action", "user": "u.username", "ip": "l.ip", "mac": "l.mac", "detail": "l.detail"}


@router.get("/information")
def information_page(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Paged, filterable audit log for one tab, or the NetSeer Details tab."""
    params = {k: v for k, v in request.query_params.items() if v}
    if params.get("tab") in (None, "details"):
        return render(request, "information.html", {
            **layout_context(request, conn, "information"), "tab": "details",
            "sys": sysinfo.snapshot(conn, request.app.state.data_dir, request.app.state.db_path)})
    tab = params.get("tab") if params.get("tab") in TABS else "account"
    level = params.get("level") if params.get("level") in LEVELS else None
    wanted = actions(tab, level)
    where = f"l.action IN ({','.join('?' * len(wanted))})" if wanted else "0"
    args: list = list(wanted)
    if params.get("q"):
        where += " AND (l.detail LIKE ? OR l.ip LIKE ? OR l.mac LIKE ? OR u.username LIKE ?)"
        args += [f"%{params['q']}%"] * 4
    base = f"FROM audit_log l LEFT JOIN users u ON u.id = l.user_id WHERE {where}"
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
    pg = paging(params, total)
    order = order_by(params, LOG_SORT, "l.id DESC")
    rows = conn.execute(f"SELECT l.*, u.username {base} ORDER BY {order}, l.id DESC LIMIT ? OFFSET ?",
                        (*args, pg["limit"], pg["offset"])).fetchall()
    oui = str(app_config("oui_csv"))
    entries = [dict(r) | {"label": EVENTS[r["action"]][2], "level": EVENTS[r["action"]][1],
                          "vendor": vendor_for(r["mac"], oui)} for r in rows]
    return render(request, "information.html", {
        **layout_context(request, conn, "information"),
        "tab": tab, "level": level, "params": params, "entries": entries, "total": total, "pg": pg, "levels": LEVELS,
        "qs": page_qs(params),
        "options": distinct_values(conn, "SELECT u.username AS v FROM audit_log l JOIN users u ON u.id = l.user_id "
                                         "UNION ALL SELECT ip FROM audit_log UNION ALL SELECT mac FROM audit_log"),
    })


@router.get("/api/system")
def system_usage(request: Request):
    """CPU, load, memory, disk and temperatures now (the Details tab refreshes them every 5 s)."""
    return sysinfo.usage(request.app.state.data_dir)


@router.post("/information/clear", dependencies=[Depends(verify_csrf)])
def clear_log(request: Request, tab: str = Form(...), admin=Depends(require_admin),
              conn: sqlite3.Connection = Depends(get_db)):
    """Delete one tab's log entries; one entry recording the wipe (who, how many) is kept."""
    if tab not in TABS:
        return redirect("/information", "error", "Unknown log.")
    wanted = actions(tab)
    n = conn.execute(f"DELETE FROM audit_log WHERE action IN ({','.join('?' * len(wanted))})", wanted).rowcount
    audit(conn, admin["id"], f"{tab}_log_cleared", f"{n} entries deleted", *who(request))
    return redirect(f"/information?tab={tab}", "ok", f"Cleared {n} entries.")
