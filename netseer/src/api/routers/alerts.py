"""Alerts page (CONCEPTS A10): packets per x minutes, alert mix, filterable alert table and raw-JSON drawer."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from netseer.src.api.deps import (distinct_values, get_db, layout_context, order_by, page_qs, paging, render,
                                  require_user)
from netseer.src.engine.alert_mix import alert_mix
from netseer.src.engine.constants import DEVICE_TYPE_LABEL

router = APIRouter(dependencies=[Depends(require_user)])

DIRECTIONS = ("ext->int", "int->ext", "int->int", "ext->ext")
TICKS = {"priority": ("1", "2", "3", "4"), "direction": DIRECTIONS, "classtype": None}
FILTER_KEYS = ("q", "src_ip", "dest_ip", "sid", *TICKS)
ALERT_SORT = {"id": "id", "time": "ts", "src": "src_ip", "dest": "dest_ip", "proto": "proto", "signature": "signature",
              "class": "classtype", "severity": "priority", "direction": "direction"}


def _filters(params: dict[str, str | list[str]]) -> tuple[str, list]:
    """WHERE clause fragments for the table filters (all parameterised)."""
    clauses, args = [], []
    if params.get("q"):
        clauses.append("(signature LIKE ? OR category LIKE ? OR classtype LIKE ?)")
        args += [f"%{params['q']}%"] * 3
    for field in ("src_ip", "dest_ip"):
        if params.get(field):
            clauses.append(f"{field} = ?")
            args.append(params[field].strip())
    if params.get("sid", "").isdigit():
        clauses.append("sid = ?")
        args.append(int(params["sid"]))
    for col, allowed in TICKS.items():               # tick boxes: any of the ticked values
        values = [v for v in params.get(col, []) if allowed is None or v in allowed]
        if values:
            clauses.append(f"{col} IN ({','.join('?' * len(values))})")
            args += [int(v) if col == "priority" else v for v in values]
    return "".join(f" AND {c}" for c in clauses), args


@router.get("/alerts")
def alerts_page(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Charts and the filterable alert table for the selected analysis."""
    ctx = layout_context(request, conn, "alerts")
    selected = ctx["selected"]
    if selected is None:
        return render(request, "alerts.html", ctx)
    params: dict = {k: v for k, v in request.query_params.items() if v and k not in TICKS}
    params |= {k: vs for k in TICKS if (vs := [v for v in request.query_params.getlist(k) if v])}
    where, args = _filters(params)
    total = conn.execute(f"SELECT COUNT(*) FROM alerts WHERE analysis_id = ?{where}", (selected["id"], *args)).fetchone()[0]
    pg = paging(params, total)
    rows = conn.execute(
        f"SELECT id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto, sid, signature, classtype, "
        f"priority, direction FROM alerts WHERE analysis_id = ?{where} "
        f"ORDER BY {order_by(params, ALERT_SORT, 'ts')}, id LIMIT ? OFFSET ?",
        (selected["id"], *args, pg["limit"], pg["offset"]),
    ).fetchall()
    minutes = default_bin_minutes(conn, selected["id"])
    return render(request, "alerts.html", {
        **ctx,
        "rows": rows,
        "total": total,
        "pg": pg,
        "params": params,
        "qs": page_qs(params),
        "ticks": {"priority": TICKS["priority"], "direction": DIRECTIONS,
                  "classtype": distinct_values(conn, "SELECT classtype AS v FROM alerts WHERE analysis_id = ?",
                                               (selected["id"],), 50)},
        "n_filters": sum(k in params for k in FILTER_KEYS),
        "bin_minutes": minutes,
        "packets": packet_series(conn, selected["id"], minutes),
        "alert_counts": alert_series(conn, selected["id"], minutes),
        "top_devices": top_devices(conn, selected["id"]),
        "device_types": DEVICE_TYPE_LABEL,
        "mix": alert_mix(conn, selected["id"]),
        "options": {col: distinct_values(conn, f"SELECT {col} AS v FROM alerts WHERE analysis_id = ?", (selected["id"],))
                    for col in ("signature", "src_ip", "dest_ip", "sid")},
    })


BIN_CHOICES = (1, 5, 10, 15, 30, 60, 120, 360, 720, 1440)
MAX_BINS = 200


def _binned(rows: Iterable[tuple[str, int]], minutes: int) -> list[tuple[str, int]]:
    """(time, count) rows summed into `minutes`-wide bins, empty bins kept as 0 so capture gaps show as drops."""
    bins: dict[datetime, int] = {}
    for ts, n in rows:
        t = datetime.fromisoformat(ts)
        epoch_min = int(t.replace(tzinfo=t.tzinfo or timezone.utc).timestamp() // 60)
        start = datetime.fromtimestamp(epoch_min // minutes * minutes * 60, timezone.utc)
        bins[start] = bins.get(start, 0) + n
    if not bins:
        return []
    t, end, out = min(bins), max(bins), []
    while t <= end:
        out.append((t.strftime("%Y-%m-%d %H:%M"), bins.get(t, 0)))
        t += timedelta(minutes=minutes)
    return out


def packet_series(conn: sqlite3.Connection, analysis_id: int, minutes: int) -> list[dict]:
    """Packets per `minutes`-wide bin from the per-minute packet_stats rows."""
    rows = conn.execute("SELECT minute, packets FROM packet_stats WHERE analysis_id = ?", (analysis_id,))
    return [{"t": t, "packets": n} for t, n in _binned(((r[0], r[1]) for r in rows), minutes)]


def alert_series(conn: sqlite3.Connection, analysis_id: int, minutes: int) -> list[dict]:
    """Alerts per `minutes`-wide bin."""
    rows = conn.execute("SELECT ts, 1 FROM alerts WHERE analysis_id = ? AND ts IS NOT NULL", (analysis_id,))
    return [{"t": t, "alerts": n} for t, n in _binned(((r[0], r[1]) for r in rows), minutes)]


def top_devices(conn: sqlite3.Connection, analysis_id: int, limit: int = 5) -> list[sqlite3.Row]:
    """The internal devices involved in the most alerts, with the alerts they sent and received."""
    return conn.execute(
        "SELECT d.ip, d.hostname, d.type, SUM(a.src_ip = d.ip) AS sent, SUM(a.dest_ip = d.ip) AS received, "
        "COUNT(*) AS total FROM devices d JOIN alerts a ON a.analysis_id = d.analysis_id "
        "AND (a.src_ip = d.ip OR a.dest_ip = d.ip) WHERE d.analysis_id = ? GROUP BY d.ip "
        "ORDER BY total DESC, d.ip LIMIT ?", (analysis_id, limit)).fetchall()


def default_bin_minutes(conn: sqlite3.Connection, analysis_id: int) -> int:
    """Smallest standard bin width that keeps the chart at MAX_BINS points or fewer."""
    lo, hi = conn.execute("SELECT MIN(minute), MAX(minute) FROM packet_stats WHERE analysis_id = ?",
                          (analysis_id,)).fetchone()
    if not lo:
        return 60
    span = (datetime.fromisoformat(hi) - datetime.fromisoformat(lo)).total_seconds() / 60 + 1
    return next((m for m in BIN_CHOICES if span / m <= MAX_BINS), BIN_CHOICES[-1])


@router.get("/api/analyses/{analysis_id}/packets")
def packets_api(analysis_id: int, minutes: int = Query(60, ge=1, le=1440), conn: sqlite3.Connection = Depends(get_db)):
    """Packets per x minutes for the Alerts chart's Update button."""
    return packet_series(conn, analysis_id, minutes)


@router.get("/api/analyses/{analysis_id}/alert-series")
def alert_series_api(analysis_id: int, minutes: int = Query(60, ge=1, le=1440),
                     conn: sqlite3.Connection = Depends(get_db)):
    """Alerts per x minutes for the Alerts chart's Update button."""
    return alert_series(conn, analysis_id, minutes)


@router.get("/api/alerts/{alert_id}")
def alert_raw(alert_id: int, conn: sqlite3.Connection = Depends(get_db)):
    """The original eve.json record of one alert (raw-JSON drawer)."""
    row = conn.execute("SELECT raw_json FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such alert.")
    return json.loads(row["raw_json"])
