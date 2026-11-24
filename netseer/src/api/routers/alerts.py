"""Alerts page (CONCEPTS A10): packets per x minutes, alert mix, filterable alert table and raw-JSON drawer."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from netseer.src.api.deps import (distinct_values, get_db, layout_context, order_by, page_qs, paging, render,
                                  require_user, severity_label)
from netseer.src.engine.alert_mix import alert_mix
from netseer.src.engine.constants import DEVICE_TYPE_LABEL

router = APIRouter(dependencies=[Depends(require_user)])

DIRECTIONS = ("ext->int", "int->ext", "int->int", "ext->ext")
TICKS = {"priority": ("1", "2", "3", "4"), "direction": DIRECTIONS, "classtype": None, "proto": None}
FILTER_KEYS = ("q", "src_ip", "dest_ip", "sid", "port", "ts_from", "ts_to", *TICKS)
FILTER_LABELS = {"q": "Search", "src_ip": "Source", "dest_ip": "Destination", "sid": "SID", "port": "Port",
                 "ts_from": "From", "ts_to": "To", "priority": "Severity", "direction": "Direction",
                 "proto": "Proto", "classtype": "Class"}
IP_PREFIX_RE = re.compile(r"^[0-9a-fA-F:.]+$")
TS_FMT = "%Y-%m-%dT%H:%M"
ALERT_SORT = {"id": "id", "time": "ts", "src": "src_ip", "dest": "dest_ip", "proto": "proto", "signature": "signature",
              "class": "classtype", "severity": "priority", "direction": "direction"}


def _clean_filters(params: dict) -> list[str]:
    """Strip text values, drop invalid ones from `params`, and return a note per invalid typed field."""
    notes: list[str] = []
    for field in ("q", "src_ip", "dest_ip", "sid", "port", "ts_from", "ts_to"):
        if isinstance(params.get(field), str):
            params[field] = params[field].strip()
    for field in ("src_ip", "dest_ip"):
        v = params.get(field)
        if not v:
            continue
        if "/" in v:
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                notes.append(f'{FILTER_LABELS[field]} "{v}"')
                params.pop(field)
        elif not IP_PREFIX_RE.fullmatch(v):
            notes.append(f'{FILTER_LABELS[field]} "{v}"')
            params.pop(field)
    v = params.get("sid")
    if v and not (v.isascii() and v.isdigit() and len(v) <= 18):      # fits SQLite's 64-bit integer
        notes.append(f'{FILTER_LABELS["sid"]} "{v}"')
        params.pop("sid")
    v = params.get("port")
    if v and not (v.isascii() and v.isdigit() and len(v) <= 5 and int(v) <= 65535):
        notes.append(f'{FILTER_LABELS["port"]} "{v}"')
        params.pop("port")
    bounds: dict[str, datetime] = {}
    for field in ("ts_from", "ts_to"):
        v = params.get(field)
        if not v:
            continue
        try:
            parsed = datetime.strptime(v, TS_FMT)
            parsed + timedelta(minutes=1)                             # ts_to's exclusive end must exist
        except (ValueError, OverflowError):
            notes.append(f'{FILTER_LABELS[field]} "{v}"')
            params.pop(field)
        else:
            bounds[field] = parsed
            params[field] = parsed.isoformat(timespec="minutes")      # zero-padded: ts is compared as text
    from_, to_ = bounds.get("ts_from"), bounds.get("ts_to")
    if from_ and to_ and from_ > to_:
        params.pop("ts_from", None)
        params.pop("ts_to", None)
        notes.append("From is after To")
    for col, allowed in TICKS.items():               # tick boxes: any of the ticked values
        values = [x for x in params.get(col, []) if allowed is None or x in allowed]
        if values:
            params[col] = values
        else:
            params.pop(col, None)
    return notes


def _filters(params: dict[str, str | list[str]], conn: sqlite3.Connection, analysis_id: int) -> tuple[str, list]:
    """WHERE clause fragments for the table filters (all parameterised)."""
    clauses, args = [], []
    if params.get("q"):
        clauses.append("(signature LIKE ? OR category LIKE ? OR classtype LIKE ?)")
        args += [f"%{params['q']}%"] * 3
    for field in ("src_ip", "dest_ip"):
        v = params.get(field)
        if not v:
            continue
        if "/" in v:                                 # CIDR: only addresses already present and inside the network
            net = ipaddress.ip_network(v, strict=False)
            inside = []
            for (ip,) in conn.execute(
                    f"SELECT DISTINCT {field} FROM alerts WHERE analysis_id = ? AND {field} IS NOT NULL",
                    (analysis_id,)):
                try:
                    if ipaddress.ip_address(ip) in net:
                        inside.append(ip)
                except ValueError:
                    continue                         # skip unparsable stored values
            clauses.append(f"{field} IN (SELECT value FROM json_each(?))")
            args.append(json.dumps(inside))
        else:
            try:
                ipaddress.ip_address(v)              # a full IP: exact match
            except ValueError:
                clauses.append(f"{field} LIKE ?")     # otherwise a partial prefix
                args.append(v + "%")
            else:
                clauses.append(f"{field} = ?")
                args.append(v)
    if params.get("sid"):
        clauses.append("sid = ?")
        args.append(int(params["sid"]))
    if params.get("port"):
        clauses.append("(src_port = ? OR dest_port = ?)")
        args += [int(params["port"]), int(params["port"])]
    if params.get("ts_from"):
        clauses.append("ts >= ?")
        args.append(params["ts_from"] + ":00")
    if params.get("ts_to"):
        clauses.append("ts < ?")
        args.append((datetime.strptime(params["ts_to"], TS_FMT) + timedelta(minutes=1)).isoformat(timespec="seconds"))
    for col, allowed in TICKS.items():               # tick boxes: any of the ticked values
        values = [v for v in params.get(col, []) if allowed is None or v in allowed]
        if values:
            clauses.append(f"{col} IN ({','.join('?' * len(values))})")
            args += [int(v) if col == "priority" else v for v in values]
    return "".join(f" AND {c}" for c in clauses), args


def _filter_chips(params: dict) -> list[dict]:
    """One chip per active filter value, each linking to the query string without that value."""
    chips: list[dict] = []
    for key in ("q", "src_ip", "dest_ip", "sid", "port", "ts_from", "ts_to", *TICKS):
        value = params.get(key)
        if key in TICKS:
            for v in value or []:
                label = f"Severity: {severity_label(int(v))}" if key == "priority" else f"{FILTER_LABELS[key]}: {v}"
                rest = [x for x in value if x != v]
                others = {k: val for k, val in params.items() if k != key}
                if rest:
                    others[key] = rest
                chips.append({"label": label, "qs": page_qs(others)})
        elif value:
            chips.append({"label": f"{FILTER_LABELS[key]}: {value}",
                          "qs": page_qs({k: val for k, val in params.items() if k != key})})
    return chips


@router.get("/alerts")
def alerts_page(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Charts and the filterable alert table for the selected analysis."""
    ctx = layout_context(request, conn, "alerts")
    selected = ctx["selected"]
    if selected is None:
        return render(request, "alerts.html", ctx)
    params: dict = {k: v for k, v in request.query_params.items() if v and k not in TICKS}
    params |= {k: vs for k in TICKS if (vs := [v for v in request.query_params.getlist(k) if v])}
    filter_notes = _clean_filters(params)
    where, args = _filters(params, conn, selected["id"])
    total = conn.execute(f"SELECT COUNT(*) FROM alerts WHERE analysis_id = ?{where}", (selected["id"], *args)).fetchone()[0]
    pg = paging(params, total)
    rows = conn.execute(
        f"SELECT id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto, sid, signature, classtype, "
        f"priority, direction FROM alerts WHERE analysis_id = ?{where} "
        f"ORDER BY {order_by(params, ALERT_SORT, 'ts')}, id LIMIT ? OFFSET ?",
        (selected["id"], *args, pg["limit"], pg["offset"]),
    ).fetchall()
    minutes = default_bin_minutes(conn, selected["id"])
    bin_label = f"{minutes // 60} h" if minutes % 60 == 0 else f"{minutes} min"
    return render(request, "alerts.html", {
        **ctx,
        "rows": rows,
        "total": total,
        "pg": pg,
        "params": params,
        "qs": page_qs(params),
        "filter_notes": filter_notes,
        "chips": _filter_chips(params),
        "ticks": {"priority": TICKS["priority"], "direction": DIRECTIONS,
                  "classtype": distinct_values(conn, "SELECT classtype AS v FROM alerts WHERE analysis_id = ?",
                                               (selected["id"],)),
                  "proto": distinct_values(conn, "SELECT proto AS v FROM alerts WHERE analysis_id = ?",
                                           (selected["id"],))},
        "n_filters": sum(k in params for k in FILTER_KEYS),
        "bin_minutes": minutes,
        "bin_label": bin_label,
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


TRAFFIC_MIN_S = 5
TRAFFIC_MAX_S = 3_600_000
TRAFFIC_DEFAULT_POINTS = 200
TRAFFIC_MAX_POINTS = 2500
TRAFFIC_DEFAULT_BINS = (5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600)


def traffic_series(conn: sqlite3.Connection, analysis_id: int, seconds: int | None = None) -> dict:
    """Traffic volume per `seconds`-wide bin split by direction (ii, ie, ei) for the Home chart."""
    lo, hi = conn.execute("SELECT MIN(second), MAX(second) FROM traffic_stats WHERE analysis_id = ?",
                          (analysis_id,)).fetchone()
    if lo is None:
        needs = conn.execute("SELECT 1 FROM packet_stats WHERE analysis_id = ? LIMIT 1",
                             (analysis_id,)).fetchone() is not None
        return {"seconds": 60, "default_seconds": 60, "raised": False, "points": [], "needs_reanalysis": needs}
    span = hi - lo + TRAFFIC_MIN_S
    default = next((b for b in TRAFFIC_DEFAULT_BINS if span / b <= TRAFFIC_DEFAULT_POINTS), 3600)
    requested = seconds or default
    floor = TRAFFIC_MIN_S
    while span / floor > TRAFFIC_MAX_POINTS:
        floor += TRAFFIC_MIN_S
    used = max(-(-requested // TRAFFIC_MIN_S) * TRAFFIC_MIN_S, floor)  # round up to a 5 s bucket
    raised = used != requested
    rows = conn.execute(
        "SELECT second / ? * ? AS t, SUM(ii_packets) AS ii_packets, SUM(ii_bytes) AS ii_bytes, "
        "SUM(ie_packets) AS ie_packets, SUM(ie_bytes) AS ie_bytes, SUM(ei_packets) AS ei_packets, "
        "SUM(ei_bytes) AS ei_bytes FROM traffic_stats WHERE analysis_id = ? GROUP BY t ORDER BY t",
        (used, used, analysis_id)).fetchall()
    by_t = {r["t"]: r for r in rows}
    points = []
    t = lo // used * used
    hi_bin = hi // used * used
    while t <= hi_bin:
        r = by_t.get(t)
        points.append({"t": datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                       "ii_packets": r["ii_packets"] if r else 0, "ii_bytes": r["ii_bytes"] if r else 0,
                       "ie_packets": r["ie_packets"] if r else 0, "ie_bytes": r["ie_bytes"] if r else 0,
                       "ei_packets": r["ei_packets"] if r else 0, "ei_bytes": r["ei_bytes"] if r else 0})
        t += used
    return {"seconds": used, "default_seconds": default, "raised": raised, "points": points,
            "needs_reanalysis": False}


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
def packets_api(analysis_id: int, minutes: int = Query(60, ge=1, le=60000), conn: sqlite3.Connection = Depends(get_db)):
    """Packets per x minutes for the Alerts chart's Update button."""
    return packet_series(conn, analysis_id, minutes)


@router.get("/api/analyses/{analysis_id}/traffic")
def traffic_api(analysis_id: int, seconds: int | None = Query(None, ge=1, le=TRAFFIC_MAX_S),
                conn: sqlite3.Connection = Depends(get_db)):
    """Traffic volume per x seconds split by direction for the Home Traffic Volume chart."""
    return traffic_series(conn, analysis_id, seconds)


@router.get("/api/analyses/{analysis_id}/alert-series")
def alert_series_api(analysis_id: int, minutes: int = Query(60, ge=1, le=60000),
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
