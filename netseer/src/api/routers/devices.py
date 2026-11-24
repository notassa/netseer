"""Devices page and Device Attribution (CONCEPTS A14, brief §6a step 3)."""

from __future__ import annotations

import ipaddress
import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from netseer.src.api.deps import (distinct_values, get_db, layout_context, order_by, page_qs, paging, redirect, render,
                                  require_admin, require_user, verify_csrf)
from netseer.src.api.routers.incidents import incident_rows
from netseer.src.database.db import audit
from netseer.src.engine.acp import ensure_acp, rescore
from netseer.src.engine.constants import DEVICE_TYPE, DEVICE_TYPE_LABEL
from netseer.src.engine.netmap import build_map
from netseer.src.engine.networks import ensure_networks
from netseer.src.engine.scorer import device_bands

router = APIRouter()


def set_device_type(conn: sqlite3.Connection, device_id: int, device_type: str) -> None:
    """Record a device's type and its asset criticality (I1), and mark it attributed."""
    if device_type not in DEVICE_TYPE:
        raise HTTPException(status_code=400, detail="Unknown device type.")
    conn.execute("UPDATE devices SET type = ?, criticality = ?, attributed = 1 WHERE id = ?",
                 (device_type, DEVICE_TYPE[device_type], device_id))


def _finish_attribution(conn: sqlite3.Connection, analysis_id: int) -> None:
    """Move the analysis to done once no device awaits attribution."""
    pending = conn.execute("SELECT 1 FROM devices WHERE analysis_id = ? AND attributed = 0", (analysis_id,)).fetchone()
    if pending is None:
        conn.execute("UPDATE analyses SET status = 'done' WHERE id = ? AND status = 'awaiting_attribution'",
                     (analysis_id,))


@router.get("/devices")
def devices_page(request: Request, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Inventory of internal hosts with the attribution modal for unattributed ones."""
    ctx = layout_context(request, conn, "devices")
    selected = ctx["selected"]
    devices = []
    if selected is not None:
        ensure_acp(conn, selected)
        rows = conn.execute("SELECT * FROM devices WHERE analysis_id = ?", (selected["id"],)).fetchall()
        bands = device_bands(conn, selected["id"])
        devices = sorted((dict(r) | {"services": json.loads(r["services_json"] or "[]"),
                                     "risk_label": bands.get(r["ip"], "Low")} for r in rows),
                         key=lambda d: (ipaddress.ip_address(d["ip"]).version, int(ipaddress.ip_address(d["ip"]))))
    networks = ensure_networks(conn, selected) if selected is not None else []
    pending = [d for d in devices if not d["attributed"]]
    awaiting = selected is not None and (selected["status"] == "awaiting_attribution" or selected["mode"] == "live")
    return render(request, "devices.html", {
        **ctx,
        "devices": devices,
        "networks": networks,
        "pending": pending,
        "show_modal": bool(pending) and awaiting,
        "types": DEVICE_TYPE_LABEL,
        **(_externals(request, conn, selected["id"]) if selected is not None else {}),
    })


EXTERNAL_SORT = {"ip": "ip", "hostname": "hostname", "direction": "direction", "first": "first_seen",
                 "last": "last_seen", "flows": "n_flows", "bytes": "bytes", "alerts": "n_alerts"}


def _externals(request: Request, conn: sqlite3.Connection, analysis_id: int) -> dict:
    """External sources table: every IP outside the LAN CIDRs, paged, searchable and server-sorted."""
    params = {k: v for k, v in request.query_params.items() if v}
    where, args = "analysis_id = ?", [analysis_id]
    if params.get("ext_q"):
        where += " AND (ip LIKE ? OR hostname LIKE ?)"
        args += [f"%{params['ext_q']}%"] * 2
    total = conn.execute(f"SELECT COUNT(*) FROM external_hosts WHERE {where}", args).fetchone()[0]
    pg = paging(params, total)
    order = order_by(params, EXTERNAL_SORT, "n_alerts DESC, bytes DESC")
    rows = [dict(r) | {"ports": json.loads(r["ports_json"] or "[]"), "peers": json.loads(r["peers_json"] or "[]")}
            for r in conn.execute(f"SELECT * FROM external_hosts WHERE {where} ORDER BY {order}, id LIMIT ? OFFSET ?",
                                  (*args, pg["limit"], pg["offset"]))]
    return {
        "externals": rows, "ext_total": total, "ext_pg": pg,
        "ext_q": params.get("ext_q", ""),
        "ext_qs": page_qs(params),
        "ext_options": distinct_values(conn, "SELECT ip AS v FROM external_hosts WHERE analysis_id = ? UNION ALL "
                                             "SELECT hostname FROM external_hosts WHERE analysis_id = ?",
                                       (analysis_id, analysis_id)),
    }


@router.get("/api/analyses/{analysis_id}/map")
def network_map(analysis_id: int, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Nodes and edges of the Devices network map (Cytoscape.js elements)."""
    analysis = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if analysis is None:
        raise HTTPException(status_code=404, detail="No such analysis.")
    ensure_networks(conn, analysis)
    return build_map(conn, analysis_id)


@router.post("/devices/attribute", dependencies=[Depends(verify_csrf)])
async def attribute(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Save the attribution modal: `type_<id>` fields, or `skip` to keep the rest Unknown."""
    form = await request.form()
    analysis_id = int(form.get("analysis_id", "0") or 0)
    ids = {r["id"] for r in conn.execute("SELECT id FROM devices WHERE analysis_id = ? AND attributed = 0",
                                         (analysis_id,))}
    skip = form.get("action") == "skip"
    for device_id in ids:
        chosen = "unknown" if skip else str(form.get(f"type_{device_id}", "unknown"))
        set_device_type(conn, device_id, chosen)
    _finish_attribution(conn, analysis_id)
    rescore(conn, analysis_id)
    audit(conn, admin["id"], "attribution_saved", f"analysis {analysis_id}: {len(ids)} devices{' (skipped)' if skip else ''}")
    return redirect("/devices", "ok", "Device types saved." if not skip else "Devices kept as Unknown. You can change them any time.")


@router.post("/devices/{device_id}/type", dependencies=[Depends(verify_csrf)])
async def change_type(device_id: int, request: Request, admin=Depends(require_admin),
                      conn: sqlite3.Connection = Depends(get_db)):
    """Change one device's type from the Devices table and re-score the analysis."""
    row = conn.execute("SELECT analysis_id, ip FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such device.")
    device_type = str((await request.form()).get("type", ""))
    set_device_type(conn, device_id, device_type)
    _finish_attribution(conn, row["analysis_id"])
    rescore(conn, row["analysis_id"])
    audit(conn, admin["id"], "device_type", f"{row['ip']} → {device_type}")
    return redirect("/devices", "ok", f"{row['ip']} is now {DEVICE_TYPE_LABEL[device_type]}.")


@router.get("/api/devices/{device_id}/incidents")
def device_incidents(device_id: int, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Incidents that involve one device, for its pop-up on the Devices page."""
    row = conn.execute("SELECT analysis_id, ip FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such device.")
    return [{"id": i["id"], "title": i["title"], "band": i["band"]}
            for i in incident_rows(conn, row["analysis_id"])
            if row["ip"] in i["src_ips"] or row["ip"] in i["dest_ips"]]
