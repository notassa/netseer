"""Incidents page and incident detail (CONCEPTS A10, brief §9): possible incidents with band, score and breakdown."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request

from netseer.src.api.deps import distinct_values, get_db, layout_context, render, require_user
from netseer.src.engine.acp import ensure_acp
from netseer.src.engine.constants import BANDS, DEVICE_TYPE_LABEL, FACTOR_NAMES, MITRE_TACTICS
from netseer.src.engine.contextor import RECON

router = APIRouter(dependencies=[Depends(require_user)])

BAND_RANK = "CASE band " + " ".join(f"WHEN '{b}' THEN {i}" for i, b in enumerate(BANDS)) + f" ELSE {len(BANDS)} END"
RULES = ("R1", "R2", "R3", "R4", "single")
TIMELINE_GROUPS = 30            # busiest groups drawn on the timeline until "Show all groups"
RAW_ALERTS = 200


def incident_rows(conn: sqlite3.Connection, analysis_id: int, where: str = "", args: tuple = (),
                  limit: int | None = None) -> list[dict]:
    """Incidents ordered by band then score (A5.3), with host lists decoded."""
    sql = (f"SELECT * FROM incidents WHERE analysis_id = ?{where} ORDER BY {BAND_RANK}, score DESC, id"
           + (f" LIMIT {int(limit)}" if limit else ""))
    return [dict(r) | {"src_ips": json.loads(r["src_ips_json"]), "dest_ips": json.loads(r["dest_ips_json"]),
                       "band_rank": BANDS.index(r["band"]) if r["band"] in BANDS else len(BANDS)}
            for r in conn.execute(sql, (analysis_id, *args))]


@router.get("/incidents")
def incidents_page(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Table of possible incidents for the selected analysis, filterable by text, band and rule."""
    ctx = layout_context(request, conn, "incidents")
    selected = ctx["selected"]
    if selected is None:
        return render(request, "incidents.html", ctx)
    ensure_acp(conn, selected)
    params = {k: v for k, v in request.query_params.items() if v}
    clauses, args = [], []
    if params.get("q"):
        clauses.append("(title LIKE ? OR src_ips_json LIKE ? OR dest_ips_json LIKE ?)")
        args += [f"%{params['q']}%"] * 3
    if params.get("band") in BANDS:
        clauses.append("band = ?")
        args.append(params["band"])
    if params.get("rule") in RULES:
        clauses.append("(',' || rule || ',') LIKE ?")
        args.append(f"%,{params['rule']},%")
    rows = incident_rows(conn, selected["id"], "".join(f" AND {c}" for c in clauses), tuple(args))
    total = conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_id = ?", (selected["id"],)).fetchone()[0]
    n_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE analysis_id = ?", (selected["id"],)).fetchone()[0]
    n_groups = conn.execute("SELECT COUNT(*) FROM alert_groups WHERE analysis_id = ?", (selected["id"],)).fetchone()[0]
    return render(request, "incidents.html", {
        **ctx, "rows": rows, "total": total, "n_alerts": n_alerts, "n_groups": n_groups, "params": params,
        "bands": BANDS, "rules": RULES,
        "options": distinct_values(conn, "SELECT title AS v FROM incidents WHERE analysis_id = ? UNION ALL "
                                         "SELECT j.value FROM incidents i, json_each(i.src_ips_json) j "
                                         "WHERE i.analysis_id = ? UNION ALL "
                                         "SELECT j.value FROM incidents i, json_each(i.dest_ips_json) j "
                                         "WHERE i.analysis_id = ?", (selected["id"],) * 3),
    })


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """One incident: factor breakdown, alert groups with a timeline, and its raw alerts."""
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such incident.")
    factors = json.loads(row["factors_json"] or "{}")
    groups = conn.execute(
        "SELECT g.* FROM incident_groups ig JOIN alert_groups g ON g.id = ig.group_id WHERE ig.incident_id = ? "
        "ORDER BY g.first_seen, g.id", (incident_id,)).fetchall()
    alerts = conn.execute(
        "SELECT a.id, a.ts, a.src_ip, a.src_port, a.dest_ip, a.dest_port, a.proto, a.sid, a.signature, a.classtype, "
        "a.priority, a.sig_severity, a.direction FROM incident_groups ig JOIN alert_groups g ON g.id = ig.group_id "
        "JOIN json_each(g.alert_ids_json) j JOIN alerts a ON a.id = j.value WHERE ig.incident_id = ? "
        "ORDER BY a.ts, a.id LIMIT ?", (incident_id, RAW_ALERTS)).fetchall()
    devices = {d["ip"]: d for d in conn.execute("SELECT ip, hostname, type FROM devices WHERE analysis_id = ?",
                                                (row["analysis_id"],))}
    pairs: dict[tuple, Counter] = defaultdict(Counter)        # (attacker, victim) → alerts per signature
    for g in groups:
        pairs[(g["src_ip"], g["dest_ip"])][g["signature"] or f"SID {g['sid']}"] += g["count"]
    attack_pairs = [{"src": src, "dest": dest, "alerts": sum(sigs.values()), "top": sigs.most_common(1)[0][0],
                     "src_dev": devices.get(src), "dest_dev": devices.get(dest)}
                    for (src, dest), sigs in sorted(pairs.items(), key=lambda kv: -sum(kv[1].values()))[:10]]
    hosts = set(json.loads(row["src_ips_json"])) | set(json.loads(row["dest_ips_json"]))
    recon_before = [r for r in conn.execute(
        "SELECT id, title, band, src_ips_json, dest_ips_json, evidence_json FROM incidents "
        "WHERE analysis_id = ? AND id != ? AND last_seen <= ?", (row["analysis_id"], incident_id, row["first_seen"]))
        if (cts := json.loads(r["evidence_json"] or "{}").get("classtypes")) and set(cts) <= RECON
        and hosts & (set(json.loads(r["src_ips_json"])) | set(json.loads(r["dest_ips_json"])))]
    return render(request, "incident.html", {
        **layout_context(request, conn, "incidents"),
        "recon_before": recon_before,
        "attack_pairs": attack_pairs,
        "n_pairs": len(pairs),
        "device_types": DEVICE_TYPE_LABEL,
        "inc": dict(row) | {"src_ips": json.loads(row["src_ips_json"]), "dest_ips": json.loads(row["dest_ips_json"])},
        "evidence": json.loads(row["evidence_json"] or "{}"),
        "factors": [(k, FACTOR_NAMES[k], factors[k]) for k in FACTOR_NAMES if k in factors],
        "groups": groups,
        "timeline": [{"label": f"{g['signature'] or g['sid']} · {g['src_ip'] or 'unknown'} → {g['dest_ip'] or 'unknown'}",
                      "start": g["first_seen"], "end": g["last_seen"], "count": g["count"]} for g in groups],
        "timeline_groups": TIMELINE_GROUPS,
        "alerts": alerts,
        "raw_limit": RAW_ALERTS,
        "tactic_names": MITRE_TACTICS,
    })
