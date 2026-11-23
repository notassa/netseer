"""Home page (CONCEPTS A10): network health gauge, top incidents, devices at risk, traffic volume, analysis status."""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, Request

from netseer.src.api.deps import get_db, layout_context, render, require_user
from netseer.src.api.routers.alerts import traffic_series
from netseer.src.api.routers.incidents import incident_rows
from netseer.src.config import get_setting
from netseer.src.engine.acp import ensure_acp
from netseer.src.engine.constants import BANDS, DEVICE_TYPE_LABEL
from netseer.src.engine.scorer import device_bands, network_health, risk_label

router = APIRouter(dependencies=[Depends(require_user)])


def format_total(nbytes: int, packets: int, unit: str) -> tuple[str, str]:
    """Human-readable total traffic for one analysis, in the user's chosen unit."""
    if unit == "packet":
        return f"{packets:,} pkt", "Total packets"
    value = nbytes * 8 if unit == "bit" else nbytes
    units = ["b", "kb", "Mb", "Gb"] if unit == "bit" else ["B", "KB", "MB", "GB"]
    label = "Total bits" if unit == "bit" else "Total bytes"
    x, i = float(value), 0
    while x >= 1000 and i < len(units) - 1:
        x /= 1000
        i += 1
    digits = 0 if (i == 0 or x >= 100) else (1 if x >= 10 else 2)
    return f"{x:.{digits}f} {units[i]}", label


@router.get("/")
def home(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Overview of the selected analysis."""
    ctx = layout_context(request, conn, "home")
    selected = ctx["selected"]
    if selected is None:
        return render(request, "home.html", ctx)
    ensure_acp(conn, selected)
    aid = selected["id"]
    net = network_health(conn, aid)
    counts = {
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE analysis_id = ?", (aid,)).fetchone()[0],
        "groups": conn.execute("SELECT COUNT(*) FROM alert_groups WHERE analysis_id = ?", (aid,)).fetchone()[0],
        "incidents": conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_id = ?", (aid,)).fetchone()[0],
        "devices": conn.execute("SELECT COUNT(*) FROM devices WHERE analysis_id = ?", (aid,)).fetchone()[0],
    }
    bands = dict(conn.execute("SELECT band, COUNT(*) FROM incidents WHERE analysis_id = ? GROUP BY band",
                              (aid,)).fetchall())
    device_band = device_bands(conn, aid)
    at_risk = [dict(d) | {"label": device_band[d["ip"]]}           # worst incident band Medium or above (A5.4)
               for d in conn.execute("SELECT ip, hostname, type, risk FROM devices WHERE analysis_id = ? "
                                     "ORDER BY risk DESC", (aid,))
               if device_band.get(d["ip"]) in ("Critical", "High", "Medium")]
    analysis = conn.execute("SELECT * FROM analyses WHERE id = ?", (aid,)).fetchone()
    nbytes, packets = conn.execute(
        "SELECT COALESCE(SUM(bytes), 0), COALESCE(SUM(packets), 0) FROM packet_stats WHERE analysis_id = ?",
        (aid,)).fetchone()
    return render(request, "home.html", {
        **ctx,
        "net": net,
        "health_label": risk_label(100 - net["health"]),
        "top_incidents": incident_rows(conn, aid, limit=5),
        "at_risk": at_risk,
        "traffic": traffic_series(conn, aid),
        "data_unit": get_setting(conn, "data_unit"),
        "total_traffic": format_total(nbytes, packets, get_setting(conn, "data_unit")),
        "counts": counts,
        "bands": [(b, bands.get(b, 0)) for b in BANDS],
        "analysis": analysis,
        "types": DEVICE_TYPE_LABEL,
        "risk_label": risk_label,
    })
