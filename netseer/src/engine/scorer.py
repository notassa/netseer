"""Scorer (ACP 6, CONCEPTS A5): incident factors, band and score; device risk and network health.

Every constant comes from `constants.py`. The pure functions below are the model; `score_incidents` and
`roll_up` apply them to an analysis and store the results (`incidents.*`, `devices.risk`).
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable

from netseer.src.config import get_setting
from netseer.src.engine import ti
from netseer.src.engine.constants import (BANDS, DAMPING_P, DEVICE_TYPE, DEVICE_TYPE_LABEL, I2_OTHER, I2_PORTS_6, I2_PORTS_9,
                                          I3_CLASSTYPE, I3_OTHER, L1_PRIORITY, L1_SIG_SEVERITY, L3_RULE, L4_DIRECTION,
                                          LEVEL_CUTS, MATRIX, RISK_CUTS)

I3_BY_CLASSTYPE = {ct: value for value, names in I3_CLASSTYPE.items() for ct in names}
RULE_WHY = {
    "single": "one alert group, no correlation rule fired",
    "R1": "R1: same attacker → same victim with different signatures",
    "R2": "R2: one source → 5 or more destinations (sweep/scan)",
    "R3": "R3: 5 or more sources → one destination (brute force/DoS)",
    "R4": "R4: MITRE tactic progression on one host",
}


# --- the model (pure functions) -------------------------------------------------------------------------------

def l1(priority: int | None, sig_severity: str | None) -> int | None:
    """Detection confidence of one alert: ET signature_severity overrides Suricata priority, except "Informational"
    (ET marks many real scans so), which yields to the priority when there is one."""
    if sig_severity in L1_SIG_SEVERITY and not (sig_severity == "Informational" and priority in L1_PRIORITY):
        return L1_SIG_SEVERITY[sig_severity]
    return L1_PRIORITY.get(priority)


def l2(n_alerts: int) -> float:
    """Activity volume: min(9, 3·log10(1 + n))."""
    return min(9.0, 3 * math.log10(1 + n_alerts))


def i2(port: int | None) -> int:
    """Service sensitivity of a port."""
    if port in I2_PORTS_9:
        return 9
    if port in I2_PORTS_6:
        return 6
    return I2_OTHER


def i3(classtype: str | None) -> int:
    """Potential technical impact of a Suricata classtype (short name)."""
    return I3_BY_CLASSTYPE.get(classtype or "", I3_OTHER)


def likelihood(values: Iterable[float | None]) -> float:
    """L = mean of the likelihood factors that are present (unknown L5 is left out, never counted as safe)."""
    present = [v for v in values if v is not None]
    return sum(present) / len(present) if present else 0.0


def impact(i1: float, i2_value: float, i3_value: float) -> float:
    """I = I3 · (0.5 + 0.5 · A/9) with A = (I1 + I2)/2: the attack type sets the ceiling, the asset scales it."""
    return i3_value * (0.5 + 0.5 * ((i1 + i2_value) / 2) / 9)


def level(x: float) -> str:
    """Low [0,3) · Medium [3,6) · High [6,9]."""
    low, high = LEVEL_CUTS
    return "Low" if x < low else "Medium" if x < high else "High"


def band(L: float, I: float) -> str:  # noqa: N803 - names follow CONCEPTS A5
    """OWASP matrix band from the likelihood and impact levels."""
    return MATRIX[(level(L), level(I))]


def score(L: float, I: float) -> float:  # noqa: N803
    """R = 10 · (L/9) · (I/9), 0–10."""
    return 10 * (L / 9) * (I / 9)


def incident_probability(R: float, age_s: float, half_life_days: float) -> float:  # noqa: N803
    """pᵢ = R/10 · 0.5^(age/half_life)."""
    return R / 10 * 0.5 ** (max(age_s, 0.0) / (half_life_days * 86400))


def union(ps: Iterable[float]) -> float:
    """P(at least one) = 1 − Π(1 − pᵢ) under independence (Munir Ch.3)."""
    return 1 - math.prod(1 - p for p in ps)


def damped_union(xs: Iterable[float]) -> float:
    """Rank-damped union (A5.4): 1 − Π_k (1 − x_(k) / k^1.5) over the values sorted worst first.

    One value gives x; more values never lower it; it stays below 1 for any number of values, and splitting one
    incident into two barely moves it.
    """
    return union(x / k ** DAMPING_P for k, x in enumerate(sorted(xs, reverse=True), 1))


def health(xs: Iterable[float]) -> tuple[float, int]:
    """(P(N), health) from the incidents' weighted probabilities xᵢ: P(N) = D(xᵢ); health = round(100·(1 − P(N)))."""
    p_n = damped_union(xs)
    return p_n, round(100 * (1 - p_n))


def risk_label(percent: float) -> str:
    """Risk colour of a percentage (network health gauge): <40 Low · 40–69 Medium · 70–89 High · ≥90 Critical."""
    return next(label for cut, label in RISK_CUTS if percent >= cut)


# --- applying it to an analysis ------------------------------------------------------------------------------

def _devices(conn: sqlite3.Connection, analysis_id: int) -> dict[str, sqlite3.Row]:
    return {r["ip"]: r for r in conn.execute("SELECT * FROM devices WHERE analysis_id = ?", (analysis_id,))}


def _incident_alerts(conn: sqlite3.Connection, analysis_id: int) -> dict[int, list[sqlite3.Row]]:
    rows = conn.execute(
        "SELECT ig.incident_id, a.id, a.priority, a.sig_severity, a.direction, a.src_port, a.dest_port, a.classtype, "
        "a.sid FROM incident_groups ig JOIN alert_groups g ON g.id = ig.group_id "
        "JOIN json_each(g.alert_ids_json) j JOIN alerts a ON a.id = j.value WHERE g.analysis_id = ?", (analysis_id,))
    out: dict[int, list[sqlite3.Row]] = defaultdict(list)
    for r in rows:
        out[r["incident_id"]].append(r)
    return out


def _factors(inc: sqlite3.Row, alerts: list[sqlite3.Row], devices: dict[str, sqlite3.Row],
             ti_results: dict[str, dict[str, dict]]) -> dict[str, dict]:
    """Every factor as {value, evidence, why} (A5.3 breakdown)."""
    f: dict[str, dict] = {}

    best = max(alerts, key=lambda a: l1(a["priority"], a["sig_severity"]) or 0)
    value = l1(best["priority"], best["sig_severity"])
    f["L1"] = {"value": value, "evidence": {"alert_id": best["id"], "sid": best["sid"], "priority": best["priority"],
                                            "signature_severity": best["sig_severity"]},
               "why": (f"Suricata priority {best['priority'] or 'unknown'}, signature severity "
                       f"{best['sig_severity'] or 'unknown'}" if value is not None else "no priority (unknown)")}

    f["L2"] = {"value": l2(inc["n_alerts"]), "evidence": {"n_alerts": inc["n_alerts"]},
               "why": f"{inc['n_alerts']} alert{'s' if inc['n_alerts'] != 1 else ''}"}

    rule = inc["rule"].split(",")[0]
    f["L3"] = {"value": L3_RULE[rule], "evidence": {"rules": inc["rule"].split(",")}, "why": RULE_WHY[rule]}

    dirs = Counter(a["direction"] for a in alerts if a["direction"] in L4_DIRECTION)
    if dirs:
        dom = max(dirs, key=lambda d: (dirs[d], L4_DIRECTION[d]))
        f["L4"] = {"value": L4_DIRECTION[dom], "evidence": {"direction": dom, "counts": dict(dirs)},
                   "why": f"mostly {dom} ({dirs[dom]} of {sum(dirs.values())} alerts)"}
    else:
        f["L4"] = {"value": None, "evidence": {}, "why": "direction unknown (left out of the mean)"}

    ips = set(json.loads(inc["src_ips_json"])) | set(json.loads(inc["dest_ips_json"]))
    rep = ti.l5({ip: ti_results[ip] for ip in ips if ip in ti_results})
    if rep is None:
        f["L5"] = {"value": None, "evidence": {}, "why": "threat intelligence off or no result (left out of the mean)"}
    else:
        f["L5"] = {"value": rep[0], "evidence": {"ip": rep[1], "source": rep[2]},
                   "why": f"{rep[1]}: reputation {rep[0]:.1f}/9 ({'AbuseIPDB' if rep[2] == 'abuseipdb' else 'VirusTotal'})"}
    involved = [devices[ip] for ip in sorted(ips) if ip in devices]
    if involved:
        dev = max(involved, key=lambda d: d["criticality"])
        f["I1"] = {"value": dev["criticality"], "evidence": {"device": dev["ip"], "type": dev["type"]},
                   "why": f"{dev['ip']} is {DEVICE_TYPE_LABEL.get(dev['type'], dev['type'])}"}
    else:
        f["I1"] = {"value": DEVICE_TYPE["unknown"], "evidence": {}, "why": "no internal device involved (Unknown)"}

    port, port_value = None, I2_OTHER
    for a in alerts:
        for p in (a["dest_port"], a["src_port"]):
            if p is not None and i2(p) > port_value:
                port, port_value = p, i2(p)
    f["I2"] = {"value": port_value, "evidence": {"port": port},
               "why": f"port {port}" if port is not None else "no sensitive service port"}

    worst = max(alerts, key=lambda a: i3(a["classtype"]))
    f["I3"] = {"value": i3(worst["classtype"]), "evidence": {"classtype": worst["classtype"], "alert_id": worst["id"]},
               "why": worst["classtype"] or "classtype unknown"}
    return f


def score_incidents(conn: sqlite3.Connection, analysis_id: int) -> int:
    """Compute and store L, I, band, R and the factor breakdown for every incident; returns the count."""
    devices = _devices(conn, analysis_id)
    alerts = _incident_alerts(conn, analysis_id)
    rows = conn.execute("SELECT * FROM incidents WHERE analysis_id = ?", (analysis_id,)).fetchall()
    ti_results = ti.cached(conn, sorted({ip for inc in rows for col in ("src_ips_json", "dest_ips_json")
                                        for ip in json.loads(inc[col])}))
    updates = []
    for inc in rows:
        f = _factors(inc, alerts[inc["id"]], devices, ti_results)
        l5 = f["L5"]["value"]
        if l5 is not None and l5 <= likelihood(f[k]["value"] for k in ("L1", "L2", "L3", "L4")):
            f["L5"] = {"value": None, "evidence": f["L5"]["evidence"] | {"reputation": l5},
                       "why": f["L5"]["why"] + ", not above L: left out (no reports is not evidence of safety)"}
        L = likelihood(f[k]["value"] for k in ("L1", "L2", "L3", "L4", "L5"))  # noqa: N806
        I = impact(f["I1"]["value"], f["I2"]["value"], f["I3"]["value"])     # noqa: N806, E741
        updates.append((L, I, band(L, I), score(L, I), json.dumps(f), inc["id"]))
    conn.execute("BEGIN")
    conn.executemany("UPDATE incidents SET likelihood = ?, impact = ?, band = ?, score = ?, factors_json = ? "
                     "WHERE id = ?", updates)
    conn.execute("COMMIT")
    return len(updates)


def analysis_end(conn: sqlite3.Connection, analysis_id: int) -> datetime:
    """Age reference (A5.4): the last alert for an offline analysis, now for a live one."""
    row = conn.execute("SELECT a.mode, (SELECT MAX(ts) FROM alerts WHERE analysis_id = a.id) AS last "
                       "FROM analyses a WHERE a.id = ?", (analysis_id,)).fetchone()
    if row is None or row["mode"] == "live" or not row["last"]:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(row["last"])


def _scored_incidents(conn: sqlite3.Connection, analysis_id: int) -> list[tuple[sqlite3.Row, float]]:
    """Non-Note incidents with their decayed probability pᵢ (A5.4)."""
    half_life = float(get_setting(conn, "half_life_days"))
    end = analysis_end(conn, analysis_id)
    return [(inc, incident_probability(inc["score"], (end - datetime.fromisoformat(inc["last_seen"])).total_seconds(),
                                       half_life))
            for inc in conn.execute("SELECT * FROM incidents WHERE analysis_id = ? AND band IS NOT NULL "
                                    "AND band != 'Note'", (analysis_id,))]


def _asset_weight(inc: sqlite3.Row) -> float:
    """wᵢ = I1/9 of the incident (Unknown when it was not scored)."""
    factors = json.loads(inc["factors_json"] or "{}")
    return (factors.get("I1", {}).get("value") or DEVICE_TYPE["unknown"]) / 9


def roll_up(conn: sqlite3.Connection, analysis_id: int) -> None:
    """Store each device's risk P(d) (0–1): the rank-damped union of pᵢ over the non-Note incidents involving it."""
    devices = _devices(conn, analysis_id)
    ps: dict[str, list[float]] = defaultdict(list)
    for inc, p in _scored_incidents(conn, analysis_id):
        for ip in set(json.loads(inc["src_ips_json"])) | set(json.loads(inc["dest_ips_json"])):
            if ip in devices:
                ps[ip].append(p)
    conn.execute("BEGIN")
    conn.executemany("UPDATE devices SET risk = ? WHERE id = ?",
                     [(damped_union(ps.get(ip, [])), d["id"]) for ip, d in devices.items()])
    conn.execute("COMMIT")


def device_bands(conn: sqlite3.Connection, analysis_id: int) -> dict[str, str]:
    """Device colour (A5.4): the worst band among the non-Note incidents involving each IP; absent if none."""
    out: dict[str, str] = {}
    for inc in conn.execute("SELECT band, src_ips_json, dest_ips_json FROM incidents WHERE analysis_id = ? "
                            "AND band IS NOT NULL AND band != 'Note'", (analysis_id,)):
        for ip in set(json.loads(inc["src_ips_json"])) | set(json.loads(inc["dest_ips_json"])):
            if ip not in out or BANDS.index(inc["band"]) < BANDS.index(out[ip]):
                out[ip] = inc["band"]
    return out


def network_health(conn: sqlite3.Connection, analysis_id: int) -> dict:
    """Home gauge (A5.4): P(N) and health over every non-Note incident, plus what explains the number.

    `top_incidents` are the 3 incidents that cost the most health `points`. The drop (100 − health) is shared out
    in proportion to −ln(1 − x_(k)/k^1.5), the log-additive split of the product, so the points add up to the drop.
    `top_devices` are the 3 devices with the largest w_d·P(d).
    """
    scored = sorted(((inc, _asset_weight(inc) * p) for inc, p in _scored_incidents(conn, analysis_id)),
                    key=lambda t: -t[1])
    xs = [x for _, x in scored]
    p_n, value = health(xs)
    logs = [-math.log(1 - x / k ** DAMPING_P) if x / k ** DAMPING_P < 1 else math.inf for k, x in enumerate(xs, 1)]
    total = sum(logs) or 1.0
    costs = [{"id": inc["id"], "title": inc["title"], "band": inc["band"], "x": x,
              "points": round((100 - value) * (lg / total if math.isfinite(total) else float(math.isinf(lg))))}
             for (inc, x), lg in zip(scored, logs)]
    rows = conn.execute("SELECT ip, hostname, type, criticality, risk FROM devices WHERE analysis_id = ?",
                        (analysis_id,)).fetchall()
    devices = sorted(({"ip": r["ip"], "hostname": r["hostname"], "type": r["type"], "risk": r["risk"],
                       "weight": r["criticality"] / 9, "contribution": r["criticality"] / 9 * r["risk"]}
                      for r in rows), key=lambda d: -d["contribution"])
    return {"p_network": p_n, "health": value, "n_scored": len(xs), "top_incidents": costs[:3],
            "top_devices": [d for d in devices[:3] if d["contribution"] > 0], "xs": sorted(xs, reverse=True)}
