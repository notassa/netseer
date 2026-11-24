"""Optional threat intelligence (CONCEPTS A5 L5, A9): AbuseIPDB and VirusTotal reputation of external IPs.

Off unless the administrator saves a key. Only public external IPs are looked up, once each; results stay in
`ti_cache` (indicator `<source>:<ip>`) until Detonate, and scoring reads the cache only, so ACP never waits on the
network.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import time

import httpx

from netseer.src.database import db
from netseer.src.engine.constants import VT_MALICIOUS_FULL
from netseer.src.keystore import get_key

SOURCES = ("abuseipdb", "virustotal")
MAX_IPS = 20                   # per enrichment run, busiest incidents first
VT_GAP_S = 15                  # VirusTotal free tier: 4 lookups a minute
TIMEOUT_S = 20


def enabled(conn: sqlite3.Connection) -> bool:
    """True when at least one TI key is set."""
    return any(get_key(conn, s) for s in SOURCES)


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def fetch(source: str, ip: str, key: str) -> dict:
    """One lookup: {"score": 0–1} (AbuseIPDB confidence / 100, or VirusTotal malicious engines / 5) plus detail.

    VirusTotal with no engine results gives score None (unknown, never safe).
    """
    if source == "abuseipdb":
        r = httpx.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": key, "Accept": "application/json"}, timeout=TIMEOUT_S)
        r.raise_for_status()
        data = r.json()["data"]
        return {"score": data["abuseConfidenceScore"] / 100, "reports": data.get("totalReports"),
                "country": data.get("countryCode")}
    r = httpx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": key}, timeout=TIMEOUT_S)
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    total = sum(stats.values())
    return {"score": min(1.0, stats.get("malicious", 0) / VT_MALICIOUS_FULL) if total else None,
            "malicious": stats.get("malicious", 0),
            "engines": total}


def cached(conn: sqlite3.Connection, ips: list[str]) -> dict[str, dict[str, dict]]:
    """Cached results per IP: {ip: {source: result}} (any age; freshness only matters for refetching)."""
    out: dict[str, dict[str, dict]] = {}
    for ip in ips:
        for r in conn.execute("SELECT source, result_json FROM ti_cache WHERE indicator IN (?, ?)",
                              (f"abuseipdb:{ip}", f"virustotal:{ip}")):
            out.setdefault(ip, {})[r["source"]] = json.loads(r["result_json"])
    return out


def l5(results: dict[str, dict[str, dict]]) -> tuple[float, str, str] | None:
    """L5 = max(AbuseIPDB/100, VT malicious/5) × 9 over the incident's IPs, with the IP and source; None if unknown."""
    best = max(((res["score"], ip, src) for ip, by in results.items() for src, res in by.items()
                if res.get("score") is not None), default=None)
    return (best[0] * 9, best[1], best[2]) if best else None


def enrich(conn: sqlite3.Connection, analysis_id: int, sleep=time.sleep) -> int:
    """Look up the external IPs of the analysis's top incidents that are not cached; returns lookups."""
    keys = {s: get_key(conn, s) for s in SOURCES}
    if not any(keys.values()):
        return 0
    ips: list[str] = []
    for r in conn.execute("SELECT src_ips_json, dest_ips_json FROM incidents WHERE analysis_id = ? ORDER BY score DESC, id",
                          (analysis_id,)):
        for ip in json.loads(r["src_ips_json"]) + json.loads(r["dest_ips_json"]):
            if ip not in ips and _public(ip) and not conn.execute(
                    "SELECT 1 FROM devices WHERE analysis_id = ? AND ip = ?", (analysis_id, ip)).fetchone():
                ips.append(ip)
    # Only IPs that still need a lookup count toward the cap, so a rerun reaches the next uncached IP.
    ips = [ip for ip in ips if any(keys[s] and not conn.execute(
        "SELECT 1 FROM ti_cache WHERE indicator = ?", (f"{s}:{ip}",)).fetchone() for s in SOURCES)]
    n = 0
    vt_called = False
    for ip in ips[:MAX_IPS]:
        for source, key in keys.items():
            if not key or conn.execute("SELECT 1 FROM ti_cache WHERE indicator = ?",
                                       (f"{source}:{ip}",)).fetchone():
                continue            # results are kept until Detonate: each IP is looked up once
            if source == "virustotal":
                if vt_called:
                    sleep(VT_GAP_S)
                vt_called = True
            try:
                result = fetch(source, ip, key)
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                db.audit(conn, None, "ti_failed", f"{source} {ip}: {exc}"[:500])
                continue
            conn.execute("INSERT OR REPLACE INTO ti_cache(indicator, source, result_json, fetched_at) VALUES (?, ?, ?, ?)",
                         (f"{source}:{ip}", source, json.dumps(result), db.utcnow()))
            n += 1
    return n
