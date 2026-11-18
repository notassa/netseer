"""MAC address → vendor, and MACs from Linux cooked captures.

Vendors come from Wireshark's `manuf` list (24/28/36-bit blocks, updated from Settings) when it has been downloaded,
else from the offline IEEE OUI list (ieee-data package). Linux cooked (SLL) captures carry no Ethernet header, so
Suricata reports no MACs; `sll_macs` reads the sender MAC that SLL keeps per packet.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import struct
import subprocess
from collections import Counter, defaultdict
from email.utils import parsedate_to_datetime
from functools import lru_cache
from pathlib import Path

import httpx

from netseer.src.config import DATABASE_DIR, app_config, get_setting
from netseer.src.database import db

PRIVATE_MAC = "Private (randomised) MAC"
MANUF_PATH = DATABASE_DIR / "manuf"
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
MACLOOKUP_URL = "https://api.maclookup.app/v2/macs/{}"   # A3: online vendor fallback (OUI only)
MACLOOKUP_MAX = 100                     # at most this many HTTP lookups per run
MACLOOKUP_TIMEOUT_S = 5
MANUF_MIN_ROWS = 10_000                 # a real list has ~50k; fewer means a broken download
SLL_LINKTYPES = {113, 276}              # Linux cooked v1, v2
SLL_MAX_PACKETS = 2_000_000
ROUTER_MAC_MIN_IPS = 3                 # one sender MAC for this many source IPs = a router's, not theirs
_SLL_LINE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5}) ethertype IPv4\b.*?: (\d{1,3}(?:\.\d{1,3}){3})(?:\.\d+)? > ")


@lru_cache(maxsize=2)
def _manuf(path: str) -> dict[int, dict[str, str]]:
    """Wireshark manuf: {bits: {hex prefix: vendor}} for 24, 28 and 36-bit blocks; {} if absent."""
    table: dict[int, dict[str, str]] = defaultdict(dict)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                cols = [c.strip() for c in line.rstrip("\n").split("\t")]
                block, _, bits = cols[0].partition("/")
                n = int(bits or 24)
                table[n][block.replace(":", "").upper()[: n // 4]] = (cols[2] if len(cols) > 2 and cols[2] else cols[1])
    except (OSError, ValueError, IndexError):
        return {}
    return dict(table)


@lru_cache(maxsize=4)
def _load(path: str) -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                if row.get("Registry") == "MA-L" and len(row.get("Assignment", "")) == 6:
                    table[row["Assignment"].upper()] = row["Organization Name"].strip()
    except OSError:
        return {}
    return table


def vendor_for(mac: str | None, oui_csv: str | Path) -> str | None:
    """Vendor name for a MAC, the private-MAC label for locally administered addresses, or None if unknown."""
    if not mac:
        return None
    hexdigits = mac.replace(":", "").replace("-", "").upper()
    if len(hexdigits) != 12:
        return None
    first = int(hexdigits[:2], 16)
    if first & 0x02:            # locally administered bit: phones and laptops randomise their MAC
        return PRIVATE_MAC
    manuf = _manuf(str(MANUF_PATH))
    for bits in (36, 28, 24):
        if (name := manuf.get(bits, {}).get(hexdigits[: bits // 4])):
            return name
    return _load(str(oui_csv)).get(hexdigits[:6])


def online_vendors(conn: sqlite3.Connection, analysis_id: int, get=httpx.get) -> int:
    """Fill `devices.vendor` for devices the local lists could not name, asking maclookup.app per OUI.

    Only the first six hex digits (the OUI) are sent, at most MACLOOKUP_MAX per run and once per OUI; answers
    (including "not found") are cached in `ti_cache` until Detonate. Returns the number of devices updated.
    """
    if not get_setting(conn, "mac_lookup_online"):
        return 0
    updated = 0
    asked: set[str] = set()
    for row in conn.execute(
            "SELECT id, mac FROM devices WHERE analysis_id = ? AND vendor IS NULL AND mac IS NOT NULL AND mac != ''",
            (analysis_id,)).fetchall():              # read all first: the loop writes to the same DB
        mac = row["mac"]
        hexdigits = mac.replace(":", "").replace("-", "").upper()
        if len(hexdigits) != 12 or not is_unicast(mac):
            continue
        if int(hexdigits[:2], 16) & 0x02:       # locally administered bit: randomised MACs are never sent
            continue
        oui = hexdigits[:6]
        indicator = f"maclookup:{oui}"
        cached = conn.execute("SELECT result_json FROM ti_cache WHERE indicator = ?", (indicator,)).fetchone()
        if cached:
            result = json.loads(cached["result_json"])
            found, company = result["found"], result["company"]
        else:
            if len(asked) >= MACLOOKUP_MAX:
                break
            asked.add(oui)
            try:
                r = get(MACLOOKUP_URL.format(oui), headers={"Accept": "application/json"}, timeout=MACLOOKUP_TIMEOUT_S)
                if r.status_code != 200:
                    break
                data = r.json()
                if not data["success"]:
                    break
                found, company = bool(data["found"]), str(data["company"])
            except (httpx.HTTPError, ValueError, KeyError):
                break
            conn.execute("INSERT OR REPLACE INTO ti_cache(indicator, source, result_json, fetched_at) VALUES (?, ?, ?, ?)",
                         (indicator, "maclookup", json.dumps({"found": found, "company": company}), db.utcnow()))
        if found and company:
            conn.execute("UPDATE devices SET vendor = ? WHERE id = ?", (company, row["id"]))
            updated += 1
    return updated


def manuf_info() -> dict:
    """Wireshark list status for Settings: entries, the list's own date (file mtime) and its generator line."""
    if not MANUF_PATH.exists():
        return {"entries": 0, "dated": None, "generator": None}
    with open(MANUF_PATH, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
    gen = re.search(r"generated by (.+?) with", first)
    return {"entries": sum(len(t) for t in _manuf(str(MANUF_PATH)).values()),
            "dated": MANUF_PATH.stat().st_mtime, "generator": gen.group(1) if gen else None}


def update_manuf(url: str = MANUF_URL) -> int:
    """Download the latest Wireshark manuf list (kept only if it parses); returns its entry count."""
    r = httpx.get(url, timeout=60, follow_redirects=True)
    r.raise_for_status()
    tmp = MANUF_PATH.with_suffix(".tmp")
    tmp.write_bytes(r.content)
    _manuf.cache_clear()
    n = sum(len(t) for t in _manuf(str(tmp)).values())
    if n < MANUF_MIN_ROWS:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"the download has only {n} entries")
    if r.headers.get("last-modified"):
        stamp = parsedate_to_datetime(r.headers["last-modified"]).timestamp()
        os.utime(tmp, (stamp, stamp))
    tmp.replace(MANUF_PATH)
    _manuf.cache_clear()
    return n


def parse_sll_line(line: str) -> tuple[str, str] | None:
    """(source IP, sender MAC) from one `tcpdump -e -nn` line of a Linux cooked capture."""
    m = _SLL_LINE.search(line)
    return (m.group(2), m.group(1)) if m else None


def sll_macs(capture: Path) -> dict[str, str]:
    """Most common sender MAC per source IP of a classic-pcap Linux cooked capture; {} for any other capture.
    IPs whose MAC is shared with ROUTER_MAC_MIN_IPS or more others' are left out (unknown, never guessed).

    shortcut: reads the first SLL_MAX_PACKETS packets only, raise it if hosts first appear late in long captures.
    """
    with open(capture, "rb") as fh:
        head = fh.read(24)
    if len(head) < 24 or head[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return {}               # pcapng (or not a pcap): Suricata already reads Ethernet MACs where they exist
    endian = "<" if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if struct.unpack(f"{endian}I", head[20:24])[0] not in SLL_LINKTYPES:
        return {}
    seen: dict[str, Counter] = defaultdict(Counter)
    proc = subprocess.Popen([str(app_config("tcpdump_bin")), "-e", "-nn", "-r", str(capture), "-c", str(SLL_MAX_PACKETS),
                             "ip"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        if (hit := parse_sll_line(line)) and is_unicast(hit[1]):
            seen[hit[0]][hit[1]] += 1
    proc.wait()
    best = {ip: c.most_common(1)[0][0] for ip, c in seen.items()}
    shared = Counter(best.values())
    # Behind a router every routed packet carries the router's MAC: such a MAC is not the host's own.
    return {ip: mac for ip, mac in best.items() if shared[mac] < ROUTER_MAC_MIN_IPS}


def is_unicast(mac: str | None) -> bool:
    """True for a usable unicast MAC (not broadcast, multicast or all-zero)."""
    if not mac or len(mac) != 17:
        return False
    first = int(mac[:2], 16)
    return not (first & 0x01) and mac != "00:00:00:00:00:00"
