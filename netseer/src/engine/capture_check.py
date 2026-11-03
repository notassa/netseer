"""Capture checks (CONCEPTS A16): gaps, overlaps, duplicates, format mixes and capture loss, shown as Info.

Every finding is one `analysis_info` row (kind 'capture'). The first row always summarises the files, so an
analysis that has been checked has at least one row.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netseer.src.config import app_config
from netseer.src.database import db

FILE_GAP_S = 60                  # silence between two files that counts as a gap
OVERLAP_S = 1                    # files overlapping by more than this interleave in the merge
SILENT_MIN = 5                   # consecutive minutes with no active flow inside the capture
STATS_TAIL_BYTES = 4 << 20       # Suricata's final stats event is near the end of eve.json


@dataclass
class FileFacts:
    """What capinfos reports for one capture file."""

    name: str
    sha256: str
    encapsulation: str | None = None
    snaplen: int | None = None
    packets: int | None = None
    start: float | None = None           # epoch seconds
    end: float | None = None
    time_order: bool | None = None
    problem: str | None = None


def _num(value: str | None, kind=float):
    try:
        return kind(value)
    except (TypeError, ValueError):
        return None


def parse_capinfos(text: str) -> dict[str, str]:
    """First data row of `capinfos -T -m … -S` output, keyed by its header."""
    rows = list(csv.DictReader(io.StringIO(text)))
    return rows[0] if rows else {}


def file_facts(path: Path, sha256: str) -> FileFacts:
    """Run capinfos on one capture (a truncated file still reports what it could read)."""
    facts = FileFacts(path.name, sha256)
    try:
        proc = subprocess.run([str(app_config("capinfos_bin")), "-T", "-m", "-a", "-e", "-c", "-l", "-E", "-o", "-S",
                               str(path)], capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        facts.problem = f"capinfos failed: {exc}"
        return facts
    row = parse_capinfos(proc.stdout)
    if proc.returncode != 0:
        facts.problem = (proc.stderr.strip().splitlines() or ["capinfos failed"])[-1]
    facts.encapsulation = row.get("File encapsulation") or None
    facts.snaplen = _num(row.get("Packet size limit"), int)
    facts.packets = _num(row.get("Number of packets"), int)
    facts.start = _num(row.get("Start time"))
    facts.end = _num(row.get("End time"))
    order = row.get("Strict time order")
    facts.time_order = None if order not in ("True", "False") else order == "True"
    return facts


def _when(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _duration(seconds: float) -> str:
    seconds = int(round(seconds))
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return " ".join(p for p in (f"{h} h" if h else "", f"{m} min" if m else "", f"{s} s" if s or not (h or m) else "") if p)


def file_findings(files: list[FileFacts]) -> list[tuple[str, str, dict]]:
    """(level, title, detail) for the files themselves and between them."""
    out: list[tuple[str, str, dict]] = []
    timed = [f for f in files if f.start is not None and f.end is not None]
    total = sum(f.packets or 0 for f in files)
    span = (f" · {_when(min(f.start for f in timed))} to {_when(max(f.end for f in timed))} UTC" if timed else "")
    out.append(("info", f"{len(files)} file{'s' if len(files) != 1 else ''}, {total:,} packets{span}",
                {"files": [f.__dict__ for f in files]}))
    for f in files:
        if f.problem:
            out.append(("warning", f"{f.name}: {f.problem}", {"file": f.name}))
        if f.time_order is False:
            out.append(("info", f"{f.name}: packets are not in time order (Suricata reads them in file order)",
                        {"file": f.name}))
    timed.sort(key=lambda f: f.start)
    for a, b in zip(timed, timed[1:]):
        gap = b.start - a.end
        if gap > FILE_GAP_S:
            out.append(("warning", f"No packets for {_duration(gap)} between {a.name} (ends {_when(a.end)}) and "
                                   f"{b.name} (starts {_when(b.start)}). A capture file may be missing.",
                        {"from": a.name, "to": b.name, "start": a.end, "end": b.start, "seconds": gap}))
        elif -gap > OVERLAP_S:
            out.append(("warning", f"{a.name} and {b.name} overlap for {_duration(-gap)}: their packets interleave "
                                   "in the merge (a duplicate capture or a second capture point)",
                        {"files": [a.name, b.name], "seconds": -gap}))
    seen: dict[str, str] = {}
    for f in files:
        if f.sha256 in seen:
            out.append(("warning", f"{f.name} is the same file as {seen[f.sha256]} (identical SHA-256): its packets "
                                   "are counted twice", {"files": [seen[f.sha256], f.name]}))
        seen.setdefault(f.sha256, f.name)
    encaps = {f.encapsulation for f in files if f.encapsulation}
    if len(encaps) > 1:
        out.append(("info", f"Files use different link types ({', '.join(sorted(encaps))}); they were merged as "
                            "classic pcap", {"link_types": sorted(encaps)}))
    snaps = {f.snaplen for f in files if f.snaplen}
    if len(snaps) > 1:
        out.append(("info", f"Files use different snapshot lengths ({', '.join(map(str, sorted(snaps)))} bytes); "
                            "packets from the smaller one may be cut short", {"snaplens": sorted(snaps)}))
    return out


def silent_stretches(conn: sqlite3.Connection, analysis_id: int,
                     skip: list[tuple[float, float]] = ()) -> list[tuple[str, str, dict]]:
    """Runs of ≥ SILENT_MIN minutes inside the capture with no active flow (none spans them, so no IP packets).

    Stretches inside an already reported gap between files (`skip`, epoch ranges) are left out.
    """
    minutes = sorted(datetime.fromisoformat(r[0]).replace(tzinfo=timezone.utc) for r in conn.execute(
        "SELECT minute FROM packet_stats WHERE analysis_id = ? AND packets > 0", (analysis_id,)))
    out = []
    for a, b in zip(minutes, minutes[1:]):
        empty = (b - a).total_seconds() / 60 - 1
        if empty < SILENT_MIN:
            continue
        start, end = a + timedelta(minutes=1), b
        if any(lo - 60 <= start.timestamp() and end.timestamp() <= hi + 60 for lo, hi in skip):
            continue
        out.append(("info", f"No traffic for {int(empty)} min ({start:%Y-%m-%d %H:%M} to {end:%H:%M} UTC) inside "
                            "the capture: the network was quiet or the capture paused",
                    {"start": start.isoformat(), "end": end.isoformat(), "minutes": int(empty)}))
    return out


def last_stats(eve: Path) -> dict | None:
    """Suricata's final `stats` event (its counters cover the whole run)."""
    try:
        with open(eve, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - STATS_TAIL_BYTES))
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    for line in reversed(tail.splitlines()):
        if '"stats"' not in line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "stats":
            return event.get("stats")
    return None


def loss_findings(stats: dict | None) -> list[tuple[str, str, dict]]:
    """Capture-loss signs from Suricata's counters."""
    if not stats:
        return []
    out = []
    tcp, decoder, capture = stats.get("tcp") or {}, stats.get("decoder") or {}, stats.get("capture") or {}
    gaps, sessions = tcp.get("reassembly_gap") or 0, tcp.get("sessions") or tcp.get("syn") or 0
    if gaps:
        per = f" across {sessions:,} TCP sessions" if sessions else ""
        out.append(("warning", f"{gaps:,} TCP reassembly gaps{per}: TCP segments are missing from the capture "
                               "(packet loss, a busy mirror port or only one direction mirrored)",
                    {"reassembly_gap": gaps, "tcp_sessions": sessions}))
    drops = capture.get("kernel_drops") or 0
    if drops:
        out.append(("warning", f"{drops:,} packets dropped by the capture interface", {"kernel_drops": drops}))
    invalid = decoder.get("invalid") or 0
    if invalid:
        out.append(("info", f"{invalid:,} of {decoder.get('pkts', 0):,} packets could not be decoded "
                            "(malformed or truncated)", {"invalid": invalid, "packets": decoder.get("pkts")}))
    return out


def run_checks(conn: sqlite3.Connection, analysis_id: int, pcap_dir: Path, eve: Path,
               truncated: str | None = None) -> int:
    """Replace the analysis's capture findings; returns how many were stored."""
    files = [file_facts(pcap_dir / r["filename"], r["sha256"]) for r in conn.execute(
        "SELECT filename, sha256 FROM analysis_files WHERE analysis_id = ? ORDER BY rowid", (analysis_id,))]
    findings = file_findings(files)
    gaps = [(d["start"], d["end"]) for _, _, d in findings if "seconds" in d and "from" in d]
    findings += silent_stretches(conn, analysis_id, gaps)
    findings += loss_findings(last_stats(eve))
    if truncated:
        findings.append(("warning", truncated, {}))
    now = db.utcnow()
    conn.execute("BEGIN")
    conn.execute("DELETE FROM analysis_info WHERE analysis_id = ? AND kind = 'capture'", (analysis_id,))
    conn.executemany("INSERT INTO analysis_info(analysis_id, kind, level, title, detail_json, created_at) "
                     "VALUES (?, 'capture', ?, ?, ?, ?)",
                     [(analysis_id, level, title, json.dumps(detail), now) for level, title, detail in findings])
    conn.execute("COMMIT")
    return len(findings)
