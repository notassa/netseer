"""Validate an analysis of UNSW-NB15 pcaps against the dataset's ground truth (UNSW-NB15_GT.csv).

Analyse the pcaps first (upload, or `python -m netseer.cli run-offline …`), with the LAN CIDRs set to the
UNSW victim networks (149.171.126.0/24 and 175.45.176.0/24 are both used in the dataset). Then:

  python -m netseer.eval.unsw_validate <analysis_id> --gt UNSW-NB15_GT.csv [--tolerance 60] [--db path]

A ground-truth attack counts as covered when an alert group of some incident joins the same two hosts (either
direction) during the attack's time span ± tolerance. Reported: coverage per attack category, and how many
incidents per band match a labelled attack (does the band ordering follow the labels?).
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from netseer.src.config import DEFAULT_DB_PATH
from netseer.src.database import db
from netseer.src.engine.constants import BANDS


def load_gt(path: Path) -> list[dict]:
    """Ground-truth rows: start/end (epoch s), category and the unordered host pair."""
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for r in csv.DictReader(fh):
            try:
                start, end = int(r["Start time"]), int(r["Last time"])
            except (KeyError, ValueError):
                continue
            rows.append({"start": start, "end": max(start, end), "category": (r.get("Attack category") or "").strip(),
                         "pair": frozenset((r.get("Source IP", "").strip(), r.get("Destination IP", "").strip()))})
    return rows


def validate(conn: sqlite3.Connection, analysis_id: int, gt: list[dict], tolerance: float) -> dict:
    """Match incidents' alert groups to ground-truth attacks."""
    by_pair: dict[frozenset, list[int]] = defaultdict(list)
    for i, row in enumerate(gt):
        by_pair[row["pair"]].append(i)
    covered: set[int] = set()
    matched_incidents: set[int] = set()
    groups = conn.execute(
        "SELECT ig.incident_id, g.src_ip, g.dest_ip, g.first_seen, g.last_seen FROM incident_groups ig "
        "JOIN alert_groups g ON g.id = ig.group_id WHERE g.analysis_id = ?", (analysis_id,))
    for g in groups:
        t0 = datetime.fromisoformat(g["first_seen"]).timestamp() - tolerance
        t1 = datetime.fromisoformat(g["last_seen"]).timestamp() + tolerance
        for i in by_pair.get(frozenset((g["src_ip"], g["dest_ip"])), []):
            if gt[i]["start"] <= t1 and gt[i]["end"] >= t0:
                covered.add(i)
                matched_incidents.add(g["incident_id"])
    # Only ground truth inside the analysed time range can be found.
    lo, hi = conn.execute("SELECT MIN(ts), MAX(ts) FROM alerts WHERE analysis_id = ?", (analysis_id,)).fetchone()
    in_range = [i for i, r in enumerate(gt) if lo and r["end"] >= datetime.fromisoformat(lo).timestamp() - tolerance
                and r["start"] <= datetime.fromisoformat(hi).timestamp() + tolerance]
    total, hit = Counter(gt[i]["category"] for i in in_range), Counter(gt[i]["category"] for i in covered)
    bands: dict[str, list[int]] = {b: [0, 0] for b in BANDS}
    for r in conn.execute("SELECT id, band FROM incidents WHERE analysis_id = ?", (analysis_id,)):
        if r["band"] in bands:
            bands[r["band"]][0 if r["id"] in matched_incidents else 1] += 1
    return {"in_range": len(in_range), "covered": len(covered), "categories": {c: (hit[c], total[c]) for c in total},
            "bands": bands}


def main(argv: list[str] | None = None) -> int:
    """Print coverage per category and labelled incidents per band."""
    parser = argparse.ArgumentParser(prog="unsw_validate")
    parser.add_argument("analysis_id", type=int)
    parser.add_argument("--gt", type=Path, required=True, help="UNSW-NB15_GT.csv")
    parser.add_argument("--tolerance", type=float, default=60, help="seconds of slack on each side of an attack")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    args = parser.parse_args(argv)
    conn = db.connect(args.db)
    try:
        r = validate(conn, args.analysis_id, load_gt(args.gt), args.tolerance)
    finally:
        conn.close()
    pct = 100 * r["covered"] / r["in_range"] if r["in_range"] else 0.0
    print(f"Ground-truth attacks in the analysed time range: {r['in_range']}; covered by an incident: "
          f"{r['covered']} ({pct:.1f}%)")
    for cat, (hit, total) in sorted(r["categories"].items(), key=lambda kv: -kv[1][1]):
        print(f"  {cat or 'unlabelled':<16} {hit:>6} / {total:<6} ({100 * hit / total:.1f}%)")
    print("Incidents per band (matching a labelled attack / not):")
    for band, (yes, no) in r["bands"].items():
        print(f"  {band:<9} {yes:>5} / {no}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
