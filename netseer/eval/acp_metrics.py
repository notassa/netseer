"""ACP metrics for the report (Table 4.13) and the union saturation check (CONCEPTS A5.4).

Usage:
  python -m netseer.eval.acp_metrics <analysis_id> [--db path] [--rerun]
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from netseer.src.config import DEFAULT_DB_PATH
from netseer.src.database import db
from netseer.src.engine.acp import run_acp
from netseer.src.engine.constants import BANDS
from netseer.src.engine.scorer import health, network_health


def metrics(conn: sqlite3.Connection, analysis_id: int) -> dict:
    """Counts, reduction percentages, band histogram and health for one analysis."""
    one = lambda sql: conn.execute(sql, (analysis_id,)).fetchone()[0]  # noqa: E731
    n_alerts = one("SELECT COUNT(*) FROM alerts WHERE analysis_id = ?")
    n_groups = one("SELECT COUNT(*) FROM alert_groups WHERE analysis_id = ?")
    n_incidents = one("SELECT COUNT(*) FROM incidents WHERE analysis_id = ?")
    bands = dict(conn.execute("SELECT band, COUNT(*) FROM incidents WHERE analysis_id = ? GROUP BY band", (analysis_id,)))
    return {
        "alerts": n_alerts, "groups": n_groups, "incidents": n_incidents,
        "group_reduction_pct": 100 * (1 - n_groups / n_alerts) if n_alerts else 0.0,
        "incident_reduction_pct": 100 * (1 - n_incidents / n_alerts) if n_alerts else 0.0,
        "bands": {b: bands.get(b, 0) for b in BANDS},
        "health": network_health(conn, analysis_id)["health"],
    }


def saturation(conn: sqlite3.Connection, analysis_id: int) -> list[tuple[int, int]]:
    """Health as network terms are added worst first: shows how the rank-damped union levels off."""
    xs = network_health(conn, analysis_id)["xs"]
    return [(k, health(xs[:k])[1]) for k in range(1, len(xs) + 1)]


def main(argv: list[str] | None = None) -> int:
    """Print the metrics (optionally re-running ACP 3–6 first to time it)."""
    parser = argparse.ArgumentParser(prog="acp_metrics")
    parser.add_argument("analysis_id", type=int)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--rerun", action="store_true", help="re-run ACP 3–6 and report its time")
    args = parser.parse_args(argv)
    conn = db.connect(args.db)
    try:
        if args.rerun:
            print(f"ACP 3–6 time: {run_acp(conn, args.analysis_id)['seconds']:.2f} s")
        m = metrics(conn, args.analysis_id)
        print(f"Raw alerts: {m['alerts']}")
        print(f"Alert groups: {m['groups']} ({m['group_reduction_pct']:.1f}% fewer than alerts)")
        print(f"Possible incidents: {m['incidents']} ({m['incident_reduction_pct']:.1f}% fewer than alerts)")
        print("Bands: " + ", ".join(f"{b} {n}" for b, n in m["bands"].items()))
        print(f"Network health: {m['health']}")
        curve = saturation(conn, args.analysis_id)
        if curve:
            print("Saturation (scored incidents added worst first → health): "
                  + ", ".join(f"{k}→{h}" for k, h in curve))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
