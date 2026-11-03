"""ACP 3–6 entry points: rebuild incidents (contextor + scorer) or only re-score them."""

from __future__ import annotations

import sqlite3
import time

from netseer.src.engine.contextor import run_contextor
from netseer.src.engine.scorer import roll_up, score_incidents


def rescore(conn: sqlite3.Connection, analysis_id: int) -> None:
    """Re-score incidents and device risk (after a device type or half-life change)."""
    score_incidents(conn, analysis_id)
    roll_up(conn, analysis_id)


def run_acp(conn: sqlite3.Connection, analysis_id: int) -> dict:
    """Aggregate, correlate, enrich and score one analysis; returns counts and timing for the logs."""
    started = time.monotonic()
    n_groups, n_incidents = run_contextor(conn, analysis_id)
    rescore(conn, analysis_id)
    return {"groups": n_groups, "incidents": n_incidents, "seconds": time.monotonic() - started}


def needs_acp(conn: sqlite3.Connection, analysis_id: int) -> bool:
    """True for an analysis analysed before C2: it has alerts but no alert groups yet."""
    row = conn.execute("SELECT EXISTS(SELECT 1 FROM alerts WHERE analysis_id = ?) AND NOT "
                       "EXISTS(SELECT 1 FROM alert_groups WHERE analysis_id = ?)", (analysis_id, analysis_id)).fetchone()
    return bool(row[0])


def ensure_acp(conn: sqlite3.Connection, analysis: sqlite3.Row | None) -> None:
    """Run ACP 3–6 once for a finished analysis from before C2 (pages call this before reading incidents)."""
    if analysis is not None and analysis["status"] in ("done", "awaiting_attribution") and needs_acp(conn, analysis["id"]):
        run_acp(conn, analysis["id"])
