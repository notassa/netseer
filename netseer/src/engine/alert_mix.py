"""Alert mix (CONCEPTS A5.5, after Munir Ch.5): shares of alerts by classtype and priority.

Descriptive only: shown as "Share of alerts (not risk)" and never used for scoring.
"""

from __future__ import annotations

import sqlite3


def _shares(conn: sqlite3.Connection, column: str, analysis_id: int) -> list[dict]:
    rows = conn.execute(
        f"SELECT {column} AS key, COUNT(*) AS n FROM alerts WHERE analysis_id = ? GROUP BY {column} ORDER BY n DESC",
        (analysis_id,),
    ).fetchall()
    total = sum(r["n"] for r in rows) or 1
    return [{"key": r["key"], "count": r["n"], "share": r["n"] / total} for r in rows]


def alert_mix(conn: sqlite3.Connection, analysis_id: int) -> dict[str, list[dict]]:
    """Return {"classtype": [...], "priority": [...]}, each item {key, count, share}; key None = unknown."""
    return {"classtype": _shares(conn, "classtype", analysis_id), "priority": _shares(conn, "priority", analysis_id)}
