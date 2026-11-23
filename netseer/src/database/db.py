"""SQLite access: connections in WAL mode and schema initialisation."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def utcnow() -> str:
    """Current UTC time as an ISO-8601 string with seconds precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with WAL, foreign keys and dict-like rows."""
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(db_path: str | Path) -> None:
    """Create the database file and all tables if they do not exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        _migrate(conn)
        conn.executescript(SCHEMA_PATH.read_text())
    finally:
        conn.close()


ADDED_COLUMNS = [("audit_log", "ip"), ("audit_log", "mac"), ("sessions", "expires_at"), ("analyses", "note")]
PACKET_STATS_COLUMNS = ("ii_packets", "ii_bytes", "ie_packets", "ie_bytes", "ei_packets", "ei_bytes")


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases from earlier builds up to the current schema (before its index script runs)."""
    for table, col in ADDED_COLUMNS:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if cols and col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
    if "hour" in {r[1] for r in conn.execute("PRAGMA table_info(packet_stats)")}:
        conn.execute("ALTER TABLE packet_stats RENAME COLUMN hour TO minute")   # 'HH:00' values stay valid
    cols = {r[1] for r in conn.execute("PRAGMA table_info(packet_stats)")}
    if cols:                                   # only if the table exists
        for col in PACKET_STATS_COLUMNS:
            if col not in cols:
                conn.execute(f"ALTER TABLE packet_stats ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")


def audit(conn: sqlite3.Connection, user_id: int | None, action: str, detail: str = "",
          ip: str | None = None, mac: str | None = None) -> None:
    """Append an entry to the audit log (CONCEPTS A9); ip/mac identify the client for account events."""
    conn.execute(
        "INSERT INTO audit_log(ts, user_id, action, detail, ip, mac) VALUES (?, ?, ?, ?, ?, ?)",
        (utcnow(), user_id, action, detail, ip, mac),
    )
