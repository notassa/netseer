"""Paths and configuration: defaults from config/netseer.toml, overridden by the `settings` table."""

from __future__ import annotations

import json
import sqlite3
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

PKG_ROOT = Path(__file__).resolve().parent.parent          # netseer/
CONFIG_DIR = PKG_ROOT / "config"
DATABASE_DIR = PKG_ROOT / "src" / "database"
WEB_DIR = PKG_ROOT / "web"
SURICATA_CONFIG = CONFIG_DIR / "suricata" / "netseer.yaml"
PASSWORD_BLOCKLIST = CONFIG_DIR / "common-passwords.txt"
DEFAULT_DB_PATH = DATABASE_DIR / "netseer.db"


@lru_cache(maxsize=1)
def _toml() -> dict[str, dict[str, Any]]:
    with open(CONFIG_DIR / "netseer.toml", "rb") as fh:
        return tomllib.load(fh)


def app_config(key: str) -> Any:
    """Return a static application value from the `[app]` table of netseer.toml."""
    return _toml()["app"][key]


def setting_defaults() -> dict[str, Any]:
    """Return the user-adjustable defaults from the `[settings]` table of netseer.toml."""
    return dict(_toml()["settings"])


def get_setting(conn: sqlite3.Connection, key: str) -> Any:
    """Return a setting: the stored override if present, otherwise the netseer.toml default."""
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return json.loads(row[0])
    return setting_defaults()[key]


def analysis_lan(conn: sqlite3.Connection, analysis_id: int) -> list[str]:
    """LAN CIDRs of one analysis: those adopted for it (CONCEPTS A17), else the global `lan_cidrs` setting."""
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (f"lan_cidrs:{analysis_id}",)).fetchone()
    return json.loads(row[0]) if row is not None else get_setting(conn, "lan_cidrs")


def adopt_lan(conn: sqlite3.Connection, analysis_id: int, cidrs: list[str]) -> None:
    """Store the LAN CIDRs adopted for one analysis (key `lan_cidrs:<id>`)."""
    conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (f"lan_cidrs:{analysis_id}", json.dumps(cidrs)))


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    """Store a setting override (JSON-encoded)."""
    if key not in setting_defaults():
        raise KeyError(key)
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(value)),
    )
