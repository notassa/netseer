"""API keys (AbuseIPDB, VirusTotal, per-provider cloud LLM), Fernet-encrypted in `api_keys` (CONCEPTS A9).

The Fernet key lives in src/database/netseer.key (mode 600, never committed); the database alone does not reveal keys.
"""

from __future__ import annotations

import os
import sqlite3

from cryptography.fernet import Fernet, InvalidToken

from netseer.src.config import DATABASE_DIR

KEY_NAMES = {"abuseipdb": "AbuseIPDB", "virustotal": "VirusTotal", "openai": "OpenAI", "claude": "Claude",
             "deepseek": "DeepSeek"}
KEY_FILE = DATABASE_DIR / "netseer.key"


def _fernet() -> Fernet:
    key_file = KEY_FILE
    if not key_file.exists():
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(Fernet.generate_key())
    return Fernet(key_file.read_bytes())


def set_key(conn: sqlite3.Connection, name: str, value: str) -> None:
    """Store (or, with an empty value, remove) one API key."""
    if name not in KEY_NAMES:
        raise KeyError(name)
    if not value:
        conn.execute("DELETE FROM api_keys WHERE name = ?", (name,))
        return
    conn.execute("INSERT OR REPLACE INTO api_keys(name, ciphertext) VALUES (?, ?)",
                 (name, _fernet().encrypt(value.encode()).decode()))


def get_key(conn: sqlite3.Connection, name: str) -> str | None:
    """The decrypted key, or None if unset (or unreadable after the key file was replaced)."""
    row = conn.execute("SELECT ciphertext FROM api_keys WHERE name = ?", (name,)).fetchone()
    if row is None:
        return None
    try:
        return _fernet().decrypt(row[0].encode()).decode()
    except InvalidToken:
        return None


def key_names(conn: sqlite3.Connection) -> set[str]:
    """Names of the keys that are set (values are never shown back)."""
    return {r[0] for r in conn.execute("SELECT name FROM api_keys")}
