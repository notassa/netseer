"""browser_env: the throwaway copy strips accounts, sessions, keys and open captures, leaving the source intact."""

from __future__ import annotations

import sqlite3

from netseer.src.api import auth
from netseer.src.database import db
from netseer.eval.browser_env import prepare_copy

ADMIN_PW = "correct horse battery staple"


def _seed_source(path) -> None:
    """A source DB with one admin, one session, one api key and one running live analysis."""
    db.init_db(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        auth.create_account(conn, "admin", ADMIN_PW, ADMIN_PW, "admin")
        admin_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]
        conn.execute("INSERT INTO sessions(token, user_id, csrf, created_at, last_seen, expires_at) "
                     "VALUES ('token', ?, 'csrf', 't', 't', 't')", (admin_id,))
        conn.execute("INSERT INTO api_keys(name, ciphertext) VALUES ('vt', 'cipher')")
        conn.execute("INSERT INTO analyses(name, mode, status, created_at, mirror_if, lan_if) "
                     "VALUES ('Live', 'live', 'running', 't', 'eth0', 'eth1')")
        conn.commit()
    finally:
        conn.close()


def _connect(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def test_prepare_copy_cleans_and_creates_admin(tmp_path):
    source = tmp_path / "source.db"
    _seed_source(source)

    username, password = prepare_copy(source, tmp_path / "copy.db")

    conn = _connect(tmp_path / "copy.db")
    try:
        users = conn.execute("SELECT username FROM users").fetchall()
        assert [u["username"] for u in users] == ["e2eadmin"]
        assert conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert conn.execute("SELECT status FROM analyses WHERE mode = 'live'").fetchone()["status"] == "stopped"
        assert auth.authenticate(conn, username, password)["username"] == "e2eadmin"
    finally:
        conn.close()


def test_source_is_unchanged(tmp_path):
    source = tmp_path / "source.db"
    _seed_source(source)

    prepare_copy(source, tmp_path / "copy.db")

    conn = _connect(source)
    try:
        assert [u["username"] for u in conn.execute("SELECT username FROM users")] == ["admin"]
        assert conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert conn.execute("SELECT status FROM analyses WHERE mode = 'live'").fetchone()["status"] == "running"
    finally:
        conn.close()
