"""Step 1: package skeleton, schema, init-db and first-launch redirect."""

from __future__ import annotations

import sqlite3

from netseer import cli

EXPECTED_TABLES = {
    "users", "login_attempts", "sessions", "audit_log", "settings", "api_keys", "analyses",
    "analysis_files", "alerts", "devices", "alert_groups", "incidents", "incident_groups",
    "interpretations", "packet_stats", "ti_cache",
}


def test_init_db_creates_schema_in_wal_mode(tmp_path):
    path = tmp_path / "n.db"
    assert cli.main(["--db", str(path), "init-db"]) == 0
    conn = sqlite3.connect(path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert EXPECTED_TABLES <= tables
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "one_per_role" in indexes


def test_first_visit_redirects_to_setup(client):
    for path in ["/", "/login", "/alerts", "/network"]:
        r = client.get(path)
        assert r.status_code == 303, path
        assert r.headers["location"] == "/setup"


def test_setup_page_renders_and_static_is_served(client):
    r = client.get("/setup")
    assert r.status_code == 200
    assert "Create administrator" in r.text
    assert 'name="csrf_token"' in r.text
    assert client.get("/static/css/app.css").status_code == 200
    assert client.get("/static/vendor/chart.umd.min.js").status_code == 200
