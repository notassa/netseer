"""Detonate: admin-only factory reset back to first launch."""

from __future__ import annotations

import pytest

from netseer.src.database import db
from netseer.tests import pcapgen
from netseer.tests.test_auth import ADMIN_PW, USER_PW, csrf, do_setup, login
from netseer.tests.test_ingest import upload


@pytest.fixture()
def loaded(client, tmp_path, monkeypatch):
    """Admin + user accounts and one stored analysis (Suricata stubbed out)."""
    from netseer.src.engine import ingest
    monkeypatch.setattr(ingest, "run_offline", lambda *a: None)
    do_setup(client)
    login(client)
    token = csrf(client, "/settings")
    client.post("/settings/users", data={"csrf_token": token, "username": "viewer", "password": USER_PW, "confirm": USER_PW})
    upload(client, [("a.pcap", pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes())])
    conn = db.connect(client.app.state.db_path)
    conn.execute("UPDATE analyses SET status = 'done'")
    (client.app.state.data_dir / "pcaps" / ".gitkeep").touch()
    return client, conn


def detonate(client, password=ADMIN_PW, confirm="DETONATE"):
    return client.post("/settings/detonate", data={"csrf_token": csrf(client, "/settings"),
                                                   "password": password, "confirm": confirm})


def test_detonate_wipes_everything_and_returns_to_setup(loaded):
    client, conn = loaded
    r = detonate(client)
    assert r.status_code == 303 and r.headers["location"] == "/setup"
    for table in ("users", "analyses", "analysis_files", "sessions", "settings", "login_attempts"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
    assert [r[0] for r in conn.execute("SELECT action FROM audit_log")] == ["netseer_detonated"]
    assert [p.name for p in (client.app.state.data_dir / "pcaps").iterdir()] == [".gitkeep"]
    assert client.get("/").headers["location"] == "/setup"
    assert do_setup(client).status_code == 303                       # first launch works again


def test_wrong_password_or_missing_word_changes_nothing(loaded):
    client, conn = loaded
    assert "Detonate refused" in client.get(detonate(client, password="wrong password guess").headers["location"]).text
    detonate(client, confirm="detonate")
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2


def test_running_analysis_blocks_detonate(loaded):
    client, conn = loaded
    conn.execute("UPDATE analyses SET status = 'running_suricata'")
    assert "still running" in client.get(detonate(client).headers["location"]).text
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2


def test_user_cannot_detonate(loaded):
    client, conn = loaded
    client.post("/logout", data={"csrf_token": csrf(client, "/settings")})
    login(client, "viewer", USER_PW)
    assert detonate(client, password=USER_PW).status_code == 403
    assert "Detonate" not in client.get("/settings").text
