"""Information page: account activity with IP/MAC, process log, admin-only access, audit_log migration."""

from __future__ import annotations

import pathlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from netseer.src.api import client as client_mod
from netseer.src.database import db
from netseer.src.engine import ingest, sysinfo
from netseer.src.engine.events import EVENTS
from netseer.tests import pcapgen
from netseer.tests.test_auth import USER_PW, csrf, do_setup, login
from netseer.tests.test_ingest import upload


def rows(client, action):
    conn = db.connect(client.app.state.db_path)
    return conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def test_login_and_logout_record_ip_and_unknown_mac(client):
    do_setup(client)
    login(client, password="wrong password guess")
    login(client)
    client.post("/logout", data={"csrf_token": csrf(client, "/settings")})
    for action in ("login_failed", "login", "logout"):
        (row,) = rows(client, action)
        assert row["ip"] == "testclient" and row["mac"] is None
    login(client)
    page = client.get("/information").text
    assert "Signed in" in page and "Failed sign-in" in page and "Signed out" in page and "testclient" in page


def test_session_expiry_is_logged(client):
    do_setup(client)
    login(client)
    conn = db.connect(client.app.state.db_path)
    old = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="seconds")
    conn.execute("UPDATE sessions SET expires_at = ?", (old,))
    client.get("/settings")
    (row,) = rows(client, "session_expired")
    assert row["user_id"] is not None and row["ip"] == "testclient"


def test_user_gets_403(client):
    do_setup(client)
    login(client)
    token = csrf(client, "/settings")
    client.post("/settings/users", data={"csrf_token": token, "username": "viewer", "password": USER_PW, "confirm": USER_PW})
    client.post("/logout", data={"csrf_token": token})
    login(client, "viewer", USER_PW)
    assert client.get("/information").status_code == 403
    assert 'href="/information"' not in client.get("/settings").text


def test_failed_analysis_appears_in_process_log(client, tmp_path, monkeypatch):
    real = ingest.app_config
    monkeypatch.setattr(ingest, "app_config", lambda k: "false" if k == "suricata_bin" else real(k))
    do_setup(client)
    login(client)
    upload(client, [("a.pcap", pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes())])
    (row,) = rows(client, "analysis_failed")
    assert "Suricata failed" in row["detail"]
    page = client.get("/information?tab=process&level=error").text
    assert "Analysis failed" in page and "Suricata failed" in page and "Upload started" not in page
    assert "Upload started" in client.get("/information?tab=process").text


def test_old_audit_log_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user_id INTEGER, "
                 "action TEXT NOT NULL, detail TEXT)")
    conn.execute("INSERT INTO audit_log(ts, action) VALUES ('t', 'login')")
    conn.commit()
    conn.close()
    db.init_db(path)
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(audit_log)")}
    assert {"ip", "mac"} <= cols


def test_client_ip_trusts_forwarded_only_from_proxy(monkeypatch):
    req = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={"x-forwarded-for": "1.2.3.4, 192.168.100.146"})
    monkeypatch.setattr(client_mod, "app_config", lambda k: [])
    assert client_mod.client_ip(req) == "127.0.0.1"
    monkeypatch.setattr(client_mod, "app_config", lambda k: ["127.0.0.1"])
    assert client_mod.client_ip(req) == "192.168.100.146"


def test_client_mac_unknown_for_loopback_and_garbage():
    assert client_mod.client_mac("127.0.0.1") is None
    assert client_mod.client_mac("testclient") is None
    assert client_mod.client_mac(None) is None


def test_clear_process_log_keeps_account_log_and_a_trace(client):
    do_setup(client)
    login(client)
    conn = db.connect(client.app.state.db_path)
    db.audit(conn, None, "analysis_failed", "analysis 9: boom")
    db.audit(conn, None, "upload_started", "x")
    r = client.post("/information/clear", data={"tab": "process", "csrf_token": csrf(client, "/information")})
    assert r.status_code == 303 and r.headers["location"] == "/information?tab=process"
    assert not rows(client, "analysis_failed") and not rows(client, "upload_started")
    assert rows(client, "setup")                                   # account activity untouched
    trace = rows(client, "process_log_cleared")
    assert len(trace) == 1 and trace[0]["detail"] == "2 entries deleted"
    assert "Clear process log" in client.get("/information?tab=process").text


def test_every_audited_action_has_a_label():
    root = pathlib.Path(__file__).parents[1]
    used = set()
    for path in root.rglob("*.py"):
        if "tests" not in path.parts:
            used |= set(re.findall(r'audit\([^,]+,\s*[^,]+,\s*f?"([a-z_]+)"', path.read_text()))
    assert used and used <= set(EVENTS), used - set(EVENTS)


def test_netseer_details_tab_and_parsers(client, tmp_path):
    (tmp_path / "meminfo").write_text("MemTotal:  16000 kB\nMemAvailable:  4000 kB\n")
    assert sysinfo.memory(tmp_path) == {"total": 16000 * 1024, "used": 12000 * 1024}
    hw = tmp_path / "class" / "hwmon" / "hwmon2"
    hw.mkdir(parents=True)
    (hw / "name").write_text("coretemp\n")
    (hw / "temp1_input").write_text("45000\n")
    (hw / "temp1_label").write_text("Package id 0\n")
    assert sysinfo.temperatures(tmp_path) == [{"sensor": "coretemp", "label": "Package id 0", "celsius": 45.0}]
    do_setup(client)
    login(client)
    page = client.get("/information?tab=details").text
    assert "NetSeer details" in page and "Up since" in page and "Network interfaces" in page
    usage = client.get("/api/system").json()
    assert 0 <= usage["cpu_percent"] <= 100 and usage["memory"]["total"] > 0
