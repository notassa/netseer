"""Step 11–12: live NIC discovery, the stall state machine (stubbed sysfs) and the eve.json tailer."""

from __future__ import annotations

import json
import os

import pytest

from netseer.src.database import db
from netseer.src.config import analysis_lan, setting_defaults
from netseer.src.engine import ingest, live
from netseer.tests.test_auth import admin_client, csrf  # noqa: F401 - fixture
from netseer.tests.test_contextor import conn  # noqa: F401 - fixture


def nic(sys_net, name, carrier="1", rx=0, physical=True):
    d = sys_net / name
    (d / "statistics").mkdir(parents=True, exist_ok=True)
    if physical:
        (d / "device").mkdir(exist_ok=True)
    (d / "operstate").write_text("up\n" if carrier == "1" else "down\n")
    (d / "carrier").write_text(f"{carrier}\n")
    (d / "address").write_text("ec:1a:c3:00:52:7e\n")
    (d / "statistics" / "rx_packets").write_text(f"{rx}\n")


@pytest.fixture()
def sys_net(tmp_path):
    root = tmp_path / "net"
    nic(root, "lo", physical=False)
    nic(root, "tailscale0", physical=False)
    nic(root, "eno1", rx=100)
    nic(root, "mirror0", carrier="0")
    return root


def test_interfaces_skip_lo_and_virtual(sys_net):
    names = {n["name"]: n for n in live.interfaces(sys_net)}
    assert set(names) == {"eno1", "mirror0"}
    assert names["eno1"]["carrier"] and not names["mirror0"]["carrier"]


def test_session_record_and_nic_choice(conn, sys_net):  # noqa: F811
    with pytest.raises(live.LiveError, match="differ"):
        live.create_session(conn, "eno1", "eno1", sys_net)
    with pytest.raises(live.LiveError):
        live.create_session(conn, "nope", "eno1", sys_net)
    sid = live.create_session(conn, "mirror0", "eno1", sys_net)
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (sid,)).fetchone()
    assert (row["mode"], row["status"], row["mirror_if"]) == ("live", "waiting_interfaces", "mirror0")
    assert row["name"].startswith("Live — mirror0 — ")
    with pytest.raises(live.LiveError, match="already open"):
        live.create_session(conn, "mirror0", "eno1", sys_net)


def test_create_session_adopts_lan_subnet_by_default(conn, sys_net, monkeypatch):  # noqa: F811
    conn.execute("DELETE FROM settings WHERE key = 'lan_cidrs'")
    monkeypatch.setattr(live, "nic_subnet", lambda name: "192.168.100.0/24")
    sid = live.create_session(conn, "mirror0", "eno1", sys_net)
    assert analysis_lan(conn, sid) == ["192.168.100.0/24"]


def test_custom_lan_list_wins_over_detected_subnet(conn, sys_net, monkeypatch):  # noqa: F811
    conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('lan_cidrs', '[\"10.0.0.0/24\"]')")
    monkeypatch.setattr(live, "nic_subnet", lambda name: "192.168.100.0/24")
    sid = live.create_session(conn, "mirror0", "eno1", sys_net)
    assert analysis_lan(conn, sid) == ["10.0.0.0/24"]


def test_no_detected_subnet_keeps_default_list(conn, sys_net, monkeypatch):  # noqa: F811
    conn.execute("DELETE FROM settings WHERE key = 'lan_cidrs'")
    monkeypatch.setattr(live, "nic_subnet", lambda name: None)
    sid = live.create_session(conn, "mirror0", "eno1", sys_net)
    assert analysis_lan(conn, sid) == setting_defaults()["lan_cidrs"]


def test_nic_subnet_parses_ip_json(monkeypatch):
    stdout = json.dumps([
        {"ifname": "eno1", "addr_info": [{"local": "192.168.100.24", "prefixlen": 24}]},
        {"ifname": "p2p0", "addr_info": [{"local": "10.0.0.1", "prefixlen": 32}]},
        {"ifname": "veth0", "addr_info": [{"local": "169.254.10.10", "prefixlen": 16}]},
    ])
    monkeypatch.setattr(live.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": stdout})())
    assert live.nic_subnet("eno1") == "192.168.100.0/24"
    assert live.nic_subnet("p2p0") is None
    assert live.nic_subnet("veth0") is None


def test_stall_states_follow_the_links_and_traffic(conn, sys_net, tmp_path):  # noqa: F811
    sid = live.create_session(conn, "mirror0", "eno1", sys_net)
    status = lambda: conn.execute("SELECT status FROM analyses WHERE id = ?", (sid,)).fetchone()[0]  # noqa: E731
    live.advance(conn, tmp_path, sys_net)
    assert status() == "waiting_interfaces"                    # mirror unplugged
    nic(sys_net, "mirror0", carrier="1", rx=50)
    live.advance(conn, tmp_path, sys_net)
    assert status() == "waiting_traffic"                       # plugged in
    live.advance(conn, tmp_path, sys_net)
    assert status() == "waiting_traffic"                       # idle: rx_packets did not rise
    nic(sys_net, "mirror0", carrier="1", rx=80)
    live.advance(conn, tmp_path, sys_net)
    assert status() == "ready"
    conn.execute("UPDATE analyses SET status = 'running', started_at = 'x' WHERE id = ?", (sid,))
    nic(sys_net, "mirror0", carrier="0", rx=80)
    live.advance(conn, tmp_path, sys_net)
    assert status() == "waiting_interfaces"                    # link dropped while running: banner, data kept
    assert "link dropped" in conn.execute("SELECT error FROM analyses WHERE id = ?", (sid,)).fetchone()[0]
    nic(sys_net, "mirror0", carrier="1", rx=90)
    live.advance(conn, tmp_path, sys_net)
    assert status() == "running"                               # links back: capture carries on


def eve_line(n: int, sid: int = 2000) -> str:
    return json.dumps({"timestamp": f"2026-10-22T10:00:{n:02d}.0+0000", "event_type": "alert", "src_ip": "203.0.113.9",
                       "dest_ip": "10.0.0.5", "proto": "TCP", "src_port": 4000, "dest_port": 22,
                       "alert": {"signature_id": sid, "signature": "ET SCAN test", "severity": 2,
                                 "category": "Attempted Information Leak"}}) + "\n"


def test_tailer_reads_new_lines_keeps_offset_and_follows_rotation(conn, tmp_path):  # noqa: F811
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (5, 'Live', 'live', 'running', 'x')")
    eve = ingest.eve_dir(tmp_path, 5) / "eve.json"
    eve.parent.mkdir(parents=True)
    eve.write_text(eve_line(1) + eve_line(2) + '{"half": ')      # the half-written line waits
    assert live.tick(conn, tmp_path, 5) == 2
    offset = conn.execute("SELECT eve_offset FROM analyses WHERE id = 5").fetchone()[0]
    assert offset == len(eve_line(1) + eve_line(2))
    first = conn.execute("SELECT id FROM incidents WHERE analysis_id = 5").fetchone()[0]
    with open(eve, "a") as fh:
        fh.write('"line"}\n' + eve_line(3))
    assert live.tick(conn, tmp_path, 5) == 2                   # completed half line + one new
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE analysis_id = 5").fetchone()[0] == 3
    assert conn.execute("SELECT id FROM incidents WHERE analysis_id = 5").fetchone()[0] == first   # id kept
    rotated = eve.with_name("eve.new")
    rotated.write_text(eve_line(4))
    os.replace(rotated, eve)                                   # new inode, shorter file: start at 0
    assert live.tick(conn, tmp_path, 5) == 1
    assert conn.execute("SELECT COUNT(*) FROM alerts WHERE analysis_id = 5").fetchone()[0] == 4


def test_explanations_survive_an_acp_rebuild(conn):  # noqa: F811
    from netseer.src.engine.acp import run_acp
    from netseer.tests.test_contextor import add_alert
    add_alert(conn, 0, "203.0.113.9", "10.0.0.5", sid=1)
    run_acp(conn, 1)
    inc = conn.execute("SELECT id FROM incidents").fetchone()[0]
    conn.execute("INSERT INTO interpretations(incident_id, intent, model, evidence_hash, created_at) "
                 "VALUES (?, 'explain_simple', 'm', 'h', 'x')", (inc,))
    add_alert(conn, 1, "203.0.113.9", "10.0.0.5", sid=1)
    run_acp(conn, 1)
    assert conn.execute("SELECT id FROM incidents").fetchone()[0] == inc
    assert conn.execute("SELECT COUNT(*) FROM interpretations").fetchone()[0] == 1


def test_stop_closes_the_record(conn, sys_net, tmp_path, monkeypatch):  # noqa: F811
    calls = []
    monkeypatch.setattr(live, "_systemctl", lambda action, nic: calls.append((action, nic)))
    sid = live.create_session(conn, "mirror0", "eno1", sys_net)
    conn.execute("UPDATE analyses SET status = 'ready' WHERE id = ?", (sid,))
    live.confirm(conn, tmp_path, sid)
    env = (tmp_path / "eves" / "live-mirror0.env").read_text()
    assert f"OUT_DIR={ingest.eve_dir(tmp_path, sid)}" in env and "EXTERNAL_NET=any" in env
    live.stop(conn, tmp_path, sid)
    row = conn.execute("SELECT status, stopped_at FROM analyses WHERE id = ?", (sid,)).fetchone()
    assert row["status"] == "stopped" and row["stopped_at"] and calls == [("start", "mirror0"), ("stop", "mirror0")]
    second = live.create_session(conn, "mirror0", "eno1", sys_net)       # a second session is a new record
    assert second != sid


def test_network_page_opens_and_stops_a_live_session(admin_client, monkeypatch):  # noqa: F811
    fake = [{"name": "eno1", "operstate": "up", "carrier": True, "mac": "x", "rx_packets": 1, "has_ipv4": True},
            {"name": "mirror0", "operstate": "down", "carrier": False, "mac": "y", "rx_packets": 0, "has_ipv4": False}]
    monkeypatch.setattr(live, "interfaces", lambda sys_net=None: fake)
    page = admin_client.get("/network").text
    assert "Open live session" in page and "mirror0 · no link" in page
    r = admin_client.post("/network/live", data={"csrf_token": csrf(admin_client, "/network"), "mirror": "mirror0",
                                                 "lan": "eno1"})
    assert r.status_code == 303
    page = admin_client.get("/network").text
    assert "Waiting for both network links" in page and "Open live session" not in page
    conn = db.connect(admin_client.app.state.db_path)
    sid = conn.execute("SELECT id FROM analyses WHERE mode = 'live'").fetchone()[0]
    assert admin_client.get(f"/api/analyses/{sid}/status").json()["message"].startswith("Waiting for both")
    admin_client.post(f"/network/live/{sid}/stop", data={"csrf_token": csrf(admin_client, "/network")})
    assert conn.execute("SELECT status FROM analyses WHERE id = ?", (sid,)).fetchone()[0] == "stopped"
