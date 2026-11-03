"""Step 5: contextor (ACP 3–5) on synthetic alerts."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from netseer.src.database import db
from netseer.src.engine.contextor import run_contextor
from netseer.src.engine.logger import direction, parse_networks

T0 = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)
NETS = parse_networks(["10.0.0.0/24"])


@pytest.fixture()
def conn(tmp_path):
    """Database with analysis 1 and LAN 10.0.0.0/24."""
    db.init_db(tmp_path / "t.db")
    c = db.connect(tmp_path / "t.db")
    c.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 'a', 'offline', 'done', 'x')")
    c.execute("INSERT INTO settings(key, value) VALUES ('lan_cidrs', ?)", (json.dumps(["10.0.0.0/24"]),))
    yield c
    c.close()


def add_alert(conn, minute: float, src: str, dest: str, sid: int = 1000, *, dest_port: int = 22, priority: int = 2,
              classtype: str = "attempted-recon", severity: str | None = None, tactic: str | None = None,
              signature: str | None = None, src_port: int = 40000) -> None:
    """Insert one alert `minute` minutes after T0."""
    conn.execute(
        "INSERT INTO alerts(analysis_id, ts, src_ip, src_port, dest_ip, dest_port, proto, sid, signature, classtype, "
        "priority, sig_severity, mitre_tactic, direction, raw_json) VALUES (1, ?, ?, ?, ?, ?, 'TCP', ?, ?, ?, ?, ?, ?, ?, '{}')",
        ((T0 + timedelta(minutes=minute)).isoformat(), src, src_port, dest, dest_port, sid,
         signature or f"Signature {sid}", classtype, priority, severity, tactic, direction(src, dest, NETS)))


def incidents(conn) -> list:
    return conn.execute("SELECT * FROM incidents WHERE analysis_id = 1 ORDER BY id").fetchall()


def test_aggregation_gap_splits_groups(conn):
    for m in (0, 1, 2, 3):
        add_alert(conn, m, "203.0.113.9", "10.0.0.5")
    add_alert(conn, 10, "203.0.113.9", "10.0.0.5")      # 7 min of silence > 300 s → a new group
    n_groups, n_incidents = run_contextor(conn, 1)
    counts = [r["count"] for r in conn.execute("SELECT count FROM alert_groups ORDER BY first_seen")]
    assert (n_groups, counts) == (2, [4, 1])
    assert n_incidents == 2                             # same key twice is not a correlation rule
    assert {r["rule"] for r in incidents(conn)} == {"single"}


def test_r1_same_pair_different_sids(conn):
    add_alert(conn, 0, "203.0.113.9", "10.0.0.5", sid=1)
    add_alert(conn, 5, "203.0.113.9", "10.0.0.5", sid=2)
    add_alert(conn, 6, "203.0.113.9", "10.0.0.6", sid=3)   # other victim: separate
    run_contextor(conn, 1)
    rows = incidents(conn)
    assert sorted(r["rule"] for r in rows) == ["R1", "single"]
    r1 = next(r for r in rows if r["rule"] == "R1")
    assert r1["n_alerts"] == 2 and r1["title"] == "203.0.113.9 → 10.0.0.5: 2 different signatures"


def test_r2_sweep_needs_five_destinations(conn):
    for i in range(5):
        add_alert(conn, i, "203.0.113.9", f"10.0.0.{10 + i}", sid=7)
    for i in range(4):                                  # only 4 targets: no sweep
        add_alert(conn, i, "198.51.100.7", f"10.0.0.{10 + i}", sid=8)
    run_contextor(conn, 1)
    rows = incidents(conn)
    assert sorted(r["rule"] for r in rows) == ["R2"] + ["single"] * 4
    r2 = next(r for r in rows if r["rule"] == "R2")
    assert len(json.loads(r2["dest_ips_json"])) == 5
    assert r2["title"].startswith("Sweep from 203.0.113.9 to 5 hosts")


def test_r3_many_sources_one_destination(conn):
    for i in range(6):
        add_alert(conn, i, f"198.51.100.{i + 1}", "10.0.0.5", sid=9)
    run_contextor(conn, 1)
    rows = incidents(conn)
    assert [r["rule"] for r in rows] == ["R3"]
    assert rows[0]["title"].startswith("6 sources → 10.0.0.5")


def test_r4_tactic_progression_on_one_host(conn):
    add_alert(conn, 0, "10.0.0.23", "10.0.0.5", sid=11, tactic="TA0007", classtype="policy-violation")
    add_alert(conn, 4, "203.0.113.9", "10.0.0.23", sid=12, tactic="TA0001", classtype="attempted-user")
    add_alert(conn, 9, "10.0.0.23", "203.0.113.50", sid=13, tactic="TA0011", dest_port=443, classtype="trojan-activity")
    run_contextor(conn, 1)
    rows = incidents(conn)
    assert [r["rule"] for r in rows] == ["R4"]
    assert rows[0]["title"] == ("Tactic progression on 10.0.0.23: Discovery → Initial Access → Command and Control")
    ev = json.loads(rows[0]["evidence_json"])
    assert [t["name"] for t in ev["tactics"]] == ["Discovery", "Initial Access", "Command and Control"]


def test_r2_r3_need_the_same_signature(conn):
    for i in range(5):                                  # 5 destinations, but 5 different signatures: not a sweep
        add_alert(conn, i, "203.0.113.9", f"10.0.0.{10 + i}", sid=20 + i)
    for i in range(5):                                  # 5 sources, but 5 different signatures: not a fan-in
        add_alert(conn, i, f"198.51.100.{i + 1}", "10.0.0.99", sid=30 + i)
    run_contextor(conn, 1)
    assert [r["rule"] for r in incidents(conn)] == ["single"] * 10


def test_r4_needs_a_forward_kill_chain_step(conn):
    add_alert(conn, 0, "10.0.0.23", "203.0.113.50", sid=13, tactic="TA0011")   # C2 first …
    add_alert(conn, 4, "203.0.113.9", "10.0.0.23", sid=12, tactic="TA0001")    # … then Initial Access: backwards
    run_contextor(conn, 1)
    assert [r["rule"] for r in incidents(conn)] == ["single", "single"]


def test_outside_correlation_window_does_not_link(conn):
    add_alert(conn, 0, "203.0.113.9", "10.0.0.5", sid=1)
    add_alert(conn, 45, "203.0.113.9", "10.0.0.5", sid=2)   # 45 min later > 30 min window
    run_contextor(conn, 1)
    assert [r["rule"] for r in incidents(conn)] == ["single", "single"]
    conn.execute("INSERT INTO settings(key, value) VALUES ('correlation_window_min', '60')")
    run_contextor(conn, 1)                                  # a wider window links them (and rebuilds cleanly)
    assert [r["rule"] for r in incidents(conn)] == ["R1"]


def test_recon_stays_its_own_incident(conn):
    for i in range(5):                                      # recon sweep …
        add_alert(conn, i, "203.0.113.9", f"10.0.0.{10 + i}", sid=7, tactic="TA0043")
    add_alert(conn, 6, "203.0.113.9", "10.0.0.10", sid=8, tactic="TA0001", classtype="attempted-admin")  # … then an exploit
    run_contextor(conn, 1)
    assert sorted(r["rule"] for r in incidents(conn)) == ["R2", "single"]   # no R1/R4 across recon and the exploit


def test_several_rules_recorded_strongest_first(conn):
    for i in range(5):                                      # R2 sweep …
        add_alert(conn, i, "203.0.113.9", f"10.0.0.{10 + i}", sid=7, tactic="TA0001", classtype="attempted-user")
    add_alert(conn, 6, "203.0.113.9", "10.0.0.10", sid=8, tactic="TA0002",        # … + R1 and R4 on 10.0.0.10
              classtype="attempted-admin")
    run_contextor(conn, 1)
    rows = incidents(conn)
    assert [r["rule"] for r in rows] == ["R4,R1,R2"]
    assert rows[0]["n_alerts"] == 6
    groups = conn.execute("SELECT COUNT(*) FROM incident_groups").fetchone()[0]
    assert groups == 6


def test_reduction_counted(conn):
    for m in range(100):
        add_alert(conn, m * 0.1, "203.0.113.9", "10.0.0.5")
    n_groups, n_incidents = run_contextor(conn, 1)
    assert (n_groups, n_incidents) == (1, 1)
    group = conn.execute("SELECT * FROM alert_groups").fetchone()
    assert group["count"] == 100 and len(json.loads(group["alert_ids_json"])) == 100
