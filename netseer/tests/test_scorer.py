"""Step 6: scorer and roll-up; the CONCEPTS A5.6 worked example must reproduce exactly."""

from __future__ import annotations

import json

import pytest

from netseer.src.engine import scorer
from netseer.src.engine.acp import run_acp
from netseer.tests.test_contextor import add_alert, conn  # noqa: F401 - fixture

SERVER, WORKSTATION = "10.0.0.5", "10.0.0.23"


# --- pure model --------------------------------------------------------------------------------------------------

def test_worked_example_pure():
    La = scorer.likelihood([4, scorer.l2(60), 5, 9, None])
    Ia = scorer.impact(9, 9, 3)
    Lb = scorer.likelihood([9, scorer.l2(12), 2, 7, None])
    Ib = scorer.impact(6, 6, 9)
    assert (round(La, 2), round(Ia, 2), scorer.band(La, Ia), round(scorer.score(La, Ia), 2)) == (5.84, 3.0, "Medium", 2.16)
    assert (round(Lb, 2), round(Ib, 2), scorer.band(Lb, Ib), round(scorer.score(Lb, Ib), 2)) == (5.34, 7.5, "High", 4.94)
    p_server, p_ws = scorer.damped_union([scorer.score(La, Ia) / 10]), scorer.damped_union([scorer.score(Lb, Ib) / 10])
    assert (round(p_server, 3), round(p_ws, 3)) == (0.216, 0.494)
    p_n, health = scorer.health([9 / 9 * p_server, 6 / 9 * p_ws])
    assert (round(p_n, 3), health) == (0.381, 62)


@pytest.mark.parametrize("x, expected", [(0, "Low"), (2.999, "Low"), (3.0, "Medium"), (5.999, "Medium"),
                                         (6.0, "High"), (9, "High")])
def test_level_edges(x, expected):
    assert scorer.level(x) == expected


def test_matrix_corners():
    assert scorer.band(2.9, 2.9) == "Note"
    assert scorer.band(3.0, 3.0) == "Medium"
    assert scorer.band(6.0, 6.0) == "Critical"
    assert scorer.band(6.0, 2.9) == "Medium"


def test_l5_missing_is_left_out_of_the_mean():
    assert scorer.likelihood([4, 6, 2, 8, None]) == 5.0
    assert scorer.likelihood([4, 6, 2, 8, 0]) == 4.0


def test_damped_union_properties():
    assert scorer.damped_union([]) == 0 and scorer.damped_union([0.4]) == pytest.approx(0.4)
    assert scorer.damped_union([0.2, 0.4]) == pytest.approx(1 - 0.6 * (1 - 0.2 / 2 ** 1.5))   # order does not matter
    xs = [0.5, 0.3]
    for extra in (0.01, 0.2, 0.5):                       # adding an incident never raises health
        assert scorer.health(xs + [extra])[1] <= scorer.health(xs)[1]
    assert scorer.health([0.5] * 1000)[1] > 0            # bounded: does not saturate
    assert scorer.union([0.5] * 1000) == pytest.approx(1)
    one, split = scorer.health([0.4, 0.2])[1], scorer.health([0.4, 0.1, 0.1])[1]   # split an incident in two
    assert abs(one - split) < 5


def test_decay_halves_at_one_half_life():
    assert scorer.incident_probability(5.0, 0, 7) == 0.5
    assert scorer.incident_probability(5.0, 7 * 86400, 7) == pytest.approx(0.25)


def test_factor_tables():
    assert scorer.l1(2, None) == 6 and scorer.l1(2, "Critical") == 9 and scorer.l1(None, None) is None
    assert scorer.l1(2, "Informational") == 6 and scorer.l1(None, "Informational") == 1 and scorer.l1(2, "Minor") == 4
    assert (scorer.i2(22), scorer.i2(443), scorer.i2(12345)) == (9, 6, 4)
    assert (scorer.i3("trojan-activity"), scorer.i3("network-scan"), scorer.i3(None)) == (9, 3, 4)
    assert scorer.risk_label(39.9) == "Low" and scorer.risk_label(40) == "Medium" and scorer.risk_label(90) == "Critical"


# --- end to end through the contextor and the database -------------------------------------------------------------

def worked_example(conn) -> None:  # noqa: F811
    """A5.6: server 10.0.0.5 (Server), workstation 10.0.0.23 (Workstation); both incidents end at minute 20."""
    for ip, dtype, crit in ((SERVER, "server", 9), (WORKSTATION, "workstation", 6)):
        conn.execute("INSERT INTO devices(analysis_id, ip, type, criticality, attributed) VALUES (1, ?, ?, ?, 1)",
                     (ip, dtype, crit))
    targets = [SERVER, "10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53"]
    for i in range(60):                       # (a) external sweep: 60 alerts, ET Minor, attempted-recon, SSH
        add_alert(conn, 20 * i / 59, "203.0.113.9", targets[i % 5], sid=2001, dest_port=22, priority=2,
                  severity="Minor", classtype="attempted-recon")
    for i in range(12):                       # (b) workstation → external C2: 12 alerts, ET Critical, trojan, 443
        add_alert(conn, 9 + i, WORKSTATION, "198.51.100.66", sid=2002, dest_port=443, priority=1,
                  severity="Critical", classtype="trojan-activity")


def test_worked_example_end_to_end(conn):  # noqa: F811
    worked_example(conn)
    stats = run_acp(conn, 1)
    assert stats["incidents"] == 2
    a, b = (conn.execute("SELECT * FROM incidents WHERE rule = ?", (r,)).fetchone() for r in ("R2", "single"))
    assert (round(a["likelihood"], 2), round(a["impact"], 2), a["band"], round(a["score"], 2)) == (5.84, 3.0, "Medium", 2.16)
    assert (round(b["likelihood"], 2), round(b["impact"], 2), b["band"], round(b["score"], 2)) == (5.34, 7.5, "High", 4.94)
    fa = json.loads(a["factors_json"])
    values = {k: fa[k]["value"] for k in fa if k != "_meta"}
    assert round(values.pop("L2"), 2) == 5.36
    assert values == {"L1": 4, "L3": 5, "L4": 9, "L5": None, "I1": 9, "I2": 9, "I3": 3}
    assert fa["I1"]["evidence"]["device"] == SERVER and fa["L2"]["why"] == "60 alerts"
    risk = dict(conn.execute("SELECT ip, risk FROM devices").fetchall())
    assert (round(risk[SERVER], 3), round(risk[WORKSTATION], 3)) == (0.216, 0.494)
    net = scorer.network_health(conn, 1)
    assert (round(net["p_network"], 3), net["health"]) == (0.381, 62)
    assert [d["ip"] for d in net["top_devices"]] == [WORKSTATION, SERVER]
    assert [i["id"] for i in net["top_incidents"]] == [b["id"], a["id"]]
    assert [i["points"] for i in net["top_incidents"]] == [32, 6]       # shares of the 38-point drop


def test_factor_meta_model_version_data_quality_and_health(conn):  # noqa: F811
    worked_example(conn)
    conn.execute("UPDATE devices SET attributed = 0 WHERE ip = ?", (WORKSTATION,))
    run_acp(conn, 1)
    rows = conn.execute("SELECT * FROM incidents").fetchall()
    for r in rows:
        meta = json.loads(r["factors_json"])["_meta"]
        assert meta["model_version"] == "A5-1.0"
        assert set(meta["data_quality"]) == {"unattributed_devices", "no_internal_device", "ti_checked"}
    b = conn.execute("SELECT * FROM incidents WHERE rule = 'single'").fetchone()
    assert WORKSTATION in json.loads(b["factors_json"])["_meta"]["data_quality"]["unattributed_devices"]
    net = scorer.network_health(conn, 1)
    assert (round(net["p_network"], 3), net["health"]) == (0.381, 62)


def test_incidents_without_devices_still_lower_health(conn):  # noqa: F811
    for i in range(5):                                  # ext→ext sweep: no LAN device involved
        add_alert(conn, i, "198.51.100.7", f"203.0.113.{10 + i}", sid=4001, dest_port=445, priority=1,
                  classtype="attempted-admin")
    run_acp(conn, 1)
    inc = conn.execute("SELECT * FROM incidents").fetchone()
    assert json.loads(inc["factors_json"])["I1"]["value"] == 5
    assert scorer.network_health(conn, 1)["health"] == round(100 * (1 - 5 / 9 * inc["score"] / 10))


def test_note_band_excluded_from_roll_up(conn):  # noqa: F811
    conn.execute("INSERT INTO devices(analysis_id, ip, type, criticality, attributed) VALUES (1, '10.0.0.7', 'guest', 3, 1)")
    add_alert(conn, 0, "10.0.0.7", "198.51.100.1", sid=3001, dest_port=12345, priority=4,
              classtype="not-suspicious")            # L ≈ 2.4, I ≈ 0.7 → Note
    run_acp(conn, 1)
    assert conn.execute("SELECT band FROM incidents").fetchone()[0] == "Note"
    assert conn.execute("SELECT risk FROM devices").fetchone()[0] == 0
    assert scorer.network_health(conn, 1)["health"] == 100


def test_older_incidents_decay(conn):  # noqa: F811
    conn.execute("INSERT INTO devices(analysis_id, ip, type, criticality, attributed) VALUES (1, ?, 'server', 9, 1)",
                 (SERVER,))
    add_alert(conn, 0, "203.0.113.9", SERVER, sid=1, priority=1, classtype="attempted-admin")
    run_acp(conn, 1)
    fresh = conn.execute("SELECT risk FROM devices").fetchone()[0]
    add_alert(conn, 7 * 24 * 60, "198.51.100.200", "10.0.0.99", sid=2, priority=4)   # analysis ends 7 days later
    run_acp(conn, 1)
    assert conn.execute("SELECT risk FROM devices").fetchone()[0] == pytest.approx(fresh / 2)
