"""ACP 1–2 logger over the eve fixture: alerts, enrichment, devices, packet statistics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netseer.src.config import CONFIG_DIR, setting_defaults
from netseer.src.database import db
from netseer.src.engine import logger
from netseer.src.engine.alert_mix import alert_mix
from netseer.src.engine.oui import PRIVATE_MAC, vendor_for

FIXTURE = Path(__file__).parent / "fixtures" / "eve_sample.json"
OUI = "/usr/share/ieee-data/oui.csv"
CLASSIFICATION = str(CONFIG_DIR / "suricata" / "classification.config")


@pytest.fixture()
def processed(tmp_path):
    path = tmp_path / "l.db"
    db.init_db(path)
    conn = db.connect(path)
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 't', 'offline', 'processing', 'x')")
    log = logger.process_eve_file(conn, 1, FIXTURE, setting_defaults()["lan_cidrs"], OUI, CLASSIFICATION)
    return conn, log


def test_alerts_are_normalised_and_enriched(processed):
    conn, log = processed
    assert log.n_alerts == 4 and log.n_bad_lines == 1
    rows = {r["sid"]: r for r in conn.execute("SELECT * FROM alerts")}
    root = rows[2100498]
    assert root["classtype"] == "bad-unknown"           # description mapped to the short name
    assert root["priority"] == 2 and root["sig_severity"] == "Informational"
    assert root["direction"] == "ext->int"
    assert root["ts"] == "2025-10-09T08:53:20.100000+00:00"
    assert json.loads(root["raw_json"])["alert"]["signature_id"] == 2100498
    nmap = rows[2024364]                                # ET SCAN: read as recon; the rule's category is kept
    assert nmap["classtype"] == "attempted-recon" and nmap["category"] == "Web Application Attack"
    assert nmap["direction"] == "int->int"
    c2 = rows[2999001]
    assert (c2["classtype"], c2["sig_severity"], c2["mitre_tactic"], c2["mitre_technique"]) == \
        ("command-and-control", "Critical", "TA0011", "T1071,T1573")
    assert c2["direction"] == "int->ext"


def test_missing_values_stay_null(processed):
    conn, _ = processed
    bare = conn.execute("SELECT * FROM alerts WHERE sid = 2999002").fetchone()
    assert bare["classtype"] is None and bare["sig_severity"] is None and bare["mitre_tactic"] is None
    assert bare["app_proto"] is None


def test_devices_are_internal_hosts_that_sent_or_answered(processed):
    conn, _ = processed
    devices = {r["ip"]: r for r in conn.execute("SELECT * FROM devices")}
    # .255 (broadcast) and .99 (unanswered scan target) are not devices; external IPs never are.
    assert set(devices) == {"192.168.100.1", "192.168.100.24", "192.168.100.50", "192.168.100.60"}
    laptop = devices["192.168.100.50"]
    assert laptop["mac"] == "3c:22:fb:11:22:33" and laptop["vendor"] == "Apple, Inc."
    assert laptop["hostname"] == "alice-laptop"
    assert laptop["type"] == "unknown" and laptop["attributed"] == 0
    server = devices["192.168.100.24"]
    assert json.loads(server["services_json"]) == [{"port": 80, "proto": "tcp", "app": "http"}]   # not closed 23
    assert devices["192.168.100.60"]["hostname"] is None
    assert server["first_seen"].startswith("2025-10-09T09:53")    # from flow start, not the flush timestamp


def test_packet_stats_per_minute(processed):
    conn, _ = processed
    stats = {r["minute"]: r["packets"] for r in conn.execute("SELECT minute, packets FROM packet_stats")}
    assert stats == {"2025-10-09T08:53": 11, "2025-10-09T09:53": 11, "2025-10-09T10:17": 3, "2025-10-09T10:18": 2}
    a = conn.execute("SELECT n_events, n_alerts FROM analyses WHERE id = 1").fetchone()
    assert (a["n_events"], a["n_alerts"]) == (17, 4)


def test_reprocessing_merges_devices_instead_of_duplicating(processed):
    conn, _ = processed
    logger.process_eve_file(conn, 1, FIXTURE, setting_defaults()["lan_cidrs"], OUI, CLASSIFICATION)
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 4


def test_alert_mix_shares(processed):
    conn, _ = processed
    mix = alert_mix(conn, 1)
    assert sum(m["count"] for m in mix["classtype"]) == 4
    assert abs(sum(m["share"] for m in mix["priority"]) - 1.0) < 1e-9
    assert {m["key"] for m in mix["classtype"]} == {"bad-unknown", "attempted-recon", "command-and-control", None}


@pytest.mark.parametrize("src,dest,expected", [
    ("192.168.1.2", "8.8.8.8", "int->ext"), ("8.8.8.8", "10.1.1.1", "ext->int"),
    ("172.16.0.1", "172.31.255.1", "int->int"), ("1.1.1.1", "8.8.8.8", "ext->ext"), (None, "8.8.8.8", None),
])
def test_direction(src, dest, expected):
    assert logger.direction(src, dest, logger.parse_networks(setting_defaults()["lan_cidrs"])) == expected


def test_vendor_lookup():
    assert vendor_for("3c:22:fb:11:22:33", OUI) == "Apple, Inc."
    assert vendor_for("da:a1:19:00:00:01", OUI) == PRIVATE_MAC
    assert vendor_for(None, OUI) is None


def test_progress_callback_reaches_one(tmp_path, monkeypatch):
    path = tmp_path / "p.db"
    db.init_db(path)
    conn = db.connect(path)
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 't', 'offline', 'processing', 'x')")
    monkeypatch.setattr(logger, "PROGRESS_EVERY", 5)
    seen = []
    logger.process_eve_file(conn, 1, FIXTURE, setting_defaults()["lan_cidrs"], OUI, CLASSIFICATION, seen.append)
    assert seen == sorted(seen) and len(seen) >= 3 and seen[-1] == 1.0


def test_spread_minutes_keeps_totals():
    parts = logger.spread_minutes("2025-10-09T08:53:40+00:00", "2025-10-09T08:55:05+00:00", 10, 1001)
    assert [p[0] for p in parts] == ["2025-10-09T08:53", "2025-10-09T08:54", "2025-10-09T08:55"]
    assert sum(p[1] for p in parts) == 10 and sum(p[2] for p in parts) == 1001
    assert logger.spread_minutes("2025-10-09T08:53:40+00:00", "2025-10-09T08:53:10+00:00", 4, 4) == \
        [("2025-10-09T08:53", 4, 4)]


@pytest.mark.parametrize("minutes,expected", [
    (1, 86), (5, 18), (60, 3), (1440, 1),     # empty bins between the two demo files count as 0
])
def test_packet_bins_keep_total(processed, minutes, expected):
    from netseer.src.api.routers.alerts import default_bin_minutes, packet_series
    conn, _ = processed
    series = packet_series(conn, 1, minutes)
    assert len(series) == expected and sum(p["packets"] for p in series) == 27
    assert default_bin_minutes(conn, 1) == 1


def test_external_sources(processed):
    conn, _ = processed
    rows = {r["ip"]: r for r in conn.execute("SELECT * FROM external_hosts")}
    assert set(rows) == {"203.0.113.10", "198.51.100.7"}          # no internal, broadcast or 0.0.0.0
    web = rows["203.0.113.10"]
    assert (web["hostname"], web["direction"], web["n_flows"], web["n_alerts"]) == ("testmynids.org", "outbound", 1, 1)
    assert json.loads(web["ports_json"]) == [80] and json.loads(web["peers_json"]) == ["192.168.100.50"]
    c2 = rows["198.51.100.7"]
    assert c2["n_alerts"] == 2 and c2["n_flows"] == 0 and c2["direction"] is None


def test_is_external():
    nets = logger.parse_networks(setting_defaults()["lan_cidrs"])
    assert logger.is_external("8.8.8.8", nets)
    for ip in ("192.168.1.5", "255.255.255.255", "0.0.0.0", "224.0.0.251", "fe80::1", "127.0.0.1", None, "junk"):
        assert not logger.is_external(ip, nets), ip


@pytest.mark.parametrize("n_ports, alerts", [(logger.SCAN_MIN_PORTS, 1), (logger.SCAN_MIN_PORTS - 1, 0)])
def test_port_scan_from_flows(tmp_path, n_ports, alerts):
    path = tmp_path / "s.db"
    db.init_db(path)
    conn = db.connect(path)
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 't', 'offline', 'processing', 'x')")
    eve = tmp_path / "eve.json"
    flows = [{"event_type": "flow", "src_ip": "192.168.1.139", "dest_ip": "192.168.1.142", "proto": "TCP",
              "src_port": 40000, "dest_port": port, "flow": {"start": f"2026-10-21T17:20:{port % 60:02d}.0+0000",
                                                              "pkts_toserver": 1, "pkts_toclient": 1}}
             for port in range(1, n_ports + 1)]
    flows.append({**flows[0], "dest_port": 8080, "flow": {**flows[0]["flow"], "pkts_toserver": 20}})  # a real session
    eve.write_text("\n".join(map(json.dumps, flows)))
    logger.process_eve_file(conn, 1, eve, setting_defaults()["lan_cidrs"], OUI, CLASSIFICATION)
    rows = conn.execute("SELECT * FROM alerts").fetchall()
    assert len(rows) == alerts
    if alerts:
        a = rows[0]
        assert a["sid"] == logger.SCAN_SID and a["classtype"] == "attempted-recon" and a["direction"] == "int->int"
        assert a["signature"] == f"NETSEER Port scan: {n_ports} ports probed" and a["mitre_technique"] == "T1046"
        assert a["ts"].startswith("2026-10-21T17:20:01")          # first probe


def test_ip_names_are_remembered_across_analyses(tmp_path):
    path = tmp_path / "n.db"
    db.init_db(path)
    conn = db.connect(path)
    for aid in (1, 2):
        conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (?, 't', 'offline', 'processing', 'x')", (aid,))
    dns = {"event_type": "http", "src_ip": "192.168.1.5", "dest_ip": "93.184.216.34", "proto": "TCP", "dest_port": 80,
           "timestamp": "2026-10-21T10:00:00.0+0000", "http": {"hostname": "example.com"}}
    bare = {**dns, "event_type": "flow", "http": None, "flow": {"start": "2026-10-21T11:00:00.0+0000", "pkts_toserver": 9,
                                                                "pkts_toclient": 9}}
    for aid, event in ((1, dns), (2, bare)):
        eve = tmp_path / f"{aid}.json"
        eve.write_text(json.dumps(event))
        logger.process_eve_file(conn, aid, eve, setting_defaults()["lan_cidrs"], OUI, CLASSIFICATION)
    assert conn.execute("SELECT name FROM ip_names WHERE ip = '93.184.216.34'").fetchone()[0] == "example.com"
    assert conn.execute("SELECT hostname FROM external_hosts WHERE analysis_id = 2").fetchone()[0] == "example.com"
