"""Devices network map (CONCEPTS A17): node caps, tree/link edges and the API."""

from __future__ import annotations

import json

from netseer.src.database import db
from netseer.src.engine.netmap import MAX_EXTERNALS, OTHER, build_map
from netseer.src.engine.networks import run_discovery
from netseer.tests.test_auth import admin_client  # noqa: F401 - fixture
from netseer.tests.test_contextor import add_alert, conn  # noqa: F401 - fixture


def seed(conn) -> None:  # noqa: F811
    conn.execute("INSERT INTO devices(analysis_id, ip, type, criticality, risk, attributed) "
                 "VALUES (1, '10.0.0.5', 'server', 9, 0.5, 1)")
    for i in range(MAX_EXTERNALS + 5):                      # 45 outside sources, each in its own /24
        add_alert(conn, i * 0.1, f"198.{i}.0.1", "10.0.0.5", sid=1)
    add_alert(conn, 1, "198.0.0.1", "10.0.0.5", sid=2)       # the busiest source gets a second alert
    run_discovery(conn, 1)
    conn.execute("INSERT INTO incidents(analysis_id, title, rule, src_ips_json, dest_ips_json, first_seen, last_seen, "
                 "n_alerts, band) VALUES (1, 't', 'single', '[]', '[\"10.0.0.5\"]', '', '', 1, 'Medium')")


def test_map_caps_outside_sources_and_links(conn):  # noqa: F811
    seed(conn)
    m = build_map(conn, 1)
    kinds = [n["data"]["kind"] for n in m["nodes"]]
    assert kinds.count("external") == MAX_EXTERNALS + 1       # 40 shown + the folded "other" node
    other = next(n["data"] for n in m["nodes"] if n["data"]["id"] == OTHER)
    assert other["label"] == "+5 other outside hosts" and other["alerts"] == 5
    server = next(n["data"] for n in m["nodes"] if n["data"]["id"] == "10.0.0.5")
    assert server["kind"] == "device" and server["risk"] == 50 and server["band"] == "medium"   # worst incident band
    assert server["network"] == "10.0.0.0/24"
    links = [e["data"] for e in m["edges"] if "link" in e.get("classes", "")]
    assert len(links) == MAX_EXTERNALS + 1                    # one per shown source + one merged "other" link
    assert max(links, key=lambda d: d["alerts"])["source"] in ("198.0.0.1", "10.0.0.5")
    assert all("alert" in e["classes"] for e in m["edges"] if "link" in e.get("classes", ""))
    assert m["summary"]["folded"] == 5 and m["summary"]["partial"]       # links from alerts only (no flows)


def test_device_colour_is_its_worst_incident_band(conn):  # noqa: F811
    seed(conn)
    conn.execute("INSERT INTO incidents(analysis_id, title, rule, src_ips_json, dest_ips_json, first_seen, last_seen, "
                 "n_alerts, band) VALUES (1, 't', 'single', '[\"10.0.0.5\"]', '[]', '', '', 1, 'High')")
    server = next(n["data"] for n in build_map(conn, 1)["nodes"] if n["data"]["id"] == "10.0.0.5")
    assert server["band"] == "high" and server["risk"] == 50             # the % stays P(d)


def test_map_api(admin_client):  # noqa: F811
    c = db.connect(admin_client.app.state.db_path)
    c.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 'a', 'offline', 'done', 'x')")
    c.execute("INSERT INTO devices(analysis_id, ip, attributed) VALUES (1, '192.168.1.10', 1)")
    r = admin_client.get("/api/analyses/1/map")
    assert r.status_code == 200
    data = r.json()
    assert {n["data"]["id"] for n in data["nodes"]} >= {"internet", "net:192.168.1.0/24", "192.168.1.10"}
    assert json.loads(c.execute("SELECT detail_json FROM analysis_info WHERE kind = 'network'").fetchone()[0])["prefix"] \
        == "192.168.1.0/24"                                   # discovery ran once for this older analysis
    assert admin_client.get("/api/analyses/99/map").status_code == 404
    c.close()


def test_clients_hang_off_their_gateway(conn):  # noqa: F811
    seed(conn)
    conn.execute("INSERT INTO devices(analysis_id, ip, type, criticality, attributed) VALUES (1, '10.0.0.1', 'network', 8, 1)")
    conn.execute("UPDATE analysis_info SET detail_json = json_set(detail_json, '$.gateway', '10.0.0.1') "
                 "WHERE kind = 'network'")
    tree = {e["data"]["target"]: e["data"]["source"] for e in build_map(conn, 1)["edges"] if e.get("classes") == "tree"}
    assert tree["10.0.0.1"] == "net:10.0.0.0/24" and tree["10.0.0.5"] == "10.0.0.1"
