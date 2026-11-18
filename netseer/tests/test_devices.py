"""Step 4: Devices page and the Device Attribution modal."""

from __future__ import annotations

import re

import pytest

from netseer.src.api.deps import COLUMN_HELP, page_qs
from netseer.src.api.routers.alerts import top_devices
from netseer.src.config import CONFIG_DIR, setting_defaults
from netseer.src.database import db
from netseer.src.engine import logger
from netseer.tests.test_auth import USER_PW, csrf, do_setup, login
from netseer.tests.test_ingest import needs_suricata, upload
from netseer.tests.test_logger import FIXTURE, OUI
from netseer.tests import pcapgen

INTERNAL_HOSTS = ["192.168.100.1", "192.168.100.24", "192.168.100.50", "192.168.100.60"]


@pytest.fixture()
def analysed(client):
    """Admin signed in; analysis 1 processed from the eve fixture and awaiting attribution, and selected."""
    do_setup(client)
    login(client)
    conn = db.connect(client.app.state.db_path)
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) "
                 "VALUES (1, 'Offline — demo', 'offline', 'awaiting_attribution', 'x')")
    logger.process_eve_file(conn, 1, FIXTURE, setting_defaults()["lan_cidrs"], OUI,
                            str(CONFIG_DIR / "suricata" / "classification.config"))
    client.cookies.set("netseer_analysis", "1")
    return client, conn


def _device_ids(conn) -> dict[str, int]:
    return {r["ip"]: r["id"] for r in conn.execute("SELECT id, ip FROM devices WHERE analysis_id = 1")}


def test_modal_lists_internal_hosts_after_upload(analysed):
    client, _ = analysed
    page = client.get("/devices").text
    assert 'class="modal-backdrop open"' in page
    modal = page.split('id="attribution-modal"', 1)[1]
    for ip in INTERNAL_HOSTS:
        assert ip in modal
    internal = page.split('id="devices-table"', 1)[1].split("External sources", 1)[0]
    assert "203.0.113.10" not in internal and "192.168.100.255" not in page
    assert "203.0.113.10" not in modal
    assert "alice-laptop" in modal and "Apple, Inc." in modal


def test_saved_types_persist_and_finish_the_analysis(analysed):
    client, conn = analysed
    ids = _device_ids(conn)
    form = {"csrf_token": csrf(client, "/devices"), "analysis_id": "1", "action": "save",
            f"type_{ids['192.168.100.24']}": "server", f"type_{ids['192.168.100.1']}": "network",
            f"type_{ids['192.168.100.50']}": "workstation", f"type_{ids['192.168.100.60']}": "unknown"}
    assert client.post("/devices/attribute", data=form).status_code == 303
    rows = {r["ip"]: r for r in conn.execute("SELECT ip, type, criticality, attributed FROM devices")}
    assert (rows["192.168.100.24"]["type"], rows["192.168.100.24"]["criticality"]) == ("server", 9)
    assert (rows["192.168.100.1"]["type"], rows["192.168.100.1"]["criticality"]) == ("network", 8)
    assert (rows["192.168.100.50"]["type"], rows["192.168.100.50"]["criticality"]) == ("workstation", 6)
    assert all(r["attributed"] == 1 for r in rows.values())
    assert conn.execute("SELECT status FROM analyses WHERE id = 1").fetchone()[0] == "done"
    page = client.get("/devices").text
    assert 'class="modal-backdrop open"' not in page
    assert '<option value="server" selected>' in page


def test_skip_keeps_unknown_and_finishes(analysed):
    client, conn = analysed
    client.post("/devices/attribute", data={"csrf_token": csrf(client, "/devices"), "analysis_id": "1", "action": "skip"})
    assert {r[0] for r in conn.execute("SELECT type FROM devices")} == {"unknown"}
    assert conn.execute("SELECT status FROM analyses WHERE id = 1").fetchone()[0] == "done"


def test_type_can_be_changed_later(analysed):
    client, conn = analysed
    token = csrf(client, "/devices")
    client.post("/devices/attribute", data={"csrf_token": token, "analysis_id": "1", "action": "skip"})
    device = _device_ids(conn)["192.168.100.60"]
    assert client.post(f"/devices/{device}/type", data={"csrf_token": token, "type": "guest"}).status_code == 303
    row = conn.execute("SELECT type, criticality FROM devices WHERE id = ?", (device,)).fetchone()
    assert (row["type"], row["criticality"]) == ("guest", 3)
    assert client.post(f"/devices/{device}/type", data={"csrf_token": token, "type": "toaster"}).status_code == 400


def test_user_sees_devices_but_cannot_attribute(analysed):
    client, conn = analysed
    token = csrf(client, "/settings")
    client.post("/settings/users", data={"csrf_token": token, "username": "viewer", "password": USER_PW, "confirm": USER_PW})
    client.post("/logout", data={"csrf_token": token})
    login(client, "viewer", USER_PW)
    page = client.get("/devices").text
    assert "192.168.100.50" in page and 'id="attribution-modal"' not in page
    token = csrf(client, "/devices")
    r = client.post("/devices/attribute", data={"csrf_token": token, "analysis_id": "1", "action": "skip"})
    assert r.status_code == 403


@pytest.mark.integration
@needs_suricata
def test_upload_then_modal_then_type_persists(client, tmp_path):
    """Brief §10 step 4 Check, end to end through Suricata."""
    do_setup(client)
    login(client)
    upload(client, [("a.pcap", pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()),
                    ("b.pcap", pcapgen.demo_part_b(tmp_path / "b.pcap").read_bytes())])
    page = client.get("/devices").text
    assert 'class="modal-backdrop open"' in page
    for ip in INTERNAL_HOSTS:
        assert ip in page
    conn = db.connect(client.app.state.db_path)
    server = conn.execute("SELECT id FROM devices WHERE ip = '192.168.100.24'").fetchone()[0]
    client.post("/devices/attribute", data={"csrf_token": csrf(client, "/devices"), "analysis_id": "1",
                                            "action": "save", f"type_{server}": "server"})
    assert conn.execute("SELECT type FROM devices WHERE id = ?", (server,)).fetchone()[0] == "server"
    assert '<option value="server" selected>' in client.get("/devices").text


def test_external_sources_table_search_and_sort(analysed):
    client, _ = analysed
    page = client.get("/devices").text
    assert "External sources" in page and "203.0.113.10" in page and "testmynids.org" in page
    assert 'list="ext-q-list"' in page and '<option value="testmynids.org">' in page
    found = client.get("/devices?ext_q=testmynids").text.split('id="external-table"', 1)[1]
    assert "203.0.113.10" in found and "198.51.100.7" not in found
    table = lambda url: client.get(url).text.split('id="external-table"', 1)[1]
    asc = table("/devices?sort=alerts&dir=asc")
    assert asc.index("203.0.113.10") < asc.index("198.51.100.7")
    desc = table("/devices?sort=alerts&dir=desc")
    assert desc.index("198.51.100.7") < desc.index("203.0.113.10")
    assert client.get("/devices?sort=ip;DROP TABLE devices&dir=asc").status_code == 200   # unknown key ignored


def test_alerts_sort_whitelist_and_search_lists(analysed):
    client, conn = analysed
    table = lambda url: client.get(url).text.split('id="alerts-table"', 1)[1]
    asc = table("/alerts?sort=severity&dir=asc")
    assert asc.index("TEST Malware C2 beacon") < asc.index("TEST alert without metadata")
    desc = table("/alerts?sort=severity&dir=desc")
    assert desc.index("TEST alert without metadata") < desc.index("TEST Malware C2 beacon")
    page = client.get("/alerts").text
    assert client.get("/alerts?sort=1;DROP TABLE alerts").status_code == 200
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 4
    assert 'list="f-src-list"' in page and '<option value="192.168.100.60">' in page
    assert 'data-key="signature"' in page and 'id="alerts-table" data-server-sort' in page


def test_alert_tick_filters_combine_values(analysed):
    client, _ = analysed
    count = lambda url: int(client.get(url).text.split("Alert table", 1)[1].split("(", 1)[1].split(" matching")[0])
    assert count("/alerts?priority=1") == 2
    assert count("/alerts?priority=1&priority=3") == 3                          # any ticked value
    assert count("/alerts?priority=9&direction=nowhere") == 4                    # values outside the lists are ignored
    assert count("/alerts?sig_severity=Critical") == 4          # sig_severity no longer filters the table
    page = client.get("/alerts?priority=1&priority=3").text
    assert '<details class="filter-frame" open>' in page and "2 active" not in page and "1 active" in page
    assert 'name="priority" value="3" checked' in page and 'name="priority" value="2" checked' not in page
    assert page_qs({"priority": ["1", "3"], "page": "2"}) == "priority=1&priority=3"           # paging keeps ticks


def test_alerts_per_minutes_and_top_devices(analysed):
    client, conn = analysed
    rows = client.get("/api/analyses/1/alert-series?minutes=60").json()
    assert sum(r["alerts"] for r in rows) == conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    page = client.get("/alerts").text
    assert 'id="alerts-chart"' in page and "Top 5 devices by alerts" in page
    top = top_devices(conn, 1)
    assert top and all(t["total"] >= t["sent"] and t["total"] >= t["received"] for t in top)
    assert [t["total"] for t in top] == sorted((t["total"] for t in top), reverse=True)


def test_column_heads_get_their_meaning_as_tooltips(analysed):
    client, _ = analysed
    page = client.get("/alerts").text
    assert "Suricata rule priority as severity" in page and 'th:not([title])' in page
    assert "[1] High" in page
    head = page.split('id="alerts-table"', 1)[1].split("</thead>", 1)[0]
    assert re.findall(r'data-key="([^"]+)"', head) == \
        ["time", "severity", "signature", "class", "direction", "src", "dest", "proto"]
    heads = set(re.findall(r"<th[^>]*>([^<{]+)</th>", page))
    assert heads and heads <= set(COLUMN_HELP), heads - set(COLUMN_HELP)     # every alerts-page column is explained
