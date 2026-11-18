"""Step 7: Incidents, Home and NetSeer configuration; changing a device type or a window re-scores Home."""

from __future__ import annotations

import json
import re

import pytest

from netseer.src.database import db
from netseer.src.engine import scorer
from netseer.src.engine.acp import needs_acp
from netseer.tests.test_auth import USER_PW, admin_client, csrf, login  # noqa: F401 - fixture
from netseer.tests.test_contextor import add_alert
from netseer.tests.test_scorer import SERVER, worked_example


@pytest.fixture()
def scored(admin_client):  # noqa: F811
    """Admin signed in; analysis 1 holds the A5.6 example (+ a late probe of the server), analysed before C2."""
    conn = db.connect(admin_client.app.state.db_path)
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 'Offline — A5.6', 'offline', 'done', 'x')")
    conn.execute("INSERT INTO settings(key, value) VALUES ('lan_cidrs', ?)", (json.dumps(["10.0.0.0/24"]),))
    worked_example(conn)
    add_alert(conn, 60, "203.0.113.9", SERVER, sid=2003, dest_port=22, priority=3, classtype="attempted-recon")
    admin_client.cookies.set("netseer_analysis", "1")
    yield admin_client, conn
    conn.close()


def health(client) -> int:
    match = re.search(r'<div class="reading"><strong>(\d+)</strong>', client.get("/").text)
    assert match, "no health reading on Home"
    return int(match.group(1))


def test_pages_build_incidents_for_analyses_from_before_c2(scored):
    client, conn = scored
    assert needs_acp(conn, 1)
    page = client.get("/incidents")
    assert page.status_code == 200 and not needs_acp(conn, 1)
    assert page.text.count('data-href="/incidents/') == 3
    assert "Sweep from 203.0.113.9 to 5 hosts" in page.text
    assert client.get("/incidents?band=High").text.count('data-href="/incidents/') == 1
    assert client.get("/incidents?rule=R2").text.count('data-href="/incidents/') == 1


def test_home_shows_health_and_top_incidents(scored):
    client, conn = scored
    page = client.get("/")
    assert page.status_code == 200
    assert "Top incidents" in page.text and "Devices at risk" in page.text
    assert 0 < health(client) <= 47      # A5.6 gives 47; the extra probe of the server can only lower it


def test_incident_detail_and_missing_incident(scored):
    client, conn = scored
    client.get("/incidents")
    inc = conn.execute("SELECT id FROM incidents WHERE rule = 'R2'").fetchone()["id"]
    page = client.get(f"/incidents/{inc}")
    assert page.status_code == 200
    for text in ("Why this band", "Activity volume", "60 alerts", "attempted-recon", "Explain with AI",
                 "Attack → Victim", SERVER, "Server/NAS", "outside the LAN"):            # the attacker is outside
        assert text in page.text
    assert client.get("/incidents/9999").status_code == 404


def test_changing_a_device_type_rescores_and_updates_home(scored):
    client, conn = scored
    health(client)                       # first view runs ACP
    before = scorer.network_health(conn, 1)["p_network"]
    server = conn.execute("SELECT id FROM devices WHERE ip = ?", (SERVER,)).fetchone()["id"]
    score_before = conn.execute("SELECT score FROM incidents WHERE rule = 'R2'").fetchone()["score"]
    r = client.post(f"/devices/{server}/type", data={"csrf_token": csrf(client, "/devices"), "type": "guest"})
    assert r.status_code == 303
    after = conn.execute("SELECT score, factors_json FROM incidents WHERE rule = 'R2'").fetchone()
    assert json.loads(after["factors_json"])["I1"]["value"] == 3 and after["score"] < score_before
    assert scorer.network_health(conn, 1)["p_network"] < before   # lower I1 → lower R → less network risk


def test_changing_the_correlation_window_rebuilds_incidents_and_updates_home(scored):
    client, conn = scored
    before = health(client)
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 3
    form = {"csrf_token": csrf(client, "/settings"), "aggregation_gap_s": "300", "correlation_window_min": "60",
            "half_life_days": "7", "max_upload_mb": "2048", "live_interval_s": "30", "inside_rules": "on",
            "lan_cidrs": "10.0.0.0/24"}
    r = client.post("/settings/config", data=form)
    assert r.status_code == 303
    # The probe 40 minutes after the sweep now joins it (R1 with the server), leaving 2 incidents.
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 2
    assert conn.execute("SELECT value FROM settings WHERE key = 'correlation_window_min'").fetchone()[0] == "60"
    assert health(client) != before
    assert conn.execute("SELECT 1 FROM audit_log WHERE action = 'config_changed'").fetchone()


@pytest.mark.parametrize("field, value", [("correlation_window_min", "0"), ("aggregation_gap_s", "abc"),
                                          ("lan_cidrs", "not-a-network"), ("max_upload_mb", "5000")])
def test_config_validation(scored, field, value):
    client, conn = scored
    form = {"csrf_token": csrf(client, "/settings"), "aggregation_gap_s": "300", "correlation_window_min": "30",
            "half_life_days": "7", "max_upload_mb": "2048", "live_interval_s": "30", "inside_rules": "on",
            "lan_cidrs": "10.0.0.0/24", field: value}
    client.post("/settings/config", data=form)
    assert conn.execute("SELECT 1 FROM settings WHERE key = ?", (field,)).fetchone() is None or field == "lan_cidrs"
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key = 'lan_cidrs'").fetchone()[0]) == ["10.0.0.0/24"]


def test_user_can_view_but_not_configure(scored):
    client, conn = scored
    client.post("/settings/users", data={"csrf_token": csrf(client, "/settings"), "username": "viewer",
                                         "password": USER_PW, "confirm": USER_PW})
    client.post("/logout", data={"csrf_token": csrf(client, "/settings")})
    login(client, "viewer", USER_PW)
    assert client.get("/").status_code == 200 and client.get("/incidents").status_code == 200
    assert "NetSeer configuration" not in client.get("/settings").text
    r = client.post("/settings/config", data={"csrf_token": csrf(client, "/settings"), "correlation_window_min": "60"})
    assert r.status_code == 403


def test_paging_twenty_rows_and_show_all():
    from netseer.src.api.deps import page_qs, paging
    assert paging({}, 45) | {} == {"page": 1, "pages": 3, "total": 45, "show_all": False, "cap": 2000,
                                    "limit": 20, "offset": 0}
    assert paging({"page": "3"}, 45)["offset"] == 40 and paging({"page": "9"}, 45)["page"] == 3
    assert paging({"all": "1", "page": "2"}, 45) | {} == {"page": 1, "pages": 3, "total": 45, "show_all": True,
                                                          "cap": 2000, "limit": 2000, "offset": 0}
    assert page_qs({"q": "x", "page": "2", "all": "1"}) == "q=x"



def test_incident_links_the_recon_before_it(scored):
    client, conn = scored
    add_alert(conn, 90, "203.0.113.9", SERVER, sid=2004, dest_port=22, classtype="attempted-admin")   # exploit after the sweep
    client.get("/incidents")                                                                         # runs ACP
    exploit = conn.execute("SELECT id FROM incidents WHERE title LIKE 'Signature 2004%'").fetchone()["id"]
    sweep = conn.execute("SELECT id FROM incidents WHERE rule = 'R2'").fetchone()["id"]
    page = client.get(f"/incidents/{exploit}").text
    assert "Preceded by recon" in page and f'href="/incidents/{sweep}"' in page
