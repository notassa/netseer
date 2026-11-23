"""Step 9: evidence package, verifier (4 crafted cases + a clean one), cached explanations and the AI page."""

from __future__ import annotations

import json

import pytest

from netseer.ai import explain, prompt_maker, verifier
from netseer.ai.schemas import ExplainOutput
from netseer.src.engine.acp import run_acp
from netseer.tests.test_auth import admin_client, csrf  # noqa: F401 - fixture
from netseer.tests.test_incidents import scored  # noqa: F401 - fixture
from netseer.tests.test_scorer import WORKSTATION


@pytest.fixture()
def incident(scored):  # noqa: F811
    client, conn = scored
    run_acp(conn, 1)
    inc = conn.execute("SELECT * FROM incidents WHERE analysis_id = 1 ORDER BY score DESC").fetchone()
    return client, conn, inc


def clean_output(evidence: dict) -> dict:
    """A reply that only restates the evidence, with valid refs."""
    band = evidence["band"]
    group = next(f for f in evidence["facts"] if f["kind"] == "group")
    return {
        "summary": f"NetSeer rates this possible incident {band} risk.",
        "what_happened": f"Alerts were raised [{group['id']}].",
        "why_it_matters": "A device may be targeted; there is no sign the attempt worked.",
        "risk_explanation": f"The band is {band}, as NetSeer scored it.",
        "uncertainty": "Whether any attempt succeeded is unknown.",
        "recommended_actions": [{"action": "Check the device's login log.", "reason": "To see if it worked.",
                                 "refs": [group["id"]]}],
        "claims": [{"text": f"The band is {band}.", "refs": ["E2"]}],
    }


def checks(evidence: dict, **changes) -> set[str]:
    out = clean_output(evidence) | changes
    return {f["check"] for f in verifier.verify(ExplainOutput.model_validate(out), evidence)["flags"]}


def test_evidence_package_has_ids_factors_hosts_and_unknowns(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert [f["id"] for f in ev["facts"]] == [f"E{i}" for i in range(1, len(ev["facts"]) + 1)]
    kinds = {f["kind"] for f in ev["facts"]}
    assert {"overview", "band", "factor", "host", "group"} <= kinds
    assert ev["band"] == inc["band"] and any("L5" in u for u in ev["unknowns"])
    assert any(WORKSTATION in f["text"] for f in ev["facts"] if f["kind"] == "host")
    assert prompt_maker.evidence_hash(ev) == prompt_maker.evidence_hash(json.loads(json.dumps(ev)))
    system, user = prompt_maker.messages(ev, "explain_simple")
    assert inc["band"] in system and '"E1"' in user


def test_unattributed_device_lists_an_unknown(incident):
    _, conn, _ = incident
    conn.execute("UPDATE devices SET attributed = 0 WHERE ip = ?", (WORKSTATION,))
    run_acp(conn, 1)
    inc = next(r for r in conn.execute("SELECT * FROM incidents").fetchall()
               if WORKSTATION in json.loads(r["factors_json"])["_meta"]["data_quality"]["unattributed_devices"])
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert any("not confirmed by the administrator" in u for u in ev["unknowns"])


def test_clean_output_passes(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert checks(ev) == set()


def test_fake_ip_is_flagged(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert checks(ev, what_happened="The attacker 203.0.113.250 scanned port 31337.") == {"entity"}


def test_wrong_band_is_flagged(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    wrong = "Low" if inc["band"] != "Low" else "High"
    assert checks(ev, risk_explanation=f"This is {wrong} risk.") == {"band"}


def test_missing_ref_is_flagged(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert checks(ev, claims=[{"text": "See the rule.", "refs": ["K99"]}]) == {"citation"}
    out = clean_output(ev) | {"claims": [{"text": "Alerts were raised.", "refs": []}]}
    assert verifier.parse(json.dumps(out))[0] is None           # no ref at all fails check 1 (schema)


def test_overclaim_is_flagged_but_hedged_wording_is_not(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert checks(ev, summary="The server was compromised.") == {"overclaim"}
    assert checks(ev, summary="The server may have been compromised.") == set()


class StubBackend:
    model = "stub"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def chat(self, system, user, schema, stop=None):
        self.calls += 1
        return self.replies.pop(0)


def test_generate_retries_once_verifies_and_caches(incident):
    _, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    stub = StubBackend(["not json", json.dumps(clean_output(ev))])
    first = explain.generate(conn, inc["id"], "explain_simple", stub)
    assert stub.calls == 2
    row = conn.execute("SELECT * FROM interpretations WHERE id = ?", (first,)).fetchone()
    assert json.loads(row["verification_json"]) == {"passed": True, "flags": [], "schema_retry": True}
    assert explain.generate(conn, inc["id"], "explain_simple", stub) == first and stub.calls == 2   # cached
    assert explain.status(conn, inc["id"], "explain_simple") == {"state": "done", "interpretation": first}
    conn.execute("UPDATE devices SET type = 'guest' WHERE ip = ?", (WORKSTATION,))      # new evidence → not cached
    assert explain.status(conn, inc["id"], "explain_simple") == {"state": "none"}


def test_analysis_summary_evidence(incident):
    _, conn, inc = incident
    ev = explain.evidence_for(conn, inc["id"], "summarise_analysis")
    assert ev["scope"] == "analysis" and ev["facts"][1]["text"].startswith("Network health is")
    assert sum(f["kind"] == "incident" for f in ev["facts"]) >= 1


def test_ai_page_shows_explanation_with_badge_and_flags(incident):
    client, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    stub = StubBackend([json.dumps(clean_output(ev) | {"summary": "The server was compromised."})])
    explain.generate(conn, inc["id"], "explain_simple", stub)
    page = client.get(f"/ai?incident={inc['id']}&intent=explain_simple")
    assert page.status_code == 200
    assert "1 flagged" in page.text and 'class="flagged"' in page.text and "E2" in page.text
    r = client.post(f"/api/incidents/{inc['id']}/explain", data={"intent": "nope", "csrf_token": csrf(client, "/ai")})
    assert r.status_code == 400
    assert client.get(f"/api/incidents/{inc['id']}/explain?intent=explain_simple").json()["state"] == "done"


def test_ai_page_shows_prompt_for_the_selected_intent(incident):
    client, conn, inc = incident
    before = conn.execute("SELECT COUNT(*) FROM interpretations").fetchone()[0]
    page = client.get(f"/ai?incident={inc['id']}&intent=what_to_do")
    assert page.status_code == 200
    assert 'id="prompt-text"' in page.text
    assert "Focus on recommended_actions" in page.text
    assert "Evidence package:" in page.text
    assert conn.execute("SELECT COUNT(*) FROM interpretations").fetchone()[0] == before


def test_saved_explanations_stay_listed_and_open_after_the_evidence_changes(incident):
    client, conn, inc = incident
    ev = prompt_maker.build_evidence(conn, inc["id"])
    first = explain.generate(conn, inc["id"], "explain_simple", StubBackend([json.dumps(clean_output(ev))]))
    explain.generate(conn, inc["id"], "what_to_do", StubBackend([json.dumps(clean_output(ev))]))
    page = client.get("/ai").text
    assert "Saved explanations" in page and page.count('href="/ai?interpretation=') == 2
    conn.execute("UPDATE devices SET type = 'guest' WHERE ip = ?", (WORKSTATION,))     # evidence changes
    old = client.get(f"/ai?interpretation={first}")
    assert old.status_code == 200 and "evidence has changed since" in old.text and "Verified" in old.text
    assert client.get("/ai?interpretation=999").status_code == 404


def test_running_explanation_reports_an_estimated_percent(incident, monkeypatch):
    _, conn, inc = incident
    inc_id = inc["id"]
    conn.executemany("INSERT INTO interpretations(incident_id, intent, model, evidence_hash, created_at, latency_s) "
                     "VALUES (?, 'explain_simple', 'm', ?, 'x', 100)", [(inc_id, f"h{i}") for i in range(3)])
    monkeypatch.setitem(explain.JOBS, (inc_id, "explain_simple"), {"state": "running", "started": explain.time.monotonic() - 50})
    s = explain.status(conn, inc_id, "explain_simple")
    assert s["state"] == "running" and s["percent"] == 50 and "started" not in s
    explain.JOBS[(inc_id, "explain_simple")]["started"] -= 500                       # far past the estimate: held at 95
    assert explain.status(conn, inc_id, "explain_simple")["percent"] == 95


def test_a_running_explanation_can_be_stopped(incident, monkeypatch):
    import threading
    client, conn, inc = incident
    entered = threading.Event()

    class SlowBackend:                          # streams until stopped, like Ollama
        model = "slow"

        def chat(self, system, user, schema, stop=None):
            entered.set()
            stop.wait(10)
            raise explain.Stopped("Stopped.")
    monkeypatch.setattr(explain, "backend_for", lambda conn: SlowBackend())
    explain.start(client.app.state.db_path, inc["id"], "explain_simple")
    assert entered.wait(5)
    r = client.post(f"/api/incidents/{inc['id']}/explain/stop",
                    data={"intent": "explain_simple", "csrf_token": csrf(client, "/ai")})
    assert r.json() == {"stopped": True}
    for _ in range(100):
        if explain.status(conn, inc["id"], "explain_simple")["state"] == "none":
            break
        explain.time.sleep(0.05)
    assert explain.status(conn, inc["id"], "explain_simple") == {"state": "none"}
    assert conn.execute("SELECT COUNT(*) FROM interpretations").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'explanation_stopped'").fetchone()[0] == 1


def test_clear_saved_explanations_of_the_selected_analysis(incident):
    client, conn, inc = incident
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (2, 'other', 'offline', 'done', 'x')")
    conn.execute("INSERT INTO incidents(id, analysis_id, title, rule, src_ips_json, dest_ips_json, n_alerts) "
                 "VALUES (999, 2, 't', 'single', '[]', '[]', 1)")
    conn.executemany("INSERT INTO interpretations(incident_id, intent, model, evidence_hash, created_at) "
                     "VALUES (?, 'explain_simple', 'm', 'h', 'x')", [(inc["id"],), (inc["id"],), (999,)])
    r = client.post("/ai/history/clear", data={"csrf_token": csrf(client, "/settings")})
    assert r.status_code == 303
    assert [r[0] for r in conn.execute("SELECT incident_id FROM interpretations")] == [999]   # other analysis kept
