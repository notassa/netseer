"""KB build + RAG (CONCEPTS A6, brief step 8): a known SID retrieves its rule, technique, mitigation and a playbook."""

from __future__ import annotations

import json

import pytest

from netseer.ai import rag
from netseer.ai.kb import build_kb
from netseer.tests.test_auth import admin_client  # noqa: F401 - fixture

RULES = (
    '# alert tcp any any -> any any (msg:"DISABLED"; sid:1; rev:1;)\n'
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flow:to_server; '
    'reference:url,doc.emergingthreats.net/2001219; reference:cve,2020-1234; classtype:attempted-recon; '
    'sid:2001219; rev:20; metadata:attack_target Server, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, '
    'mitre_technique_id T1595, mitre_technique_name Active_Scanning;)\n'
    'alert http any any -> any any (msg:"ET POLICY curl User-Agent; with semicolon"; classtype:policy-violation; '
    'sid:2013028; rev:3;)\n'
)
CLASSIFICATION = ("config classification: attempted-recon,Attempted Information Leak,2\n"
                  "config classification: policy-violation,Potential Corporate Privacy Violation,1\n")


def _obj(kind, n, **fields):
    return {"type": kind, "id": f"{kind}--00000000-0000-4000-8000-00000000000{n}", "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-01T00:00:00.000Z", **fields}


def _ref(ext_id, path):
    return [{"source_name": "mitre-attack", "external_id": ext_id, "url": f"https://attack.mitre.org/{path}"}]


@pytest.fixture
def kb(tmp_path):
    tactic = _obj("x-mitre-tactic", 1, name="Reconnaissance", description="Gathering information.",
                  x_mitre_shortname="reconnaissance", external_references=_ref("TA0043", "tactics/TA0043"))
    tech = _obj("attack-pattern", 2, name="Active Scanning", description="Adversaries scan victims.\n\nMore text.",
                kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
                external_references=_ref("T1595", "techniques/T1595"))
    mit = _obj("course-of-action", 3, name="Pre-compromise", description="Limit what is exposed.",
               external_references=_ref("M1056", "mitigations/M1056"))
    rel = _obj("relationship", 4, relationship_type="mitigates", source_ref=mit["id"], target_ref=tech["id"])
    (tmp_path / "attack.json").write_text(json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000",
                                                      "objects": [tactic, tech, mit, rel]}))
    (tmp_path / "rules").write_text(RULES)
    (tmp_path / "classification.config").write_text(CLASSIFICATION)
    out = tmp_path / "kb.db"
    counts = build_kb.build(out, tmp_path / "rules", tmp_path / "attack.json", tmp_path / "classification.config")
    return out, counts


def test_parse_rule_reads_metadata_and_skips_disabled():
    assert build_kb.parse_rule(RULES.splitlines()[0]) is None
    rule = build_kb.parse_rule(RULES.splitlines()[1])
    assert rule["sid"] == 2001219 and rule["classtype"] == "attempted-recon" and rule["techniques"] == "T1595"
    assert rule["cves"] == "CVE-2020-1234" and rule["attack_target"] == "Server"
    assert build_kb.parse_rule(RULES.splitlines()[2])["msg"] == "ET POLICY curl User-Agent; with semicolon"


def test_build_counts(kb):
    _, counts = kb
    assert counts == {"kb_rules": 2, "kb_attack": 3, "kb_mitigates": 1, "kb_classtype": 2,
                      "kb_playbooks": len(json.loads(build_kb.PLAYBOOKS_PATH.read_text()))}


def test_known_sid_retrieves_rule_technique_mitigation_and_playbook(kb):
    path, _ = kb
    items = rag.retrieve([2001219], text="ET SCAN Potential SSH Scan", kb_path=path)
    kinds = {(i["kind"], i["key"]) for i in items}
    assert {("rule", "2001219"), ("technique", "T1595"), ("mitigation", "M1056"), ("classtype", "attempted-recon")} <= kinds
    playbooks = [i["key"] for i in items if i["kind"] == "playbook"]
    assert playbooks[0] == "PB-SCAN"
    assert next(i for i in items if i["kind"] == "technique")["text"] == "Adversaries scan victims."


def test_no_kb_means_no_knowledge(tmp_path):
    assert rag.retrieve([2001219], kb_path=tmp_path / "missing.db") == []


def test_settings_rebuilds_the_kb_in_the_background(admin_client, monkeypatch):  # noqa: F811
    import time

    from netseer.src.api.routers import settings
    from netseer.src.database import db
    from netseer.tests.test_auth import csrf

    monkeypatch.setattr(settings.build_kb, "build", lambda: {"kb_rules": 7})
    r = admin_client.post("/settings/kb-rebuild", data={"csrf_token": csrf(admin_client, "/settings")})
    assert r.status_code == 303
    conn = db.connect(admin_client.app.state.db_path)
    for _ in range(50):
        row = conn.execute("SELECT detail FROM audit_log WHERE action = 'kb_rebuilt'").fetchone()
        if row:
            break
        time.sleep(0.05)
    assert row["detail"] == "kb_rules 7"
    assert "AI knowledge base" in admin_client.get("/settings").text
