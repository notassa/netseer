"""Step 10: optional TI and cloud LLM, both off without keys (L5 left out); keys are stored encrypted."""

from __future__ import annotations

import json

import httpx
import pytest

from netseer.ai import llm_caller, prompt_maker
from netseer.src import keystore
from netseer.src.database import db
from netseer.src.engine import ti
from netseer.src.engine.acp import rescore, run_acp
from netseer.src.engine.scorer import network_health
from netseer.tests.test_auth import admin_client, csrf  # noqa: F401 - fixture
from netseer.tests.test_contextor import conn  # noqa: F401 - fixture
from netseer.tests.test_incidents import scored  # noqa: F401 - fixture

EXT = "198.51.100.66"          # the A5.6 C2 server (a documentation address, so _public is patched)


@pytest.fixture(autouse=True)
def key_file(tmp_path, monkeypatch):
    monkeypatch.setattr(keystore, "KEY_FILE", tmp_path / "netseer.key")


def test_no_keys_means_no_ti_and_l5_left_out(scored):  # noqa: F811
    client, conn = scored
    run_acp(conn, 1)
    assert not ti.enabled(conn) and ti.enrich(conn, 1) == 0
    factors = [json.loads(r[0]) for r in conn.execute("SELECT factors_json FROM incidents WHERE analysis_id = 1")]
    assert all(f["L5"]["value"] is None for f in factors)
    assert client.get("/settings").status_code == 200 and client.get("/ai").status_code == 200
    assert isinstance(llm_caller.backend_for(conn), llm_caller.OllamaBackend)


def test_ti_result_sets_l5_and_reaches_the_evidence(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    run_acp(conn, 1)
    health_before = network_health(conn, 1)["health"]
    keystore.set_key(conn, "abuseipdb", "secret-abuse-key")
    calls = []
    monkeypatch.setattr(ti, "_public", lambda ip: ip == EXT)
    monkeypatch.setattr(ti, "fetch", lambda source, ip, key: calls.append((source, ip, key)) or {"score": 0.9})
    assert ti.enrich(conn, 1) == 1 and calls == [("abuseipdb", EXT, "secret-abuse-key")]
    assert ti.enrich(conn, 1) == 0                                    # cached for a day
    rescore(conn, 1)
    inc = conn.execute("SELECT * FROM incidents WHERE dest_ips_json LIKE ?", (f"%{EXT}%",)).fetchone()
    l5 = json.loads(inc["factors_json"])["L5"]
    assert l5["value"] == pytest.approx(8.1) and l5["evidence"] == {"ip": EXT, "source": "abuseipdb"}
    assert network_health(conn, 1)["health"] <= health_before
    ev = prompt_maker.build_evidence(conn, inc["id"])
    assert any(f["kind"] == "ti" and EXT in f["text"] for f in ev["facts"])


def test_clean_reputation_never_lowers_likelihood(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    run_acp(conn, 1)
    before = conn.execute("SELECT likelihood FROM incidents WHERE dest_ips_json LIKE ?", (f"%{EXT}%",)).fetchone()[0]
    keystore.set_key(conn, "abuseipdb", "k")
    monkeypatch.setattr(ti, "_public", lambda ip: ip == EXT)
    monkeypatch.setattr(ti, "fetch", lambda source, ip, key: {"score": 0.0})
    ti.enrich(conn, 1)
    rescore(conn, 1)
    inc = conn.execute("SELECT * FROM incidents WHERE dest_ips_json LIKE ?", (f"%{EXT}%",)).fetchone()
    l5 = json.loads(inc["factors_json"])["L5"]
    assert inc["likelihood"] == pytest.approx(before)
    assert l5["value"] is None and l5["evidence"]["reputation"] == 0.0 and "left out" in l5["why"]


@pytest.mark.parametrize("stats, score", [({"malicious": 5, "harmless": 80}, 1.0), ({"malicious": 2, "harmless": 88}, 0.4),
                                          ({}, None)])
def test_virustotal_scales_by_engines_and_unknown_is_not_safe(monkeypatch, stats, score):
    body = {"data": {"attributes": {"last_analysis_stats": stats}}}
    resp = httpx.Response(200, json=body, request=httpx.Request("GET", "https://x"))
    monkeypatch.setattr(httpx, "get", lambda *a, **k: resp)
    assert ti.fetch("virustotal", EXT, "k")["score"] == (pytest.approx(score) if score is not None else None)
    assert ti.l5({EXT: {"virustotal": {"score": None}}}) is None


def test_keys_are_encrypted_and_write_only(scored):  # noqa: F811
    client, conn = scored
    r = client.post("/settings/ai", data={"csrf_token": csrf(client, "/settings"), "llm_backend": "cloud",
                                          "llm_model": "llama3.2:3b", "cloud_provider": "openai",
                                          "cloud_model": "", "key_virustotal": "vt-secret"})
    assert r.status_code == 303
    row = conn.execute("SELECT ciphertext FROM api_keys WHERE name = 'virustotal'").fetchone()
    assert row and "vt-secret" not in row[0] and keystore.get_key(conn, "virustotal") == "vt-secret"
    page = client.get("/settings").text
    assert "vt-secret" not in page and "paste a key to enable" in page
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key = 'llm_backend'").fetchone()[0]) == "ollama"


def test_cloud_backend_posts_openai_style(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    for key, value in (("llm_backend", "cloud"), ("cloud_model", "small-model")):
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, json.dumps(value)))
    keystore.set_key(conn, "openai", "sk-test")
    sent = {}

    def post(url, json, timeout, headers):  # noqa: A002 - mirrors httpx.post
        sent.update(url=url, body=json, headers=headers)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]}, request=httpx.Request("POST", url))
    monkeypatch.setattr(llm_caller.httpx, "post", post)
    backend = llm_caller.backend_for(conn)
    assert isinstance(backend, llm_caller.CloudBackend) and backend.chat("s", "u", {"type": "object"}) == "{}"
    assert sent["url"] == "https://api.openai.com/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer sk-test" and sent["body"]["model"] == "small-model"
    assert sent["body"]["response_format"]["type"] == "json_schema"


def test_settings_sections_are_tabs_and_saves_return_to_their_tab(scored):  # noqa: F811
    client, _ = scored
    page = client.get("/settings").text
    for tab in ("theme", "accounts", "config", "ai", "kb", "oui", "detonate"):
        assert f'id="tab-{tab}"' in page and f'href="#tab-{tab}"' in page
    r = client.post("/settings/ai", data={"csrf_token": csrf(client, "/settings"), "llm_backend": "ollama",
                                          "llm_model": "llama3.2:3b", "cloud_provider": "openai", "cloud_model": ""})
    assert r.headers["location"] == "/settings#tab-ai"


def test_deepseek_backend_uses_json_object(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    for key, value in (("llm_backend", "cloud"), ("cloud_provider", "deepseek"), ("cloud_model", "deepseek-flash")):
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, json.dumps(value)))
    keystore.set_key(conn, "deepseek", "sk-test")
    sent = {}

    def post(url, json, timeout, headers):  # noqa: A002 - mirrors httpx.post
        sent.update(url=url, body=json, headers=headers)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]}, request=httpx.Request("POST", url))
    monkeypatch.setattr(llm_caller.httpx, "post", post)
    backend = llm_caller.backend_for(conn)
    assert backend.chat("s", "u", {"type": "object"}) == "{}"
    assert sent["url"] == "https://api.deepseek.com/chat/completions"
    assert sent["body"]["response_format"] == {"type": "json_object"}
    assert "JSON schema of the reply" in sent["body"]["messages"][0]["content"]
    assert "temperature" in sent["body"]


def test_claude_backend_uses_strict_json_schema_and_no_temperature(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    for key, value in (("llm_backend", "cloud"), ("cloud_provider", "claude"), ("cloud_model", "claude-haiku-5-5")):
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, json.dumps(value)))
    keystore.set_key(conn, "claude", "sk-test")
    sent = {}

    def post(url, json, timeout, headers):  # noqa: A002 - mirrors httpx.post
        sent.update(url=url, body=json, headers=headers)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]}, request=httpx.Request("POST", url))
    monkeypatch.setattr(llm_caller.httpx, "post", post)
    backend = llm_caller.backend_for(conn)
    assert backend.chat("s", "u", {"type": "object"}) == "{}"
    assert sent["url"] == "https://api.anthropic.com/v1/chat/completions"
    assert sent["body"]["response_format"]["type"] == "json_schema"
    assert sent["body"]["response_format"]["json_schema"]["strict"] is True
    assert "temperature" not in sent["body"]


def test_cloud_http_error_redacts_the_key(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    for key, value in (("llm_backend", "cloud"), ("cloud_model", "small-model")):
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, json.dumps(value)))
    keystore.set_key(conn, "openai", "sk-secret-xyz")

    def post(url, json, timeout, headers):  # noqa: A002 - mirrors httpx.post
        return httpx.Response(400, text="bad request: sk-secret-xyz leaked", request=httpx.Request("POST", url))
    monkeypatch.setattr(llm_caller.httpx, "post", post)
    backend = llm_caller.backend_for(conn)
    with pytest.raises(llm_caller.LLMError) as exc:
        backend.chat("s", "u", {"type": "object"})
    assert "HTTP 400" in str(exc.value) and "sk-secret-xyz" not in str(exc.value)


def test_keys_per_provider_are_encrypted_and_never_leaked(scored, monkeypatch):  # noqa: F811
    client, conn = scored
    r = client.post("/settings/ai", data={"csrf_token": csrf(client, "/settings"), "llm_backend": "cloud",
                                          "llm_model": "llama3.2:3b", "cloud_provider": "deepseek",
                                          "cloud_model": "deepseek-flash", "key_deepseek": "sk-secret-xyz"})
    assert r.status_code == 303
    row = conn.execute("SELECT ciphertext FROM api_keys WHERE name = 'deepseek'").fetchone()
    assert row and "sk-secret-xyz" not in row[0] and keystore.get_key(conn, "deepseek") == "sk-secret-xyz"
    assert "sk-secret-xyz" not in client.get("/settings").text
    monkeypatch.setattr(llm_caller.httpx, "get", lambda *a, **k: (_ for _ in ()).throw(httpx.HTTPError("x")))
    r = client.get("/settings/ai/models", params={"provider": "deepseek"})
    assert r.status_code == 200
    assert r.json() == {"models": ["deepseek-flash", "deepseek-v4-pro"], "source": "built-in"}
    for detail in (row[0] for row in conn.execute("SELECT detail FROM audit_log")):
        assert "sk-secret-xyz" not in detail


def test_cloud_keys_are_not_shared_across_providers(scored):  # noqa: F811
    _, conn = scored
    for key, value in (("llm_backend", "cloud"), ("cloud_provider", "deepseek"), ("cloud_model", "deepseek-flash")):
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, json.dumps(value)))
    keystore.set_key(conn, "openai", "sk-openai")
    with pytest.raises(llm_caller.LLMError):
        llm_caller.backend_for(conn)


def test_migrate_drops_legacy_cloud_key_and_url(tmp_path):
    db_path = tmp_path / "legacy.db"
    db.init_db(db_path)
    conn = db.connect(db_path)
    conn.execute("INSERT INTO api_keys(name, ciphertext) VALUES ('cloud_llm', 'x')")
    conn.execute("INSERT INTO settings(key, value) VALUES ('cloud_url', ?)", (json.dumps("https://x"),))
    conn.close()
    db.init_db(db_path)
    conn = db.connect(db_path)
    assert conn.execute("SELECT 1 FROM api_keys WHERE name = 'cloud_llm'").fetchone() is None
    assert conn.execute("SELECT 1 FROM settings WHERE key = 'cloud_url'").fetchone() is None
    conn.close()


def test_ti_results_are_kept_until_detonate(scored, monkeypatch):  # noqa: F811
    _, conn = scored
    run_acp(conn, 1)
    keystore.set_key(conn, "abuseipdb", "k")
    monkeypatch.setattr(ti, "_public", lambda ip: ip == EXT)
    calls = []
    monkeypatch.setattr(ti, "fetch", lambda source, ip, key: calls.append(ip) or {"score": 0.5})
    ti.enrich(conn, 1)
    conn.execute("UPDATE ti_cache SET fetched_at = '2000-01-01T00:00:00+00:00'")       # very old
    assert ti.enrich(conn, 1) == 0 and calls == [EXT]


def test_cached_ips_do_not_use_the_20_ip_cap(conn, monkeypatch):  # noqa: F811
    keystore.set_key(conn, "abuseipdb", "k")
    monkeypatch.setattr(ti, "_public", lambda ip: True)
    ips = [f"203.0.113.{i}" for i in range(21)]
    conn.execute("INSERT INTO incidents(analysis_id, title, rule, src_ips_json, dest_ips_json, n_alerts, score) "
                 "VALUES (1, 't', 'r', '[]', ?, 1, 0)", (json.dumps(ips),))
    for ip in ips[:20]:                                    # the first 20 are already cached
        conn.execute("INSERT INTO ti_cache(indicator, source, result_json, fetched_at) "
                     "VALUES (?, 'abuseipdb', ?, 'x')", (f"abuseipdb:{ip}", json.dumps({"score": 0.0})))
    calls = []
    monkeypatch.setattr(ti, "fetch", lambda source, ip, key: calls.append(ip) or {"score": 0.5})
    assert ti.enrich(conn, 1) == 1 and calls == [ips[20]]  # reaches the 21st IP


def test_virustotal_rate_limit_waits_between_calls_even_on_failure(conn, monkeypatch):  # noqa: F811
    keystore.set_key(conn, "virustotal", "k")
    monkeypatch.setattr(ti, "_public", lambda ip: True)
    ips = ["203.0.113.1", "203.0.113.2"]
    conn.execute("INSERT INTO incidents(analysis_id, title, rule, src_ips_json, dest_ips_json, n_alerts, score) "
                 "VALUES (1, 't', 'r', '[]', ?, 1, 0)", (json.dumps(ips),))
    calls, sleeps = [], []
    def fetch(source, ip, key):
        calls.append((source, ip))
        if ip == ips[0]:
            raise httpx.HTTPError("boom")
        return {"score": 0.5}
    monkeypatch.setattr(ti, "fetch", fetch)
    assert ti.enrich(conn, 1, sleep=sleeps.append) == 1
    assert calls == [("virustotal", ips[0]), ("virustotal", ips[1])]
    assert sleeps == [ti.VT_GAP_S]                          # none before the first VT call, one before the second
