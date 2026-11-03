"""Offline ingest: validation, storage, merge order, and the full upload → Suricata → logger pipeline."""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
from datetime import datetime

import pytest

from netseer.src.database import db
from netseer.src.api.routers import network
from netseer.src.engine import ingest
from netseer.tests import pcapgen
from netseer.tests.test_auth import USER_PW, csrf

RULES = "/var/lib/suricata/rules/suricata.rules"
needs_suricata = pytest.mark.skipif(
    not (shutil.which("suricata") and os.access(RULES, os.R_OK)),
    reason="Suricata rules not readable (run as a member of the 'suricata' group)",
)


@pytest.fixture()
def conn(tmp_path):
    db.init_db(tmp_path / "i.db")
    return db.connect(tmp_path / "i.db")


def test_bad_magic_is_rejected_and_nothing_kept(conn, tmp_path):
    good = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    with pytest.raises(ingest.IngestError, match="not a pcap"):
        ingest.create_offline_analysis(conn, tmp_path / "data", [("a.pcap", io.BytesIO(good)),
                                                                  ("evil.pcap", io.BytesIO(b"MZ\x90\x00 not a capture"))], 10**9)
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0
    assert not any((tmp_path / "data" / "pcaps").iterdir())


def test_size_cap(conn, tmp_path):
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    with pytest.raises(ingest.IngestError, match="limit"):
        ingest.create_offline_analysis(conn, tmp_path / "data", [("a.pcap", io.BytesIO(data))], len(data) - 1)


def test_valid_upload_is_stored_with_sha256_and_auto_name(conn, tmp_path):
    a = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    b = pcapgen.demo_part_b(tmp_path / "b.pcap").read_bytes()
    aid = ingest.create_offline_analysis(conn, tmp_path / "data",
                                         [("../../etc/lab a.pcap", io.BytesIO(a)), ("b.pcap", io.BytesIO(b))], 10**9)
    files = conn.execute("SELECT filename, sha256, size FROM analysis_files WHERE analysis_id = ?", (aid,)).fetchall()
    assert [f["filename"] for f in files] == ["lab_a.pcap", "b.pcap"]      # path stripped, unsafe chars replaced
    assert files[0]["sha256"] == hashlib.sha256(a).hexdigest() and files[0]["size"] == len(a)
    assert (tmp_path / "data" / "pcaps" / str(aid) / "lab_a.pcap").read_bytes() == a
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (aid,)).fetchone()
    assert row["status"] == "queued" and row["mode"] == "offline"
    assert re.fullmatch(r"Offline — lab_a\.pcap — \d{4}-\d\d-\d\d \d\d:\d\d", row["name"])


def test_auto_name_single_file():
    assert ingest.auto_name(["x.pcap"], datetime(2026, 1, 2, 3, 4)) == "Offline — x.pcap — 2026-01-02 03:04"


@pytest.mark.skipif(not shutil.which("mergecap"), reason="mergecap not installed")
def test_merge_is_chronological_regardless_of_upload_order(tmp_path):
    later = pcapgen.demo_part_b(tmp_path / "later.pcap")
    earlier = pcapgen.demo_part_a(tmp_path / "earlier.pcap")
    merged = ingest.merge_captures([later, earlier], tmp_path / "m.pcapng")
    subprocess.run(["editcap", "-F", "pcap", str(merged), str(tmp_path / "m.pcap")], check=True)
    ts = pcapgen.read_pcap_timestamps(tmp_path / "m.pcap")
    assert ts == sorted(ts)
    assert len(ts) == len(pcapgen.read_pcap_timestamps(later)) + len(pcapgen.read_pcap_timestamps(earlier))
    assert ts[0] == pcapgen.read_pcap_timestamps(earlier)[0]


@pytest.mark.skipif(not shutil.which("mergecap"), reason="mergecap not installed")
def test_merge_of_mixed_snaplen_captures_is_classic_pcap(tmp_path):
    """Regression: a pcapng merge keeps two interfaces and Suricata's libpcap refuses it."""
    a = pcapgen.demo_part_a(tmp_path / "a.pcap")
    b = pcapgen.demo_part_b(tmp_path / "b.pcap")
    raw = bytearray(b.read_bytes())
    raw[16:20] = (262144).to_bytes(4, "little")           # snaplen as tcpdump writes it
    b.write_bytes(raw)
    merged = ingest.merge_captures([a, b], tmp_path / "m.pcap")
    assert merged.read_bytes()[:4] == bytes.fromhex("d4c3b2a1")
    assert len(pcapgen.read_pcap_timestamps(merged)) == len(pcapgen.read_pcap_timestamps(a)) + len(pcapgen.read_pcap_timestamps(b))


def test_suricata_unopenable_capture_is_a_failure(tmp_path):
    (tmp_path / "suricata.log").write_text(
        "[1 - RX#01] Error: pcap: failed to get first packet timestamp. pcap_next_ex(): -1\n"
        "[1 - RX#01] Warning: pcap: Failed to init pcap file /x/merged.pcap, skipping\n")
    with pytest.raises(ingest.IngestError, match="could not read the capture"):
        ingest._check_suricata_read(tmp_path)


def test_truncated_capture_is_a_warning(tmp_path):
    """Real log of a 568 MB capture whose last packet was cut off when it was recorded."""
    (tmp_path / "suricata.log").write_text(
        "[57857 - RX#01] 2026-10-21 04:20:07 Error: pcap: error code -1 truncated dump file; tried to read 1516 "
        "captured bytes, only got 1083 for /x/27.pcap\n"
        "[57857 - RX#01] 2026-10-21 04:20:07 Notice: pcap: read 0 files, 1067724 packets, 578989789 bytes\n")
    warning = ingest._check_suricata_read(tmp_path)
    assert warning.startswith("Note: the capture ends mid-packet") and "1067724 packets" in warning


def test_clean_log_has_no_warning(tmp_path):
    (tmp_path / "suricata.log").write_text("[1 - RX#01] Notice: pcap: read 1 file, 22 packets, 2058 bytes\n")
    assert ingest._check_suricata_read(tmp_path) is None


def test_incomplete_upload_is_rejected(client, tmp_path):
    headers = admin(client)
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    aid = client.post("/api/uploads", json={"name": "a.pcap", "size": len(data)}, headers=headers).json()["id"]
    r = client.put(f"/api/analyses/{aid}/file", content=data[:-100], headers=headers)
    assert r.status_code == 400 and "incomplete" in r.json()["detail"]
    assert db.connect(client.app.state.db_path).execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0


@pytest.mark.integration
@needs_suricata
def test_failed_analysis_can_be_rerun(client, tmp_path, monkeypatch):
    real = ingest.app_config
    monkeypatch.setattr(ingest, "app_config", lambda k: "false" if k == "suricata_bin" else real(k))
    admin(client)
    aid = upload(client, [("a.pcap", pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes())])
    conn = db.connect(client.app.state.db_path)
    assert conn.execute("SELECT status FROM analyses").fetchone()[0] == "failed"
    monkeypatch.setattr(ingest, "app_config", real)
    r = client.post(f"/network/analyses/{aid}/rerun", data={"csrf_token": csrf(client, "/network")})
    assert r.status_code == 303
    row = conn.execute("SELECT status, n_alerts, error FROM analyses").fetchone()
    assert (row["status"], row["n_alerts"], row["error"]) == ("awaiting_attribution", 1, None)
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'analysis_rerun'").fetchone()[0] == 1


def test_delete_removes_rows_and_files(conn, tmp_path):
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    aid = ingest.create_offline_analysis(conn, tmp_path / "data", [("a.pcap", io.BytesIO(data))], 10**9)
    conn.execute("UPDATE analyses SET status = 'done' WHERE id = ?", (aid,))
    ingest.delete_analysis(conn, tmp_path / "data", aid)
    assert conn.execute("SELECT COUNT(*) FROM analysis_files").fetchone()[0] == 0
    assert not (tmp_path / "data" / "pcaps" / str(aid)).exists()


def test_running_analysis_cannot_be_deleted(conn, tmp_path):
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    aid = ingest.create_offline_analysis(conn, tmp_path / "data", [("a.pcap", io.BytesIO(data))], 10**9)
    with pytest.raises(ingest.IngestError, match="still running"):
        ingest.delete_analysis(conn, tmp_path / "data", aid)


def upload(client, files: list[tuple[str, bytes]], chunk: int | None = None, analyse: bool = True,
           analysis_id: int | None = None):
    """Upload files one at a time into one session, like network.html (announce → PUT → start); return its id.

    Only the last file starts the analysis (TestClient runs the background job inside that request).
    """
    headers = {"X-CSRF-Token": csrf(client, "/network")}
    aid = analysis_id
    for i, (name, data) in enumerate(files):
        r = client.post("/api/uploads", json={"name": name, "size": len(data), "analysis_id": aid}, headers=headers)
        assert r.status_code == 200, r.text
        aid = r.json()["id"]
        body = data if chunk is None else (data[k:k + chunk] for k in range(0, len(data), chunk))
        r = client.put(f"/api/analyses/{aid}/file", content=body, headers=headers)
        assert r.status_code == 200, r.text
        r = client.post(f"/api/analyses/{aid}/start", json={"analyse": analyse and i == len(files) - 1}, headers=headers)
        assert r.status_code == 200, r.text
    return aid


def admin(client):
    from netseer.tests.test_auth import do_setup, login
    do_setup(client)
    login(client)
    return {"X-CSRF-Token": csrf(client, "/network")}


def test_user_cannot_upload(client, tmp_path):
    from netseer.tests.test_auth import login
    admin(client)
    token = csrf(client, "/settings")
    client.post("/settings/users", data={"csrf_token": token, "username": "viewer", "password": USER_PW, "confirm": USER_PW})
    client.post("/logout", data={"csrf_token": token})
    login(client, "viewer", USER_PW)
    r = client.post("/api/uploads", json={"name": "a.pcap", "size": 10},
                    headers={"X-CSRF-Token": csrf(client, "/network")})
    assert r.status_code == 403


def test_upload_needs_csrf_header(client):
    admin(client)
    assert client.post("/api/uploads", json={"name": "a.pcap", "size": 10}).status_code == 400


def test_streamed_upload_in_chunks_keeps_sha256(client, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "run_offline", lambda *a: None)
    admin(client)
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes() + b"\0" * (3 << 20)   # >1 MB body
    aid = upload(client, [("big.pcap", data)], chunk=64 * 1024)
    conn = db.connect(client.app.state.db_path)
    row = conn.execute("SELECT sha256, size FROM analysis_files WHERE analysis_id = ?", (aid,)).fetchone()
    assert (row["sha256"], row["size"]) == (hashlib.sha256(data).hexdigest(), len(data))
    assert conn.execute("SELECT status FROM analyses").fetchone()[0] == "queued"


def test_file_over_cap_is_rejected_mid_stream_and_removed(client, tmp_path, monkeypatch):
    headers = admin(client)
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    r = client.post("/api/uploads", json={"name": "a.pcap", "size": 100}, headers=headers)
    aid = r.json()["id"]                                 # announced small, sends more: the stream cap still holds
    monkeypatch.setattr(network, "_max_file_bytes", lambda conn: 100)
    r = client.put(f"/api/analyses/{aid}/file", content=data, headers=headers)
    assert r.status_code == 400 and "per-file limit" in r.json()["detail"]
    conn = db.connect(client.app.state.db_path)
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0
    assert not (client.app.state.data_dir / "pcaps" / str(aid)).exists()


def test_announced_size_over_cap_is_refused(client):
    headers = admin(client)
    r = client.post("/api/uploads", json={"name": "huge.pcap", "size": 3 << 30}, headers=headers)
    assert r.status_code == 400 and "2048 MB per-file limit" in r.json()["detail"]


def test_low_disk_refuses_upload(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(100, 90, 10 << 20))
    with pytest.raises(ingest.IngestError, match="Not enough free disk"):
        ingest.begin_upload(conn, tmp_path / "data", "a.pcap", 5 << 20, 1 << 30)


def test_start_refuses_before_the_file_arrives(client, tmp_path):
    headers = admin(client)
    data = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    aid = client.post("/api/uploads", json={"name": "a.pcap", "size": len(data)}, headers=headers).json()["id"]
    r = client.post(f"/api/analyses/{aid}/start", headers=headers)
    assert r.status_code == 400 and "not finished" in r.json()["detail"]


def test_restart_fails_uploading_and_running_jobs(conn, tmp_path):
    aid = ingest.begin_upload(conn, tmp_path / "data", "a.pcap", 10, 1 << 30)
    ingest.mark_interrupted(conn)
    assert conn.execute("SELECT status FROM analyses WHERE id = ?", (aid,)).fetchone()[0] == "failed"
    assert conn.execute("SELECT action FROM audit_log").fetchone()[0] == "analysis_interrupted"


def test_read_position_follows_an_open_file(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"x" * 10000)
    with open(path, "rb") as fh:
        fh.read(4096)
        assert ingest.read_position(os.getpid(), path) == 4096
    assert ingest.read_position(os.getpid(), path) is None


@pytest.mark.integration
@needs_suricata
def test_two_uploads_into_one_session_span_both_files_and_rename_persists(client, tmp_path):
    """Brief §10 step 3 Check, with one-file-at-a-time uploads into a session."""
    admin(client)
    a = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    b = pcapgen.demo_part_b(tmp_path / "b.pcap").read_bytes()
    seen = []
    real = ingest.set_progress
    ingest.set_progress = lambda aid, stage, pct=None, detail="": (seen.append(stage), real(aid, stage, pct, detail))
    try:
        upload(client, [("part-b.pcap", b), ("part-a.pcap", a)])
    finally:
        ingest.set_progress = real
    assert seen[0] == "queued" and "merging" in seen and "loading rules" in seen and "processing" in seen and "correlating" in seen and seen[-1] == "checking capture"
    assert not (client.app.state.data_dir / "pcaps" / "1" / "merged.pcap").exists()
    assert (client.app.state.data_dir / "pcaps" / "1" / "part-a.pcap").exists()
    token = csrf(client, "/network")
    conn = db.connect(client.app.state.db_path)
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 1
    analysis = conn.execute("SELECT * FROM analyses").fetchone()
    assert analysis["status"] == "awaiting_attribution", analysis["error"]
    assert analysis["name"].startswith("Offline — part-b.pcap — ")
    sids = {r["sid"]: r["ts"] for r in conn.execute("SELECT sid, ts FROM alerts WHERE analysis_id = ?", (analysis["id"],))}
    assert sids[2100498].startswith("2025-10-09T08:53")     # from part A
    assert sids[2024364].startswith("2025-10-09T09:53")     # from part B
    page = client.get("/alerts").text
    assert "GPL ATTACK_RESPONSE id check returned root" in page and "Detected Alert Classes" in page
    alert_id = conn.execute("SELECT id FROM alerts WHERE sid = 2100498").fetchone()[0]
    assert client.get(f"/api/alerts/{alert_id}").json()["alert"]["signature_id"] == 2100498

    r = client.post(f"/network/analyses/{analysis['id']}/rename", data={"csrf_token": token, "name": "Lab capture"})
    assert r.status_code == 303
    assert conn.execute("SELECT name FROM analyses").fetchone()[0] == "Lab capture"
    assert "Lab capture" in client.get("/network").text


def test_session_collects_files_and_waits_as_pending(client, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "run_offline", lambda *a: None)
    admin(client)
    a = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    aid = upload(client, [("cap.pcap", a)], analyse=False)
    conn = db.connect(client.app.state.db_path)
    assert conn.execute("SELECT status FROM analyses").fetchone()[0] == "pending"
    b = pcapgen.demo_part_b(tmp_path / "b.pcap").read_bytes()
    upload(client, [("cap.pcap", b)], analyse=False, analysis_id=aid)          # same name, other file → renamed
    names = [r[0] for r in conn.execute("SELECT filename FROM analysis_files WHERE analysis_id = ? ORDER BY rowid", (aid,))]
    assert names == ["cap.pcap", "1_cap.pcap"]
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 1
    page = client.get("/network").text
    assert "Add to: " in page and ">Analyse</button>" in page


def test_failed_add_keeps_the_session(client, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "run_offline", lambda *a: None)
    headers = admin(client)
    a = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    aid = upload(client, [("a.pcap", a)], analyse=False)
    r = client.post("/api/uploads", json={"name": "evil.pcap", "size": 20, "analysis_id": aid}, headers=headers)
    r = client.put(f"/api/analyses/{aid}/file", content=b"MZ not a capture 123", headers=headers)
    assert r.status_code == 400
    conn = db.connect(client.app.state.db_path)
    assert conn.execute("SELECT status FROM analyses").fetchone()[0] == "pending"
    assert [r[0] for r in conn.execute("SELECT filename FROM analysis_files")] == ["a.pcap"]
    assert sorted(p.name for p in (client.app.state.data_dir / "pcaps" / str(aid)).iterdir()) == ["a.pcap"]


def test_busy_session_refuses_new_files(client, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "run_offline", lambda *a: None)
    headers = admin(client)
    aid = upload(client, [("a.pcap", pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes())])
    db.connect(client.app.state.db_path).execute("UPDATE analyses SET status = 'running_suricata'")
    r = client.post("/api/uploads", json={"name": "b.pcap", "size": 10, "analysis_id": aid}, headers=headers)
    assert r.status_code == 400 and "busy" in r.json()["detail"]


def test_admin_note(client):
    headers = admin(client)
    conn = db.connect(client.app.state.db_path)
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 'x', 'offline', 'done', 't')")
    token = headers["X-CSRF-Token"]
    assert client.post("/network/analyses/1/note", data={"csrf_token": token, "note": "Office, Monday"}).status_code == 303
    assert conn.execute("SELECT note FROM analyses").fetchone()[0] == "Office, Monday"
    assert "Office, Monday" in client.get("/network").text
    client.post("/network/analyses/1/note", data={"csrf_token": token, "note": "x" * 1001})
    assert conn.execute("SELECT note FROM analyses").fetchone()[0] == "Office, Monday"
    from netseer.tests.test_auth import login
    client.post("/settings/users", data={"csrf_token": token, "username": "viewer", "password": USER_PW, "confirm": USER_PW})
    client.post("/logout", data={"csrf_token": token})
    login(client, "viewer", USER_PW)
    assert client.post("/network/analyses/1/note", data={"csrf_token": csrf(client, "/network"), "note": "y"}).status_code == 403


def test_stop_kills_the_run_clears_results_and_keeps_the_capture(conn, tmp_path, monkeypatch):
    import threading
    import time
    fake = tmp_path / "suricata"
    fake.write_text("#!/bin/sh\nsleep 30\n")
    fake.chmod(0o755)
    real = ingest.app_config
    monkeypatch.setattr(ingest, "app_config", lambda k: str(fake) if k == "suricata_bin" else real(k))
    data = tmp_path / "data"
    aid = ingest.create_offline_analysis(conn, data, [("a.pcap", io.BytesIO(
        pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()))], 10**9)
    job = threading.Thread(target=ingest.run_offline, args=(tmp_path / "i.db", data, aid))
    job.start()
    while (ingest.get_progress(aid) or {}).get("stage") != "loading rules":
        time.sleep(0.05)
    started = time.monotonic()
    ingest.stop(conn, data, aid)
    job.join(timeout=10)
    assert not job.is_alive() and time.monotonic() - started < 5          # the 30 s "Suricata" was killed
    row = conn.execute("SELECT status FROM analyses WHERE id = ?", (aid,)).fetchone()
    assert row["status"] == "stopped"
    assert (ingest.pcap_dir(data, aid) / "a.pcap").exists() and not ingest.eve_dir(data, aid).exists()
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'analysis_stopped'").fetchone()[0] == 1


def test_stop_without_a_job_clears_at_once(conn, tmp_path):
    data = tmp_path / "data"
    aid = ingest.create_offline_analysis(conn, data, [("a.pcap", io.BytesIO(
        pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()))], 10**9)
    conn.execute("UPDATE analyses SET status = 'processing' WHERE id = ?", (aid,))     # left over by a restart
    ingest.stop(conn, data, aid)
    assert conn.execute("SELECT status FROM analyses WHERE id = ?", (aid,)).fetchone()[0] == "stopped"


@pytest.mark.parametrize("inside, expected", [(True, True), (False, False)])
def test_inside_rules_switch_sets_external_net(conn, tmp_path, monkeypatch, inside, expected):
    conn.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 't', 'offline', 'queued', 'x')")
    conn.execute("INSERT INTO settings(key, value) VALUES ('inside_rules', ?)", ("true" if inside else "false",))
    seen = []

    def fake_run(cmd, what, poll=None):
        seen.extend(cmd)
        raise ingest.IngestError("stop here")
    monkeypatch.setattr(ingest, "_run", fake_run)
    (tmp_path / "x.pcap").write_bytes(b"x")
    with pytest.raises(ingest.IngestError):
        ingest._detect(conn, tmp_path, 1, tmp_path / "x.pcap")
    assert ("vars.address-groups.EXTERNAL_NET=any" in seen) is expected


def test_same_capture_twice_is_refused(conn, tmp_path):
    a = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    ingest.create_offline_analysis(conn, tmp_path / "data", [("a.pcap", io.BytesIO(a))], 10**9)
    with pytest.raises(ingest.IngestError, match="already uploaded"):
        ingest.create_offline_analysis(conn, tmp_path / "data", [("copy.pcap", io.BytesIO(a))], 10**9)
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 1


def test_right_magic_with_a_broken_header_is_refused(conn, tmp_path):
    fake = bytes.fromhex("d4c3b2a1") + b"\x09\x00" + bytes(40)          # pcap magic, version 9, snaplen 0
    with pytest.raises(ingest.IngestError, match="not a valid pcap"):
        ingest.create_offline_analysis(conn, tmp_path / "data", [("fake.pcap", io.BytesIO(fake))], 10**9)
    good = pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes()
    assert ingest.is_capture_header(good[:28])
    shb = bytes.fromhex("0a0d0d0a") + (28).to_bytes(4, "little") + bytes.fromhex("4d3c2b1a") + bytes(16)
    assert ingest.is_capture_header(shb) and not ingest.is_capture_header(shb[:8] + bytes(20))   # pcapng


def test_deleting_a_file_clears_results_and_the_last_file_deletes_the_session(client, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "run_offline", lambda *a: None)
    admin(client)
    aid = upload(client, [("a.pcap", pcapgen.demo_part_a(tmp_path / "a.pcap").read_bytes())], analyse=False)
    upload(client, [("b.pcap", pcapgen.demo_part_b(tmp_path / "b.pcap").read_bytes())], analyse=False, analysis_id=aid)
    conn = db.connect(client.app.state.db_path)
    conn.execute("UPDATE analyses SET status = 'done', n_alerts = 3 WHERE id = ?", (aid,))
    token = csrf(client, "/network")
    client.post(f"/network/analyses/{aid}/files/delete", data={"csrf_token": token, "filename": "a.pcap"})
    row = conn.execute("SELECT status, n_alerts FROM analyses WHERE id = ?", (aid,)).fetchone()
    assert (row["status"], row["n_alerts"]) == ("pending", 0)
    assert [r[0] for r in conn.execute("SELECT filename FROM analysis_files")] == ["b.pcap"]
    assert not (ingest.pcap_dir(client.app.state.data_dir, aid) / "a.pcap").exists()
    client.post(f"/network/analyses/{aid}/files/delete", data={"csrf_token": token, "filename": "b.pcap"})
    assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 0
    r = client.post(f"/network/analyses/{aid}/files/delete", data={"csrf_token": token, "filename": "../x"})
    assert r.status_code == 404
