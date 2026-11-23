"""Capture checks (CONCEPTS A16): gaps, overlaps, duplicates, silent stretches and capture loss."""

from __future__ import annotations

import json
import shutil

import pytest

from netseer.src.database import db
from netseer.src.engine import capture_check as cc
from netseer.tests import pcapgen

CAPINFOS = ("File name,File encapsulation,Packet size limit,Packet size limit min (inferred),Packet size limit max "
            "(inferred),Number of packets,Start time,End time,Strict time order\n"
            "14.pcap,linux-sll,65535,n/a,n/a,3463943,1424241354.956536,1424242847.889266,True\n")


def facts(name, start, end, sha="a", packets=10, encap="ether", snap=65535, order=True):
    return cc.FileFacts(name, sha, encap, snap, packets, start, end, order)


def titles(findings):
    return [t for _, t, _ in findings]


def test_parse_capinfos_row():
    row = cc.parse_capinfos(CAPINFOS)
    assert row["File encapsulation"] == "linux-sll" and row["Number of packets"] == "3463943"
    assert float(row["End time"]) - float(row["Start time"]) == pytest.approx(1492.93273)


def test_gap_between_files_is_reported():
    found = cc.file_findings([facts("14.pcap", 1424241354.9, 1424242847.9, "x"),
                              facts("16.pcap", 1424244396.0, 1424246006.8, "y")])
    assert found[0][1].startswith("2 files, 20 packets · 2015-02-18 06:35:54 to 2015-02-18 07:53:26 UTC")
    gap = [f for f in found if "may be missing" in f[1]]
    assert len(gap) == 1 and gap[0][0] == "warning"
    assert "No packets for 25 min 48 s between 14.pcap (ends 2015-02-18 07:00:47)" in gap[0][1]


def test_overlap_duplicate_and_mixed_formats():
    found = cc.file_findings([facts("a.pcap", 100, 200, "same"), facts("b.pcap", 150, 260, "same", snap=96,
                                                                       encap="linux-sll", order=False)])
    text = " | ".join(titles(found))
    assert "overlap for 50 s" in text and "same file as a.pcap" in text
    assert "different link types" in text and "different snapshot lengths (96, 65535 bytes)" in text
    assert "b.pcap: packets are not in time order" in text


def test_small_gap_and_touching_files_are_fine():
    found = cc.file_findings([facts("a", 0, 100, "1"), facts("b", 130, 200, "2"), facts("c", 200.5, 300, "3")])
    assert titles(found)[1:] == []


@pytest.fixture()
def conn(tmp_path):
    db.init_db(tmp_path / "t.db")
    c = db.connect(tmp_path / "t.db")
    c.execute("INSERT INTO analyses(id, name, mode, status, created_at) VALUES (1, 'a', 'offline', 'done', 'x')")
    yield c
    c.close()


def test_silent_stretch_inside_the_capture(conn):
    for m in ("09:00", "09:01", "09:02", "09:11", "09:12", "09:14"):
        conn.execute("INSERT INTO packet_stats(analysis_id, minute, packets, bytes) VALUES (1, ?, 5, 500)", (f"2026-10-21T{m}",))
    found = cc.silent_stretches(conn, 1)
    assert titles(found) == ["No traffic for 8 min (2026-10-21 09:03 to 09:11 UTC) inside the capture: the network "
                             "was quiet or the capture paused"]
    gap = (found[0][2]["start"], found[0][2]["end"])
    from datetime import datetime
    skip = [(datetime.fromisoformat(gap[0]).timestamp(), datetime.fromisoformat(gap[1]).timestamp())]
    assert cc.silent_stretches(conn, 1, skip) == []      # already reported as a gap between files


def test_capture_loss_from_suricata_stats(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text('{"event_type":"flow"}\n' + json.dumps({"event_type": "stats", "stats": {
        "decoder": {"pkts": 1000, "invalid": 3}, "tcp": {"reassembly_gap": 90625, "sessions": 5000}}}) + "\n")
    found = cc.loss_findings(cc.last_stats(eve))
    assert [lv for lv, _, _ in found] == ["warning", "info"]
    assert found[0][1].startswith("90,625 TCP reassembly gaps across 5,000 TCP sessions")
    assert cc.loss_findings(None) == [] and cc.last_stats(tmp_path / "missing.json") is None


@pytest.mark.skipif(shutil.which("capinfos") is None, reason="needs capinfos (wireshark-common)")
def test_run_checks_on_real_files(conn, tmp_path):
    a = pcapgen.demo_part_a(tmp_path / "a.pcap")
    b = pcapgen.demo_part_b(tmp_path / "b.pcap")
    for f in (a, b, a):
        conn.execute("INSERT INTO analysis_files VALUES (1, ?, ?, ?)", (f.name, f"sha-{f.name}", f.stat().st_size))
    n = cc.run_checks(conn, 1, tmp_path, tmp_path / "eve.json", truncated="Note: the capture ends mid-packet")
    rows = conn.execute("SELECT level, title FROM analysis_info WHERE analysis_id = 1 ORDER BY id").fetchall()
    assert n == len(rows)
    text = " | ".join(r["title"] for r in rows)
    assert rows[0]["title"].startswith("3 files")
    assert "between a.pcap" in text and "may be missing" in text          # demo part B starts an hour later
    assert "b.pcap and a.pcap overlap" in text or "a.pcap and b.pcap overlap" in text or "same file" in text
    assert rows[-1]["title"] == "Note: the capture ends mid-packet"
    cc.run_checks(conn, 1, tmp_path, tmp_path / "eve.json")              # re-running replaces the rows
    assert conn.execute("SELECT COUNT(*) FROM analysis_info").fetchone()[0] == n - 1
