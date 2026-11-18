"""Offline ingest (brief §6a): validate pcaps, merge them, run Suricata, then ACP 1–2.

Status flow: queued → running_suricata → processing → awaiting_attribution → done | failed | stopped.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from netseer.src.config import CONFIG_DIR, SURICATA_CONFIG, adopt_lan, analysis_lan, app_config, get_setting
from netseer.src.database import db
from netseer.src.engine import oui, ti
from netseer.src.engine.acp import rescore, run_acp
from netseer.src.engine.capture_check import run_checks
from netseer.src.engine.logger import process_eve_file
from netseer.src.engine.networks import run_discovery, to_adopt
from netseer.src.engine.oui import sll_macs, vendor_for

PCAP_MAGICS = {bytes.fromhex(m) for m in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a")}
ACTIVE_STATUSES = ("uploading", "queued", "running_suricata", "processing")
CHUNK = 1 << 20

_run_lock = threading.Lock()     # one Suricata run at a time: rule loading alone needs ~1 GB RAM
_progress_lock = threading.Lock()
PROGRESS: dict[int, dict] = {}
_expected: dict[int, tuple[str, int, str | None]] = {}  # open uploads: id → (file name, size, previous status)
_stop: set[int] = set()          # analyses whose run the administrator stopped


class IngestError(ValueError):
    """A user-facing ingest failure (bad file, size cap, tool error)."""


class Stopped(IngestError):
    """The administrator stopped the run."""


def stop(conn: sqlite3.Connection, data_dir: Path, analysis_id: int) -> None:
    """Stop an offline job at its next progress check (about a second); results are cleared, captures kept.

    An analysis left active by a restart has no job, so it is cleared at once.
    """
    if get_progress(analysis_id) is not None:
        _stop.add(analysis_id)
    else:
        _clear_stopped(conn, data_dir, analysis_id)


def _clear_stopped(conn: sqlite3.Connection, data_dir: Path, analysis_id: int) -> None:
    if conn.in_transaction:
        conn.execute("ROLLBACK")
    _clear_results(conn, analysis_id)
    shutil.rmtree(eve_dir(data_dir, analysis_id), ignore_errors=True)
    (pcap_dir(data_dir, analysis_id) / "merged.pcap").unlink(missing_ok=True)
    _set_status(conn, analysis_id, "stopped", stopped_at=db.utcnow())
    db.audit(conn, None, "analysis_stopped", f"analysis {analysis_id}: stopped; results cleared, captures kept")


def _check_stop(analysis_id: int) -> None:
    if analysis_id in _stop:
        raise Stopped("Stopped by the administrator.")


def is_pcap_magic(head: bytes) -> bool:
    """True if the first four bytes are a pcap (any byte order / ns variant) or pcapng magic."""
    return head[:4] in PCAP_MAGICS


def is_capture_header(head: bytes) -> bool:
    """True if the first 28 bytes are a real pcap global header (version 2.x, snaplen > 0) or a pcapng Section
    Header Block (byte-order magic 0x1A2B3C4D), not just the right 4-byte magic."""
    if len(head) < 24 or not is_pcap_magic(head):
        return False
    if head[:4] == bytes.fromhex("0a0d0d0a"):
        return len(head) >= 12 and head[8:12] in (bytes.fromhex("4d3c2b1a"), bytes.fromhex("1a2b3c4d"))
    order = "<" if head[:4] in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")) else ">"
    major, _minor, _zone, _sigfigs, snaplen = struct.unpack(order + "HHiII", head[4:20])
    return major == 2 and snaplen > 0


def safe_filename(name: str) -> str:
    """Basename restricted to [A-Za-z0-9._-], at most 100 characters."""
    base = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or "").name).strip("._") or "capture.pcap"
    return base[-100:]


def auto_name(filenames: list[str], when: datetime) -> str:
    """Offline — <first file> (+N) — <YYYY-MM-DD HH:MM> (CONCEPTS A13)."""
    extra = f" (+{len(filenames) - 1})" if len(filenames) > 1 else ""
    return f"Offline — {filenames[0]}{extra} — {when:%Y-%m-%d %H:%M}"


def pcap_dir(data_dir: Path, analysis_id: int) -> Path:
    """Directory holding an analysis's uploaded (and merged) captures."""
    return Path(data_dir) / "pcaps" / str(analysis_id)


def eve_dir(data_dir: Path, analysis_id: int) -> Path:
    """Directory holding an analysis's Suricata output."""
    return Path(data_dir) / "eves" / str(analysis_id)


def set_progress(analysis_id: int, stage: str, pct: float | None = None, detail: str = "") -> None:
    """Record the live stage of a job (in memory: one uvicorn process; lost on restart, like the job itself)."""
    with _progress_lock:
        PROGRESS[analysis_id] = {"stage": stage, "pct": None if pct is None else round(min(pct, 100.0), 1),
                                 "detail": detail}


def get_progress(analysis_id: int) -> dict | None:
    """The live stage of a job, or None when no job is running for it."""
    with _progress_lock:
        return PROGRESS.get(analysis_id)


def begin_upload(conn: sqlite3.Connection, data_dir: Path, name: str, size: int, max_file_bytes: int,
                 analysis_id: int | None = None) -> int:
    """Open a one-file upload into a new session or an existing offline session; return the analysis id.

    Checks the per-file cap and free disk. The analysis stays `uploading` until `finish_upload`.
    """
    if size > max_file_bytes:
        raise IngestError(f"{Path(name).name} is larger than the {max_file_bytes // (1 << 20)} MB per-file limit.")
    factor = float(app_config("min_free_disk_factor"))
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(data_dir).free
    if free < size * factor:
        raise IngestError(f"Not enough free disk space: {free / (1 << 30):.1f} GB free, about "
                          f"{size * factor / (1 << 30):.1f} GB needed. Delete old analyses first.")
    stored = safe_filename(name)
    if analysis_id is None:
        cur = conn.execute("INSERT INTO analyses(name, mode, status, created_at) VALUES (?, 'offline', 'uploading', ?)",
                           (auto_name([stored], datetime.now()), db.utcnow()))
        analysis_id, previous = int(cur.lastrowid), None
    else:
        row = conn.execute("SELECT mode, status FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        if row is None or row["mode"] != "offline":
            raise IngestError("Choose an existing offline session or start a new one.")
        if row["status"] in ACTIVE_STATUSES:
            raise IngestError("This session is busy (uploading or analysing). Wait for it to finish.")
        taken = {r[0] for r in conn.execute("SELECT filename FROM analysis_files WHERE analysis_id = ?", (analysis_id,))}
        base, n = stored, 1
        while stored in taken | {"merged.pcap"}:
            stored, n = f"{n}_{base}", n + 1
        previous = row["status"]
        conn.execute("UPDATE analyses SET status = 'uploading' WHERE id = ?", (analysis_id,))
    pcap_dir(data_dir, analysis_id).mkdir(parents=True, exist_ok=True)
    _expected[analysis_id] = (stored, size, previous)
    return analysis_id


class FileSink:
    """Streams one uploaded file to disk: magic check on the first bytes, size cap, SHA-256."""

    def __init__(self, conn: sqlite3.Connection, data_dir: Path, analysis_id: int, max_bytes: int):
        if analysis_id not in _expected:
            raise IngestError("This upload is not open (it may have been cancelled or NetSeer restarted).")
        self.conn, self.analysis_id, self.max_bytes = conn, analysis_id, max_bytes
        self.name, self.expected_size, _ = _expected[analysis_id]
        self.path = pcap_dir(data_dir, analysis_id) / self.name
        self.digest, self.size, self.head = hashlib.sha256(), 0, b""
        self.out = open(self.path, "wb")

    def write(self, chunk: bytes) -> None:
        """Append a chunk; raise IngestError on a bad magic number or when the cap is passed."""
        if len(self.head) < 28:
            self.head += chunk[:28 - len(self.head)]
            if len(self.head) >= 4 and not is_pcap_magic(self.head):
                raise IngestError(f"{self.name} is not a pcap or pcapng file.")
        self.size += len(chunk)
        if self.size > self.max_bytes:
            raise IngestError(f"{self.name} is larger than the {self.max_bytes // (1 << 20)} MB per-file limit.")
        self.digest.update(chunk)
        self.out.write(chunk)

    def finish(self) -> None:
        """Close the file and record it in analysis_files; refuse a broken header or a file already uploaded."""
        self.out.close()
        if not is_capture_header(self.head):
            raise IngestError(f"{self.name} is not a valid pcap or pcapng file (bad file header).")
        if self.size != self.expected_size:
            raise IngestError(f"Upload of {self.name} is incomplete: got {self.size} of {self.expected_size} bytes.")
        dup = self.conn.execute("SELECT f.filename, a.name FROM analysis_files f JOIN analyses a ON a.id = f.analysis_id "
                                "WHERE f.sha256 = ?", (self.digest.hexdigest(),)).fetchone()
        if dup:
            raise IngestError(f"{self.name} was already uploaded (as {dup[0]} in \"{dup[1]}\"); each capture is kept once.")
        self.conn.execute("INSERT INTO analysis_files(analysis_id, filename, sha256, size) VALUES (?, ?, ?, ?)",
                          (self.analysis_id, self.name, self.digest.hexdigest(), self.size))


def abort_upload(conn: sqlite3.Connection, data_dir: Path, analysis_id: int) -> None:
    """Undo a failed upload: a new session disappears; an existing session keeps its earlier files and status."""
    name, _, previous = _expected.pop(analysis_id, (None, 0, None))
    if previous is None:
        conn.execute("DELETE FROM analyses WHERE id = ? AND status = 'uploading'", (analysis_id,))
        shutil.rmtree(pcap_dir(data_dir, analysis_id), ignore_errors=True)
        return
    conn.execute("DELETE FROM analysis_files WHERE analysis_id = ? AND filename = ?", (analysis_id, name))
    (pcap_dir(data_dir, analysis_id) / name).unlink(missing_ok=True)
    conn.execute("UPDATE analyses SET status = ? WHERE id = ?", (previous, analysis_id))


def finish_upload(conn: sqlite3.Connection, analysis_id: int) -> None:
    """Close the upload once its file is stored; the session waits as `pending` until it is analysed."""
    entry = _expected.get(analysis_id)
    stored = {r[0] for r in conn.execute("SELECT filename FROM analysis_files WHERE analysis_id = ?", (analysis_id,))}
    if entry is None or entry[0] not in stored:
        raise IngestError("The file has not finished uploading.")
    del _expected[analysis_id]
    conn.execute("UPDATE analyses SET status = 'pending' WHERE id = ?", (analysis_id,))


def create_offline_analysis(conn: sqlite3.Connection, data_dir: Path, uploads: Iterable[tuple[str, BinaryIO]],
                            max_file_bytes: int) -> int:
    """Store local captures (CLI, tests) as one session, file by file, through the same checks as the web upload."""
    analysis_id: int | None = None
    try:
        for name, fh in uploads:
            size = fh.seek(0, os.SEEK_END)
            fh.seek(0)
            analysis_id = begin_upload(conn, data_dir, name, size, max_file_bytes, analysis_id)
            sink = FileSink(conn, data_dir, analysis_id, max_file_bytes)
            try:
                while chunk := fh.read(CHUNK):
                    sink.write(chunk)
            finally:
                sink.out.close()
            sink.finish()
            finish_upload(conn, analysis_id)
    except BaseException:
        if analysis_id is not None:
            _expected.pop(analysis_id, None)
            delete_analysis(conn, data_dir, analysis_id, force=True)
        raise
    if analysis_id is None:
        raise IngestError("Choose at least one pcap or pcapng file.")
    conn.execute("UPDATE analyses SET status = 'queued' WHERE id = ?", (analysis_id,))
    return analysis_id


def read_position(pid: int, path: Path) -> int | None:
    """Byte offset process `pid` has reached in `path` (from /proc/<pid>/fdinfo), or None if not open."""
    target = str(Path(path).resolve())
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                with open(f"/proc/{pid}/fdinfo/{fd}") as fh:
                    return int(fh.readline().split()[1])     # first line: "pos:\t<offset>"
    except (OSError, ValueError, IndexError):
        pass
    return None


def _run(cmd: list[str], what: str, poll: Callable[[int], None] | None = None) -> None:
    """Run a tool; call `poll(pid)` every second while it runs; raise IngestError on failure."""
    with subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as proc:
        while True:
            try:
                proc.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                if poll:
                    try:
                        poll(proc.pid)
                    except Stopped:
                        proc.terminate()
                        proc.wait()
                        raise
        stderr = proc.stderr.read() if proc.stderr else ""
    if proc.returncode != 0:
        tail = stderr.strip().splitlines()[-3:]
        raise IngestError(f"{what} failed (exit {proc.returncode}): {' | '.join(tail)}")


def merge_captures(files: list[Path], out: Path, analysis_id: int | None = None) -> Path:
    """Merge captures in chronological order into one classic pcap.

    Classic pcap, not pcapng: mergecap keeps one pcapng interface per input, and libpcap (Suricata) refuses
    a file whose interfaces differ in snaplen or link type.
    """
    total = sum(f.stat().st_size for f in files) or 1

    def poll(_pid: int) -> None:
        if analysis_id is not None:
            _check_stop(analysis_id)
        if analysis_id is not None and out.exists():
            set_progress(analysis_id, "merging", 100 * out.stat().st_size / total)
    _run([str(app_config("mergecap_bin")), "-F", "pcap", "-w", str(out), *map(str, files)], "mergecap", poll)
    return out


def classification_file() -> str:
    """Suricata's classification.config, or the repo copy when the rules directory is unreadable."""
    path = str(app_config("classification_file"))
    return path if os.access(path, os.R_OK) else str(CONFIG_DIR / "suricata" / "classification.config")


def _set_status(conn: sqlite3.Connection, analysis_id: int, status: str, **cols: str | None) -> None:
    sets = ", ".join(["status = ?"] + [f"{c} = ?" for c in cols])
    conn.execute(f"UPDATE analyses SET {sets} WHERE id = ?", (status, *cols.values(), analysis_id))


def _detect(conn: sqlite3.Connection, data_dir: Path, analysis_id: int, capture: Path) -> tuple:
    """Run Suricata with the analysis's LAN as HOME_NET, read its eve.json (ACP 1–2) and discover the networks.
    Returns (logger, networks, truncation warning or None)."""
    out = eve_dir(data_dir, analysis_id)
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    lan = analysis_lan(conn, analysis_id)
    size = capture.stat().st_size or 1

    def suricata_poll(pid: int) -> None:
        _check_stop(analysis_id)
        pos = read_position(pid, capture)
        if pos:
            set_progress(analysis_id, "reading capture", 100 * pos / size)
        elif (get_progress(analysis_id) or {}).get("stage") != "reading capture":
            set_progress(analysis_id, "loading rules")
    _set_status(conn, analysis_id, "running_suricata")
    set_progress(analysis_id, "loading rules")
    _run([str(app_config("suricata_bin")), "-c", str(SURICATA_CONFIG), "-r", str(capture), "-l", str(out),
          "-k", "none", "--set", f"vars.address-groups.HOME_NET=[{','.join(lan)}]",
          # inside_rules: ET rules written as $EXTERNAL_NET → $HOME_NET also fire for an attacker inside the LAN
          *(["--set", "vars.address-groups.EXTERNAL_NET=any"] if get_setting(conn, "inside_rules") else [])], "Suricata", suricata_poll)
    eve = out / "eve.json"
    if not eve.exists():
        raise IngestError("Suricata produced no eve.json.")
    warning = _check_suricata_read(out)
    if warning:
        db.audit(conn, None, "capture_truncated", f"analysis {analysis_id}: {warning}")
    _set_status(conn, analysis_id, "processing")
    set_progress(analysis_id, "processing", 0)

    def on_progress(fraction: float) -> None:
        _check_stop(analysis_id)
        set_progress(analysis_id, "processing", 100 * fraction)
    log = process_eve_file(conn, analysis_id, eve, lan, str(app_config("oui_csv")), classification_file(),
                           on_progress=on_progress)
    if macs := sll_macs(capture):        # Linux cooked capture: no Ethernet header, so no MACs in eve.json
        oui_csv = str(app_config("oui_csv"))
        conn.executemany("UPDATE devices SET mac = ?, vendor = ? WHERE analysis_id = ? AND ip = ? AND mac IS NULL",
                         [(mac, vendor_for(mac, oui_csv), analysis_id, ip) for ip, mac in macs.items()])
    return log, run_discovery(conn, analysis_id, log.evidence), warning


def run_offline(db_path: Path, data_dir: Path, analysis_id: int) -> None:
    """Background job: merge the captures, run Suricata, run ACP 1–6 and the capture checks, then await attribution."""
    conn = db.connect(db_path)
    started = time.monotonic()
    merged: Path | None = None
    try:
        with _run_lock:
            _check_stop(analysis_id)           # stopped while queued behind another run
            _set_status(conn, analysis_id, "running_suricata", started_at=db.utcnow())
            files = [pcap_dir(data_dir, analysis_id) / r["filename"] for r in conn.execute(
                "SELECT filename FROM analysis_files WHERE analysis_id = ? ORDER BY rowid", (analysis_id,))]
            capture = files[0]
            if len(files) > 1:
                set_progress(analysis_id, "merging", 0)
                capture = merged = merge_captures(files, pcap_dir(data_dir, analysis_id) / "merged.pcap", analysis_id)
            size = capture.stat().st_size or 1
            log, nets, warning = _detect(conn, data_dir, analysis_id, capture)
            if adopt := to_adopt(conn, analysis_id, nets):
                adopt_lan(conn, analysis_id, analysis_lan(conn, analysis_id) + adopt)
                db.audit(conn, None, "lan_adopted", f"analysis {analysis_id}: {', '.join(adopt)} looked local; "
                                                    "analysing again with them as LAN")
                _clear_results(conn, analysis_id)
                log, nets, warning = _detect(conn, data_dir, analysis_id, capture)
            _check_stop(analysis_id)
            set_progress(analysis_id, "correlating")
            acp = run_acp(conn, analysis_id)
            set_progress(analysis_id, "checking capture")
            run_checks(conn, analysis_id, pcap_dir(data_dir, analysis_id), eve_dir(data_dir, analysis_id) / "eve.json", warning)
            if merged is not None:
                merged.unlink(missing_ok=True)       # originals are kept; the merged copy is rebuildable
            n_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
            pending = conn.execute("SELECT 1 FROM devices WHERE analysis_id = ? AND attributed = 0",
                                   (analysis_id,)).fetchone()
            _set_status(conn, analysis_id, "awaiting_attribution" if pending else "done", stopped_at=db.utcnow(),
                        error=warning)
            secs = time.monotonic() - started
            db.audit(conn, None, "analysis_succeeded",
                     f"analysis {analysis_id}: {size / (1 << 20):.0f} MB in {secs:.0f} s "
                     f"({size / (1 << 20) / max(secs, 0.001):.1f} MB/s), {log.n_events} events, "
                     f"{log.n_alerts} alerts, {n_devices} devices, {acp['groups']} alert groups, "
                     f"{acp['incidents']} possible incidents")
        oui.online_vendors(conn, analysis_id)          # A3: fill unknown vendors from maclookup.app
        if ti.enrich(conn, analysis_id):     # optional TI, outside the Suricata lock; re-score with L5
            rescore(conn, analysis_id)
    except Stopped:
        _clear_stopped(conn, data_dir, analysis_id)
    except Exception as exc:  # noqa: BLE001 - any failure is recorded on the analysis and shown in the UI
        _set_status(conn, analysis_id, "failed", error=str(exc)[:500], stopped_at=db.utcnow())
        db.audit(conn, None, "analysis_failed", f"analysis {analysis_id}: {exc}{_suricata_log_tail(data_dir, analysis_id)}"[:1000])
    finally:
        _stop.discard(analysis_id)
        with _progress_lock:
            PROGRESS.pop(analysis_id, None)
        conn.close()


def _check_suricata_read(out: Path) -> str | None:
    """Read Suricata's log: raise if it could not open the capture (it still exits 0); return a warning
    when the capture ends mid-packet (the recording was cut off), else None."""
    try:
        log = (out / "suricata.log").read_text(errors="replace")
    except OSError:
        return None
    lines = log.splitlines()
    for line in lines:
        if "Failed to init pcap file" in line or "pcap file reader thread failed" in line:
            raise IngestError(f"Suricata could not read the capture: {line.split(': ', 2)[-1]}")
    if not any("Error: pcap:" in line for line in lines):
        return None
    packets = next((m.group(1) for line in lines if (m := re.search(r"pcap: read .*?([\d,]+) packets", line))), "all")
    return (f"Note: the capture ends mid-packet (the recording was cut off); the {packets} packets "
            "before that point were analysed.")


def _suricata_log_tail(data_dir: Path, analysis_id: int) -> str:
    try:
        lines = (eve_dir(data_dir, analysis_id) / "suricata.log").read_text(errors="replace").strip().splitlines()
    except OSError:
        return ""
    return " | suricata.log: " + " | ".join(lines[-3:]) if lines else ""


def mark_interrupted(conn: sqlite3.Connection) -> None:
    """At start-up, fail offline jobs that were cut off by a restart."""
    rows = conn.execute(f"SELECT id FROM analyses WHERE mode = 'offline' AND status IN "
                        f"({','.join('?' * len(ACTIVE_STATUSES))})", ACTIVE_STATUSES).fetchall()
    for row in rows:
        conn.execute("UPDATE analyses SET status = 'failed', error = 'Interrupted by a NetSeer restart; upload again.' "
                     "WHERE id = ?", (row["id"],))
        db.audit(conn, None, "analysis_interrupted", f"analysis {row['id']}: NetSeer restarted during the job")


def delete_analysis(conn: sqlite3.Connection, data_dir: Path, analysis_id: int, force: bool = False) -> None:
    """Delete an analysis, its rows (cascade) and its stored captures and Suricata output."""
    row = conn.execute("SELECT status FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        raise IngestError("No such analysis.")
    if row["status"] in ACTIVE_STATUSES and not force:
        raise IngestError("This analysis is still running. Wait for it to finish before deleting it.")
    conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.execute("DELETE FROM settings WHERE key = ?", (f"lan_cidrs:{analysis_id}",))
    shutil.rmtree(pcap_dir(data_dir, analysis_id), ignore_errors=True)
    shutil.rmtree(eve_dir(data_dir, analysis_id), ignore_errors=True)


def delete_file(conn: sqlite3.Connection, data_dir: Path, analysis_id: int, filename: str) -> bool:
    """Remove one capture from an offline session: its results are cleared and it waits as `pending` for
    Analyse. Deleting the last file deletes the session; returns True then."""
    row = conn.execute("SELECT status FROM analyses WHERE id = ? AND mode = 'offline'", (analysis_id,)).fetchone()
    if row is None:
        raise IngestError("No such offline session.")
    if row["status"] in ACTIVE_STATUSES:
        raise IngestError("This session is busy (uploading or analysing). Wait for it to finish.")
    if conn.execute("DELETE FROM analysis_files WHERE analysis_id = ? AND filename = ?",
                    (analysis_id, filename)).rowcount == 0:
        raise IngestError("No such file in this session.")
    (pcap_dir(data_dir, analysis_id) / filename).unlink(missing_ok=True)
    if not conn.execute("SELECT 1 FROM analysis_files WHERE analysis_id = ?", (analysis_id,)).fetchone():
        delete_analysis(conn, data_dir, analysis_id)
        return True
    _clear_results(conn, analysis_id)
    conn.execute("DELETE FROM analysis_info WHERE analysis_id = ? AND kind = 'capture'", (analysis_id,))
    conn.execute("UPDATE analyses SET status = 'pending', error = NULL, started_at = NULL, stopped_at = NULL "
                 "WHERE id = ?", (analysis_id,))
    shutil.rmtree(eve_dir(data_dir, analysis_id), ignore_errors=True)
    return False


def _clear_results(conn: sqlite3.Connection, analysis_id: int, commit: bool = True) -> None:
    """Delete everything an analysis run produced (its captures, files and settings stay)."""
    if commit:
        conn.execute("BEGIN")
    for table in ("incidents", "alert_groups", "alerts", "devices", "packet_stats", "external_hosts", "analysis_info",
                  "host_links"):
        conn.execute(f"DELETE FROM {table} WHERE analysis_id = ?", (analysis_id,))
    conn.execute("UPDATE analyses SET n_events = 0, n_alerts = 0 WHERE id = ?", (analysis_id,))
    if commit:
        conn.execute("COMMIT")


def reset_analysis(conn: sqlite3.Connection, data_dir: Path, analysis_id: int) -> None:
    """Clear an analysis's results so its stored captures can be analysed again; leaves it queued."""
    row = conn.execute("SELECT status FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        raise IngestError("No such analysis.")
    if row["status"] in ACTIVE_STATUSES:
        raise IngestError("This analysis is still running.")
    files = [r[0] for r in conn.execute("SELECT filename FROM analysis_files WHERE analysis_id = ?", (analysis_id,))]
    if not files or not all((pcap_dir(data_dir, analysis_id) / f).exists() for f in files):
        raise IngestError("The stored capture files are missing; upload them again.")
    conn.execute("BEGIN")
    _clear_results(conn, analysis_id, commit=False)
    conn.execute("UPDATE analyses SET status = 'queued', error = NULL, "
                 "started_at = NULL, stopped_at = NULL WHERE id = ?", (analysis_id,))
    conn.execute("COMMIT")
    shutil.rmtree(eve_dir(data_dir, analysis_id), ignore_errors=True)
    _stop.discard(analysis_id)
    set_progress(analysis_id, "queued")


def detonate(conn: sqlite3.Connection, data_dir: Path) -> None:
    """Factory reset: delete every row and every stored capture/eve file (keeps .gitkeep)."""
    conn.execute("BEGIN")
    for table in ("analyses", "interpretations", "sessions", "users", "login_attempts", "audit_log",
                  "settings", "api_keys", "ti_cache", "ip_names"):
        conn.execute(f"DELETE FROM {table}")      # analyses cascades to files, alerts, devices, groups, incidents
    conn.execute("COMMIT")
    conn.execute("VACUUM")
    for sub in ("pcaps", "eves"):
        for child in (Path(data_dir) / sub).glob("*"):
            if child.name != ".gitkeep":
                shutil.rmtree(child) if child.is_dir() else child.unlink()
    with _progress_lock:
        PROGRESS.clear()
    _expected.clear()
