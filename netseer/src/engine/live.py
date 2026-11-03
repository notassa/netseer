"""Real-time mode (CONCEPTS A13, brief §6c): NIC discovery, the stall state machine, the capture unit and the tailer.

A live session is one `analyses` row (mode 'live') that moves through
waiting_interfaces → waiting_traffic → ready → running → stopped. A monitor thread in the app advances every open
session every POLL_S seconds and, while it runs, tails its eve.json every live processing interval: new lines go
through the logger (ACP 1–2), then ACP 3–6 is rebuilt for the session (incident ids are kept, A4).
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from netseer.src.config import analysis_lan, app_config, get_setting
from netseer.src.database import db
from netseer.src.engine.acp import run_acp
from netseer.src.engine.ingest import classification_file, eve_dir
from netseer.src.engine.logger import EveLogger, load_classtypes, parse_networks

SYS_NET = Path("/sys/class/net")
POLL_S = 5                            # state polls; waiting_traffic needs rx_packets to rise between two of them
OPEN_STATES = ("waiting_interfaces", "waiting_traffic", "ready", "running")
MESSAGES = {
    "waiting_interfaces": "Waiting for both network links: check the cables of {mirror} (mirror) and {lan} (LAN).",
    "waiting_traffic": "Waiting for traffic on {mirror}: check the switch mirror (SPAN) port.",
    "ready": "Traffic is arriving on {mirror}. Start the capture when you are ready.",
    "running": "Capturing on {mirror}.",
    "stopped": "Stopped.",
}

_rx: dict[int, int] = {}             # session → mirror rx_packets at the last poll
_inode: dict[int, int] = {}          # session → inode of its eve.json at the last read (rotation check)
_last_tick: dict[int, float] = {}
_lock = threading.Lock()              # one advance/tick pass at a time (monitor thread and Stop button)


class LiveError(ValueError):
    """A user-facing live-mode problem (bad NIC choice, capture unit failure)."""


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:                   # e.g. `carrier` of an interface that is administratively down
        return None


def interfaces(sys_net: Path = SYS_NET) -> list[dict]:
    """Physical NICs (no lo, no virtual ones) with operstate, carrier, MAC, rx packets and whether they have an IPv4."""
    try:
        addrs = json.loads(subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True).stdout or "[]")
    except (OSError, ValueError):
        addrs = []
    with_ip = {a["ifname"] for a in addrs if a.get("addr_info")}
    out = []
    for nic in sorted(sys_net.iterdir()):
        if nic.name == "lo" or not (nic / "device").exists():
            continue
        carrier = _read(nic / "carrier")
        rx = _read(nic / "statistics" / "rx_packets")
        out.append({"name": nic.name, "operstate": _read(nic / "operstate"), "carrier": carrier == "1",
                    "mac": _read(nic / "address"), "rx_packets": int(rx) if rx and rx.isdigit() else 0,
                    "has_ipv4": nic.name in with_ip})
    return out


def create_session(conn, mirror: str, lan: str, sys_net: Path = SYS_NET) -> int:
    """Open a new live session (one analysis record per session) in waiting_interfaces."""
    names = {n["name"]: n for n in interfaces(sys_net)}
    if mirror not in names or lan not in names:
        raise LiveError("Choose two network interfaces of this machine.")
    if mirror == lan:
        raise LiveError("The mirror and LAN interfaces must differ.")
    if conn.execute("SELECT 1 FROM analyses WHERE mode = 'live' AND status IN (?, ?, ?, ?)", OPEN_STATES).fetchone():
        raise LiveError("A live session is already open; stop it first.")
    name = f"Live — {mirror} — {datetime.now(timezone.utc):%Y-%m-%d %H:%M}"
    return conn.execute("INSERT INTO analyses(name, mode, status, created_at, mirror_if, lan_if) "
                        "VALUES (?, 'live', 'waiting_interfaces', ?, ?, ?)",
                        (name, db.utcnow(), mirror, lan)).lastrowid


def next_state(status: str, mirror: dict | None, lan: dict | None, rx_before: int | None) -> str:
    """The state machine (pure): where a session goes from `status` given the two NICs now."""
    links_up = bool(mirror and lan and mirror["carrier"] and lan["carrier"])
    if not links_up:
        return "waiting_interfaces" if status != "stopped" else status
    if status == "waiting_interfaces":
        return "waiting_traffic"
    if status == "waiting_traffic" and rx_before is not None and mirror["rx_packets"] > rx_before:
        return "ready"
    return status


def message(row) -> str:
    """Plain-language stall message for a session."""
    return MESSAGES.get(row["status"], "").format(mirror=row["mirror_if"], lan=row["lan_if"])


def _systemctl(action: str, nic: str) -> None:
    unit = f"netseer-live@{nic}.service"
    r = subprocess.run(["sudo", "-n", "systemctl", action, unit], capture_output=True, text=True)
    if r.returncode != 0:
        raise LiveError(f"Could not {action} {unit}: {(r.stderr or r.stdout).strip()[:300]}")


def _env_file(data_dir: Path, nic: str) -> Path:
    return Path(data_dir) / "eves" / f"live-{nic}.env"


def confirm(conn, data_dir: Path, analysis_id: int) -> None:
    """ready → running: write the unit's settings and start Suricata on the mirror NIC."""
    row = conn.execute("SELECT * FROM analyses WHERE id = ? AND mode = 'live'", (analysis_id,)).fetchone()
    if row is None or row["status"] != "ready":
        raise LiveError("The session is not ready yet.")
    out = eve_dir(data_dir, analysis_id).resolve()       # the unit does not run in our working directory
    out.mkdir(parents=True, exist_ok=True)
    external = "any" if get_setting(conn, "inside_rules") else "!$HOME_NET"
    _env_file(data_dir, row["mirror_if"]).write_text(
        f"OUT_DIR={out}\nHOME_NET=[{','.join(analysis_lan(conn, analysis_id))}]\nEXTERNAL_NET={external}\n")
    _systemctl("start", row["mirror_if"])
    conn.execute("UPDATE analyses SET status = 'running', started_at = ?, error = NULL WHERE id = ?",
                 (db.utcnow(), analysis_id))
    db.audit(conn, None, "live_started", f"analysis {analysis_id} on {row['mirror_if']}")


def stop(conn, data_dir: Path, analysis_id: int) -> None:
    """Stop a session: stop the capture unit (if it runs), read what is left, close the record."""
    with _lock:
        row = conn.execute("SELECT * FROM analyses WHERE id = ? AND mode = 'live'", (analysis_id,)).fetchone()
        if row is None or row["status"] not in OPEN_STATES:
            raise LiveError("This live session is not open.")
        if row["started_at"]:
            _systemctl("stop", row["mirror_if"])
            tick(conn, data_dir, analysis_id)
        conn.execute("UPDATE analyses SET status = 'stopped', stopped_at = ? WHERE id = ?", (db.utcnow(), analysis_id))
        db.audit(conn, None, "live_stopped", f"analysis {analysis_id}")
        for state in (_rx, _inode, _last_tick):
            state.pop(analysis_id, None)


def _new_lines(eve: Path, offset: int, analysis_id: int) -> tuple[list[str], int]:
    """Complete lines after `offset`; a new inode or a shorter file (rotation) starts again at 0."""
    try:
        st = eve.stat()
    except FileNotFoundError:
        return [], offset
    if _inode.get(analysis_id) not in (None, st.st_ino) or st.st_size < offset:
        offset = 0
    _inode[analysis_id] = st.st_ino
    with open(eve, "rb") as fh:
        fh.seek(offset)
        data = fh.read()
    end = data.rfind(b"\n") + 1                # a half-written last line waits for the next tick
    return data[:end].decode("utf-8", errors="replace").splitlines(), offset + end


def tick(conn, data_dir: Path, analysis_id: int) -> int:
    """Tail the session's eve.json: logger over the new lines, then ACP 3–6; returns the number of new lines.

    shortcut: the port-scan check sees one interval's flows at a time, so a scan slower than SCAN_MIN_PORTS
    ports per interval is missed; keep probe counts across ticks if that matters.
    """
    row = conn.execute("SELECT eve_offset FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    lines, offset = _new_lines(eve_dir(data_dir, analysis_id) / "eve.json", row["eve_offset"], analysis_id)
    _last_tick[analysis_id] = time.monotonic()
    if not lines:
        if offset != row["eve_offset"]:
            conn.execute("UPDATE analyses SET eve_offset = ? WHERE id = ?", (offset, analysis_id))
        return 0
    log = EveLogger(analysis_id, parse_networks(analysis_lan(conn, analysis_id)), str(app_config("oui_csv")),
                    load_classtypes(classification_file()))
    for line in lines:
        log.feed(conn, line)
    log.finish(conn)
    conn.execute("UPDATE analyses SET eve_offset = ? WHERE id = ?", (offset, analysis_id))
    if log.n_alerts:
        run_acp(conn, analysis_id)
    return len(lines)


def advance(conn, data_dir: Path, sys_net: Path = SYS_NET) -> None:
    """One monitor pass: move every open session through the state machine and tail the running ones."""
    with _lock:
        nics = {n["name"]: n for n in interfaces(sys_net)}
        interval = float(get_setting(conn, "live_interval_s"))
        for row in conn.execute("SELECT * FROM analyses WHERE mode = 'live' AND status IN (?, ?, ?, ?)",
                                OPEN_STATES).fetchall():
            mirror, lan = nics.get(row["mirror_if"]), nics.get(row["lan_if"])
            status = row["status"]
            new = next_state(status, mirror, lan, _rx.get(row["id"]))
            if status == "running" and new == "waiting_interfaces":
                conn.execute("UPDATE analyses SET status = ?, error = ? WHERE id = ?",
                             (new, "A link dropped while capturing; data so far is kept.", row["id"]))
                db.audit(conn, None, "live_link_down", f"analysis {row['id']}")
            elif row["started_at"] and new == "waiting_traffic":
                # the capture was started before: links are back, so carry on capturing
                conn.execute("UPDATE analyses SET status = 'running', error = NULL WHERE id = ?", (row["id"],))
                new = "running"
            elif new != status:
                conn.execute("UPDATE analyses SET status = ? WHERE id = ?", (new, row["id"]))
            if mirror:
                _rx[row["id"]] = mirror["rx_packets"]
            if new == "running" and time.monotonic() - _last_tick.get(row["id"], 0) >= interval:
                tick(conn, data_dir, row["id"])


def start_monitor(db_path: Path, data_dir: Path) -> threading.Thread:
    """Run `advance` every POLL_S seconds in a daemon thread for the app's lifetime."""
    def loop() -> None:
        while True:
            conn = db.connect(db_path)
            try:
                advance(conn, data_dir)
            except Exception as exc:  # noqa: BLE001 - keep monitoring; the failure is logged
                db.audit(conn, None, "live_error", str(exc)[:500])
            finally:
                conn.close()
            time.sleep(POLL_S)
    thread = threading.Thread(target=loop, name="netseer-live", daemon=True)
    thread.start()
    return thread


def can_control(nic: str) -> bool:
    """True when sudo lets this user start the capture unit for `nic` without a password."""
    r = subprocess.run(["sudo", "-n", "-l", "/usr/bin/systemctl", "start", f"netseer-live@{nic}.service"],
                       capture_output=True, text=True)
    return r.returncode == 0
