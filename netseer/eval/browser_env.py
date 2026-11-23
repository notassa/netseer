"""Throwaway browser-check environment: a cleaned copy of the NetSeer database and a server to run it.

A browser check (e.g. a Playwright script) must not touch the real database. This module copies the real
database (read-only, safe while the live site runs), strips accounts/sessions/keys and any open capture, then
boots a server on the copy with credentials for the check. The check receives the URL and credentials through
NETSEER_E2E_URL / NETSEER_E2E_USER / NETSEER_E2E_PASSWORD.

Usage:
  python -m netseer.eval.browser_env --port 8765 -- <command...>
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from netseer.src.api.auth import create_account
from netseer.src.config import DEFAULT_DB_PATH, set_setting
from netseer.src.database import db
from netseer.src.engine import live

E2E_USERNAME = "e2eadmin"
PLAYWRIGHT_BROWSERS = Path("~/.local/share/netseer-playwright/browsers").expanduser()


def prepare_copy(source: Path, target: Path) -> tuple[str, str]:
    """Copy `source` to `target`, clean it and return the (username, password) of the throwaway admin."""
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()

    db.init_db(target)   # migrations only; never touches the source

    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    try:
        # foreign keys stay off so audit rows (user_id without a live user) survive the wipe.
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM login_attempts")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM api_keys")
        conn.execute("UPDATE analyses SET status = 'stopped' WHERE mode = 'live' AND status IN (?, ?, ?, ?)",
                     live.OPEN_STATES)
        set_setting(conn, "mac_lookup_online", False)   # no network lookups from the throwaway copy
        password = secrets.token_urlsafe(24) + "aA1!"
        create_account(conn, E2E_USERNAME, password, password, "admin")
        conn.commit()
    finally:
        conn.close()
    return E2E_USERNAME, password


def _check_port_free(port: int) -> None:
    """Raise SystemExit when something already listens on 127.0.0.1:`port`."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(f"Port {port} is already in use on 127.0.0.1; free it before running the check.")


def _stop_server(proc: subprocess.Popen) -> None:
    """Terminate the server, wait up to 10 s, then kill it."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _wait_for_login(proc: subprocess.Popen, port: int, timeout: float) -> bool:
    """True once GET /login answers; False if the server exits or `timeout` seconds pass."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=1.0):
                return True
        except urllib.error.HTTPError:
            return True   # the server answered, even if the page errored
        except OSError:
            time.sleep(0.2)
    return False


def run(command: list[str], port: int, source: Path) -> int:
    """Boot a cleaned copy on 127.0.0.1:`port`, run `command` against it and return its exit code."""
    _check_port_free(port)
    with tempfile.TemporaryDirectory(prefix="netseer-e2e-") as tmp:
        tmp_path = Path(tmp)
        target = tmp_path / "copy.db"
        data_dir = tmp_path / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        username, password = prepare_copy(source, target)

        env = os.environ.copy()
        env["NETSEER_DB"] = str(target)
        env["NETSEER_DATA"] = str(data_dir)
        env["NETSEER_E2E_URL"] = f"http://127.0.0.1:{port}"
        env["NETSEER_E2E_USER"] = username
        env["NETSEER_E2E_PASSWORD"] = password
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(PLAYWRIGHT_BROWSERS)

        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "netseer.src.api.main:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            env=env,
        )
        try:
            if not _wait_for_login(proc, port, 30.0):
                return 1
            return subprocess.run(command, env=env).returncode
        finally:
            _stop_server(proc)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse `--port` and the check command, then run it."""
    parser = argparse.ArgumentParser(prog="browser_env")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command to run is required, e.g. --port 8765 -- python check.py")
    return run(command, args.port, DEFAULT_DB_PATH)


if __name__ == "__main__":
    sys.exit(main())
