"""Authentication (CONCEPTS A9, A12; brief §8): password policy, Argon2id, lockout, sessions."""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from netseer.src.api.client import client_mac
from netseer.src.config import PASSWORD_BLOCKLIST, app_config, get_setting
from netseer.src.database.db import audit, utcnow

MIN_PASSWORD_LEN = 15
MAX_PASSWORD_LEN = 128
LOCK_THRESHOLD = 5                      # failures ...
LOCK_WINDOW = timedelta(minutes=15)     # ... within this window ...
LOCK_DURATION = timedelta(minutes=5)    # ... lock the username for this long
MAX_SESSION = timedelta(minutes=60)     # Extend never pushes expiry further ahead than this
NO_AUTO_LOGOUT_CAP = timedelta(hours=12)   # with auto-logout off, a session still ends this long after sign-in
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")

GENERIC_LOGIN_ERROR = "Invalid username or password."
LOCKED_ERROR = "Too many failed attempts. Sign-in is locked for 5 minutes."

_hasher = PasswordHasher()              # Argon2id, RFC 9106 low-memory profile
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


class AuthError(ValueError):
    """A user-facing validation or authentication failure."""


@lru_cache(maxsize=1)
def _blocklist() -> frozenset[str]:
    lines = PASSWORD_BLOCKLIST.read_text(encoding="utf-8", errors="ignore").splitlines()
    return frozenset(l.strip().lower() for l in lines if l.strip() and not l.startswith("#"))


def normalise_username(username: str) -> str:
    """Usernames are case-insensitive; store and compare them lower-cased."""
    return username.strip().lower()


def validate_username(username: str) -> str:
    """Return the normalised username or raise AuthError."""
    name = normalise_username(username)
    if not USERNAME_RE.match(name):
        raise AuthError("Username must be 3–32 characters: letters, digits, dot, dash or underscore.")
    return name


def validate_password(password: str, username: str) -> None:
    """Apply the NIST SP 800-63B-4 policy: length, blocklist, not the username. No composition rules."""
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if len(password) > MAX_PASSWORD_LEN:
        raise AuthError(f"Password must be at most {MAX_PASSWORD_LEN} characters.")
    if password.lower() == normalise_username(username):
        raise AuthError("Password must not be the same as the username.")
    if password.lower() in _blocklist():
        raise AuthError("This password is too common. Choose a different passphrase.")


def hash_password(password: str) -> str:
    """Argon2id hash of a password."""
    return _hasher.hash(password)


def create_account(conn: sqlite3.Connection, username: str, password: str, confirm: str, role: str) -> int:
    """Create an account after validation; enforce one admin and at most one user."""
    name = validate_username(username)
    if password != confirm:
        raise AuthError("The passwords do not match.")
    validate_password(password, name)
    if conn.execute("SELECT 1 FROM users WHERE role = ?", (role,)).fetchone():
        raise AuthError("NetSeer allows one administrator and one user. Delete the existing user first."
                        if role == "user" else "An administrator already exists.")
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone():
        raise AuthError("That username is already taken.")
    try:
        cur = conn.execute(
            "INSERT INTO users(username, pw_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (name, hash_password(password), role, utcnow()),
        )
    except sqlite3.IntegrityError as exc:       # one_per_role index: concurrent creation
        raise AuthError("NetSeer allows one administrator and one user.") from exc
    return int(cur.lastrowid)


def set_password(conn: sqlite3.Connection, user_id: int, password: str, confirm: str) -> None:
    """Reset a password (policy applies) and end the account's sessions."""
    row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise AuthError("No such account.")
    if password != confirm:
        raise AuthError("The passwords do not match.")
    validate_password(password, row["username"])
    conn.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hash_password(password), user_id))
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def lock_remaining(conn: sqlite3.Connection, username: str, now: datetime | None = None) -> timedelta:
    """Time left on a lockout: 5 consecutive failures within 15 min lock for 5 min from the last one."""
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT ts, success FROM login_attempts WHERE username = ? AND ts >= ? ORDER BY ts DESC, rowid DESC",
        (normalise_username(username), (now - LOCK_WINDOW).isoformat(timespec="seconds")),
    ).fetchall()
    failures = 0
    for row in rows:
        if row["success"]:
            break
        failures += 1
    if failures < LOCK_THRESHOLD:
        return timedelta(0)
    last_failure = datetime.fromisoformat(rows[0]["ts"])
    return max(timedelta(0), last_failure + LOCK_DURATION - now)


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row:
    """Return the user row for valid credentials, or raise AuthError with a generic message.

    Lockout applies to any submitted username, so the response never reveals whether an account exists.
    """
    name = normalise_username(username)
    if lock_remaining(conn, name) > timedelta(0):
        raise AuthError(LOCKED_ERROR)
    user = conn.execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()
    ok = False
    try:
        ok = _hasher.verify(user["pw_hash"] if user else _DUMMY_HASH, password) and user is not None
    except (VerifyMismatchError, InvalidHashError):
        ok = False
    conn.execute("INSERT INTO login_attempts(username, ts, success) VALUES (?, ?, ?)", (name, utcnow(), int(ok)))
    if not ok:
        if lock_remaining(conn, name) > timedelta(0):
            raise AuthError(LOCKED_ERROR)
        raise AuthError(GENERIC_LOGIN_ERROR)
    return user


def _token_key(token: str) -> str:
    """Sessions are stored by SHA-256 of the cookie token, so a database leak does not leak sessions."""
    return hashlib.sha256(token.encode()).hexdigest()


def _session_length() -> timedelta:
    return timedelta(minutes=int(app_config("session_minutes")))


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    """Create a server-side session (valid for session_minutes) and return the 32-byte random cookie token."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    stamp = now.isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO sessions(token, user_id, csrf, created_at, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (_token_key(token), user_id, secrets.token_urlsafe(32), stamp, stamp,
         (now + _session_length()).isoformat(timespec="seconds")),
    )
    return token


def load_session(conn: sqlite3.Connection, token: str, ip: str | None = None) -> tuple[sqlite3.Row, sqlite3.Row] | None:
    """Return (session, user) for a live token; expire (and audit) it once `expires_at` has passed.

    Requests never extend a session (only `extend_session` does), so background polling cannot keep it alive.
    With auto-logout off (Settings > Accounts) the session ends NO_AUTO_LOGOUT_CAP after sign-in instead.
    """
    key = _token_key(token)
    session = conn.execute("SELECT * FROM sessions WHERE token = ?", (key,)).fetchone()
    if session is None:
        return None
    auto = get_setting(conn, "auto_logout")
    created = datetime.fromisoformat(session["created_at"])
    length = _session_length() if auto else NO_AUTO_LOGOUT_CAP
    expires = (session["expires_at"] if auto else None) or (created + length).isoformat()
    if datetime.now(timezone.utc) > datetime.fromisoformat(expires):
        conn.execute("DELETE FROM sessions WHERE token = ?", (key,))
        audit(conn, session["user_id"], "session_expired", f"session time ({length}) ran out", ip, client_mac(ip))
        return None
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        return None
    conn.execute("UPDATE sessions SET last_seen = ? WHERE token = ?", (utcnow(), key))
    return (session if auto else dict(session) | {"expires_at": None}), user   # no expiry → no countdown shown


def extend_session(conn: sqlite3.Connection, token: str) -> str:
    """Add session_minutes to the remaining time (never more than MAX_SESSION ahead); return the new expiry."""
    key = _token_key(token)
    row = conn.execute("SELECT expires_at FROM sessions WHERE token = ?", (key,)).fetchone()
    now = datetime.now(timezone.utc)
    current = max(datetime.fromisoformat(row["expires_at"]), now) if row and row["expires_at"] else now
    new = min(current + _session_length(), now + MAX_SESSION).isoformat(timespec="seconds")
    conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?", (new, key))
    return new


def delete_session(conn: sqlite3.Connection, token: str) -> None:
    """End a session (logout)."""
    conn.execute("DELETE FROM sessions WHERE token = ?", (_token_key(token),))
