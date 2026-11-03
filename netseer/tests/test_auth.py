"""Step 2: setup lock, account cap, password policy, lockout, sessions, CSRF, RBAC, logout."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

from netseer.src.api import auth
from netseer.src.database import db

ADMIN_PW = "correct horse battery staple"
USER_PW = "violet harbour lantern morning"


def csrf(client, path: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


def do_setup(client, username="admin", password=ADMIN_PW):
    token = csrf(client, "/setup")
    return client.post("/setup", data={"csrf_token": token, "username": username,
                                       "password": password, "confirm": password})


def login(client, username="admin", password=ADMIN_PW):
    token = csrf(client, "/login")
    return client.post("/login", data={"csrf_token": token, "username": username, "password": password})


@pytest.fixture()
def admin_client(client):
    assert do_setup(client).status_code == 303
    assert login(client).status_code == 303
    return client


def conn_of(client):
    return db.connect(client.app.state.db_path)


def test_setup_creates_admin_then_returns_404(client):
    r = do_setup(client)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/setup").status_code == 404
    r = client.post("/setup", data={"csrf_token": "x", "username": "evil", "password": ADMIN_PW, "confirm": ADMIN_PW})
    assert r.status_code in (400, 404)
    assert conn_of(client).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


@pytest.mark.parametrize("password,username,message", [
    ("short pass", "admin", "at least 15"),
    ("passwordpassword", "admin", "too common"),
    ("administrator01", "administrator01", "same as the username"),
])
def test_password_policy(client, password, username, message):
    r = do_setup(client, username=username, password=password)
    assert r.status_code == 400
    assert message in r.text
    assert client.get("/setup").status_code == 200


def test_post_without_csrf_is_rejected(client):
    client.get("/setup")
    r = client.post("/setup", data={"username": "admin", "password": ADMIN_PW, "confirm": ADMIN_PW})
    assert r.status_code == 400


def test_login_sets_session_and_home_requires_it(client):
    do_setup(client)
    assert client.get("/").headers["location"] == "/login"
    r = login(client)
    assert r.status_code == 303 and r.headers["location"] == "/"
    set_cookie = r.headers["set-cookie"]
    assert "netseer_session=" in set_cookie and "HttpOnly" in set_cookie and "SameSite=lax" in set_cookie
    assert client.get("/").status_code == 200


def test_third_account_is_refused(admin_client):
    token = csrf(admin_client, "/settings")
    form = {"csrf_token": token, "username": "viewer", "password": USER_PW, "confirm": USER_PW}
    admin_client.post("/settings/users", data=form)
    r = admin_client.post("/settings/users", data={**form, "username": "viewer2"})
    assert r.status_code == 303
    page = admin_client.get("/settings").text
    assert "one administrator and one user" in page
    conn = conn_of(admin_client)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    with pytest.raises(auth.AuthError):
        auth.create_account(conn, "third", USER_PW, USER_PW, role="admin")


def test_user_gets_403_on_admin_routes(admin_client):
    token = csrf(admin_client, "/settings")
    admin_client.post("/settings/users", data={"csrf_token": token, "username": "viewer",
                                               "password": USER_PW, "confirm": USER_PW})
    admin_client.post("/logout", data={"csrf_token": token})
    assert login(admin_client, "viewer", USER_PW).status_code == 303
    token = csrf(admin_client, "/settings")
    r = admin_client.post("/settings/users", data={"csrf_token": token, "username": "x", "password": USER_PW,
                                                   "confirm": USER_PW})
    assert r.status_code == 403
    admin_id = conn_of(admin_client).execute("SELECT id FROM users WHERE role='admin'").fetchone()[0]
    assert admin_client.post(f"/settings/users/{admin_id}/delete", data={"csrf_token": token}).status_code == 403
    assert "Create the user account" not in admin_client.get("/settings").text


def test_admin_account_cannot_be_deleted(admin_client):
    token = csrf(admin_client, "/settings")
    admin_id = conn_of(admin_client).execute("SELECT id FROM users WHERE role='admin'").fetchone()[0]
    assert admin_client.post(f"/settings/users/{admin_id}/delete", data={"csrf_token": token}).status_code == 404


def test_logout_deletes_session_and_redirects_to_login(admin_client):
    token = csrf(admin_client, "/settings")
    r = admin_client.post("/logout", data={"csrf_token": token})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert conn_of(admin_client).execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert admin_client.get("/settings").headers["location"] == "/login"


def test_lockout_after_five_failures_for_five_minutes(client):
    do_setup(client)
    for _ in range(5):
        r = login(client, password="wrong password guess")
        assert r.status_code == 401
    assert auth.LOCKED_ERROR in r.text
    r = login(client)                       # correct password, still locked
    assert r.status_code == 401 and auth.LOCKED_ERROR in r.text
    conn = conn_of(client)
    six_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(timespec="seconds")
    conn.execute("UPDATE login_attempts SET ts = ?", (six_min_ago,))
    assert login(client).status_code == 303
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log")]
    assert actions.count("login_failed") == 4 and "login_locked" in actions and "login" in actions


def test_lockout_also_applies_to_unknown_usernames(client):
    do_setup(client)
    for _ in range(5):
        r = login(client, username="nobody", password="wrong password guess")
    assert auth.LOCKED_ERROR in r.text


def test_session_expires_when_time_runs_out(admin_client):
    conn = conn_of(admin_client)
    old = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="seconds")
    conn.execute("UPDATE sessions SET expires_at = ?", (old,))
    assert admin_client.get("/settings").headers["location"] == "/login"
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_theme_persists_per_account(admin_client):
    token = csrf(admin_client, "/settings")
    admin_client.post("/settings/theme", data={"csrf_token": token, "theme": "black"})
    page = admin_client.get("/settings").text
    assert 'data-theme="black"' in page
    assert '<button class="brand" id="sidebar-toggle"' in page and "menu-toggle" not in page


def test_passwords_are_argon2id(admin_client):
    pw_hash = conn_of(admin_client).execute("SELECT pw_hash FROM users").fetchone()[0]
    assert pw_hash.startswith("$argon2id$")


def _expires(client) -> datetime:
    row = conn_of(client).execute("SELECT expires_at FROM sessions").fetchone()
    return datetime.fromisoformat(row[0])


def test_session_lasts_ten_minutes_and_requests_do_not_extend_it(admin_client):
    first = _expires(admin_client)
    assert timedelta(minutes=9) < first - datetime.now(timezone.utc) <= timedelta(minutes=10)
    for path in ("/settings", "/network", "/api/session"):
        admin_client.get(path)
    assert _expires(admin_client) == first
    info = admin_client.get("/api/session").json()
    assert 540 < info["remaining_s"] <= 600
    assert 'id="session-timer"' in admin_client.get("/settings").text


def test_extend_adds_ten_minutes_up_to_an_hour(admin_client):
    headers = {"X-CSRF-Token": csrf(admin_client, "/settings")}
    first = _expires(admin_client)
    r = admin_client.post("/api/session/extend", headers=headers)
    assert r.status_code == 200 and 1140 < r.json()["remaining_s"] <= 1200
    assert _expires(admin_client) - first == timedelta(minutes=10)
    for _ in range(10):
        admin_client.post("/api/session/extend", headers=headers)
    assert _expires(admin_client) - datetime.now(timezone.utc) <= timedelta(minutes=60)
    assert admin_client.post("/api/session/extend").status_code == 400         # CSRF header required


def test_session_api_needs_a_session(client):
    do_setup(client)
    assert client.get("/api/session").status_code == 401


def test_auto_logout_off_keeps_sessions_up_to_twelve_hours(admin_client):
    from datetime import datetime, timedelta, timezone
    client = admin_client
    r = client.post("/settings/auto-logout", data={"csrf_token": csrf(client, "/settings")})   # box unticked → off
    assert r.status_code == 303
    conn = conn_of(client)
    ago = lambda **kw: (datetime.now(timezone.utc) - timedelta(**kw)).isoformat(timespec="seconds")  # noqa: E731
    conn.execute("UPDATE sessions SET expires_at = ?, created_at = ?", (ago(minutes=1), ago(hours=2)))
    page = client.get("/settings")
    assert page.status_code == 200 and 'id="session-timer"' not in page.text and "at most 12 hours" in page.text
    conn.execute("UPDATE sessions SET created_at = ?", (ago(hours=13),))
    client.get("/settings")
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0                # past the 12 h cap
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'auto_logout_off'").fetchone()[0] == 1
