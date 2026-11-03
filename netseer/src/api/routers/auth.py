"""Login and logout routes (brief §8)."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request

from netseer.src.api import auth
from netseer.src.api.client import who
from netseer.src.api.deps import (SESSION_COOKIE, get_db, redirect, render, require_user, session_remaining,
                                  set_cookie, verify_csrf, verify_csrf_header)
from netseer.src.database.db import audit

router = APIRouter()


@router.get("/login")
def login_form(request: Request):
    """Username and password form; signed-in users go straight to Home."""
    if getattr(request.state, "user", None) is not None:
        return redirect("/")
    return render(request, "login.html")


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    conn: sqlite3.Connection = Depends(get_db),
):
    """Check credentials (with lockout), start a new session and set its cookie."""
    try:
        user = auth.authenticate(conn, username, password)
    except auth.AuthError as exc:
        locked = str(exc) == auth.LOCKED_ERROR
        audit(conn, None, "login_locked" if locked else "login_failed", auth.normalise_username(username)[:64],
              *who(request))
        return render(request, "login.html", {"error": str(exc), "username": username}, status_code=401)
    token = auth.create_session(conn, user["id"])
    audit(conn, user["id"], "login", user["username"], *who(request))
    response = redirect("/")
    set_cookie(response, SESSION_COOKIE, token)
    return response


@router.get("/api/session")
def session_info(request: Request, user=Depends(require_user)):
    """Remaining session time for the top-bar countdown (reading it never extends the session)."""
    return {"expires_at": request.state.session["expires_at"],
            "remaining_s": session_remaining(request.state.session)}


@router.post("/api/session/extend", dependencies=[Depends(verify_csrf_header)])
def session_extend(request: Request, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """The Extend button: add 10 minutes to the session."""
    expires = auth.extend_session(conn, request.cookies.get(SESSION_COOKIE, ""))
    audit(conn, user["id"], "session_extended", f"until {expires}", *who(request))
    remaining = int((datetime.fromisoformat(expires) - datetime.now(timezone.utc)).total_seconds())
    return {"expires_at": expires, "remaining_s": remaining}


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Delete the server-side session and return to the login page."""
    token = request.cookies.get(SESSION_COOKIE)
    user = getattr(request.state, "user", None)
    if token:
        auth.delete_session(conn, token)
    if user is not None:
        audit(conn, user["id"], "logout", user["username"], *who(request))
    response = redirect("/login", "info", "You have been signed out.")
    response.delete_cookie(SESSION_COOKIE)
    return response
