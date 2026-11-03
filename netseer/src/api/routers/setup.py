"""First-launch administrator setup (CONCEPTS A12). Returns 404 once an admin exists."""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, Form, HTTPException, Request

from netseer.src.api import auth
from netseer.src.api.client import who
from netseer.src.api.deps import get_db, redirect, render, verify_csrf
from netseer.src.database.db import audit

router = APIRouter()


def admin_exists(conn: sqlite3.Connection) -> bool:
    """True when the administrator account has been created."""
    return conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone() is not None


@router.get("/setup")
def setup_form(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Show the Create administrator form on first launch."""
    if admin_exists(conn):
        raise HTTPException(status_code=404)
    return render(request, "setup.html")


@router.post("/setup", dependencies=[Depends(verify_csrf)])
def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    conn: sqlite3.Connection = Depends(get_db),
):
    """Create the administrator, then send them to the login page."""
    if admin_exists(conn):
        raise HTTPException(status_code=404)
    try:
        user_id = auth.create_account(conn, username, password, confirm, role="admin")
    except auth.AuthError as exc:
        return render(request, "setup.html", {"error": str(exc), "username": username}, status_code=400)
    audit(conn, user_id, "setup", f"administrator '{auth.normalise_username(username)}' created", *who(request))
    request.app.state.admin_exists = True
    return redirect("/login", "ok", "Administrator created. Sign in to continue.")
