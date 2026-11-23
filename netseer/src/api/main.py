"""FastAPI application factory. Run: uvicorn netseer.src.api.main:app --host 0.0.0.0 --port 8000"""

from __future__ import annotations

import os
from http import HTTPStatus
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from netseer.src.api import auth as auth_core
from netseer.src.api.client import client_ip
from netseer.src.api.deps import FLASH_COOKIE, SESSION_COOKIE, LoginRequired, render
from netseer.src.api.routers import (ai, alerts, auth, devices, home, incidents, information, network, settings,
                                     setup)
from netseer.src.config import DATABASE_DIR, DEFAULT_DB_PATH, WEB_DIR
from netseer.src.database import db
from netseer.src.engine import ingest, live


def create_app(db_path: str | Path | None = None, data_dir: str | Path | None = None) -> FastAPI:
    """Build the app. `db_path` and `data_dir` (holding pcaps/ and eves/) default to src/database/."""
    app = FastAPI(title="NetSeer", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db_path = Path(db_path or os.environ.get("NETSEER_DB") or DEFAULT_DB_PATH)
    app.state.data_dir = Path(data_dir or os.environ.get("NETSEER_DATA") or DATABASE_DIR)
    app.state.admin_exists = False
    db.init_db(app.state.db_path)
    conn = db.connect(app.state.db_path)
    try:
        ingest.mark_interrupted(conn)
    finally:
        conn.close()

    # Real-time sessions advance in one monitor thread; started with the server, not by test clients.
    app.router.on_startup.append(lambda: live.start_monitor(app.state.db_path, app.state.data_dir))
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    for module in (setup, auth, settings, network, alerts, devices, incidents, home, information, ai):
        app.include_router(module.router)

    @app.middleware("http")
    async def session_and_first_launch(request: Request, call_next):
        """Redirect to /setup until an admin exists; then attach the session's user to the request."""
        path = request.url.path
        if path.startswith("/static"):
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-cache"  # revalidate, so pages never run a stale app.js
            return response
        conn = db.connect(app.state.db_path)
        try:
            if not app.state.admin_exists:
                app.state.admin_exists = setup.admin_exists(conn)
                if not app.state.admin_exists and path != "/setup":
                    return RedirectResponse("/setup", status_code=303)
            request.state.user = request.state.session = None
            token = request.cookies.get(SESSION_COOKIE)
            if token:
                loaded = auth_core.load_session(conn, token, client_ip(request))
                if loaded:
                    request.state.session, request.state.user = loaded
        finally:
            conn.close()
        response = await call_next(request)
        sets_flash = any(v.startswith(f"{FLASH_COOKIE}=".encode()) for k, v in response.raw_headers if k == b"set-cookie")
        if FLASH_COOKIE in request.cookies and not sets_flash:
            response.delete_cookie(FLASH_COOKIE)
        return response

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Not signed in."}, status_code=401)
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        title = HTTPStatus(exc.status_code).phrase
        detail = exc.detail if exc.detail != title else "The page you asked for is not available."
        return render(request, "error.html", {"status_code": exc.status_code, "title": title, "detail": detail},
                      status_code=exc.status_code)

    return app


app = create_app()
