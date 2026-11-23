"""Network page (CONCEPTS A10, A13): mode selection, offline upload, analyses browser, analysis selection."""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.requests import ClientDisconnect

from netseer.src.api.deps import (ANALYSIS_COOKIE, get_db, layout_context, redirect, render, require_admin,
                                  require_user, set_cookie, verify_csrf, verify_csrf_header)
from netseer.src.config import get_setting
from netseer.src.database.db import audit
from netseer.src.engine import ingest, live
from netseer.src.engine.capture_check import run_checks

router = APIRouter()

MAX_NAME_LEN = 120


def _analysis(conn: sqlite3.Connection, analysis_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such analysis.")
    return row


@router.get("/network")
def network_page(request: Request, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Mode choice, upload form and the analyses browser."""
    rows = conn.execute(
        "SELECT a.*, COUNT(f.filename) AS n_files, COALESCE(SUM(f.size), 0) AS total_size "
        "FROM analyses a LEFT JOIN analysis_files f ON f.analysis_id = a.id GROUP BY a.id ORDER BY a.id DESC"
    ).fetchall()
    files: dict[int, list] = {}
    for f in conn.execute("SELECT * FROM analysis_files ORDER BY rowid"):
        files.setdefault(f["analysis_id"], []).append(f)
    _check_older_analyses(request, conn, rows)
    info: dict[int, list] = {}
    for r in conn.execute("SELECT * FROM analysis_info WHERE kind = 'capture' ORDER BY id"):
        info.setdefault(r["analysis_id"], []).append(r)
    return render(request, "network.html", {
        **layout_context(request, conn, "network"),
        "rows": rows,
        "files": files,
        "info": info,
        "sessions": [r for r in rows if r["mode"] == "offline" and r["status"] not in ingest.ACTIVE_STATUSES],
        "max_upload_mb": get_setting(conn, "max_upload_mb"),
        "active_statuses": ingest.ACTIVE_STATUSES + live.OPEN_STATES,
        "nics": live.interfaces(),
        "live_open": any(r["mode"] == "live" and r["status"] in live.OPEN_STATES for r in rows),
        "live_message": live.message,
    })


def _check_older_analyses(request: Request, conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> None:
    """Run the capture checks (A16) once for finished analyses made before they existed."""
    checked = {r[0] for r in conn.execute("SELECT DISTINCT analysis_id FROM analysis_info WHERE kind = 'capture'")}
    data_dir = request.app.state.data_dir
    for a in rows:
        if a["id"] in checked or a["status"] not in ("done", "awaiting_attribution") or a["mode"] != "offline":
            continue
        eve = ingest.eve_dir(data_dir, a["id"]) / "eve.json"
        if eve.exists():
            run_checks(conn, a["id"], ingest.pcap_dir(data_dir, a["id"]), eve)


class UploadRequest(BaseModel):
    name: str = Field(max_length=255)
    size: int = Field(ge=0)
    analysis_id: int | None = None          # add to this existing session; None = new session
    session_name: str | None = Field(default=None, max_length=MAX_NAME_LEN)


class StartRequest(BaseModel):
    analyse: bool = True


def _max_file_bytes(conn: sqlite3.Connection) -> int:
    return int(get_setting(conn, "max_upload_mb")) * (1 << 20)


@router.post("/api/uploads", dependencies=[Depends(verify_csrf_header)])
def begin_upload(body: UploadRequest, request: Request, admin=Depends(require_admin),
                 conn: sqlite3.Connection = Depends(get_db)):
    """Step 1: announce one file (name, size) for a new or existing session; checks the cap and free disk."""
    try:
        analysis_id = ingest.begin_upload(conn, request.app.state.data_dir, body.name, body.size,
                                          _max_file_bytes(conn), body.analysis_id, body.session_name)
    except ingest.IngestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(conn, admin["id"], "upload_started",
          f"analysis {analysis_id}: {body.name} ({body.size / (1 << 20):.0f} MB)"
          f"{' added to the session' if body.analysis_id else ' (new session)'}"[:1000])
    response = JSONResponse({"id": analysis_id})
    set_cookie(response, ANALYSIS_COOKIE, str(analysis_id))
    return response


@router.put("/api/analyses/{analysis_id}/file", dependencies=[Depends(verify_csrf_header)])
async def upload_file(analysis_id: int, request: Request, admin=Depends(require_admin),
                      conn: sqlite3.Connection = Depends(get_db)):
    """Step 2: stream the file's raw bytes straight to disk (no multipart temp copy)."""
    data_dir = request.app.state.data_dir
    try:
        sink = ingest.FileSink(conn, data_dir, analysis_id, _max_file_bytes(conn))
        try:
            # shortcut: blocking disk writes inside the event loop; fine for one admin uploading at a time.
            async for chunk in request.stream():
                sink.write(chunk)
        finally:
            sink.out.close()
        sink.finish()
    except ingest.IngestError as exc:
        ingest.abort_upload(conn, data_dir, analysis_id)
        audit(conn, admin["id"], "analysis_failed", f"analysis {analysis_id}: upload rejected: {exc}"[:1000])
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ClientDisconnect:
        ingest.abort_upload(conn, data_dir, analysis_id)
        audit(conn, admin["id"], "analysis_failed", f"analysis {analysis_id}: upload cancelled by the browser")
        raise HTTPException(status_code=400, detail="Upload cancelled.") from None
    return {"stored": sink.name, "size": sink.size}


@router.post("/api/analyses/{analysis_id}/start", dependencies=[Depends(verify_csrf_header)])
def start_analysis(analysis_id: int, request: Request, background: BackgroundTasks, body: StartRequest = StartRequest(),
                   admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Step 3: close the upload; analyse all the session's files now, or leave it `pending` for more files."""
    try:
        ingest.finish_upload(conn, analysis_id)
        if body.analyse:
            ingest.reset_analysis(conn, request.app.state.data_dir, analysis_id)
    except ingest.IngestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not body.analyse:
        return {"id": analysis_id, "status": "pending"}
    background.add_task(ingest.run_offline, request.app.state.db_path, request.app.state.data_dir, analysis_id)
    return {"id": analysis_id, "status": "queued"}


@router.post("/analyses/select", dependencies=[Depends(verify_csrf)])
def select_analysis(analysis_id: str = Form(""), next: str = Form("/"), user=Depends(require_user),
                    conn: sqlite3.Connection = Depends(get_db)):
    """Remember the selected analysis (cookie); every page except Settings is scoped to it."""
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    response = redirect(target)
    if analysis_id.isdigit():
        _analysis(conn, int(analysis_id))
        set_cookie(response, ANALYSIS_COOKIE, analysis_id)
    return response


@router.post("/network/analyses/{analysis_id}/rename", dependencies=[Depends(verify_csrf)])
def rename_analysis(analysis_id: int, name: str = Form(...), user=Depends(require_user),
                    conn: sqlite3.Connection = Depends(get_db)):
    """Rename an analysis (CONCEPTS A13: users can rename)."""
    _analysis(conn, analysis_id)
    name = " ".join(name.split())
    if not 1 <= len(name) <= MAX_NAME_LEN:
        return redirect("/network", "error", f"A name must be 1–{MAX_NAME_LEN} characters.")
    conn.execute("UPDATE analyses SET name = ? WHERE id = ?", (name, analysis_id))
    audit(conn, user["id"], "analysis_renamed", f"{analysis_id}: {name}")
    return redirect("/network", "ok", "Analysis renamed.")


MAX_NOTE_LEN = 1000


@router.post("/network/analyses/{analysis_id}/note", dependencies=[Depends(verify_csrf)])
def save_note(analysis_id: int, note: str = Form(""), admin=Depends(require_admin),
              conn: sqlite3.Connection = Depends(get_db)):
    """Save the administrator's note on an analysis."""
    _analysis(conn, analysis_id)
    note = note.strip()
    if len(note) > MAX_NOTE_LEN:
        return redirect("/network", "error", f"A note can be at most {MAX_NOTE_LEN} characters.")
    conn.execute("UPDATE analyses SET note = ? WHERE id = ?", (note or None, analysis_id))
    audit(conn, admin["id"], "analysis_note", f"analysis {analysis_id}: {note}"[:500])
    return redirect("/network", "ok", "Note saved.")


@router.post("/network/analyses/{analysis_id}/delete", dependencies=[Depends(verify_csrf)])
def delete_analysis(request: Request, analysis_id: int, admin=Depends(require_admin),
                    conn: sqlite3.Connection = Depends(get_db)):
    """Delete an analysis and its stored files (administrator only)."""
    row = _analysis(conn, analysis_id)
    try:
        ingest.delete_analysis(conn, request.app.state.data_dir, analysis_id)
    except ingest.IngestError as exc:
        return redirect("/network", "error", str(exc))
    audit(conn, admin["id"], "analysis_deleted", f"{analysis_id}: {row['name']}")
    return redirect("/network", "ok", "Analysis deleted.")


@router.post("/network/analyses/{analysis_id}/files/delete", dependencies=[Depends(verify_csrf)])
def delete_file(request: Request, analysis_id: int, filename: str = Form(...), admin=Depends(require_admin),
                conn: sqlite3.Connection = Depends(get_db)):
    """Delete one capture file of a session; its results are cleared until it is analysed again."""
    _analysis(conn, analysis_id)
    try:
        gone = ingest.delete_file(conn, request.app.state.data_dir, analysis_id, filename)
    except ingest.IngestError as exc:
        return redirect("/network", "error", str(exc))
    audit(conn, admin["id"], "file_deleted", f"analysis {analysis_id}: {filename}" + ("; session deleted" if gone else ""))
    return redirect("/network", "ok", "File deleted; the session was empty and is gone." if gone else
                    "File deleted. Press Analyse to re-run the session with its other files.")


@router.post("/network/analyses/{analysis_id}/rerun", dependencies=[Depends(verify_csrf)])
def rerun_analysis(request: Request, analysis_id: int, background: BackgroundTasks, admin=Depends(require_admin),
                   conn: sqlite3.Connection = Depends(get_db)):
    """Analyse the stored captures again (e.g. after a failure) without re-uploading them."""
    _analysis(conn, analysis_id)
    try:
        ingest.reset_analysis(conn, request.app.state.data_dir, analysis_id)
    except ingest.IngestError as exc:
        return redirect("/network", "error", str(exc))
    audit(conn, admin["id"], "analysis_rerun", f"analysis {analysis_id}")
    background.add_task(ingest.run_offline, request.app.state.db_path, request.app.state.data_dir, analysis_id)
    response = redirect("/network", "info", "Analysing the stored capture again; this page updates by itself.")
    set_cookie(response, ANALYSIS_COOKIE, str(analysis_id))
    return response


@router.post("/api/analyses/{analysis_id}/stop", dependencies=[Depends(verify_csrf_header)])
def stop_analysis(analysis_id: int, request: Request, admin=Depends(require_admin),
                  conn: sqlite3.Connection = Depends(get_db)):
    """Stop a queued or running analysis; its results are cleared and its captures kept for a re-run."""
    if _analysis(conn, analysis_id)["status"] not in ("queued", "running_suricata", "processing"):
        raise HTTPException(status_code=400, detail="This analysis is not running.")
    ingest.stop(conn, request.app.state.data_dir, analysis_id)
    audit(conn, admin["id"], "analysis_stop_requested", f"analysis {analysis_id}")
    return {"id": analysis_id, "status": "stopping"}


@router.post("/network/live", dependencies=[Depends(verify_csrf)])
def open_live(request: Request, mirror: str = Form(...), lan: str = Form(...), admin=Depends(require_admin),
              conn: sqlite3.Connection = Depends(get_db)):
    """Open a real-time session: a new analysis record that waits for links and traffic (A13)."""
    try:
        analysis_id = live.create_session(conn, mirror, lan)
    except live.LiveError as exc:
        return redirect("/network", "error", str(exc))
    audit(conn, admin["id"], "live_opened", f"analysis {analysis_id}: mirror {mirror}, LAN {lan}")
    response = redirect("/network", "info", "Live session opened; it starts once the links are up and traffic arrives.")
    set_cookie(response, ANALYSIS_COOKIE, str(analysis_id))
    return response


@router.post("/network/live/{analysis_id}/{action}", dependencies=[Depends(verify_csrf)])
def control_live(request: Request, analysis_id: int, action: str, admin=Depends(require_admin),
                 conn: sqlite3.Connection = Depends(get_db)):
    """Start the capture of a ready session, or stop a session."""
    if action not in ("start", "stop"):
        raise HTTPException(status_code=404)
    _analysis(conn, analysis_id)
    try:
        (live.confirm if action == "start" else live.stop)(conn, request.app.state.data_dir, analysis_id)
    except live.LiveError as exc:
        return redirect("/network", "error", str(exc))
    return redirect("/network", "ok", "Capture started." if action == "start" else "Live session stopped.")


@router.get("/api/analyses/{analysis_id}/status")
def analysis_status(analysis_id: int, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Job progress for the Network page poller."""
    row = _analysis(conn, analysis_id)
    return {k: row[k] for k in ("id", "name", "status", "n_events", "n_alerts", "error", "started_at", "stopped_at")} \
        | {"progress": ingest.get_progress(analysis_id), "message": live.message(row) if row["mode"] == "live" else None}
