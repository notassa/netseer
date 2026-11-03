"""AI page (CONCEPTS A7–A8, brief §9): sectioned explanation, Prompt Maker buttons, verifier badge, ref chips."""

from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from markupsafe import Markup, escape

from netseer.ai import explain
from netseer.ai.prompt_maker import INTENTS
from netseer.ai.verifier import SENTENCE
from netseer.src.api.client import who
from netseer.src.api.deps import get_db, layout_context, redirect, render, require_admin, require_user, verify_csrf
from netseer.src.database.db import audit

router = APIRouter(dependencies=[Depends(require_user)])

INCIDENT_CHOICES = 50
HISTORY = 100                # saved explanations listed per analysis
SECTIONS = (("summary", "Summary"), ("what_happened", "What happened"), ("why_it_matters", "Why it matters"),
            ("risk_explanation", "Risk"), ("uncertainty", "What we don't know"))
CHECK_NAMES = {"schema": "Schema", "citation": "Missing or wrong reference", "entity": "Not in the evidence",
               "overclaim": "Overclaim", "band": "Band mismatch"}


def marked(text: str, flags: list[dict]) -> Markup:
    """The text with flagged sentences wrapped in <mark class="flagged"> (escaped)."""
    by_text = {f["text"]: f for f in flags if f["text"]}
    parts = []
    for sentence in SENTENCE.split(text or ""):
        f = by_text.get(sentence) or by_text.get(text)
        parts.append(Markup('<mark class="flagged" title="{}">{}</mark>').format(
            f"{CHECK_NAMES[f['check']]}: {f['detail']}", sentence) if f else escape(sentence))
    return Markup(" ").join(parts)


def _incident(conn: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such incident.")
    return row


def _intent(intent: str) -> str:
    if intent not in INTENTS:
        raise HTTPException(status_code=400, detail="Unknown question.")
    return intent


@router.get("/ai")
def ai_page(request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """Explanation of one incident (default: the selected analysis's top incident) for one Prompt Maker intent."""
    ctx = layout_context(request, conn, "ai")
    params = request.query_params
    intent = _intent(params.get("intent", "explain_simple"))
    incident_id = params.get("incident", "")
    saved = None
    if params.get("interpretation", "").isdigit():
        saved = conn.execute("SELECT * FROM interpretations WHERE id = ?", (int(params["interpretation"]),)).fetchone()
        if saved is None:
            raise HTTPException(status_code=404, detail="No such saved explanation.")
        incident_id, intent = str(saved["incident_id"]), _intent(saved["intent"])
    if incident_id.isdigit():
        inc = _incident(conn, int(incident_id))
    else:
        inc = conn.execute("SELECT * FROM incidents WHERE analysis_id = ? ORDER BY score DESC LIMIT 1",
                           (ctx["selected"]["id"] if ctx["selected"] else -1,)).fetchone()
    choices = conn.execute("SELECT id, title, band, score FROM incidents WHERE analysis_id = ? ORDER BY score DESC "
                           "LIMIT ?", (inc["analysis_id"] if inc else -1, INCIDENT_CHOICES)).fetchall()
    result = None
    state = {"state": "none"}
    if inc is not None:
        state = explain.status(conn, inc["id"], intent)
        row = saved or (conn.execute("SELECT * FROM interpretations WHERE id = ?", (state["interpretation"],)).fetchone()
                        if state["state"] == "done" else None)
        if row is not None:
            stored = json.loads(row["output_json"])
            verification = json.loads(row["verification_json"])
            facts = {f["id"]: f["text"] for f in stored["evidence"]["facts"]}
            facts |= {k["id"]: f"{k['title']}: {k['text']}" for k in stored["evidence"]["knowledge"]}
            result = {"row": row, "out": stored["output"], "evidence": stored["evidence"], "facts": facts,
                      "verification": verification, "flags": verification["flags"],
                      "outdated": state.get("interpretation") != row["id"]}
    history = conn.execute(
        "SELECT p.id, p.intent, p.model, p.created_at, p.latency_s, p.verification_json, i.id AS incident_id, i.title, "
        "i.band FROM interpretations p JOIN incidents i ON i.id = p.incident_id WHERE i.analysis_id = ? "
        "ORDER BY p.id DESC LIMIT ?", (inc["analysis_id"] if inc else -1, HISTORY)).fetchall()
    history = [dict(h) | {"flags": len(json.loads(h["verification_json"])["flags"])} for h in history]
    return render(request, "ai.html", {
        **ctx, "inc": inc, "intent": intent, "intents": INTENTS, "choices": choices, "state": state,
        "result": result, "history": history, "sections": SECTIONS, "marked": marked, "check_names": CHECK_NAMES,
    })


@router.post("/api/incidents/{incident_id}/explain", dependencies=[Depends(verify_csrf)])
def start_explain(request: Request, incident_id: int, intent: str = Form(...), conn: sqlite3.Connection = Depends(get_db)):
    """Start (or reuse) an explanation in the background; poll the GET for its state."""
    _incident(conn, incident_id)
    _intent(intent)
    if explain.status(conn, incident_id, intent)["state"] != "done":
        explain.start(request.app.state.db_path, incident_id, intent)
    return explain.status(conn, incident_id, intent)


@router.post("/api/incidents/{incident_id}/explain/stop", dependencies=[Depends(verify_csrf)])
def stop_explain(incident_id: int, intent: str = Form(...), conn: sqlite3.Connection = Depends(get_db)):
    """Stop a running explanation (the model stops generating; nothing is saved)."""
    _incident(conn, incident_id)
    return {"stopped": explain.stop_job(incident_id, _intent(intent))}


@router.post("/ai/history/clear", dependencies=[Depends(verify_csrf)])
def clear_history(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Delete every saved explanation of the selected analysis (administrator only)."""
    selected = layout_context(request, conn, "ai")["selected"]
    if selected is None:
        return redirect("/ai", "error", "Choose an analysis first.")
    n = conn.execute("DELETE FROM interpretations WHERE incident_id IN "
                     "(SELECT id FROM incidents WHERE analysis_id = ?)", (selected["id"],)).rowcount
    audit(conn, admin["id"], "explanations_cleared", f"analysis {selected['id']}: {n} explanations", *who(request))
    return redirect("/ai", "ok", f"{n} saved explanation{'s' if n != 1 else ''} cleared.")


@router.get("/api/incidents/{incident_id}/explain")
def explain_state(incident_id: int, intent: str, conn: sqlite3.Connection = Depends(get_db)):
    """State of an explanation: done (with its id), running, failed (with the error) or none."""
    _incident(conn, incident_id)
    return explain.status(conn, incident_id, _intent(intent))
