"""Generate, verify and cache explanations (brief §7).

An explanation is cached per (incident, intent, evidence hash) in `interpretations`; a changed evidence package
(re-scored, new device type, rebuilt KB) gets a new one. Jobs run in the background, one model call at a time.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from netseer.ai import prompt_maker
from netseer.ai.llm_caller import LLMBackend, Stopped, backend_for
from netseer.ai.verifier import parse, verify
from netseer.src.database import db

_llm_lock = threading.Lock()                 # CPU-only Ollama: one generation at a time
_jobs_lock = threading.Lock()
JOBS: dict[tuple[int, str], dict] = {}        # (incident, intent) → {"state": "running"|"failed", "error", "started"}
EXPECTED_S = 90.0                            # assumed length of a run before any explanation has been timed


def evidence_for(conn: sqlite3.Connection, incident_id: int, intent: str) -> dict:
    """The evidence package an intent needs: the incident's, or its analysis's for "Summarise this analysis"."""
    if intent not in prompt_maker.INTENTS:
        raise ValueError(f"Unknown intent {intent!r}.")
    if intent == "summarise_analysis":
        row = conn.execute("SELECT analysis_id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            raise KeyError(incident_id)
        return prompt_maker.build_analysis_evidence(conn, row["analysis_id"])
    return prompt_maker.build_evidence(conn, incident_id)


def cached(conn: sqlite3.Connection, evidence: dict, intent: str) -> sqlite3.Row | None:
    """The stored interpretation for this exact evidence, if any."""
    return conn.execute(
        "SELECT * FROM interpretations WHERE incident_id = ? AND intent = ? AND evidence_hash = ? ORDER BY id DESC",
        (evidence["incident_id"], intent, prompt_maker.evidence_hash(evidence))).fetchone()


def generate(conn: sqlite3.Connection, incident_id: int, intent: str, backend: LLMBackend | None = None,
             stop: threading.Event | None = None) -> int:
    """Explain, verify and store (or reuse) one interpretation; returns its id. Raises LLMError when the model fails
    and Stopped once `stop` is set (also while waiting for the model)."""
    evidence = evidence_for(conn, incident_id, intent)
    if evidence["incident_id"] is None:
        raise ValueError("This analysis has no possible incidents to summarise.")
    hit = cached(conn, evidence, intent)
    if hit is not None:
        return hit["id"]
    backend = backend or backend_for(conn)
    system, user = prompt_maker.messages(evidence, intent)
    schema = prompt_maker.output_schema()
    with _llm_lock:
        started = time.monotonic()
        raw = _chat(backend, system, user, schema, stop)
        out, error = parse(raw)
        retried = out is None
        if retried:                          # check 1: one retry, told what was wrong
            raw = _chat(backend, system, f"{user}\n\nYour previous reply was rejected: {error}. "
                                         "Reply again with JSON that matches the schema exactly.", schema, stop)
            out, error = parse(raw)
        latency = time.monotonic() - started
    if out is None:
        verification = {"passed": False, "flags": [{"check": "schema", "text": "", "detail": error}]}
        output = {"raw": raw[:4000]}
    else:
        verification = verify(out, evidence)
        output = out.model_dump()
    verification["schema_retry"] = retried
    cur = conn.execute(
        "INSERT INTO interpretations(incident_id, intent, model, evidence_hash, output_json, verification_json, "
        "created_at, latency_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (evidence["incident_id"], intent, backend.model, prompt_maker.evidence_hash(evidence),
         json.dumps({"output": output, "evidence": evidence}), json.dumps(verification), db.utcnow(), latency))
    return cur.lastrowid


def _chat(backend: LLMBackend, system: str, user: str, schema: dict, stop: threading.Event | None) -> str:
    if stop is not None and stop.is_set():
        raise Stopped("Stopped.")
    raw = backend.chat(system, user, schema, stop=stop)
    if stop is not None and stop.is_set():           # a backend that cannot stop mid-reply: drop the answer
        raise Stopped("Stopped.")
    return raw


def stop_job(incident_id: int, intent: str) -> bool:
    """Stop a running explanation; True if one was running."""
    with _jobs_lock:
        job = JOBS.get((incident_id, intent))
    if job is None or job["state"] != "running":
        return False
    job["stop"].set()
    return True


def start(db_path: Path, incident_id: int, intent: str) -> None:
    """Generate in a background thread unless the same job is already running."""
    key = (incident_id, intent)
    with _jobs_lock:
        if JOBS.get(key, {}).get("state") == "running":
            return
        JOBS[key] = job_state = {"state": "running", "started": time.monotonic(), "stop": threading.Event()}

    def job() -> None:
        conn = db.connect(db_path)
        try:
            generate(conn, incident_id, intent, stop=job_state["stop"])
            with _jobs_lock:
                JOBS.pop(key, None)
        except Stopped:
            with _jobs_lock:
                JOBS.pop(key, None)
            db.audit(conn, None, "explanation_stopped", f"incident {incident_id} ({intent})")
        except Exception as exc:  # noqa: BLE001 - shown on the AI page and in the process log
            with _jobs_lock:
                JOBS[key] = {"state": "failed", "error": str(exc)[:300]}
            db.audit(conn, None, "explanation_failed", f"incident {incident_id} ({intent}): {exc}"[:1000])
        finally:
            conn.close()
    threading.Thread(target=job, daemon=True).start()


def status(conn: sqlite3.Connection, incident_id: int, intent: str) -> dict:
    """{"state": "done", "interpretation": id} | {"state": "running", "percent"} | {"state": "failed", "error"} |
    {"state": "none"}. A running job's percent is an estimate from the last 10 timed runs, held at 95 until done."""
    hit = cached(conn, evidence_for(conn, incident_id, intent), intent)
    if hit is not None:
        return {"state": "done", "interpretation": hit["id"]}
    with _jobs_lock:
        job = dict(JOBS.get((incident_id, intent), {"state": "none"}))
    started = job.pop("started", None)
    job.pop("stop", None)
    if job["state"] == "running" and started is not None:
        expected = conn.execute("SELECT AVG(latency_s) FROM (SELECT latency_s FROM interpretations WHERE latency_s "
                                "IS NOT NULL ORDER BY id DESC LIMIT 10)").fetchone()[0] or EXPECTED_S
        job["percent"] = round(min(95.0, 100 * (time.monotonic() - started) / expected))
    return job
