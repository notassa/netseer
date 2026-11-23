"""Settings page (CONCEPTS A10, A15): theme for everyone; accounts and NetSeer configuration for the administrator."""

from __future__ import annotations

import ipaddress
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from netseer.ai.kb import build_kb
from netseer.src import keystore
from netseer.src.api import auth
from netseer.src.api.client import who
from netseer.src.api.deps import (ANALYSIS_COOKIE, SESSION_COOKIE, get_db, layout_context, redirect, render,
                                  require_admin, require_user, verify_csrf)
from netseer.src.config import app_config, get_setting, set_setting
from netseer.src.database.db import audit, connect
from netseer.src.engine import ingest, oui
from netseer.src.engine.acp import run_acp
from netseer.src.engine.scorer import roll_up

router = APIRouter(prefix="/settings")

THEMES = ("white", "black")

# A15 numeric settings: key → (label, type, min, max, unit).
CONFIG_FIELDS = {
    "aggregation_gap_s": ("Aggregation gap", int, 10, 86400, "seconds"),
    "correlation_window_min": ("Correlation window", int, 1, 1440, "minutes"),
    "half_life_days": ("Risk decay half-life", float, 0.1, 365, "days"),
    "max_upload_mb": ("Max pcap upload size (per file)", int, 1, 2048, "MB"),
    "live_interval_s": ("Live processing interval", int, 5, 3600, "seconds"),
}
WINDOW_KEYS = ("aggregation_gap_s", "correlation_window_min")
AI_FIELDS = ("llm_backend", "llm_model", "cloud_url", "cloud_model")
DATA_UNITS = {"bit": "bit (b, kb, Mb, Gb)", "byte": "byte (B, KB, MB, GB)", "packet": "packet (pkt)"}
_kb_lock = threading.Lock()      # one knowledge-base rebuild at a time
_oui_lock = threading.Lock()


def _kb_status() -> dict:
    built = build_kb.KB_PATH.stat().st_mtime if build_kb.KB_PATH.exists() else None
    return {"building": _kb_lock.locked(),
            "built": datetime.fromtimestamp(built, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if built else None}


@router.get("")
def settings_page(request: Request, user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Theme selector, plus account management for the administrator."""
    accounts = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY role").fetchall()
    return render(request, "settings.html", {
        **layout_context(request, conn, "settings"),
        "accounts": accounts if user["role"] == "admin" else [],
        "has_user": any(a["role"] == "user" for a in accounts),
        "config_fields": CONFIG_FIELDS,
        "config": {key: get_setting(conn, key) for key in (*CONFIG_FIELDS, "lan_cidrs", "inside_rules", "mac_lookup_online", "data_unit")},
        "data_units": DATA_UNITS,
        "kb": _kb_status(),
        "oui": oui.manuf_info() | {"updating": _oui_lock.locked()},
        "ai": {key: get_setting(conn, key) for key in AI_FIELDS},
        "key_names": keystore.KEY_NAMES,
        "keys_set": keystore.key_names(conn),
        "auto_logout": get_setting(conn, "auto_logout"),
    })


def _parse_config(form, conn: sqlite3.Connection) -> dict:
    """Validate the configuration form; raises ValueError with a plain message."""
    values = {}
    for key, (label, kind, low, high, unit) in CONFIG_FIELDS.items():
        try:
            value = kind(str(form.get(key, "")).strip())
        except ValueError:
            raise ValueError(f"{label} must be a number.") from None
        if not low <= value <= high:
            raise ValueError(f"{label} must be between {low} and {high} {unit}.")
        values[key] = value
    data_unit = form.get("data_unit", get_setting(conn, "data_unit"))
    if data_unit not in DATA_UNITS:
        raise ValueError("Pick a data representation.")
    values["data_unit"] = data_unit
    values["inside_rules"] = form.get("inside_rules") == "on"
    values["mac_lookup_online"] = form.get("mac_lookup_online") == "on"
    cidrs = [c.strip() for c in str(form.get("lan_cidrs", "")).replace(",", "\n").splitlines() if c.strip()]
    if not cidrs:
        raise ValueError("Give at least one LAN CIDR.")
    try:
        values["lan_cidrs"] = [str(ipaddress.ip_network(c, strict=False)) for c in cidrs]
    except ValueError:
        raise ValueError("LAN CIDRs must look like 192.168.1.0/24, one per line.") from None
    return values


@router.post("/config", dependencies=[Depends(verify_csrf)])
async def save_config(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Save NetSeer configuration (A15); a window change re-runs ACP 3–6, a half-life change re-scores device risk."""
    try:
        values = _parse_config(await request.form(), conn)
    except ValueError as exc:
        return redirect("/settings#tab-config", "error", str(exc))
    changed = [k for k, v in values.items() if v != get_setting(conn, k)]
    if not changed:
        return redirect("/settings#tab-config", "info", "Nothing changed.")
    for key in changed:
        set_setting(conn, key, values[key])
    selected = layout_context(request, conn, "settings")["selected"]
    note = ""
    if selected is not None and selected["status"] not in ingest.ACTIVE_STATUSES:
        if any(k in WINDOW_KEYS for k in changed):
            stats = run_acp(conn, selected["id"])
            note = f" Analysis re-run: {stats['groups']} alert groups, {stats['incidents']} possible incidents."
        elif "half_life_days" in changed:
            roll_up(conn, selected["id"])
            note = " Device risk re-scored."
    audit(conn, admin["id"], "config_changed",
          ", ".join(f"{k} = {values[k]}" for k in changed) + (f"; analysis {selected['id']} re-scored" if note else ""))
    return redirect("/settings#tab-config", "ok", "Configuration saved." + note)


@router.post("/ai", dependencies=[Depends(verify_csrf)])
async def save_ai(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """LLM backend and model, cloud API settings and API keys (A15). Keys are write-only: blank keeps, Remove clears."""
    form = await request.form()
    values = {key: str(form.get(key, "")).strip() for key in AI_FIELDS}
    if values["llm_backend"] not in ("ollama", "cloud"):
        return redirect("/settings#tab-ai", "error", "Pick the local or the cloud LLM.")
    if not values["llm_model"]:
        return redirect("/settings#tab-ai", "error", "Give the local model name.")
    if values["cloud_url"] and not values["cloud_url"].startswith("https://"):
        return redirect("/settings#tab-ai", "error", "The cloud API URL must start with https://.")
    changed = [k for k, v in values.items() if v != get_setting(conn, k)]
    for key in changed:
        set_setting(conn, key, values[key])
    for name in keystore.KEY_NAMES:
        if form.get(f"remove_{name}"):
            keystore.set_key(conn, name, "")
            changed.append(f"{name} key removed")
        elif value := str(form.get(f"key_{name}", "")).strip():
            keystore.set_key(conn, name, value)
            changed.append(f"{name} key set")
    if values["llm_backend"] == "cloud" and not (values["cloud_model"] and "cloud_llm" in keystore.key_names(conn)):
        set_setting(conn, "llm_backend", "ollama")
        changed.append("llm_backend = ollama (cloud needs a model and a key)")
    if not changed:
        return redirect("/settings#tab-ai", "info", "Nothing changed.")
    audit(conn, admin["id"], "config_changed",
          "; ".join(c if " " in c else f"{c} = {values[c]}" for c in changed), *who(request))
    return redirect("/settings#tab-ai", "ok", "AI settings saved.")


@router.post("/kb-rebuild", dependencies=[Depends(verify_csrf)])
def kb_rebuild(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Rebuild the AI knowledge base in the background (CONCEPTS A6, A15)."""
    if not _kb_lock.acquire(blocking=False):
        return redirect("/settings#tab-kb", "info", "The knowledge base is already being rebuilt.")
    db_path = request.app.state.db_path

    def job() -> None:
        try:
            counts = build_kb.build()
            detail = ", ".join(f"{k} {v}" for k, v in counts.items())
            event = "kb_rebuilt"
        except Exception as exc:  # noqa: BLE001 - recorded in the process log
            detail, event = str(exc)[:500], "kb_rebuild_failed"
        finally:
            _kb_lock.release()
        log = connect(db_path)
        audit(log, None, event, detail)
        log.close()
    threading.Thread(target=job, daemon=True).start()
    audit(conn, admin["id"], "kb_rebuild", "started", *who(request))
    return redirect("/settings#tab-kb", "ok", "Rebuilding the knowledge base (about 20 seconds).")


@router.post("/rules-update", dependencies=[Depends(verify_csrf)])
def rules_update(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Update the Suricata rules (`sudo suricata-update`, no arguments allowed) and rebuild the knowledge base."""
    if not _kb_lock.acquire(blocking=False):
        return redirect("/settings#tab-kb", "info", "The rules or knowledge base are already being updated.")
    db_path = request.app.state.db_path

    def job() -> None:
        try:
            r = subprocess.run(["sudo", "-n", "/usr/bin/suricata-update"], capture_output=True, text=True, timeout=900)
            if r.returncode != 0:
                raise RuntimeError((r.stderr or r.stdout).strip().splitlines()[-1:] or ["failed"])
            counts = build_kb.build()
            detail, event = "rules updated; knowledge base " + ", ".join(f"{k} {v}" for k, v in counts.items()), \
                "rules_updated"
        except Exception as exc:  # noqa: BLE001 - recorded in the process log
            detail, event = str(exc)[:500], "rules_update_failed"
        finally:
            _kb_lock.release()
        log = connect(db_path)
        audit(log, None, event, detail)
        log.close()
    threading.Thread(target=job, daemon=True).start()
    audit(conn, admin["id"], "rules_update", "started", *who(request))
    return redirect("/settings#tab-kb", "ok", "Updating the Suricata rules, then the knowledge base (a few minutes). "
                                               "New rules apply to the next analysis or live session.")


@router.post("/oui-update", dependencies=[Depends(verify_csrf)])
def oui_update(request: Request, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Download the latest Wireshark MAC vendor list in the background and refresh stored device vendors."""
    if not _oui_lock.acquire(blocking=False):
        return redirect("/settings#tab-oui", "info", "The MAC vendor list is already being updated.")
    db_path = request.app.state.db_path

    def job() -> None:
        log = connect(db_path)
        try:
            n = oui.update_manuf()
            oui_csv = str(app_config("oui_csv"))
            rows = log.execute("SELECT id, mac FROM devices WHERE mac IS NOT NULL").fetchall()
            log.executemany("UPDATE devices SET vendor = ? WHERE id = ?",
                            [(oui.vendor_for(r["mac"], oui_csv), r["id"]) for r in rows])
            audit(log, None, "oui_updated", f"{n} vendor entries; {len(rows)} device vendors refreshed")
        except Exception as exc:  # noqa: BLE001 - recorded in the process log
            audit(log, None, "oui_update_failed", str(exc)[:500])
        finally:
            _oui_lock.release()
            log.close()
    threading.Thread(target=job, daemon=True).start()
    audit(conn, admin["id"], "oui_update", "started", *who(request))
    return redirect("/settings#tab-oui", "ok", "Downloading the Wireshark MAC vendor list (a few seconds).")


@router.post("/theme", dependencies=[Depends(verify_csrf)])
def set_theme(request: Request, theme: str = Form(...), user=Depends(require_user), conn: sqlite3.Connection = Depends(get_db)):
    """Store the signed-in account's theme (white or black)."""
    if theme not in THEMES:
        raise HTTPException(status_code=400, detail="Unknown theme.")
    conn.execute("UPDATE users SET theme = ? WHERE id = ?", (theme, user["id"]))
    audit(conn, user["id"], "theme", theme, *who(request))
    return redirect("/settings#tab-theme", "ok", f"Theme set to {theme}.")


@router.post("/auto-logout", dependencies=[Depends(verify_csrf)])
def set_auto_logout(request: Request, enabled: str = Form(""), admin=Depends(require_admin),
                    conn: sqlite3.Connection = Depends(get_db)):
    """Turn auto-logout on (sessions end after session_minutes unless extended) or off (12 h cap) for both accounts."""
    on = enabled == "on"
    set_setting(conn, "auto_logout", on)
    audit(conn, admin["id"], "auto_logout_on" if on else "auto_logout_off", "", *who(request))
    return redirect("/settings#tab-accounts", "ok", f"Auto-logout turned {'on' if on else 'off'}.")


@router.post("/users", dependencies=[Depends(verify_csrf)])
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
    admin=Depends(require_admin),
    conn: sqlite3.Connection = Depends(get_db),
):
    """Create the single view-only user account."""
    try:
        auth.create_account(conn, username, password, confirm, role="user")
    except auth.AuthError as exc:
        return redirect("/settings#tab-accounts", "error", str(exc))
    audit(conn, admin["id"], "user_create", auth.normalise_username(username), *who(request))
    return redirect("/settings#tab-accounts", "ok", "User account created.")


def _user_account(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'user'", (user_id,)).fetchone()
    if row is None:       # the admin account cannot be reset or deleted here
        raise HTTPException(status_code=404)
    return row


@router.post("/users/{user_id}/reset", dependencies=[Depends(verify_csrf)])
def reset_user(
    request: Request,
    user_id: int,
    password: str = Form(...),
    confirm: str = Form(...),
    admin=Depends(require_admin),
    conn: sqlite3.Connection = Depends(get_db),
):
    """Set a new password for the user account and sign it out everywhere."""
    row = _user_account(conn, user_id)
    try:
        auth.set_password(conn, user_id, password, confirm)
    except auth.AuthError as exc:
        return redirect("/settings#tab-accounts", "error", str(exc))
    audit(conn, admin["id"], "user_reset", row["username"], *who(request))
    return redirect("/settings#tab-accounts", "ok", "User password reset.")


@router.post("/detonate", dependencies=[Depends(verify_csrf)])
def detonate(request: Request, password: str = Form(""), confirm: str = Form(""), admin=Depends(require_admin),
             conn: sqlite3.Connection = Depends(get_db)):
    """Factory reset (CONCEPTS A12): wipe every analysis, file, account, setting and log; back to first launch."""
    busy = conn.execute(f"SELECT 1 FROM analyses WHERE status IN ({','.join('?' * len(ingest.ACTIVE_STATUSES))})",
                        ingest.ACTIVE_STATUSES).fetchone()
    if busy:
        return redirect("/settings#tab-detonate", "error", "An analysis is still running. Wait for it to finish before detonating.")
    if confirm.strip() != "DETONATE":
        return redirect("/settings#tab-detonate", "error", "Type DETONATE to confirm.")
    try:
        auth.authenticate(conn, admin["username"], password)
    except auth.AuthError as exc:
        return redirect("/settings#tab-detonate", "error", f"Detonate refused: {exc}")
    ip, mac = who(request)
    ingest.detonate(conn, request.app.state.data_dir)
    audit(conn, None, "netseer_detonated", f"factory reset by administrator '{admin['username']}'", ip, mac)
    request.app.state.admin_exists = False
    response = RedirectResponse("/setup", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(ANALYSIS_COOKIE)
    return response


@router.post("/users/{user_id}/delete", dependencies=[Depends(verify_csrf)])
def delete_user(request: Request, user_id: int, admin=Depends(require_admin), conn: sqlite3.Connection = Depends(get_db)):
    """Delete the user account (its sessions go with it)."""
    row = _user_account(conn, user_id)
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    audit(conn, admin["id"], "user_delete", row["username"], *who(request))
    return redirect("/settings#tab-accounts", "ok", "User account deleted.")
