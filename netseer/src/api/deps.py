"""Shared FastAPI dependencies: database, templates, RBAC, CSRF, flash messages and page rendering."""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from netseer.src.config import WEB_DIR, app_config
from netseer.src.database import db

SESSION_COOKIE = "netseer_session"
PRE_CSRF_COOKIE = "netseer_pre"
FLASH_COOKIE = "netseer_flash"
ANALYSIS_COOKIE = "netseer_analysis"

STATUS_CLASS = {
    "done": "ok",
    "awaiting_attribution": "info",
    "pending": "info",
    "failed": "danger",
    "stopped": "warn",
    "queued": "warn",
    "running_suricata": "warn",
    "processing": "warn",
    "waiting_interfaces": "warn",
    "waiting_traffic": "warn",
    "ready": "info",
    "running": "ok",
}

templates = Jinja2Templates(directory=WEB_DIR / "templates")
templates.env.filters["status_class"] = lambda s: STATUS_CLASS.get(s, "")

# Tooltip for every table column head with this text (layout.html sets it on <th> elements without a title).
COLUMN_HELP = {
    "Actions": "What you can do with this row",
    "Alerts": "Number of Suricata (or NetSeer scan) alerts counted here",
    "Attacker (source)": "Address that sent the traffic that raised the alerts, as Suricata saw it",
    "Victim (destination)": "Address that received that traffic, as Suricata saw it",
    "Band": "Risk band from the OWASP matrix of likelihood and impact levels: Note < Low < Medium < High < Critical",
    "By": "Account that did it",
    "Check": "Verifier result: Verified, or how many claims were flagged",
    "Class": "Attack category (Suricata classtype); ET SCAN rules are read as attempted-recon",
    "Confidence": "How sure the network discovery is: certain (VLAN/DHCP) > strong (broadcast/gateway) > probable (/24 guess)",
    "Created": "When it was created",
    "Created (UTC)": "When it was created, in UTC",
    "Data": "Amount of traffic in bytes",
    "Destination": "Destination address and port of the traffic",
    "Detail": "More information about the event",
    "Device": "Internal device (LAN address) and its name if known",
    "Direction": "ext→int inbound, int→ext outbound, int→int inside the LAN, ext→ext outside only (relative to the LAN CIDRs)",
    "Event": "What happened",
    "Events": "eve.json records Suricata wrote (alerts, flows, DNS, TLS, …)",
    "Evidence": "What the value or finding is based on",
    "Factor": "Risk factor: L1–L5 likelihood, I1–I3 impact (CONCEPTS A5.2)",
    "Files": "Capture files in this analysis (merged in time order)",
    "First seen (UTC)": "Time of the first alert or packet, in UTC",
    "Flows": "Number of network flows (connections) Suricata recorded",
    "Gateway": "Router of this network: its internal address receives traffic bound for the internet",
    "Hostname": "Name from DHCP, DNS, TLS SNI or HTTP host (remembered across analyses)",
    "Hosts": "Addresses involved",
    "Incident": "Possible incident the row belongs to",
    "IP": "IP address",
    "Interface": "Network card name on this machine",
    "State": "Whether the cable has a link, and the kernel's operational state",
    "Addresses": "IP addresses set on the card (a mirror card has none)",
    "Received packets": "Packets the card has received since boot",
    "Last seen": "Time of the last alert or packet",
    "Last seen (UTC)": "Time of the last alert or packet, in UTC",
    "Level": "info or warning",
    "MAC": "Hardware address of the device",
    "MAC / vendor": "Hardware address and the maker it belongs to",
    "Main signature": "The rule that raised the most alerts for this pair",
    "Mode": "offline (uploaded captures) or live (mirror port)",
    "Model": "Language model that wrote the explanation",
    "Name": "Analysis name (you can rename it)",
    "Network": "Network prefix (subnet) the address belongs to",
    "Note": "Administrator's note",
    "Ports": "Destination ports used",
    "Priority": "Suricata rule priority: 1 = highest … 4 = lowest",
    "Proto": "Transport protocol / application protocol",
    "Question": "Prompt Maker button used",
    "Received": "Alerts where this device was the destination",
    "Risk": "Device risk P(d): combined, time-decayed probability from its incidents; colour = its worst incident band",
    "Role": "Administrator (manage) or User (view only)",
    "Rule": "Correlation rule that linked the incident: R1 pair, R2 sweep, R3 fan-in, R4 tactic progression, single",
    "Score": "R = 10 · (L/9) · (I/9), 0–10; sorts incidents inside a band",
    "Seconds": "Time the model took to answer",
    "Seen (UTC)": "First and last time seen, in UTC",
    "Sent": "Alerts where this device was the source",
    "Services": "Ports this device answered on (services it offers)",
    "Severity": "ET signature_severity: Critical, Major, Minor, Informational",
    "Signature": "Rule message and SID (signature ID)",
    "Source": "Source address and port of the traffic",
    "Span (UTC)": "From the first to the last alert of the incident, in UTC",
    "Status": "Processing stage or result of the analysis",
    "Talked to": "Internal hosts this outside address exchanged traffic with",
    "Time": "When it happened",
    "Time (UTC)": "When it happened, in UTC",
    "Title": "Plain summary of the possible incident",
    "Total": "All alerts involving this device",
    "Type": "Device type from Device attribution; sets asset criticality I1 (Server 9 … Guest 3)",
    "User": "Account involved",
    "Username": "Sign-in name",
    "Value (0–9)": "Factor value on the 0–9 scale; 'left out' when unknown",
    "Vendor": "Maker of the network card, from the MAC address",
    "VLAN": "802.1Q VLAN ID seen on the traffic",
    "Why": "One-line reason for the value",
}
templates.env.globals["column_help"] = COLUMN_HELP


class LoginRequired(Exception):
    """Raised when a page needs a signed-in user; handled as a redirect to /login."""


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    """Yield a per-request SQLite connection."""
    conn = db.connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


def require_user(request: Request) -> sqlite3.Row:
    """Dependency: the signed-in user, or redirect to /login."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise LoginRequired()
    return user


def require_role(role: str) -> Callable[[Request], sqlite3.Row]:
    """Dependency factory for RBAC: 403 unless the signed-in user has `role`."""
    def dependency(request: Request) -> sqlite3.Row:
        user = require_user(request)
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="This action needs the administrator account.")
        return user
    return dependency


require_admin = require_role("admin")


def set_cookie(response: HTMLResponse | RedirectResponse, name: str, value: str) -> None:
    """Set an HttpOnly, SameSite=Lax cookie (Secure when configured for TLS)."""
    response.set_cookie(name, value, httponly=True, samesite="lax", secure=bool(app_config("secure_cookies")))


def redirect(url: str, kind: str | None = None, message: str | None = None) -> RedirectResponse:
    """303 redirect, optionally carrying a one-time flash message."""
    response = RedirectResponse(url, status_code=303)
    if message:
        payload = base64.urlsafe_b64encode(json.dumps([kind or "info", message]).encode()).decode()
        set_cookie(response, FLASH_COOKIE, payload)
    return response


def read_flash(request: Request) -> list[tuple[str, str]]:
    """Decode the flash cookie, if any (the session middleware clears it after the request)."""
    raw = request.cookies.get(FLASH_COOKIE)
    if not raw:
        return []
    try:
        kind, message = json.loads(base64.urlsafe_b64decode(raw.encode()))
        return [(str(kind), str(message))]
    except (ValueError, TypeError):
        return []


def layout_context(request: Request, conn: sqlite3.Connection, active: str) -> dict[str, Any]:
    """Context for the signed-in layout: active nav item, all analyses and the selected one (cookie)."""
    analyses = conn.execute("SELECT id, name, mode, status, error FROM analyses ORDER BY id DESC").fetchall()
    try:
        selected_id = int(request.cookies.get(ANALYSIS_COOKIE, ""))
    except ValueError:
        selected_id = None
    selected = next((a for a in analyses if a["id"] == selected_id), None)
    new_devices = 0
    if selected is not None and selected["mode"] == "live":      # live attribution banner (A13)
        new_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE analysis_id = ? AND attributed = 0",
                                   (selected["id"],)).fetchone()[0]
    return {"active": active, "analyses": analyses, "selected": selected, "live_new_devices": new_devices}


def order_by(params: dict[str, str], columns: dict[str, str], default: str) -> str:
    """ORDER BY expression from ?sort=&dir= (server-sorted tables); only whitelisted keys reach the SQL."""
    key = params.get("sort")
    if key not in columns:
        return default
    return f"{columns[key]} {'DESC' if params.get('dir') == 'desc' else 'ASC'}"


PAGE_SIZE = 20             # rows per page in server-paged tables
SHOW_ALL_CAP = 2000        # "Show all" returns at most this many rows


def paging(params: dict[str, str], total: int) -> dict[str, Any]:
    """Window of a server-paged table: 20 rows per page, or every row (up to SHOW_ALL_CAP) with ?all=1."""
    pages = max(1, -(-total // PAGE_SIZE))
    show_all = params.get("all") == "1"
    page = 1 if show_all or not params.get("page", "").isdigit() else min(pages, max(1, int(params["page"])))
    return {"page": page, "pages": pages, "total": total, "show_all": show_all, "cap": SHOW_ALL_CAP,
            "limit": SHOW_ALL_CAP if show_all else PAGE_SIZE, "offset": 0 if show_all else (page - 1) * PAGE_SIZE}


def page_qs(params: dict[str, str | list[str]], *drop: str) -> str:
    """Query string of the current filters without paging keys (and any extra keys in `drop`)."""
    return urlencode({k: v for k, v in params.items() if k not in ("page", "all", *drop)}, doseq=True)


def distinct_values(conn: sqlite3.Connection, sql: str, args: tuple = (), limit: int = 500) -> list:
    """Suggestions for a type-or-pick search box: the most frequent non-empty values of `sql`'s first column."""
    return [r[0] for r in conn.execute(f"SELECT v FROM ({sql}) WHERE v IS NOT NULL AND v != '' "
                                       f"GROUP BY v ORDER BY COUNT(*) DESC LIMIT {int(limit)}", args)]


def csrf_token_for(request: Request) -> str:
    """Return the CSRF token for this request: the session's token or a pre-login token.

    A new pre-login token is kept in request.state so that `render` can set its cookie.
    """
    session = getattr(request.state, "session", None)
    if session is not None:
        return session["csrf"]
    token = request.cookies.get(PRE_CSRF_COOKIE)
    if not token:
        token = getattr(request.state, "new_pre_csrf", None) or secrets.token_urlsafe(32)
        request.state.new_pre_csrf = token
    return token


def verify_csrf(request: Request, csrf_token: str = Form("")) -> None:
    """Reject a POST whose form token does not match the session (or pre-login) token."""
    check_csrf(request, csrf_token)


def verify_csrf_header(request: Request) -> None:
    """CSRF check for JavaScript calls with a non-form body: token in the X-CSRF-Token header."""
    check_csrf(request, request.headers.get("x-csrf-token", ""))


def check_csrf(request: Request, csrf_token: str) -> None:
    """Compare a submitted token with the session (or pre-login) token."""
    session = getattr(request.state, "session", None)
    expected = session["csrf"] if session is not None else request.cookies.get(PRE_CSRF_COOKIE, "")
    if not expected or not hmac.compare_digest(expected, csrf_token):
        raise HTTPException(status_code=400, detail="Invalid or missing CSRF token. Reload the page and try again.")


def session_remaining(session: sqlite3.Row | None) -> int:
    """Seconds left in a session (0 if none or expired)."""
    if session is None or not session["expires_at"]:
        return 0
    return max(0, int((datetime.fromisoformat(session["expires_at"]) - datetime.now(timezone.utc)).total_seconds()))


def render(request: Request, name: str, context: dict[str, Any] | None = None, status_code: int = 200) -> HTMLResponse:
    """Render a template with the common context (user, CSRF token, flash messages)."""
    ctx: dict[str, Any] = {
        "user": getattr(request.state, "user", None),
        "csrf_token": csrf_token_for(request),
        "flashes": read_flash(request),
        "now_local": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "session_remaining": session_remaining(getattr(request.state, "session", None)),
    }
    ctx.update(context or {})
    response = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    new_pre = getattr(request.state, "new_pre_csrf", None)
    if new_pre:
        set_cookie(response, PRE_CSRF_COOKIE, new_pre)
    return response
