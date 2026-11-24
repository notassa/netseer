"""Audit-log event catalogue for the Information page: action → (tab, level, plain label)."""

from __future__ import annotations

EVENTS: dict[str, tuple[str, str, str]] = {
    # Account activity
    "setup": ("account", "info", "Administrator created"),
    "login": ("account", "info", "Signed in"),
    "login_failed": ("account", "warning", "Failed sign-in"),
    "login_locked": ("account", "error", "Sign-in locked (too many failures)"),
    "logout": ("account", "info", "Signed out"),
    "session_expired": ("account", "info", "Session expired (time ran out)"),
    "session_extended": ("account", "info", "Session extended (+10 min)"),
    "user_create": ("account", "info", "User account created"),
    "user_reset": ("account", "warning", "User password reset"),
    "user_delete": ("account", "warning", "User account deleted"),
    "theme": ("account", "info", "Theme changed"),
    "netseer_detonated": ("account", "warning", "NetSeer detonated (factory reset)"),
    "account_log_cleared": ("account", "warning", "Account activity log cleared"),
    # Process log
    "upload_started": ("process", "info", "Upload started"),
    "analysis_succeeded": ("process", "info", "Analysis succeeded"),
    "analysis_reprocess": ("process", "info", "Live reprocess started"),
    "analysis_reprocessed": ("process", "info", "Live session reprocessed from stored eve.json"),
    "analysis_failed": ("process", "error", "Analysis failed"),
    "analysis_interrupted": ("process", "warning", "Analysis interrupted"),
    "capture_truncated": ("process", "warning", "Capture cut off (analysed up to the cut)"),
    "analysis_rerun": ("process", "info", "Analysis started again"),
    "attribution_saved": ("process", "info", "Device types saved"),
    "device_type": ("process", "info", "Device type changed"),
    "analysis_renamed": ("process", "info", "Analysis renamed"),
    "analysis_note": ("process", "info", "Note saved"),
    "analysis_deleted": ("process", "warning", "Analysis deleted"),
    "config_changed": ("process", "info", "NetSeer configuration changed"),
    "process_log_cleared": ("process", "warning", "Process log cleared"),
    "lan_adopted": ("process", "info", "Looks-local networks adopted as LAN (analysed again)"),
    "kb_rebuild": ("process", "info", "Knowledge base rebuild started"),
    "kb_rebuilt": ("process", "info", "Knowledge base rebuilt"),
    "kb_rebuild_failed": ("process", "error", "Knowledge base rebuild failed"),
    "oui_update": ("process", "info", "MAC vendor list update started"),
    "oui_updated": ("process", "info", "MAC vendor list updated"),
    "oui_update_failed": ("process", "error", "MAC vendor list update failed"),
    "explanation_failed": ("process", "error", "AI explanation failed"),
    "ti_failed": ("process", "warning", "Threat intelligence lookup failed"),
    "analysis_stop_requested": ("process", "info", "Analysis stop requested"),
    "analysis_stopped": ("process", "warning", "Analysis stopped (results cleared, captures kept)"),
    "file_deleted": ("process", "warning", "Capture file deleted"),
    "explanation_stopped": ("process", "info", "AI explanation stopped"),
    "explanations_cleared": ("process", "warning", "Saved AI explanations cleared"),
    "live_opened": ("process", "info", "Live session opened"),
    "live_started": ("process", "info", "Live capture started"),
    "live_stopped": ("process", "info", "Live session stopped"),
    "live_link_down": ("process", "warning", "Live link dropped (data kept)"),
    "live_error": ("process", "error", "Live monitor error"),
    "rules_update": ("process", "info", "Suricata rules update started"),
    "rules_updated": ("process", "info", "Suricata rules updated"),
    "rules_update_failed": ("process", "error", "Suricata rules update failed"),
    "auto_logout_on": ("account", "info", "Auto-logout turned on"),
    "auto_logout_off": ("account", "warning", "Auto-logout turned off"),
}


def actions(tab: str, level: str | None = None) -> list[str]:
    """Actions shown on a tab, optionally only those of one level."""
    return [a for a, (t, lv, _) in EVENTS.items() if t == tab and (level is None or lv == level)]
