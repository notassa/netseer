"""Evidence package and Prompt Maker (CONCEPTS A7, brief §7).

Every fact the model may use gets an ID: `E#` for what NetSeer observed and scored, `K#` for retrieved knowledge.
`unknowns` says what is missing. The Prompt Maker intents only change the instruction, never the evidence.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3

from netseer.ai import rag
from netseer.ai.schemas import ExplainOutput
from netseer.src.engine import ti
from netseer.src.engine.constants import FACTOR_NAMES
from netseer.src.engine.scorer import network_health

MAX_HOSTS = 5
MAX_GROUPS = 5
MAX_INCIDENTS = 5
KNOWLEDGE_CHARS = 250          # per K# item; keeps the prompt inside num_ctx 4096

INTENTS = {
    "explain_simple": ("Explain simply",
                       "Explain this possible incident to someone with no security background. Short sentences, no jargon."),
    "what_to_do": ("What should I do now?",
                   "Focus on recommended_actions: 3 to 5 concrete, safe steps in order, each with its reason."),
    "is_serious": ("Is this serious?",
                   "Answer whether this needs attention now. Restate the band and explain what drives it."),
    "technical": ("Explain technically",
                  "Explain for an IT technician: signatures, ports, ATT&CK techniques and the scoring factors."),
    "summarise_analysis": ("Summarise this analysis",
                           "Summarise the whole analysis: network health, the most important possible incidents, "
                           "and what to look at first."),
}

SYSTEM_PROMPT = """You explain network security alerts to non-experts for NetSeer.
Rules:
- Use ONLY the facts in the evidence package. Do not invent IP addresses, ports, numbers, dates or names.
- Every claim and every recommended action must cite the IDs it relies on (E# or K#) in "refs".
- Never say a device was compromised, hacked, infected or that an attack succeeded unless an E# fact says so.
  Alerts show attempts and suspicious traffic, not proof.
- Put what is not known in "uncertainty" (see "unknowns").
- In "risk_explanation", restate NetSeer's band exactly as given ({band}); do not re-score it.
- Plain language, about 250 words or fewer in total.
Reply with JSON only, matching the schema."""


def _ts(value: str | None) -> str:
    return (value or "unknown")[:19].replace("T", " ")


def _host_fact(conn: sqlite3.Connection, analysis_id: int, ip: str, role: str) -> str:
    dev = conn.execute("SELECT type, vendor, hostname, mac FROM devices WHERE analysis_id = ? AND ip = ?",
                       (analysis_id, ip)).fetchone()
    if dev is not None:
        extra = ", ".join(f"{k} {dev[k]}" for k in ("hostname", "vendor") if dev[k])
        return f"{role} {ip} is an internal device of type {dev['type'] or 'unknown'}" + (f" ({extra})" if extra else "")
    ext = conn.execute("SELECT hostname FROM external_hosts WHERE analysis_id = ? AND ip = ?", (analysis_id, ip)).fetchone()
    name = f" (name {ext['hostname']})" if ext is not None and ext["hostname"] else ""
    return f"{role} {ip} is outside the LAN{name}"


class _Package:
    def __init__(self) -> None:
        self.facts: list[dict] = []
        self.knowledge: list[dict] = []
        self.unknowns: list[str] = []

    def fact(self, text: str, kind: str) -> str:
        fid = f"E{len(self.facts) + 1}"
        self.facts.append({"id": fid, "kind": kind, "text": text})
        return fid

    def know(self, items: list[dict]) -> None:
        for it in items:
            text = it["text"] if len(it["text"]) <= KNOWLEDGE_CHARS else it["text"][:KNOWLEDGE_CHARS] + " …"
            self.knowledge.append({"id": f"K{len(self.knowledge) + 1}", "kind": it["kind"], "key": it["key"],
                                   "title": it["title"], "text": text, "url": it.get("url")})

    def done(self, band: str, **head) -> dict:
        if not rag.kb_ready():
            self.unknowns.append("The knowledge base is not built, so no background knowledge (K#) is included.")
        return {**head, "band": band, "facts": self.facts, "knowledge": self.knowledge, "unknowns": self.unknowns}


def build_evidence(conn: sqlite3.Connection, incident_id: int) -> dict:
    """The evidence package of one possible incident."""
    inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if inc is None:
        raise KeyError(incident_id)
    ev = json.loads(inc["evidence_json"] or "{}")
    factors = json.loads(inc["factors_json"] or "{}")
    p = _Package()
    p.fact(f"Possible incident \"{inc['title']}\": {inc['n_alerts']} alerts in {ev.get('groups', 0)} alert group{'s' if ev.get('groups', 0) != 1 else ''} "
           f"from {_ts(inc['first_seen'])} to {_ts(inc['last_seen'])} UTC.", "overview")
    p.fact(f"NetSeer's risk band is {inc['band']} (likelihood L {inc['likelihood']:.1f} of 9, impact I "
           f"{inc['impact']:.1f} of 9, score R {inc['score']:.1f} of 10).", "band")
    for key, name in FACTOR_NAMES.items():
        f = factors.get(key)
        if f is None:
            continue
        if f["value"] is None:
            p.unknowns.append(f"{key} {name}: {f['why']}.")
        else:
            p.fact(f"Risk factor {key} {name} = {f['value']:.1f} of 9: {f['why']}.", "factor")
    ips = [(ip, "Source") for ip in json.loads(inc["src_ips_json"] or "[]")] + \
          [(ip, "Destination") for ip in json.loads(inc["dest_ips_json"] or "[]")]
    for ip, role in ips[:MAX_HOSTS]:
        text = _host_fact(conn, inc["analysis_id"], ip, role)
        p.fact(text, "host")
        if "type unknown" in text:
            p.unknowns.append(f"The owner has not said what kind of device {ip} is.")
    if len(ips) > MAX_HOSTS:
        p.unknowns.append(f"{len(ips) - MAX_HOSTS} more hosts are involved but not listed.")
    groups = conn.execute(
        "SELECT g.* FROM incident_groups ig JOIN alert_groups g ON g.id = ig.group_id WHERE ig.incident_id = ? "
        "ORDER BY g.count DESC, g.first_seen LIMIT ?", (incident_id, MAX_GROUPS)).fetchall()
    for g in groups:
        p.fact(f"Alert group: SID {g['sid']} \"{g['signature']}\" ({g['classtype'] or 'no classtype'}), "
               f"{g['src_ip']} -> {g['dest_ip']} port {g['dest_port'] if g['dest_port'] is not None else 'unknown'}"
               f"/{g['proto'] or '?'}, {g['count']} alerts from {_ts(g['first_seen'])} to {_ts(g['last_seen'])} UTC.",
               "group")
    if ev.get("groups", 0) > len(groups):
        p.unknowns.append(f"{ev['groups'] - len(groups)} smaller alert groups are not listed.")
    if ev.get("tactics"):
        p.fact("ATT&CK tactics named by the rules: " + ", ".join(f"{t['id']} {t['name']}" for t in ev["tactics"])
               + (f"; techniques: {', '.join(ev['techniques'])}." if ev.get("techniques") else "."), "attack")
    reputation = ti.cached(conn, [ip for ip, _ in ips])
    for ip, by_source in reputation.items():
        for source, res in by_source.items():
            p.fact(f"Threat intelligence: {ip} is rated {res['score']:.0%} malicious by "
                   f"{'AbuseIPDB' if source == 'abuseipdb' else 'VirusTotal'}.", "ti")
    success = {c: n for c, n in (ev.get("classtypes") or {}).items() if c.startswith("successful-")}
    if success:
        p.fact("Suricata's rules classed " + ", ".join(f"{n} alerts as {c}" for c, n in success.items())
               + ": traffic typical of a successful attack. This is a strong sign, not proof.", "success")
    else:
        p.unknowns.append("Whether any attempt succeeded: network alerts alone do not show it.")
    sids = [s["sid"] for s in ev.get("signatures", [])]
    p.know(rag.retrieve(sids, list(ev.get("classtypes") or {}), ev.get("techniques", []),
                        " ".join([inc["title"], *(s["signature"] for s in ev.get("signatures", [])[:3])])))
    return p.done(inc["band"], scope="incident", incident_id=incident_id, analysis_id=inc["analysis_id"],
                  success_signal=bool(success))


def build_analysis_evidence(conn: sqlite3.Connection, analysis_id: int) -> dict:
    """The evidence package of a whole analysis ("Summarise this analysis"): health and the top incidents."""
    a = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if a is None:
        raise KeyError(analysis_id)
    net = network_health(conn, analysis_id)
    incs = conn.execute("SELECT * FROM incidents WHERE analysis_id = ? AND band != 'Note' ORDER BY score DESC "
                        "LIMIT ?", (analysis_id, MAX_INCIDENTS)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM incidents WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
    n_dev = conn.execute("SELECT COUNT(*) FROM devices WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
    p = _Package()
    p.fact(f"Analysis \"{a['name']}\": {a['n_alerts']} alerts, {total} possible incidents, {n_dev} internal devices.",
           "overview")
    p.fact(f"Network health is {net['health']:.0f} of 100 (100 means no risk found).", "band")
    classes: dict[str, int] = {}
    sids: list[int] = []
    for inc in incs:
        ev = json.loads(inc["evidence_json"] or "{}")
        p.fact(f"Possible incident \"{inc['title']}\": band {inc['band']}, score R {inc['score']:.1f} of 10, "
               f"{inc['n_alerts']} alerts from {_ts(inc['first_seen'])} to {_ts(inc['last_seen'])} UTC.", "incident")
        for c, n in (ev.get("classtypes") or {}).items():
            classes[c] = classes.get(c, 0) + n
        sids += [s["sid"] for s in ev.get("signatures", [])[:1]]
    if total > len(incs):
        p.unknowns.append(f"{total - len(incs)} lower-ranked possible incidents are not listed.")
    p.unknowns.append("Whether any attempt succeeded: network alerts alone do not show it.")
    p.know(rag.retrieve(sids, sorted(classes, key=classes.get, reverse=True)[:3]))
    top = incs[0]["band"] if incs else "Note"
    return p.done(top, scope="analysis", incident_id=incs[0]["id"] if incs else None, analysis_id=analysis_id,
                  success_signal=False)


def evidence_hash(evidence: dict) -> str:
    """Stable hash of an evidence package (the interpretation cache key)."""
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()[:16]


def messages(evidence: dict, intent: str) -> tuple[str, str]:
    """(system prompt, user prompt) for one intent."""
    instruction = INTENTS[intent][1]
    package = {"facts": evidence["facts"], "unknowns": evidence["unknowns"],
               "knowledge": [{k: v for k, v in item.items() if k != "url"} for item in evidence["knowledge"]]}
    band = "network health, not a band" if evidence["scope"] == "analysis" else evidence["band"]
    return (SYSTEM_PROMPT.format(band=band),
            f"{instruction}\n\nEvidence package:\n{json.dumps(package, ensure_ascii=False)}")


def output_schema() -> dict:
    """The JSON schema the backend must follow."""
    return ExplainOutput.model_json_schema()
