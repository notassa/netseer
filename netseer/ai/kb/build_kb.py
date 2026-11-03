"""Build the RAG knowledge base (CONCEPTS A6) offline into ai/kb/kb.db.

Tables: kb_rules (every enabled Suricata rule), kb_attack (ATT&CK tactics, techniques, mitigations),
kb_mitigates (mitigation → technique), kb_classtype (classification.config in plain words) and the FTS5 table
kb_playbooks (playbooks.json). The database is replaced atomically, so the app can keep reading the old one.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

KB_DIR = Path(__file__).resolve().parent
KB_PATH = KB_DIR / "kb.db"
STIX_PATH = KB_DIR / "enterprise-attack.json"
PLAYBOOKS_PATH = KB_DIR / "playbooks.json"
RULES_PATH = Path("/var/lib/suricata/rules/suricata.rules")

SCHEMA = """
CREATE TABLE kb_rules(sid INTEGER PRIMARY KEY, msg TEXT, classtype TEXT, tactics TEXT, techniques TEXT, cves TEXT,
                      attack_target TEXT, refs TEXT);
CREATE TABLE kb_attack(id TEXT PRIMARY KEY, kind TEXT, name TEXT, description TEXT, tactics TEXT, url TEXT);
CREATE TABLE kb_mitigates(mitigation_id TEXT, technique_id TEXT, PRIMARY KEY(technique_id, mitigation_id));
CREATE TABLE kb_classtype(name TEXT PRIMARY KEY, description TEXT, priority INTEGER, plain TEXT);
CREATE VIRTUAL TABLE kb_playbooks USING fts5(id UNINDEXED, category, title, tags, body);
"""

# Plain-language versions of the classtypes non-experts meet most often; the rest keep Suricata's description.
PLAIN_CLASSTYPES = {
    "attempted-recon": "Someone tried to learn about your systems (scanning or probing).",
    "successful-recon-limited": "Some information about a system was exposed to someone probing it.",
    "successful-recon-largescale": "A lot of information about your systems was exposed.",
    "attempted-dos": "Someone tried to overload a system so it stops working.",
    "successful-dos": "A system may have been overloaded and stopped working.",
    "attempted-user": "Someone tried to get user-level access to a system.",
    "attempted-admin": "Someone tried to get administrator access to a system.",
    "successful-user": "Someone may have gained user-level access to a system.",
    "successful-admin": "Someone may have gained administrator access to a system.",
    "web-application-attack": "Someone sent a request built to attack a website or web app.",
    "trojan-activity": "A device behaved like it is infected with malware.",
    "command-and-control": "A device may be talking to a server that controls malware.",
    "bad-unknown": "Traffic that looks suspicious but is not clearly an attack.",
    "policy-violation": "Traffic that breaks a usual security policy (for example plain-text logins or games).",
    "protocol-command-decode": "An unusual or risky command was seen inside a network protocol.",
    "misc-activity": "Unusual activity worth a look, usually low risk.",
    "not-suspicious": "Normal traffic, recorded for context.",
    "unknown": "Traffic of an unknown kind.",
    "network-scan": "Someone scanned the network to find devices or open ports.",
    "default-login-attempt": "Someone tried to log in with a default username or password.",
    "credential-theft": "Someone may be trying to steal passwords or logins.",
    "exploit-kit": "Traffic from a toolkit that attacks browsers or plugins.",
    "domain-c2": "A device looked up a domain linked to malware control servers.",
    "social-engineering": "Content built to trick people, such as phishing.",
}

_OPTION = re.compile(r'(\w+)\s*:\s*("(?:[^"\\]|\\.)*"|[^;]*);')


def parse_rule(line: str) -> dict | None:
    """Fields of one enabled rule line (None for comments, disabled rules and lines without a sid)."""
    line = line.strip()
    if not line or line.startswith("#") or "(" not in line:
        return None
    opts: dict[str, list[str]] = {}
    for key, value in _OPTION.findall(line[line.index("(") + 1:]):
        opts.setdefault(key, []).append(value.strip().strip('"'))
    if "sid" not in opts:
        return None
    meta: dict[str, list[str]] = {}
    for part in ",".join(opts.get("metadata", [])).split(","):
        key, _, value = part.strip().partition(" ")
        if key:
            meta.setdefault(key, []).append(value.strip())
    refs = opts.get("reference", [])
    return {
        "sid": int(opts["sid"][0]),
        "msg": opts.get("msg", [""])[0],
        "classtype": opts.get("classtype", [None])[0],
        "tactics": ",".join(meta.get("mitre_tactic_id", [])),
        "techniques": ",".join(meta.get("mitre_technique_id", [])),
        "cves": ",".join(f"CVE-{r.split(',', 1)[1]}" for r in refs if r.lower().startswith("cve,")),
        "attack_target": ",".join(meta.get("attack_target", [])),
        "refs": json.dumps([r.split(",", 1)[1] for r in refs if r.lower().startswith("url,")][:3]),
    }


def _first_paragraph(text: str | None, limit: int = 600) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", (text or "").split("\n\n")[0]).strip()
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + " …"


def _attack_rows(stix_path: Path) -> tuple[list[tuple], list[tuple]]:
    """ATT&CK tactics, techniques and mitigations, plus mitigation → technique links, via mitreattack-python."""
    from mitreattack.stix20 import MitreAttackData

    data = MitreAttackData(str(stix_path))
    rows: list[tuple] = []

    def ext(obj) -> tuple[str | None, str | None]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id"), ref.get("url")
        return None, None

    for t in data.get_tactics(remove_revoked_deprecated=True):
        tid, url = ext(t)
        rows.append((tid, "tactic", t["name"], _first_paragraph(t.get("description")), t["x_mitre_shortname"], url))
    for t in data.get_techniques(remove_revoked_deprecated=True):
        tid, url = ext(t)
        phases = ",".join(p["phase_name"] for p in t.get("kill_chain_phases", []))
        rows.append((tid, "technique", t["name"], _first_paragraph(t.get("description")), phases, url))
    for m in data.get_mitigations(remove_revoked_deprecated=True):
        mid, url = ext(m)
        rows.append((mid, "mitigation", m["name"], _first_paragraph(m.get("description")), None, url))
    links = []
    for tech_stix, items in data.get_all_mitigations_mitigating_all_techniques().items():
        tid = data.get_attack_id(tech_stix)
        for item in items:
            mid = data.get_attack_id(item["object"]["id"])
            if tid and mid:
                links.append((mid, tid))
    return [r for r in rows if r[0]], links


def build(out: Path = KB_PATH, rules: Path = RULES_PATH, stix: Path = STIX_PATH, classification: Path | None = None,
          playbooks: Path = PLAYBOOKS_PATH) -> dict[str, int]:
    """Build the knowledge base into `out` and return the row count per table."""
    tmp = out.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    conn = sqlite3.connect(tmp)
    try:
        conn.executescript(SCHEMA)
        with open(rules, encoding="utf-8", errors="replace") as fh:
            rule_rows = [r for r in map(parse_rule, fh) if r]
        conn.executemany("INSERT OR REPLACE INTO kb_rules VALUES (:sid, :msg, :classtype, :tactics, :techniques, "
                         ":cves, :attack_target, :refs)", rule_rows)
        attack, links = _attack_rows(stix)
        conn.executemany("INSERT OR REPLACE INTO kb_attack VALUES (?, ?, ?, ?, ?, ?)", attack)
        conn.executemany("INSERT OR IGNORE INTO kb_mitigates VALUES (?, ?)", links)
        if classification is None:
            from netseer.src.engine.ingest import classification_file
            classification = Path(classification_file())
        for line in classification.read_text().splitlines():
            if line.startswith("config classification:"):
                name, desc, prio = (p.strip() for p in line.split(":", 1)[1].split(","))
                conn.execute("INSERT OR REPLACE INTO kb_classtype VALUES (?, ?, ?, ?)",
                             (name, desc, int(prio), PLAIN_CLASSTYPES.get(name, desc)))
        for pb in json.loads(playbooks.read_text()):
            conn.execute("INSERT INTO kb_playbooks VALUES (?, ?, ?, ?, ?)",
                         (pb["id"], pb["category"], pb["title"], " ".join(pb["tags"]), "\n".join(pb["steps"])))
        conn.commit()
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("kb_rules", "kb_attack", "kb_mitigates", "kb_classtype", "kb_playbooks")}
    finally:
        conn.close()
    tmp.replace(out)
    return counts
