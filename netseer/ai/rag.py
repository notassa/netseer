"""Retrieval for the evidence package (CONCEPTS A6).

Deterministic first: SID → rule → ATT&CK technique/tactic → mitigations and classtype, by key. Then FTS5/BM25 over the
playbooks with the classtypes, techniques and signature words as the query. No embeddings.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from netseer.ai.kb.build_kb import KB_PATH

MAX_RULES = 3
MAX_TECHNIQUES = 3
MAX_MITIGATIONS = 1          # per technique
MAX_PLAYBOOKS = 2
MAX_CLASSTYPES = 2
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]+")


def kb_ready(kb_path: Path = KB_PATH) -> bool:
    """True when the knowledge base has been built."""
    return kb_path.exists()


def _query(words: Iterable[str]) -> str:
    """An FTS5 OR-query of quoted tokens (quoting keeps '-' and '.' from being read as operators)."""
    tokens = dict.fromkeys(t.lower() for w in words for t in _TOKEN.findall(w or "") if len(t) > 2)
    return " OR ".join(f'"{t}"' for t in tokens)


def retrieve(sids: Iterable[int], classtypes: Iterable[str] = (), techniques: Iterable[str] = (),
             text: str = "", kb_path: Path = KB_PATH) -> list[dict]:
    """Knowledge items for an incident: {kind, key, title, text, url}, in a stable order; [] without a KB."""
    if not kb_ready(kb_path):
        return []
    conn = sqlite3.connect(f"file:{kb_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    items: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, key: str, title: str, body: str, url: str | None = None) -> None:
        if (kind, key) not in seen:
            seen.add((kind, key))
            items.append({"kind": kind, "key": key, "title": title, "text": body, "url": url})

    try:
        techs = list(dict.fromkeys(techniques))
        classes = list(dict.fromkeys(c for c in classtypes if c))
        for sid in list(dict.fromkeys(sids))[:MAX_RULES]:
            rule = conn.execute("SELECT * FROM kb_rules WHERE sid = ?", (sid,)).fetchone()
            if rule is None:
                continue
            extra = [f"CVE: {rule['cves']}" if rule["cves"] else "", f"target: {rule['attack_target']}"
                     if rule["attack_target"] else "", f"ATT&CK: {rule['techniques']}" if rule["techniques"] else ""]
            add("rule", str(sid), rule["msg"], "; ".join(e for e in extra if e) or "no extra metadata")
            techs += [t for t in (rule["techniques"] or "").split(",") if t]
            classes += [rule["classtype"]] if rule["classtype"] else []
        for tid in list(dict.fromkeys(techs))[:MAX_TECHNIQUES]:
            tech = conn.execute("SELECT * FROM kb_attack WHERE id = ?", (tid,)).fetchone()
            if tech is None:
                continue
            add("technique", tid, tech["name"], tech["description"], tech["url"])
            for m in conn.execute("SELECT a.* FROM kb_mitigates k JOIN kb_attack a ON a.id = k.mitigation_id "
                                  "WHERE k.technique_id = ? ORDER BY a.id LIMIT ?", (tid, MAX_MITIGATIONS)):
                add("mitigation", m["id"], m["name"], m["description"], m["url"])
        for name in list(dict.fromkeys(classes))[:MAX_CLASSTYPES]:
            ct = conn.execute("SELECT * FROM kb_classtype WHERE name = ?", (name,)).fetchone()
            if ct is not None:
                add("classtype", name, ct["description"], ct["plain"])
        query = _query([*classes, *techs, text])
        if query:
            for pb in conn.execute("SELECT id, title, body FROM kb_playbooks WHERE kb_playbooks MATCH ? "
                                   "ORDER BY bm25(kb_playbooks, 0, 2, 1, 5, 1) LIMIT ?", (query, MAX_PLAYBOOKS)):
                add("playbook", pb["id"], pb["title"], pb["body"])
    finally:
        conn.close()
    return items
