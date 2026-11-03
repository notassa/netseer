"""Hallucination check (CONCEPTS A8): checks 1–5 on one model reply, against its evidence package.

1 schema (pydantic), 2 citations, 3 entities (IPs, ports, SIDs, CVEs, ATT&CK IDs, counts, timestamps),
4 overclaim (compromise or success asserted without evidence), 5 risk consistency (the band restated unchanged).
Check 6 (faithfulness) runs in evaluation only.
"""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from netseer.ai.schemas import TEXT_FIELDS, ExplainOutput

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT = re.compile(r"\bports?\s+(\d{1,5})\b", re.I)
SID = re.compile(r"\bSID\s*:?\s*(\d{4,10})\b", re.I)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
ATTACK_ID = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4})\b")
COUNT = re.compile(r"\b(\d[\d,]*)\s+(?:alerts?|hosts?|devices?|signatures?|groups?|attempts?|incidents?|events?)\b", re.I)
DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
TIME = re.compile(r"\b\d{2}:\d{2}(?::\d{2})?\b")
REF = re.compile(r"\b[EK]\d+\b")
BANDS = ("critical", "high", "medium", "low", "note")
BAND_SAID = re.compile(r"\b(critical|high|medium|low|note)\b(?=[\s-]+(?:risk|band|severity|priority|level))|"
                       r"\b(?:band|risk level|rated|rating)\s*(?:is|of|:|as)?\s*(critical|high|medium|low|note)\b", re.I)
OVERCLAIM = re.compile(r"\b(?:was|were|has been|have been|is|are|got)\s+(?:compromised|hacked|breached|infected|"
                       r"taken over)\b|\b(?:attack|exploit|login|intrusion|attempt)s?\s+(?:was|were)\s+successful\b|"
                       r"\bsuccessfully\s+(?:attacked|exploited|compromised|logged in|breached)\b|\b(?:gained|got|took)\s+"
                       r"(?:access|control)\b|\b(?:stole|exfiltrated)\b|\bsucceeded\b", re.I)
HEDGE = re.compile(r"\b(?:may|might|could|possibl[ey]|perhaps|not|no|never|unknown|unclear|whether|if|unless|"
                   r"cannot|can't|isn't|wasn't|without)\b", re.I)
SENTENCE = re.compile(r"(?<=[.!?])\s+")


def parse(raw: str) -> tuple[ExplainOutput | None, str | None]:
    """Check 1: the reply as ExplainOutput, or (None, why it failed)."""
    try:
        return ExplainOutput.model_validate_json(raw), None
    except ValidationError as exc:
        return None, f"the reply does not match the schema ({exc.error_count()} errors)"


def _texts(out: ExplainOutput) -> list[str]:
    return [getattr(out, f) for f in TEXT_FIELDS] + [c.text for c in out.claims] + \
           [s for a in out.recommended_actions for s in (a.action, a.reason)]


def _numbers(text: str) -> set[str]:
    return {n.replace(",", "") for n in re.findall(r"\d[\d,]*(?:\.\d+)?", text)}


def verify(out: ExplainOutput, evidence: dict) -> dict:
    """Checks 2–5; returns {passed, flags[{check, text, detail}]}. Each flag names the sentence to highlight."""
    flags: list[dict] = []
    ids = {f["id"] for f in evidence["facts"]} | {k["id"] for k in evidence["knowledge"]}
    corpus = json.dumps(evidence, ensure_ascii=False)
    numbers = _numbers(corpus)

    def flag(check: str, text: str, detail: str) -> None:
        if not any(f["check"] == check and f["text"] == text for f in flags):
            flags.append({"check": check, "text": text, "detail": detail})

    # 2 citations
    for item, text in [(c, c.text) for c in out.claims] + [(a, a.action) for a in out.recommended_actions]:
        if not item.refs:
            flag("citation", text, "cites no evidence")
        for ref in item.refs:
            if ref not in ids:
                flag("citation", text, f"cites {ref}, which does not exist")
    for text in _texts(out):
        for ref in REF.findall(text):
            if ref not in ids:
                flag("citation", text, f"mentions {ref}, which does not exist")

    # 3 entities, 4 overclaim, per sentence
    for text in _texts(out):
        for sentence in SENTENCE.split(text):
            found = [(ip, "IP address") for ip in IP.findall(sentence) if ip not in corpus]
            found += [(p, "port") for p in PORT.findall(sentence) if p not in numbers]
            found += [(s, "SID") for s in SID.findall(sentence) if s not in numbers]
            found += [(c, "CVE") for c in CVE.findall(sentence) if c.upper() not in corpus.upper()]
            found += [(t, "ATT&CK ID") for t in ATTACK_ID.findall(sentence) if t not in corpus]
            found += [(n, "count") for n in COUNT.findall(sentence) if n.replace(",", "") not in numbers]
            found += [(d, "date") for d in DATE.findall(sentence) if d not in corpus]
            found += [(t, "time") for t in TIME.findall(sentence) if t not in corpus]
            for value, kind in found:
                flag("entity", sentence, f"{kind} {value} is not in the evidence")
            if not evidence.get("success_signal") and OVERCLAIM.search(sentence) and not HEDGE.search(sentence):
                flag("overclaim", sentence, "asserts compromise or success that the evidence does not show")

    # 5 risk consistency (incidents only: an analysis summary has a health number, checked as an entity)
    if evidence.get("scope") == "incident":
        band = evidence["band"].lower()
        prose = [getattr(out, f) for f in TEXT_FIELDS] + [c.text for c in out.claims]   # not actions: "low-risk step"
        said = {(m.group(1) or m.group(2)).lower() for t in prose for m in BAND_SAID.finditer(t)}
        for other in sorted(said - {band}):
            flag("band", next(t for t in prose if re.search(rf"\b{other}\b", t, re.I)),
                 f"states {other.title()} but NetSeer's band is {evidence['band']}")
        if not re.search(rf"\b{band}\b", out.risk_explanation, re.I):
            flag("band", out.risk_explanation, f"does not restate NetSeer's band ({evidence['band']})")
    return {"passed": not flags, "flags": flags}
