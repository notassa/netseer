"""Contextor (ACP 3–5, CONCEPTS A4): alerts → alert groups → possible incidents.

ACP 3 aggregates alerts on (src_ip, dest_ip, sid, proto, dest_port); a gap longer than the aggregation window
starts a new group. ACP 4 links groups into possible incidents with rules R1–R4 (R2/R3 per signature, R4 only for a
forward kill-chain step; recon only links with recon) when no gap inside them exceeds the correlation window (union-find), recording which rules
linked each incident. ACP 5 adds plain context (signatures, classtypes,
ATT&CK tactics, directions, ports, internal hosts) to `evidence_json` and a title from a fixed template.
Scoring is left to the scorer (ACP 6).
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable

from netseer.src.config import analysis_lan, get_setting
from netseer.src.engine.constants import FAN_IN_MIN_SOURCES, L3_RULE, MITRE_TACTICS, SWEEP_MIN_HOSTS
from netseer.src.engine.logger import is_internal, parse_networks


@dataclass
class Group:
    """One alert group (ACP 3)."""

    src_ip: str | None
    dest_ip: str | None
    sid: int | None
    proto: str | None
    dest_port: int | None
    signature: str | None
    classtype: str | None
    first_seen: str
    last_seen: str
    t0: datetime
    t1: datetime
    alert_ids: list[int] = field(default_factory=list)
    max_priority: int | None = None
    tactics: list[str] = field(default_factory=list)       # in order of first appearance
    techniques: set[str] = field(default_factory=set)
    directions: Counter = field(default_factory=Counter)
    id: int | None = None


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def aggregate(alerts: Iterable[sqlite3.Row], gap_s: float) -> list[Group]:
    """Group alerts (ordered by ts) on the A4 key; a silence longer than `gap_s` starts a new group."""
    open_groups: dict[tuple, Group] = {}
    groups: list[Group] = []
    gap = timedelta(seconds=gap_s)
    for a in alerts:
        key = (a["src_ip"], a["dest_ip"], a["sid"], a["proto"], a["dest_port"])
        t = _ts(a["ts"])
        g = open_groups.get(key)
        if g is None or t - g.t1 > gap:
            g = Group(a["src_ip"], a["dest_ip"], a["sid"], a["proto"], a["dest_port"], a["signature"],
                      a["classtype"], a["ts"], a["ts"], t, t)
            open_groups[key] = g
            groups.append(g)
        g.last_seen, g.t1 = a["ts"], t
        g.alert_ids.append(a["id"])
        if a["priority"] is not None:
            g.max_priority = a["priority"] if g.max_priority is None else min(g.max_priority, a["priority"])
        for tactic in (a["mitre_tactic"] or "").split(","):
            if tactic and tactic not in g.tactics:
                g.tactics.append(tactic)
        g.techniques.update(t for t in (a["mitre_technique"] or "").split(",") if t)
        if a["direction"]:
            g.directions[a["direction"]] += 1
    return groups


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        self.parent[self.find(i)] = self.find(j)


KILL_CHAIN = {t: i for i, t in enumerate(MITRE_TACTICS)}
TITLE_ORDER = ("R4", "R3", "R2", "R1")     # widest picture first: a sweep reads better than one of its pairs
RECON = {"attempted-recon", "network-scan", "successful-recon-limited", "successful-recon-largescale"}


def _forward_step(run: list[int], groups: list[Group]) -> bool:
    """True when a group shows a tactic later in the kill chain than a tactic of a group that started before it."""
    lowest = float("inf")
    for i in sorted(run, key=lambda k: groups[k].t0):
        idx = [KILL_CHAIN[t] for t in groups[i].tactics if t in KILL_CHAIN]
        if idx and max(idx) > lowest:
            return True
        lowest = min([lowest, *idx])
    return False


def _windows(members: list[int], groups: list[Group], window: timedelta) -> list[list[int]]:
    """Split groups (by first_seen) into runs where each group starts within `window` of the run's latest end."""
    runs: list[list[int]] = []
    end: datetime | None = None
    for i in sorted(members, key=lambda k: groups[k].t0):
        if end is None or groups[i].t0 - end > window:
            runs.append([])
            end = groups[i].t1
        runs[-1].append(i)
        end = max(end, groups[i].t1)
    return runs


def correlate(groups: list[Group], window_min: float, internal: Callable[[str | None], bool]) -> list[tuple[list[int], list[str]]]:
    """Link groups with R1–R4 inside the correlation window.

    Returns (group indexes, rules) per possible incident; rules are strongest first, ["single"] if none fired.
    """
    window = timedelta(minutes=window_min)
    uf = _UnionFind(len(groups))
    fired: dict[int, set[str]] = defaultdict(set)

    def link(members: list[int], rule: str) -> None:
        for i in members:
            uf.union(i, members[0])
            fired[i].add(rule)

    # Recon (scans, sweeps) only links with recon, so a scan stays its own incident; R4 leaves recon out.
    by_pair, by_src, by_dest, by_host = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for i, g in enumerate(groups):
        recon = g.classtype in RECON
        by_pair[(g.src_ip, g.dest_ip, recon)].append(i)
        by_src[(g.src_ip, g.sid)].append(i)
        by_dest[(g.dest_ip, g.sid)].append(i)
        if g.tactics and not recon:
            for host in {g.src_ip, g.dest_ip}:
                if internal(host):
                    by_host[host].append(i)

    checks = [
        ("R1", by_pair, lambda run: len({groups[i].sid for i in run}) >= 2),
        ("R2", by_src, lambda run: len({groups[i].dest_ip for i in run}) >= SWEEP_MIN_HOSTS),
        ("R3", by_dest, lambda run: len({groups[i].src_ip for i in run}) >= FAN_IN_MIN_SOURCES),
        ("R4", by_host, lambda run: _forward_step(run, groups)),
    ]
    for rule, buckets, fires in checks:
        for members in buckets.values():
            for run in _windows(members, groups, window):
                if len(run) > 1 and fires(run):
                    link(run, rule)

    incidents: dict[int, list[int]] = defaultdict(list)
    for i in range(len(groups)):
        incidents[uf.find(i)].append(i)
    out = []
    for members in incidents.values():
        rules = set().union(*(fired[i] for i in members)) or {"single"}
        out.append((members, sorted(rules, key=lambda r: -L3_RULE[r])))
    return out


def _title(rule: str, members: list[Group], internal: Callable[[str | None], bool]) -> str:
    """Plain title from a fixed template for the incident's strongest rule."""
    sig = Counter()
    for g in members:
        sig[g.signature or f"SID {g.sid}"] += len(g.alert_ids)
    top = sig.most_common(1)[0][0]
    srcs = sorted({g.src_ip or "unknown" for g in members})
    dests = sorted({g.dest_ip or "unknown" for g in members})
    if rule == "R4":
        hosts = Counter(h for g in members for h in {g.src_ip, g.dest_ip} if internal(h))
        host = hosts.most_common(1)[0][0] if hosts else dests[0]
        seen: list[str] = []
        for g in sorted(members, key=lambda g: g.t0):
            seen += [t for t in g.tactics if t not in seen]
        return f"Tactic progression on {host}: " + " → ".join(MITRE_TACTICS.get(t, t) for t in seen)
    if rule == "R3":
        return f"{len(srcs)} sources → {dests[0] if len(dests) == 1 else f'{len(dests)} hosts'} ({top})"
    if rule == "R2":
        return f"Sweep from {srcs[0] if len(srcs) == 1 else f'{len(srcs)} sources'} to {len(dests)} hosts ({top})"
    if rule == "R1":
        return f"{srcs[0]} → {dests[0]}: {len(sig)} different signatures"
    if srcs == dests == ["unknown"]:
        return f"{top} (no addresses)"
    return f"{top}: {srcs[0]} → {dests[0]}" if len(srcs) == len(dests) == 1 else f"{top}: {len(srcs)} → {len(dests)} hosts"


def _evidence(rules: list[str], members: list[Group], internal: Callable[[str | None], bool]) -> dict:
    """ACP 5 incident context, read by the Incidents page and (in C3) the evidence package."""
    sigs: Counter = Counter()
    classtypes: Counter = Counter()
    directions: Counter = Counter()
    ports: Counter = Counter()
    tactics: list[str] = []
    techniques: set[str] = set()
    for g in sorted(members, key=lambda g: g.t0):
        n = len(g.alert_ids)
        sigs[(g.sid, g.signature)] += n
        classtypes[g.classtype or "unknown"] += n
        directions.update(g.directions)
        if g.dest_port is not None:
            ports[g.dest_port] += n
        tactics += [t for t in g.tactics if t not in tactics]
        techniques |= g.techniques
    hosts = sorted({h for g in members for h in (g.src_ip, g.dest_ip) if internal(h)})
    return {
        "rules": rules,
        "groups": len(members),
        "signatures": [{"sid": s, "signature": name, "alerts": n} for (s, name), n in sigs.most_common(10)],
        "classtypes": dict(classtypes.most_common()),
        "tactics": [{"id": t, "name": MITRE_TACTICS.get(t, t)} for t in tactics],
        "techniques": sorted(techniques),
        "directions": dict(directions.most_common()),
        "dest_ports": [p for p, _ in ports.most_common(10)],
        "internal_hosts": hosts,
    }


def run_contextor(conn: sqlite3.Connection, analysis_id: int) -> tuple[int, int]:
    """Rebuild the analysis's alert groups and possible incidents; returns (n_groups, n_incidents)."""
    nets = parse_networks(analysis_lan(conn, analysis_id))
    internal = lambda ip: is_internal(ip, nets)  # noqa: E731
    alerts = conn.execute(
        "SELECT id, ts, src_ip, dest_ip, sid, proto, dest_port, signature, classtype, priority, mitre_tactic, "
        "mitre_technique, direction FROM alerts WHERE analysis_id = ? ORDER BY ts, id", (analysis_id,))
    groups = aggregate(alerts, float(get_setting(conn, "aggregation_gap_s")))
    incidents = correlate(groups, float(get_setting(conn, "correlation_window_min")), internal)

    # An incident keeps its id (and so its saved explanations) while its first alert stays the same: live sessions
    # rebuild ACP every interval, and a window change re-runs it.
    old = dict(conn.execute(
        "SELECT MIN(j.value), ig.incident_id FROM incident_groups ig JOIN alert_groups g ON g.id = ig.group_id "
        "JOIN json_each(g.alert_ids_json) j WHERE g.analysis_id = ? GROUP BY ig.incident_id", (analysis_id,)).fetchall())
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM alert_groups WHERE analysis_id = ?", (analysis_id,))
        for g in groups:
            g.id = conn.execute(
                "INSERT INTO alert_groups(analysis_id, src_ip, dest_ip, sid, signature, classtype, proto, dest_port, "
                "first_seen, last_seen, count, max_priority, rep_alert_id, alert_ids_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (analysis_id, g.src_ip, g.dest_ip, g.sid, g.signature, g.classtype, g.proto, g.dest_port,
                 g.first_seen, g.last_seen, len(g.alert_ids), g.max_priority, g.alert_ids[0],
                 json.dumps(g.alert_ids))).lastrowid
        kept = []
        for indexes, rules in incidents:
            members = [groups[i] for i in indexes]
            values = (_title(next((r for r in TITLE_ORDER if r in rules), rules[0]), members, internal),
                      ",".join(rules),
                      json.dumps(sorted({g.src_ip for g in members if g.src_ip})),
                      json.dumps(sorted({g.dest_ip for g in members if g.dest_ip})),
                      min(g.first_seen for g in members), max(g.last_seen for g in members),
                      sum(len(g.alert_ids) for g in members), json.dumps(_evidence(rules, members, internal)))
            incident_id = old.pop(min(a for g in members for a in g.alert_ids), None)
            if incident_id is None:
                incident_id = conn.execute(
                    "INSERT INTO incidents(analysis_id, title, rule, src_ips_json, dest_ips_json, first_seen, "
                    "last_seen, n_alerts, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (analysis_id, *values)).lastrowid
            else:
                conn.execute("UPDATE incidents SET title = ?, rule = ?, src_ips_json = ?, dest_ips_json = ?, "
                             "first_seen = ?, last_seen = ?, n_alerts = ?, evidence_json = ? WHERE id = ?",
                             (*values, incident_id))
            kept.append(incident_id)
            conn.executemany("INSERT INTO incident_groups(incident_id, group_id) VALUES (?, ?)",
                             [(incident_id, g.id) for g in members])
        conn.execute(f"DELETE FROM incidents WHERE analysis_id = ? AND id NOT IN ({','.join('?' * len(kept))})",
                     (analysis_id, *kept))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return len(groups), len(incidents)
