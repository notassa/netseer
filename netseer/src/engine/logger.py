"""ACP 1 Normalise + 2 Preliminary enrich: eve.json → alerts, devices and packet statistics.

Missing values are stored as NULL (shown as "unknown"); nothing is guessed (CONCEPTS A2).
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from netseer.src.engine.evidence import NetEvidence
from netseer.src.engine.oui import is_unicast, vendor_for

ALERT_BATCH = 1000
PROGRESS_EVERY = 5000
NULL_IPS = {"0.0.0.0", "255.255.255.255"}
SCAN_MIN_PORTS = 50            # probed ports on one host that make a port scan (NetSeer's own check, CONCEPTS A3)
SCAN_PROBE_PKTS = 3            # a TCP flow with at most this many packets to the server is a probe
SCAN_SID = 9000001

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=4)
def load_classtypes(path: str) -> dict[str, str]:
    """Map classtype description → short name from Suricata's classification.config.

    eve.json alerts carry only the description (`alert.category`); the short name (e.g. `attempted-recon`)
    is what the risk model (CONCEPTS A5.2 I3) uses.
    """
    table: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return table
    for line in lines:
        if line.startswith("config classification:"):
            parts = [p.strip() for p in line.split(":", 1)[1].split(",")]
            if len(parts) >= 2:
                table[parts[1]] = parts[0]
    return table


def parse_networks(cidrs: Iterable[str]) -> list[IPNetwork]:
    """Parse the LAN CIDR setting."""
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def is_internal(ip: str | None, nets: list[IPNetwork]) -> bool:
    """True for a unicast address inside the LAN CIDRs."""
    if not ip or ip in NULL_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    return any(addr in net for net in nets if net.version == addr.version)


def direction(src: str | None, dest: str | None, nets: list[IPNetwork]) -> str | None:
    """Traffic direction relative to the LAN: ext->int, int->ext, int->int or ext->ext."""
    if not src or not dest:
        return None
    s = "int" if is_internal(src, nets) else "ext"
    d = "int" if is_internal(dest, nets) else "ext"
    return f"{s}->{d}"


def to_utc(ts: str | None) -> str | None:
    """Normalise a Suricata timestamp (e.g. 2025-10-09T09:53:20.080000+0000) to ISO-8601 UTC."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def spread_minutes(start: str, end: str, packets: int, nbytes: int) -> list[tuple[str, int, int]]:
    """Split a flow's packets/bytes evenly over the UTC minutes it spans (remainder to the first minute)."""
    t0 = datetime.fromisoformat(start).replace(second=0, microsecond=0)
    t1 = max(datetime.fromisoformat(end).replace(second=0, microsecond=0), t0)
    n = int((t1 - t0).total_seconds() // 60) + 1
    return [((t0 + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M"),
             packets // n + (packets % n if i == 0 else 0), nbytes // n + (nbytes % n if i == 0 else 0))
            for i in range(n)]


def _first(meta: dict[str, Any], key: str) -> str | None:
    values = meta.get(key) or []
    return values[0] if values else None


def _joined(meta: dict[str, Any], key: str) -> str | None:
    values = meta.get(key) or []
    return ",".join(values) if values else None


@dataclass
class _Host:
    first_seen: str | None = None
    last_seen: str | None = None
    active: bool = False                     # sent traffic, or answered a flow
    macs: Counter = field(default_factory=Counter)
    services: set[tuple[int, str, str | None]] = field(default_factory=set)

    def seen(self, ts: str | None) -> None:
        if ts:
            self.first_seen = min(self.first_seen or ts, ts)
            self.last_seen = max(self.last_seen or ts, ts)


@dataclass
class _External:
    first_seen: str | None = None
    last_seen: str | None = None
    n_flows: int = 0
    n_alerts: int = 0
    bytes: int = 0
    inbound: bool = False                    # it opened a flow toward an internal host
    outbound: bool = False                   # an internal host opened a flow toward it
    ports: set[int] = field(default_factory=set)
    peers: set[str] = field(default_factory=set)
    names: Counter = field(default_factory=Counter)   # HTTP host / TLS SNI seen toward it

    def seen(self, ts: str | None) -> None:
        if ts:
            self.first_seen = min(self.first_seen or ts, ts)
            self.last_seen = max(self.last_seen or ts, ts)


EXTERNAL_LIST_CAP = 20


def is_external(ip: str | None, nets: list[IPNetwork]) -> bool:
    """True for a routable unicast address outside the LAN CIDRs (not broadcast, link-local, loopback...)."""
    if not ip or ip in NULL_IPS or is_internal(ip, nets):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified or addr.is_link_local or addr.is_loopback
                or addr.is_reserved)


@dataclass
class EveLogger:
    """Streams eve.json events for one analysis and writes the normalised, enriched rows.

    A device is an internal IP that sent traffic or answered a flow, so broadcast addresses and
    unanswered scan targets do not become phantom devices.
    """

    analysis_id: int
    nets: list[IPNetwork]
    oui_csv: str
    classtypes: dict[str, str]
    n_events: int = 0
    n_alerts: int = 0
    n_bad_lines: int = 0
    _alerts: list[tuple] = field(default_factory=list)
    _hosts: dict[str, _Host] = field(default_factory=dict)
    _mac_hostname: dict[str, str] = field(default_factory=dict)
    _mac_ip: dict[str, str] = field(default_factory=dict)
    _packets: dict[str, list[int]] = field(default_factory=dict)
    _externals: dict[str, _External] = field(default_factory=dict)
    _dns_names: dict[str, str] = field(default_factory=dict)     # IP → name, from DNS answers
    _probes: dict[tuple[str, str], list] = field(default_factory=dict)   # (src, dest) → [first start, probed ports]
    evidence: NetEvidence = field(default_factory=NetEvidence)   # subnet/VLAN evidence and map links (A17)

    def _internal(self, ip: str | None) -> bool:
        return is_internal(ip, self.nets)

    def feed(self, conn: sqlite3.Connection, line: str) -> None:
        """Process one eve.json line."""
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self.n_bad_lines += 1
            return
        etype = event.get("event_type")
        if etype == "stats":
            return
        self.n_events += 1
        ts = to_utc(event.get("timestamp"))
        if etype == "flow":
            # Flows flushed at the end of a pcap carry an unrelated `timestamp`; their own start/end are reliable.
            flow = event.get("flow") or {}
            times = [to_utc(flow.get("start")), to_utc(flow.get("end"))]
        else:
            times = [ts]
        self._track_hosts(event, times)
        self._track_externals(event, etype, times)
        self.evidence.observe(event, etype, self._internal, times)
        if etype == "alert":
            self._alerts.append(self._alert_row(event, ts, line))
            if len(self._alerts) >= ALERT_BATCH:
                self._flush_alerts(conn)
        elif etype == "flow":
            self._flow(event)
        elif etype == "dhcp":
            self._dhcp(event.get("dhcp") or {})

    def _alert_row(self, event: dict[str, Any], ts: str | None, raw: str) -> tuple:
        alert = event.get("alert") or {}
        meta = alert.get("metadata") or {}
        category = alert.get("category")
        classtype = self.classtypes.get(category or "")
        if (alert.get("signature") or "").startswith("ET SCAN"):
            classtype = "attempted-recon"     # ET files many scans under bad-unknown/misc; the raw JSON keeps the rule's
        return (
            self.analysis_id, ts, event.get("flow_id"), event.get("src_ip"), event.get("src_port"),
            event.get("dest_ip"), event.get("dest_port"), event.get("proto"), event.get("app_proto"),
            alert.get("signature_id"), alert.get("signature"), category, classtype,
            alert.get("severity"), _first(meta, "signature_severity"), _joined(meta, "mitre_tactic_id"),
            _joined(meta, "mitre_technique_id"), direction(event.get("src_ip"), event.get("dest_ip"), self.nets), raw,
        )

    def _host(self, ip: str | None) -> _Host | None:
        if not is_internal(ip, self.nets):
            return None
        return self._hosts.setdefault(ip, _Host())

    def _track_hosts(self, event: dict[str, Any], times: list[str | None]) -> None:
        ether = event.get("ether") or {}
        src_macs = ether.get("src_macs") or ([ether["src_mac"]] if ether.get("src_mac") else [])
        dest_macs = ether.get("dest_macs") or ([ether["dest_mac"]] if ether.get("dest_mac") else [])
        for ip, macs, is_src in ((event.get("src_ip"), src_macs, True), (event.get("dest_ip"), dest_macs, False)):
            host = self._host(ip)
            if host is None:
                continue
            for ts in times:
                host.seen(ts)
            if is_src:
                host.active = True
            for mac in macs:
                if is_unicast(mac):
                    host.macs[mac.lower()] += 1

    def _track_externals(self, event: dict[str, Any], etype: str | None, times: list[str | None]) -> None:
        src, dest = event.get("src_ip"), event.get("dest_ip")
        if etype == "dns":
            for answer in (event.get("dns") or {}).get("answers") or []:
                if answer.get("rrtype") in ("A", "AAAA") and answer.get("rdata") and answer.get("rrname"):
                    self._dns_names[answer["rdata"]] = answer["rrname"]
        for ip, other, is_src in ((src, dest, True), (dest, src, False)):
            if not is_external(ip, self.nets):
                continue
            ext = self._externals.setdefault(ip, _External())
            for ts in times:
                ext.seen(ts)
            internal_peer = is_internal(other, self.nets)
            if internal_peer and len(ext.peers) < EXTERNAL_LIST_CAP:
                ext.peers.add(other)
            if etype == "alert":
                ext.n_alerts += 1
            elif etype == "flow":
                flow = event.get("flow") or {}
                ext.n_flows += 1
                ext.bytes += int(flow.get("bytes_toserver") or 0) + int(flow.get("bytes_toclient") or 0)
                if internal_peer:
                    ext.inbound |= is_src
                    ext.outbound |= not is_src
                if not is_src and event.get("dest_port") is not None and len(ext.ports) < EXTERNAL_LIST_CAP:
                    ext.ports.add(int(event["dest_port"]))
            elif not is_src:
                name = (event.get("http") or {}).get("hostname") or (event.get("tls") or {}).get("sni")
                if name:
                    ext.names[name] += 1

    def _flow(self, event: dict[str, Any]) -> None:
        flow = event.get("flow") or {}
        start = to_utc(flow.get("start"))
        if (event.get("proto") == "TCP" and event.get("dest_port") is not None and start
                and int(flow.get("pkts_toserver") or 0) <= SCAN_PROBE_PKTS):
            probe = self._probes.setdefault((event.get("src_ip"), event.get("dest_ip")), [start, set()])
            probe[0] = min(probe[0], start)
            probe[1].add(int(event["dest_port"]))
        if start:
            packets = int(flow.get("pkts_toserver") or 0) + int(flow.get("pkts_toclient") or 0)
            nbytes = int(flow.get("bytes_toserver") or 0) + int(flow.get("bytes_toclient") or 0)
            for minute, p, b in spread_minutes(start, to_utc(flow.get("end")) or start, packets, nbytes):
                bucket = self._packets.setdefault(minute, [0, 0])
                bucket[0] += p
                bucket[1] += b
        server = self._host(event.get("dest_ip"))
        if server is None:
            return
        proto = (event.get("proto") or "").lower()
        answered = int(flow.get("pkts_toclient") or 0) > 0
        if answered:
            server.active = True
        tc_flags = int((event.get("tcp") or {}).get("tcp_flags_tc") or "0", 16)
        offered = (proto == "tcp" and tc_flags & 0x12 == 0x12) or (proto == "udp" and answered)
        if offered and event.get("dest_port") is not None:
            server.services.add((int(event["dest_port"]), proto, event.get("app_proto")))

    def _dhcp(self, dhcp: dict[str, Any]) -> None:
        mac = (dhcp.get("client_mac") or "").lower()
        if not mac:
            return
        if dhcp.get("hostname"):
            self._mac_hostname[mac] = dhcp["hostname"]
        for key in ("assigned_ip", "client_ip"):
            ip = dhcp.get(key)
            if ip and ip not in NULL_IPS:
                self._mac_ip[mac] = ip

    def _flush_alerts(self, conn: sqlite3.Connection) -> None:
        if not self._alerts:
            return
        conn.execute("BEGIN")
        conn.executemany(
            "INSERT INTO alerts(analysis_id, ts, flow_id, src_ip, src_port, dest_ip, dest_port, proto, app_proto, "
            "sid, signature, category, classtype, priority, sig_severity, mitre_tactic, mitre_technique, direction, "
            "raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            self._alerts,
        )
        conn.execute("COMMIT")
        self.n_alerts += len(self._alerts)
        self._alerts.clear()

    def _hostname_for(self, ip: str, mac: str | None) -> str | None:
        if mac and mac in self._mac_hostname:
            return self._mac_hostname[mac]
        for dhcp_mac, dhcp_ip in self._mac_ip.items():
            if dhcp_ip == ip and dhcp_mac in self._mac_hostname:
                return self._mac_hostname[dhcp_mac]
        return None

    def _scan_alerts(self) -> None:
        """NetSeer's port-scan check: one alert per (source, host) probed on SCAN_MIN_PORTS or more TCP ports.

        Suricata has no port-scan tracker, and ET SCAN rules mostly need $EXTERNAL_NET → $HOME_NET.
        shortcut: vertical scans only; a one-port-many-hosts scan relies on R2 over Suricata's alerts.
        """
        for (src, dest), (first, ports) in self._probes.items():
            if len(ports) < SCAN_MIN_PORTS:
                continue
            event = {"timestamp": first, "event_type": "alert", "src_ip": src, "dest_ip": dest, "proto": "TCP",
                     "alert": {"signature_id": SCAN_SID, "signature": f"NETSEER Port scan: {len(ports)} ports probed",
                               "category": "Attempted Information Leak", "severity": 2,
                               "metadata": {"mitre_tactic_id": ["TA0007"], "mitre_technique_id": ["T1046"]}},
                     "netseer": {"ports": sorted(ports)[:100]}}
            self._alerts.append(self._alert_row(event, first, json.dumps(event)))

    def finish(self, conn: sqlite3.Connection) -> None:
        """Write remaining alerts, devices and packet statistics, and update the analysis counters."""
        self._scan_alerts()
        self._flush_alerts(conn)
        conn.execute("BEGIN")
        for ip, host in self._hosts.items():
            if not host.active:
                continue
            mac = host.macs.most_common(1)[0][0] if host.macs else None
            self._upsert_device(conn, ip, host, mac)
        for minute, (packets, nbytes) in self._packets.items():
            conn.execute(
                "INSERT INTO packet_stats(analysis_id, minute, packets, bytes) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(analysis_id, minute) DO UPDATE SET packets = packets + excluded.packets, "
                "bytes = bytes + excluded.bytes",
                (self.analysis_id, minute, packets, nbytes),
            )
        for ip, ext in self._externals.items():
            hostname = ext.names.most_common(1)[0][0] if ext.names else self._dns_names.get(ip)
            direction_ = "both" if ext.inbound and ext.outbound else "inbound" if ext.inbound else \
                "outbound" if ext.outbound else None
            # shortcut: counts add up and lists are replaced on conflict; fine while offline re-runs reset the rows first.
            conn.execute(
                "INSERT INTO external_hosts(analysis_id, ip, hostname, direction, first_seen, last_seen, n_flows, "
                "n_alerts, bytes, ports_json, peers_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(analysis_id, ip) DO UPDATE SET hostname = COALESCE(excluded.hostname, hostname), "
                "direction = COALESCE(excluded.direction, direction), n_flows = n_flows + excluded.n_flows, "
                "n_alerts = n_alerts + excluded.n_alerts, bytes = bytes + excluded.bytes, "
                "ports_json = excluded.ports_json, peers_json = excluded.peers_json, "
                "first_seen = MIN(COALESCE(first_seen, excluded.first_seen), COALESCE(excluded.first_seen, first_seen)), "
                "last_seen = MAX(COALESCE(last_seen, excluded.last_seen), COALESCE(excluded.last_seen, last_seen))",
                (self.analysis_id, ip, hostname, direction_, ext.first_seen, ext.last_seen, ext.n_flows, ext.n_alerts,
                 ext.bytes, json.dumps(sorted(ext.ports)), json.dumps(sorted(ext.peers, key=ipaddress.ip_address))),
            )
        self.evidence.write_links(conn, self.analysis_id)
        # Global IP → name memory: learn this analysis's names, then fill the names it lacks from earlier analyses.
        for table in ("devices", "external_hosts"):
            conn.execute(f"INSERT INTO ip_names(ip, name, updated_at) SELECT ip, hostname, datetime('now') FROM {table} "
                         "WHERE analysis_id = ? AND hostname IS NOT NULL ON CONFLICT(ip) DO UPDATE SET "
                         "name = excluded.name, updated_at = excluded.updated_at", (self.analysis_id,))
            conn.execute(f"UPDATE {table} SET hostname = (SELECT name FROM ip_names n WHERE n.ip = {table}.ip) "
                         "WHERE analysis_id = ? AND hostname IS NULL", (self.analysis_id,))
        conn.execute(
            "UPDATE analyses SET n_events = n_events + ?, n_alerts = n_alerts + ? WHERE id = ?",
            (self.n_events, self.n_alerts, self.analysis_id),
        )
        conn.execute("COMMIT")

    def _upsert_device(self, conn: sqlite3.Connection, ip: str, host: _Host, mac: str | None) -> None:
        existing = conn.execute(
            "SELECT services_json FROM devices WHERE analysis_id = ? AND ip = ?", (self.analysis_id, ip)
        ).fetchone()
        services = {(s["port"], s["proto"], s["app"]) for s in json.loads(existing[0] or "[]")} if existing else set()
        services |= host.services
        services_json = json.dumps([{"port": p, "proto": pr, "app": a} for p, pr, a in sorted(services, key=lambda s: (s[0], s[1]))])
        conn.execute(
            "INSERT INTO devices(analysis_id, ip, mac, vendor, hostname, services_json, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(analysis_id, ip) DO UPDATE SET mac = COALESCE(excluded.mac, mac), "
            "vendor = COALESCE(excluded.vendor, vendor), hostname = COALESCE(excluded.hostname, hostname), "
            "services_json = excluded.services_json, "
            "first_seen = MIN(COALESCE(first_seen, excluded.first_seen), COALESCE(excluded.first_seen, first_seen)), "
            "last_seen = MAX(COALESCE(last_seen, excluded.last_seen), COALESCE(excluded.last_seen, last_seen))",
            (self.analysis_id, ip, mac, vendor_for(mac, self.oui_csv), self._hostname_for(ip, mac),
             services_json, host.first_seen, host.last_seen),
        )


def process_eve_file(conn: sqlite3.Connection, analysis_id: int, eve_path: Path, lan_cidrs: Iterable[str],
                     oui_csv: str, classification_file: str,
                     on_progress: Callable[[float], None] | None = None) -> EveLogger:
    """Run ACP 1–2 over a whole eve.json file (offline mode) and return the logger with its counters.

    `on_progress(fraction)` is called every PROGRESS_EVERY lines and once at the end.
    """
    log = EveLogger(analysis_id, parse_networks(lan_cidrs), oui_csv, load_classtypes(classification_file))
    total = Path(eve_path).stat().st_size or 1
    with open(eve_path, "rb") as fh:
        for n, raw in enumerate(fh, 1):
            log.feed(conn, raw.decode("utf-8", errors="replace"))
            if on_progress and n % PROGRESS_EVERY == 0:
                on_progress(fh.tell() / total)
    log.finish(conn)
    if on_progress:
        on_progress(1.0)
    return log
