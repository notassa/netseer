"""Network discovery (CONCEPTS A17): probable subnets and VLANs, stored as Info rows (kind 'network').

Confidence, strongest first:
  certain      802.1Q VLAN tags; a DHCP subnet mask (with its router)
  strong       a directed broadcast (unanswered traffic to an address whose host bits are all 1);
               the gateway, i.e. the internal IP owning the MAC that internal traffic leaves through
  probable     remaining active internal hosts grouped by /24
  looks local  outside the LAN CIDRs, but hosts there talk to each other or to other outside networks,
               so the capture point sits inside it (e.g. UNSW-NB15's 149.171.126.0/24)
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

from netseer.src.config import analysis_lan, get_setting
from netseer.src.database import db
from netseer.src.engine.evidence import NetEvidence
from netseer.src.engine.logger import is_external, is_internal, parse_networks

CONFIDENCE = ("certain", "strong", "probable", "looks local")
BROADCAST_PREFIXES = (16, 24, 25, 26)   # common masks, widest first; smaller "broadcasts" are often plain hosts
BROADCAST_MIN_FLOWS = 2
GATEWAY_MIN_SHARE = 0.2                 # a MAC carrying ≥ 20 % of internal↔Internet flows is a gateway
LOCAL_MIN_HOSTS = 3                     # outside /24 with this many hosts talking among outside networks
WIDEST_PREFIX = 16                      # a VLAN spread wider than this is listed per /24 instead


@dataclass
class Net:
    """One probable network."""

    prefix: ipaddress.IPv4Network
    confidence: str
    evidence: list[str] = field(default_factory=list)
    vlans: set[int] = field(default_factory=set)
    gateway: str | None = None
    gateway_mac: str | None = None
    hosts: set[str] = field(default_factory=set)


def _v4(ip: str | None) -> ipaddress.IPv4Address | None:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    return addr if addr.version == 4 else None


def broadcast_prefix(ip: str) -> ipaddress.IPv4Network | None:
    """First prefix in BROADCAST_PREFIXES for which `ip` is the broadcast address (all host bits 1).

    The host bits of x.x.1.255 are also all 1 for a /23, so the address alone is ambiguous; the common masks are
    tried in order (/16 for x.x.255.255, then /24, /25, /26).
    """
    addr = _v4(ip)
    if addr is None:
        return None
    for p in BROADCAST_PREFIXES:
        mask = (1 << (32 - p)) - 1
        if int(addr) & mask == mask:
            return ipaddress.ip_network(f"{ip}/{p}", strict=False)
    return None


def covering(ips: list[ipaddress.IPv4Address]) -> ipaddress.IPv4Network:
    """Smallest network containing every address."""
    net = ipaddress.ip_network(f"{min(ips)}/32")
    while not all(ip in net for ip in ips):
        net = net.supernet()
    return net


class _Found:
    def __init__(self) -> None:
        self.nets: dict[ipaddress.IPv4Network, Net] = {}

    def add(self, prefix: ipaddress.IPv4Network, confidence: str, evidence: str, **extra) -> Net:
        net = self.nets.get(prefix)
        if net is None:
            net = self.nets[prefix] = Net(prefix, confidence)
        elif CONFIDENCE.index(confidence) < CONFIDENCE.index(net.confidence):
            net.confidence = confidence
        if evidence not in net.evidence:
            net.evidence.append(evidence)
        net.vlans |= extra.get("vlans", set())
        net.gateway = net.gateway or extra.get("gateway")
        net.gateway_mac = net.gateway_mac or extra.get("gateway_mac")
        return net


def _pairs(conn: sqlite3.Connection, analysis_id: int) -> list[tuple[str, str]]:
    """Host pairs seen talking: the map links, or the alerts for analyses made before links were recorded."""
    rows = conn.execute("SELECT a, b FROM host_links WHERE analysis_id = ? AND flows > 0", (analysis_id,)).fetchall()
    if not rows:
        rows = conn.execute("SELECT DISTINCT src_ip, dest_ip FROM alerts WHERE analysis_id = ? AND src_ip IS NOT NULL "
                            "AND dest_ip IS NOT NULL", (analysis_id,)).fetchall()
    return [(r[0], r[1]) for r in rows]


def discover(conn: sqlite3.Connection, analysis_id: int, evidence: NetEvidence | None = None) -> list[Net]:
    """Probable networks of an analysis, strongest and LAN networks first."""
    lan = parse_networks(analysis_lan(conn, analysis_id))
    devices = {r["ip"]: (r["mac"] or "").lower() for r in conn.execute(
        "SELECT ip, mac FROM devices WHERE analysis_id = ?", (analysis_id,)) if _v4(r["ip"])}
    found = _Found()
    if evidence is not None:
        by_vlan: dict[int, list[ipaddress.IPv4Address]] = defaultdict(list)
        for ip, tags in evidence.vlans.items():
            if (addr := _v4(ip)) and (is_internal(ip, lan) or ip in devices):
                for tag in tags:
                    by_vlan[tag].append(addr)
        for tag, ips in by_vlan.items():
            net = covering(ips)
            parts = [net] if net.prefixlen >= WIDEST_PREFIX else \
                sorted({ipaddress.ip_network(f"{ip}/24", strict=False) for ip in ips})
            for part in parts:
                found.add(part, "certain", f"802.1Q VLAN {tag} ({sum(ip in part for ip in ips)} hosts tagged)",
                          vlans={tag})
        for opt in evidence.dhcp.values():
            base = (opt["routers"] or [None])[0] or opt["ip"]
            if not _v4(base) or base == "0.0.0.0":
                continue
            try:
                prefix = ipaddress.ip_network(f"{base}/{opt['mask']}", strict=False)
            except ValueError:
                continue
            router = (opt["routers"] or [None])[0]
            found.add(prefix, "certain", f"DHCP: subnet mask {opt['mask']}"
                      + (f", router {', '.join(opt['routers'])}" if opt["routers"] else "")
                      + (f" (from {opt['server']})" if opt.get("server") else ""), gateway=router)
        for ip, flows in evidence.unanswered.items():
            prefix = broadcast_prefix(ip)
            if prefix and flows >= BROADCAST_MIN_FLOWS and ip not in devices:
                found.add(prefix, "strong", f"directed broadcast to {ip} ({flows} unanswered flows)")
        total = sum(evidence.gateway_macs.values())
        mac_ips = defaultdict(list)
        for ip, mac in devices.items():
            if mac:
                mac_ips[mac].append(ip)
        for mac, n in evidence.gateway_macs.most_common(3):
            if not total or n / total < GATEWAY_MIN_SHARE:
                continue
            for ip in sorted(mac_ips.get(mac, []), key=ipaddress.ip_address)[:1]:
                prefix = min((p for p in found.nets if _v4(ip) in p), key=lambda p: p.prefixlen,
                             default=ipaddress.ip_network(f"{ip}/24", strict=False))
                found.add(prefix, "strong" if prefix not in found.nets else found.nets[prefix].confidence,
                          f"gateway {ip} ({mac}) carries {100 * n / total:.0f}% of the traffic to and from the Internet",
                          gateway=ip, gateway_mac=mac)
    for ip in devices:
        addr = _v4(ip)
        if not any(addr in p for p in found.nets):
            found.add(ipaddress.ip_network(f"{ip}/24", strict=False), "probable", "active internal hosts in this /24")
    outside: dict[ipaddress.IPv4Network, set[str]] = defaultdict(set)
    for a, b in _pairs(conn, analysis_id):
        if is_external(a, lan) and is_external(b, lan) and _v4(a) and _v4(b):
            for ip in (a, b):
                outside[ipaddress.ip_network(f"{ip}/24", strict=False)].add(ip)
    for prefix, hosts in outside.items():
        if len(hosts) >= LOCAL_MIN_HOSTS:
            found.add(prefix, "looks local", f"{len(hosts)} hosts here talk to other networks outside the LAN CIDRs: "
                                             "the capture point is inside this network").hosts |= hosts
    nets = list(found.nets.values())
    # A probable /24 inside a stronger network is part of it.
    nets = [n for n in nets if not (n.confidence == "probable" and any(
        o is not n and o.confidence != "probable" and n.prefix.subnet_of(o.prefix) for o in nets))]
    adopted = [a for a in set(lan) - set(parse_networks(get_setting(conn, "lan_cidrs"))) if a.version == 4]
    for n in nets:
        n.hosts |= {ip for ip in devices if _v4(ip) in n.prefix}
        if any(n.prefix.subnet_of(a) for a in adopted):
            n.evidence.append("adopted as LAN for this analysis (it looked local, or is the live LAN adapter's subnet)")
    in_lan = lambda n: any(n.prefix.subnet_of(l) for l in lan if l.version == 4)  # noqa: E731
    return sorted(nets, key=lambda n: (not in_lan(n), CONFIDENCE.index(n.confidence), n.prefix))


def to_adopt(conn: sqlite3.Connection, analysis_id: int, nets: list[Net]) -> list[str]:
    """Prefixes outside the LAN whose hosts talk among outside networks (looks local, possibly also backed by DHCP or
    VLAN evidence) to adopt as the analysis's LAN: once per analysis, and only when they hold more hosts than its
    internal devices (e.g. UNSW-NB15, whose testbed uses public addresses)."""
    if conn.execute("SELECT 1 FROM settings WHERE key = ?", (f"lan_cidrs:{analysis_id}",)).fetchone():
        return []
    lan = [n for n in parse_networks(analysis_lan(conn, analysis_id)) if n.version == 4]
    local = [n for n in nets if n.hosts and not any(n.prefix.subnet_of(l) for l in lan)]
    n_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
    return [str(n.prefix) for n in local] if sum(len(n.hosts) for n in local) > n_devices else []


def link_alerts(conn: sqlite3.Connection, analysis_id: int) -> None:
    """Count alerts per host pair in host_links (pairs seen only in alerts are added)."""
    conn.execute("BEGIN")
    conn.execute("UPDATE host_links SET alerts = 0 WHERE analysis_id = ?", (analysis_id,))
    conn.execute(
        "INSERT INTO host_links(analysis_id, a, b, flows, bytes, alerts, first_seen, last_seen) "
        "SELECT analysis_id, MIN(src_ip, dest_ip), MAX(src_ip, dest_ip), 0, 0, COUNT(*), MIN(ts), MAX(ts) FROM alerts "
        "WHERE analysis_id = ? AND src_ip IS NOT NULL AND dest_ip IS NOT NULL GROUP BY 2, 3 "
        "ON CONFLICT(analysis_id, a, b) DO UPDATE SET alerts = excluded.alerts", (analysis_id,))
    conn.execute("COMMIT")


def run_discovery(conn: sqlite3.Connection, analysis_id: int, evidence: NetEvidence | None = None) -> list[Net]:
    """Count alerts per link, discover the networks and replace the analysis's 'network' Info rows."""
    link_alerts(conn, analysis_id)
    lan = parse_networks(analysis_lan(conn, analysis_id))
    nets = discover(conn, analysis_id, evidence)
    now = db.utcnow()
    conn.execute("BEGIN")
    conn.execute("DELETE FROM analysis_info WHERE analysis_id = ? AND kind = 'network'", (analysis_id,))
    conn.executemany(
        "INSERT INTO analysis_info(analysis_id, kind, level, title, detail_json, created_at) VALUES (?, 'network', ?, ?, ?, ?)",
        [(analysis_id, "info" if n.confidence != "looks local" else "warning", str(n.prefix), json.dumps({
            "prefix": str(n.prefix), "confidence": n.confidence, "evidence": n.evidence, "vlans": sorted(n.vlans),
            "gateway": n.gateway, "gateway_mac": n.gateway_mac, "hosts": len(n.hosts),
            "sample": sorted(n.hosts, key=ipaddress.ip_address)[:10],
            "in_lan": any(n.prefix.subnet_of(l) for l in lan if l.version == 4)}), now) for n in nets])
    conn.execute("COMMIT")
    return nets


def stored(conn: sqlite3.Connection, analysis_id: int) -> list[dict]:
    """The analysis's networks as stored by run_discovery."""
    return [json.loads(r[0]) for r in conn.execute(
        "SELECT detail_json FROM analysis_info WHERE analysis_id = ? AND kind = 'network' ORDER BY id", (analysis_id,))]


def ensure_networks(conn: sqlite3.Connection, analysis: sqlite3.Row) -> list[dict]:
    """Stored networks; discovered once (without logger evidence) for finished analyses made before A17."""
    found = stored(conn, analysis["id"])
    if not found and analysis["status"] in ("done", "awaiting_attribution"):
        run_discovery(conn, analysis["id"])
        found = stored(conn, analysis["id"])
    return found
