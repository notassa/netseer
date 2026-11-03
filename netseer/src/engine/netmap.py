"""Network map data for the Devices page (CONCEPTS A17), in Cytoscape.js element format.

Nodes: an Internet root, the discovered networks, the hosts inside them (internal devices and hosts of
"looks local" networks), the busiest outside sources (the rest folded into one node). Edges: `tree` edges
(Internet → network → host, Internet → outside source) give the Tree layout its shape; `link` edges are the
observed traffic between hosts (host_links), red when they carried alerts.
"""

from __future__ import annotations

import ipaddress
import json
import math
import sqlite3
from collections import defaultdict

from netseer.src.engine.networks import stored
from netseer.src.engine.scorer import device_bands

MAX_EXTERNALS = 40               # outside sources drawn one by one; the rest become "other"
MAX_NETWORK_HOSTS = 250          # hosts drawn per network
MAX_LINKS = 1500                 # traffic edges kept (most alerts, then most bytes)
OTHER = "other-external"


def _addr(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def build_map(conn: sqlite3.Connection, analysis_id: int) -> dict:
    """{"nodes": [...], "edges": [...], "summary": {...}} for one analysis."""
    devices = {r["ip"]: r for r in conn.execute("SELECT * FROM devices WHERE analysis_id = ?", (analysis_id,))}
    bands = device_bands(conn, analysis_id)
    nets = stored(conn, analysis_id)
    parsed = sorted(((ipaddress.ip_network(n["prefix"]), n) for n in nets), key=lambda t: -t[0].prefixlen)
    links = conn.execute("SELECT a, b, flows, bytes, alerts FROM host_links WHERE analysis_id = ?",
                         (analysis_id,)).fetchall()
    fallback = not any(r["flows"] for r in links)
    pairs: list[tuple[str, str, int, int, int]] = [(r["a"], r["b"], r["flows"], r["bytes"], r["alerts"]) for r in links]
    if fallback:                                   # analyses from before host_links: add external peers
        for r in conn.execute("SELECT ip, n_flows, bytes, peers_json FROM external_hosts WHERE analysis_id = ?",
                              (analysis_id,)):
            for peer in json.loads(r["peers_json"] or "[]"):
                pairs.append((min(r["ip"], peer), max(r["ip"], peer), 1, 0, 0))

    def network_of(ip: str):
        addr = _addr(ip)
        return next((n for net, n in parsed if addr is not None and addr.version == net.version and addr in net), None)

    alerts_by_ip, bytes_by_ip = defaultdict(int), defaultdict(int)
    for a, b, _, nbytes, n_alerts in pairs:
        for ip in (a, b):
            alerts_by_ip[ip] += n_alerts
            bytes_by_ip[ip] += nbytes
    hosts = set(devices) | {ip for p in pairs for ip in p[:2]}
    members: dict[str, list[str]] = defaultdict(list)
    outside: list[str] = []
    for ip in hosts:
        net = network_of(ip)
        if ip in devices or net is not None:
            members[net["prefix"] if net else "unassigned"].append(ip)
        else:
            outside.append(ip)
    outside.sort(key=lambda ip: (-alerts_by_ip[ip], -bytes_by_ip[ip], ip))
    shown_outside = set(outside[:MAX_EXTERNALS])
    folded = outside[MAX_EXTERNALS:]

    nodes = [{"data": {"id": "internet", "label": "Internet", "kind": "internet"}}]
    edges = []
    shown: dict[str, str] = {}                 # ip → node id
    for prefix, ips in members.items():
        net = next((n for n in nets if n["prefix"] == prefix), None)
        net_id = f"net:{prefix}"
        nodes.append({"data": {"id": net_id, "kind": "network", "label": prefix if net else "No network found",
                               "confidence": net["confidence"] if net else None, "in_lan": net["in_lan"] if net else True,
                               "evidence": net["evidence"] if net else [], "gateway": net["gateway"] if net else None}})
        edges.append({"data": {"id": f"t:{net_id}", "source": "internet", "target": net_id}, "classes": "tree"})
        ips.sort(key=lambda ip: (-alerts_by_ip[ip], _addr(ip) or ip))
        shown_ips = ips[:MAX_NETWORK_HOSTS]
        gateway = net["gateway"] if net and net["gateway"] in shown_ips else None      # clients hang off their router
        for ip in shown_ips:
            d = devices.get(ip)
            data = {"id": ip, "kind": "device" if d else "host", "network": prefix, "alerts": alerts_by_ip[ip],
                    "bytes": bytes_by_ip[ip], "gateway": bool(net and net["gateway"] == ip)}
            if d:
                data |= {"mac": d["mac"], "vendor": d["vendor"], "hostname": d["hostname"], "type": d["type"],
                         "risk": round(100 * d["risk"]), "band": bands.get(ip, "Low").lower()}
            data["label"] = ip + (f"\n{d['hostname']}" if d and d["hostname"] else "")
            nodes.append({"data": data})
            parent = gateway if gateway and ip != gateway else net_id
            edges.append({"data": {"id": f"t:{ip}", "source": parent, "target": ip}, "classes": "tree"})
            shown[ip] = ip
    for ip in sorted(shown_outside, key=lambda ip: (-alerts_by_ip[ip], -bytes_by_ip[ip])):
        nodes.append({"data": {"id": ip, "label": ip, "kind": "external", "alerts": alerts_by_ip[ip],
                               "bytes": bytes_by_ip[ip]}})
        edges.append({"data": {"id": f"t:{ip}", "source": "internet", "target": ip}, "classes": "tree"})
        shown[ip] = ip
    if folded:
        nodes.append({"data": {"id": OTHER, "kind": "external", "label": f"+{len(folded)} other outside hosts",
                               "alerts": sum(alerts_by_ip[i] for i in folded), "bytes": sum(bytes_by_ip[i] for i in folded)}})
        edges.append({"data": {"id": f"t:{OTHER}", "source": "internet", "target": OTHER}, "classes": "tree"})
        for ip in folded:
            shown[ip] = OTHER

    merged: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for a, b, flows, nbytes, n_alerts in pairs:
        sa, sb = shown.get(a), shown.get(b)
        if not sa or not sb or sa == sb:
            continue
        key = (sa, sb) if sa < sb else (sb, sa)
        m = merged[key]
        m[0] += flows
        m[1] += nbytes
        m[2] += n_alerts
    ranked = sorted(merged.items(), key=lambda kv: (-kv[1][2], -kv[1][1]))[:MAX_LINKS]
    for i, ((a, b), (flows, nbytes, n_alerts)) in enumerate(ranked):
        edges.append({"data": {"id": f"l{i}", "source": a, "target": b, "flows": flows, "bytes": nbytes,
                               "alerts": n_alerts, "width": round(1 + min(6.0, math.log10(1 + nbytes) / 1.5), 2)},
                      "classes": "link alert" if n_alerts else "link"})
    return {"nodes": nodes, "edges": edges, "summary": {
        "networks": len(members), "hosts": sum(min(len(v), MAX_NETWORK_HOSTS) for v in members.values()),
        "outside": len(outside), "folded": len(folded), "links": len(ranked), "links_total": len(merged),
        "partial": fallback}}
