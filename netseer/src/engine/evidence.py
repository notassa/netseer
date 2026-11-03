"""Network evidence gathered while the logger streams eve.json (CONCEPTS A17).

Kept small and bounded: VLAN tags per IP, DHCP subnet options, the MACs that internal traffic leaves through
(gateways), unanswered destinations that may be directed broadcasts, and per-pair traffic for the network map.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

MAX_LINKS = 200_000              # distinct host pairs kept for the map
MAX_VLAN_IPS = 100_000
MAX_VLANS_PER_IP = 4


def _macs(ether: dict[str, Any], side: str) -> list[str]:
    macs = ether.get(f"{side}_macs") or ([ether[f"{side}_mac"]] if ether.get(f"{side}_mac") else [])
    return [m.lower() for m in macs if m and int(m.split(":")[0], 16) & 1 == 0]      # unicast only


@dataclass
class NetEvidence:
    """Evidence for subnet/VLAN discovery and the map's edges."""

    vlans: dict[str, set[int]] = field(default_factory=dict)
    dhcp: dict[tuple, dict] = field(default_factory=dict)          # (mask, routers) → options
    gateway_macs: Counter = field(default_factory=Counter)
    unanswered: Counter = field(default_factory=Counter)           # destination IP → flows without a reply
    links: dict[tuple[str, str], list] = field(default_factory=dict)   # (a, b) → [flows, bytes, first, last]

    def observe(self, event: dict[str, Any], etype: str | None, internal: Callable[[str | None], bool],
                times: list[str | None]) -> None:
        """Take what this event says about the network."""
        src, dest = event.get("src_ip"), event.get("dest_ip")
        for vlan in event.get("vlan") or []:
            for ip in (src, dest):
                if ip and (ip in self.vlans or len(self.vlans) < MAX_VLAN_IPS):
                    tags = self.vlans.setdefault(ip, set())
                    if len(tags) < MAX_VLANS_PER_IP:
                        tags.add(int(vlan))
        if etype == "dhcp":
            dhcp = event.get("dhcp") or {}
            if dhcp.get("subnet_mask"):
                key = (dhcp["subnet_mask"], tuple(dhcp.get("routers") or []))
                self.dhcp.setdefault(key, {"mask": dhcp["subnet_mask"], "routers": list(dhcp.get("routers") or []),
                                           "ip": dhcp.get("assigned_ip") or dhcp.get("client_ip"),
                                           "server": src})
        if etype != "flow" or not src or not dest:
            return
        flow = event.get("flow") or {}
        ether = event.get("ether") or {}
        if internal(src) and not internal(dest):
            self.gateway_macs.update(_macs(ether, "dest"))
        elif internal(dest) and not internal(src):
            self.gateway_macs.update(_macs(ether, "src"))
        if int(flow.get("pkts_toclient") or 0) == 0 and dest.count(".") == 3 and int(dest.rsplit(".", 1)[1]) & 3 == 3:
            self.unanswered[dest] += 1                     # host bits end in ones: a broadcast candidate
        a, b = (src, dest) if src < dest else (dest, src)
        link = self.links.get((a, b))
        if link is None:
            if len(self.links) >= MAX_LINKS:
                return
            link = self.links[(a, b)] = [0, 0, None, None]
        link[0] += 1
        link[1] += int(flow.get("bytes_toserver") or 0) + int(flow.get("bytes_toclient") or 0)
        for ts in times:
            if ts:
                link[2] = min(link[2] or ts, ts)
                link[3] = max(link[3] or ts, ts)

    def write_links(self, conn: sqlite3.Connection, analysis_id: int) -> None:
        """Store the host pairs (inside the caller's transaction)."""
        conn.executemany(
            "INSERT INTO host_links(analysis_id, a, b, flows, bytes, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(analysis_id, a, b) DO UPDATE SET flows = flows + excluded.flows, bytes = bytes + excluded.bytes, "
            "first_seen = MIN(COALESCE(first_seen, excluded.first_seen), COALESCE(excluded.first_seen, first_seen)), "
            "last_seen = MAX(COALESCE(last_seen, excluded.last_seen), COALESCE(excluded.last_seen, last_seen))",
            [(analysis_id, a, b, *v) for (a, b), v in self.links.items()])
