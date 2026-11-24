"""Network discovery (CONCEPTS A17): VLAN, DHCP, broadcast, gateway, /24 grouping and outside-but-local."""

from __future__ import annotations

import ipaddress

from netseer.src.engine import networks
from netseer.src.engine.evidence import NetEvidence
from netseer.tests.test_contextor import add_alert, conn  # noqa: F401 - fixture

GW_MAC = "00:11:22:33:44:55"


def internal(ip):
    return bool(ip) and ipaddress.ip_address(ip) in ipaddress.ip_network("10.0.0.0/16")


def flow(src, dest, *, reply=True, vlan=None, src_mac="aa:aa:aa:00:00:01", dest_mac=GW_MAC, nbytes=100):
    event = {"event_type": "flow", "src_ip": src, "dest_ip": dest, "ether": {"src_macs": [src_mac], "dest_macs": [dest_mac]},
             "flow": {"pkts_toclient": 1 if reply else 0, "bytes_toserver": nbytes, "bytes_toclient": 0}}
    if vlan is not None:
        event["vlan"] = [vlan]
    return event


def arp(src, dest, opcode="request"):
    return {"event_type": "arp", "ether": {},
            "arp": {"hw_type": "ethernet", "proto_type": "ipv4", "opcode": opcode,
                    "src_mac": "20:53:83:58:7e:78", "src_ip": src,
                    "dest_mac": "00:00:00:00:00:00", "dest_ip": dest}}


def device(conn, ip, mac=None):  # noqa: F811
    conn.execute("INSERT INTO devices(analysis_id, ip, mac, attributed) VALUES (1, ?, ?, 1)", (ip, mac))


def test_evidence_collects_vlans_gateway_broadcasts_and_links():
    ev = NetEvidence()
    ts = ["2026-10-21T09:00:00+00:00"]
    ev.observe(flow("10.0.0.5", "8.8.8.8", vlan=10), "flow", internal, ts)
    ev.observe(flow("10.0.0.5", "8.8.8.8", vlan=10), "flow", internal, ts)
    ev.observe(flow("10.0.0.23", "10.0.0.255", reply=False, dest_mac="ff:ff:ff:ff:ff:ff"), "flow", internal, ts)
    ev.observe({"event_type": "dhcp", "src_ip": "10.0.0.1", "dhcp": {"subnet_mask": "255.255.255.0",
                "routers": ["10.0.0.1"], "assigned_ip": "10.0.0.23"}}, "dhcp", internal, ts)
    assert ev.vlans["10.0.0.5"] == {10} and ev.gateway_macs == {GW_MAC: 2}
    assert ev.unanswered == {"10.0.0.255": 1}
    assert ev.links[("10.0.0.5", "8.8.8.8")][:2] == [2, 200]
    assert list(ev.dhcp.values())[0]["routers"] == ["10.0.0.1"]


def test_broadcast_prefix():
    assert str(networks.broadcast_prefix("192.168.1.255")) == "192.168.1.0/24"
    assert str(networks.broadcast_prefix("10.1.255.255")) == "10.1.0.0/16"
    assert str(networks.broadcast_prefix("192.168.1.127")) == "192.168.1.0/25"
    assert networks.broadcast_prefix("192.168.1.7") is None          # /29 and smaller: too weak


def by_prefix(nets):
    return {str(n.prefix): n for n in nets}


def test_certain_and_strong_evidence(conn):  # noqa: F811
    conn.execute("UPDATE settings SET value = '[\"10.0.0.0/16\"]' WHERE key = 'lan_cidrs'")
    device(conn, "10.0.0.1", GW_MAC)
    device(conn, "10.0.0.5")
    device(conn, "10.0.0.23")
    device(conn, "10.0.7.9")                                   # nothing but its address: probable /24
    ev = NetEvidence()
    ev.vlans = {"10.0.0.5": {10}, "10.0.0.23": {10}}
    ev.dhcp = {("255.255.255.0", ("10.0.0.1",)): {"mask": "255.255.255.0", "routers": ["10.0.0.1"],
                                                  "ip": "10.0.0.23", "server": "10.0.0.1"}}
    ev.unanswered.update({"10.0.0.255": 4, "10.0.3.255": 1})
    ev.gateway_macs.update({GW_MAC: 90, "aa:bb:cc:dd:ee:ff": 10})
    nets = by_prefix(networks.discover(conn, 1, ev))
    lan24 = nets["10.0.0.0/24"]
    assert lan24.confidence == "certain" and lan24.gateway == "10.0.0.1" and lan24.gateway_mac == GW_MAC
    assert any(e.startswith("DHCP: subnet mask 255.255.255.0") for e in lan24.evidence)
    assert any(e.startswith("directed broadcast to 10.0.0.255") for e in lan24.evidence)
    assert any(e.startswith("gateway 10.0.0.1") for e in lan24.evidence)
    assert nets["10.0.0.0/27"].vlans == {10} and nets["10.0.0.0/27"].confidence == "certain"
    assert nets["10.0.7.0/24"].confidence == "probable"
    assert "10.0.3.0/24" not in nets                            # one unanswered flow is not enough
    assert lan24.hosts == {"10.0.0.1", "10.0.0.5", "10.0.0.23"}


def test_outside_networks_that_look_local(conn):  # noqa: F811
    for i in range(3):                                         # UNSW style: outside hosts attack outside servers
        add_alert(conn, i, f"175.45.176.{i}", f"149.171.126.{10 + i}", sid=1)
    add_alert(conn, 5, "10.0.0.5", "8.8.8.8", sid=2)           # ordinary Internet use: not local
    nets = by_prefix(networks.run_discovery(conn, 1))
    assert nets["149.171.126.0/24"].confidence == "looks local" and len(nets["149.171.126.0/24"].hosts) == 3
    assert "175.45.176.0/24" in nets and "8.8.8.0/24" not in nets
    rows = networks.stored(conn, 1)
    assert {r["prefix"] for r in rows} >= {"149.171.126.0/24", "175.45.176.0/24"}
    assert all(not r["in_lan"] for r in rows if r["confidence"] == "looks local")
    links = conn.execute("SELECT a, b, alerts FROM host_links WHERE analysis_id = 1 ORDER BY a").fetchall()
    assert ("149.171.126.12", "175.45.176.2", 1) in [tuple(r) for r in links]      # stored with a < b


def test_looks_local_networks_are_adopted_once(conn):  # noqa: F811
    from netseer.src.config import adopt_lan, analysis_lan
    for i in range(3):
        add_alert(conn, i, f"175.45.176.{i}", f"149.171.126.{10 + i}", sid=1)
    device(conn, "10.0.0.5")                                   # one stray RFC1918 host < 6 local hosts
    ev = NetEvidence()                                         # DHCP makes 175.45.176.0/24 "certain", still outside
    ev.dhcp = {("255.255.255.0", ()): {"mask": "255.255.255.0", "routers": [], "ip": "175.45.176.1", "server": None}}
    nets = networks.run_discovery(conn, 1, ev)
    assert by_prefix(nets)["175.45.176.0/24"].confidence == "certain"
    adopt = networks.to_adopt(conn, 1, nets)
    assert set(adopt) == {"149.171.126.0/24", "175.45.176.0/24"}
    adopt_lan(conn, 1, analysis_lan(conn, 1) + adopt)
    global_lan = analysis_lan(conn, 2)                         # another analysis keeps the global setting
    assert analysis_lan(conn, 1) == global_lan + adopt and "149.171.126.0/24" not in global_lan
    for i in range(3):                                         # the re-run's logger makes them devices
        device(conn, f"175.45.176.{i}")
        device(conn, f"149.171.126.{10 + i}")
    nets = by_prefix(networks.run_discovery(conn, 1))
    assert nets["149.171.126.0/24"].evidence[-1].startswith("adopted as LAN")
    assert networks.to_adopt(conn, 1, list(nets.values())) == []           # never twice


def test_few_outside_hosts_are_not_adopted(conn):  # noqa: F811
    for i in range(3):
        add_alert(conn, i, f"175.45.176.{i}", f"149.171.126.{10 + i}", sid=1)
    for i in range(7):
        device(conn, f"10.0.0.{i + 1}")                        # a real LAN with more hosts
    assert networks.to_adopt(conn, 1, networks.run_discovery(conn, 1)) == []


def test_evidence_collects_arp_askers_and_router_advertisements():
    ev = NetEvidence()
    ts = ["2026-10-21T09:00:00+00:00"]
    ev.observe(arp("10.0.5.1", "10.0.5.24"), "arp", internal, ts)
    ev.observe(arp("10.0.5.2", "10.0.5.24"), "arp", internal, ts)
    ev.observe(arp("10.0.5.2", "10.0.5.24"), "arp", internal, ts)            # duplicate asker: one entry
    ev.observe(arp("10.0.5.24", "10.0.5.24"), "arp", internal, ts)           # gratuitous: ignored
    ev.observe(arp("0.0.0.0", "10.0.5.24"), "arp", internal, ts)             # unspecified: ignored
    ev.observe(arp("10.0.5.9", "10.0.5.24", opcode="reply"), "arp", internal, ts)   # reply: ignored
    assert ev.arp_askers == {"10.0.5.24": {"10.0.5.1", "10.0.5.2"}}
    ra = {"event_type": "flow", "src_ip": "fe80:0000:0000:0000:0000:0000:0000:0001",
          "dest_ip": "ff02:0000:0000:0000:0000:0000:0000:0001", "ip_v": 6, "proto": "IPv6-ICMP",
          "icmp_type": 134, "icmp_code": 0,
          "ether": {"dest_macs": ["33:33:00:00:00:01"], "src_macs": ["20:53:83:58:7e:78"]}, "flow": {}}
    ev.observe(ra, "flow", internal, ts)
    assert ev.routers6 == {"fe80::1": "20:53:83:58:7e:78"}


def test_arp_finds_gateway_by_askers(conn):  # noqa: F811
    conn.execute("UPDATE settings SET value = '[\"10.0.0.0/16\"]' WHERE key = 'lan_cidrs'")
    ev = NetEvidence()
    ev.arp_askers = {
        "10.0.5.1": {"10.0.5.10", "10.0.5.11", "10.0.5.12"},                  # 3 askers, suffix .1
        "10.0.5.50": {"10.0.5.10", "10.0.5.11", "10.0.5.12", "10.0.5.13"},    # 4 askers, not a suffix
        "10.0.6.7": {"10.0.6.10", "10.0.6.11"},                               # 2 askers: not enough
        "10.0.7.9": {"10.0.7.10", "10.0.7.11", "10.0.7.12"},                  # 3 askers
    }
    nets = by_prefix(networks.discover(conn, 1, ev))
    assert nets["10.0.5.0/24"].gateway == "10.0.5.1"                          # suffix beats 4 askers
    assert "10.0.6.0/24" not in nets
    assert nets["10.0.7.0/24"].gateway == "10.0.7.9"


def test_router_advertisement_links_ipv6_to_ipv4_gateway(conn):  # noqa: F811
    conn.execute("UPDATE settings SET value = '[\"10.0.0.0/16\"]' WHERE key = 'lan_cidrs'")
    device(conn, "10.0.8.1", "20:53:83:58:7e:78")
    device(conn, "10.0.8.5")
    ev = NetEvidence()
    ev.routers6 = {"fe80::1": "20:53:83:58:7e:78"}
    net = by_prefix(networks.discover(conn, 1, ev))["10.0.8.0/24"]
    assert net.gateway == "10.0.8.1" and net.gateway6 == "fe80::1" and net.confidence == "strong"


def test_dhcp_router_beats_arp_gateway(conn):  # noqa: F811
    conn.execute("UPDATE settings SET value = '[\"10.0.0.0/16\"]' WHERE key = 'lan_cidrs'")
    ev = NetEvidence()
    ev.dhcp = {("255.255.255.0", ("10.0.9.1",)): {"mask": "255.255.255.0", "routers": ["10.0.9.1"],
                                                  "ip": "10.0.9.23", "server": "10.0.9.1"}}
    ev.arp_askers = {"10.0.9.254": {"10.0.9.10", "10.0.9.11", "10.0.9.12"}}
    net = by_prefix(networks.discover(conn, 1, ev))["10.0.9.0/24"]
    assert net.gateway == "10.0.9.1"                                          # DHCP router keeps priority
    assert any(e.startswith("ARP: 3 hosts asked who has 10.0.9.254") for e in net.evidence)
