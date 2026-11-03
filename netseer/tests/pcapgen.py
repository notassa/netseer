"""Deterministic pcap writer for tests (pcaps are never committed, so fixtures are generated).

Builds Ethernet/IPv4 TCP sessions, UDP datagrams and DHCP exchanges with valid checksums.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path

ROUTER_MAC = "00:11:22:33:44:01"


def _mac(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def _ip(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0,
                         _ip(src), _ip(dst))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def _l4_checksum(src: str, dst: str, proto: int, segment: bytes) -> int:
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, proto, len(segment))
    return _checksum(pseudo + segment)


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, data: bytes = b"") -> bytes:
    """A TCP segment (no options) with a valid checksum."""
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 64240, 0, 0) + data
    csum = _l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp_datagram(src: str, dst: str, sport: int, dport: int, data: bytes) -> bytes:
    """A UDP datagram with a valid checksum."""
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    csum = _l4_checksum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Capture:
    """Accumulates timestamped Ethernet frames and writes a classic pcap."""

    start: float
    frames: list[tuple[float, bytes]] = field(default_factory=list)
    clock: float = 0.0
    ident: int = 1

    def __post_init__(self) -> None:
        self.clock = self.start

    def _frame(self, src_mac: str, dst_mac: str, ip_packet: bytes, gap: float) -> None:
        self.clock += gap
        self.frames.append((self.clock, _mac(dst_mac) + _mac(src_mac) + b"\x08\x00" + ip_packet))

    def tcp_session(self, client: tuple[str, str, int], server: tuple[str, str, int],
                    request: bytes, response: bytes = b"", gap: float = 0.01) -> None:
        """Client (ip, mac, port) opens a TCP session to server (ip, mac, port), exchanges data and closes."""
        cip, cmac, cport = client
        sip, smac, sport = server
        c_seq, s_seq = 1000, 5000

        def c2s(flags: int, data: bytes = b"") -> None:
            nonlocal c_seq
            seg = tcp_segment(cip, sip, cport, sport, c_seq, s_seq, flags, data)
            self._frame(cmac, smac, _ipv4(cip, sip, 6, seg, self._next_id()), gap)
            c_seq += len(data) + (1 if flags & (SYN | FIN) else 0)

        def s2c(flags: int, data: bytes = b"") -> None:
            nonlocal s_seq
            seg = tcp_segment(sip, cip, sport, cport, s_seq, c_seq, flags, data)
            self._frame(smac, cmac, _ipv4(sip, cip, 6, seg, self._next_id()), gap)
            s_seq += len(data) + (1 if flags & (SYN | FIN) else 0)

        c2s(SYN)
        s_seq_ack = s_seq
        seg = tcp_segment(sip, cip, sport, cport, s_seq_ack, c_seq, SYN | ACK)
        self._frame(smac, cmac, _ipv4(sip, cip, 6, seg, self._next_id()), gap)
        s_seq += 1
        c2s(ACK)
        c2s(PSH | ACK, request)
        if response:
            s2c(PSH | ACK, response)
        c2s(ACK)
        c2s(FIN | ACK)
        s2c(FIN | ACK)
        c2s(ACK)

    def tcp_probe_closed(self, client: tuple[str, str, int], server: tuple[str, str, int], gap: float = 0.01) -> None:
        """A SYN answered by RST (closed port): no service should be inferred."""
        cip, cmac, cport = client
        sip, smac, sport = server
        seg = tcp_segment(cip, sip, cport, sport, 1, 0, SYN)
        self._frame(cmac, smac, _ipv4(cip, sip, 6, seg, self._next_id()), gap)
        seg = tcp_segment(sip, cip, sport, cport, 0, 2, RST | ACK)
        self._frame(smac, cmac, _ipv4(sip, cip, 6, seg, self._next_id()), gap)

    def udp(self, src: tuple[str, str, int], dst: tuple[str, str, int], data: bytes, gap: float = 0.01) -> None:
        """One UDP datagram from src (ip, mac, port) to dst (ip, mac, port)."""
        sip, smac, sport = src
        dip, dmac, dport = dst
        self._frame(smac, dmac, _ipv4(sip, dip, 17, udp_datagram(sip, dip, sport, dport, data), self._next_id()), gap)

    def dhcp_exchange(self, client_mac: str, hostname: str, assigned_ip: str, server_ip: str,
                      server_mac: str = ROUTER_MAC, xid: int = 0x1234ABCD, gap: float = 0.01) -> None:
        """DHCP REQUEST (with hostname) and ACK assigning `assigned_ip`."""
        def bootp(op: int, yiaddr: str, options: bytes) -> bytes:
            return (struct.pack("!BBBBIHH4s4s4s4s", op, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, _ip(yiaddr),
                                b"\0" * 4, b"\0" * 4)
                    + _mac(client_mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63" + options + b"\xff")

        name = hostname.encode()
        req = bootp(1, "0.0.0.0", b"\x35\x01\x03" + b"\x32\x04" + _ip(assigned_ip) + b"\x0c" + bytes([len(name)]) + name)
        self.udp(("0.0.0.0", client_mac, 68), ("255.255.255.255", "ff:ff:ff:ff:ff:ff", 67), req, gap)
        ack = bootp(2, assigned_ip, b"\x35\x01\x05" + b"\x36\x04" + _ip(server_ip) + b"\x01\x04" + _ip("255.255.255.0")
                    + b"\x33\x04\x00\x01\x51\x80")
        self.udp((server_ip, server_mac, 67), (assigned_ip, client_mac, 68), ack, gap)

    def _next_id(self) -> int:
        self.ident += 1
        return self.ident

    def write(self, path: Path) -> Path:
        """Write frames as a classic little-endian pcap (magic d4c3b2a1 on disk)."""
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in sorted(self.frames, key=lambda f: f[0]):
                sec = int(ts)
                fh.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)))
                fh.write(frame)
        return path


def read_pcap_timestamps(path: Path) -> list[float]:
    """Packet timestamps of a classic pcap (for merge-order tests)."""
    data = Path(path).read_bytes()
    out, off = [], 24
    while off + 16 <= len(data):
        sec, usec, incl, _ = struct.unpack("<IIII", data[off:off + 16])
        out.append(sec + usec / 1e6)
        off += 16 + incl
    return out


# --- Demo scenario used by ingest/logger tests ----------------------------------------------------
LAN_CLIENT = ("192.168.100.50", "3c:22:fb:11:22:33")      # Apple OUI
LAN_SCANNER = ("192.168.100.60", "8c:04:ba:00:00:60")     # Dell OUI
LAN_SERVER = ("192.168.100.24", "8c:04:ba:9f:c8:ec")      # Dell OUI
GATEWAY = ("192.168.100.1", ROUTER_MAC)
EXTERNAL = "203.0.113.10"                                  # TEST-NET-3, outside RFC1918

ID_ROOT_RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 39\r\n\r\n"
                    b"uid=0(root) gid=0(root) groups=0(root)\n")


def demo_part_a(path: Path, start: float = 1_760_000_000.0) -> Path:
    """Client gets its address by DHCP, then fetches a page answering 'uid=0(root)' (testmynids style)."""
    cap = Capture(start)
    cap.dhcp_exchange(LAN_CLIENT[1], "alice-laptop", LAN_CLIENT[0], GATEWAY[0])
    cap.tcp_session((LAN_CLIENT[0], LAN_CLIENT[1], 50000), (EXTERNAL, ROUTER_MAC, 80),
                    b"GET /uid/index.html HTTP/1.1\r\nHost: testmynids.org\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
                    ID_ROOT_RESPONSE)
    return cap.write(path)


def demo_part_b(path: Path, start: float = 1_760_003_600.0) -> Path:
    """One hour later: an internal host probes the server with an Nmap NSE user-agent."""
    cap = Capture(start)
    cap.tcp_probe_closed((LAN_SCANNER[0], LAN_SCANNER[1], 40001), (LAN_SERVER[0], LAN_SERVER[1], 23))
    cap.tcp_session((LAN_SCANNER[0], LAN_SCANNER[1], 40002), (LAN_SERVER[0], LAN_SERVER[1], 80),
                    b"GET / HTTP/1.1\r\nHost: 192.168.100.24\r\n"
                    b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    return cap.write(path)
