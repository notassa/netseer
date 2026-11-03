"""Who is calling: client IP (proxy-aware) and MAC from the server's neighbour (ARP) table."""

from __future__ import annotations

import ipaddress
import json
import subprocess

from fastapi import Request

from netseer.src.config import app_config


def client_ip(request: Request) -> str | None:
    """The client's IP; X-Forwarded-For is trusted only from configured proxies (Nginx at cutover)."""
    peer = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if peer in app_config("trusted_proxies") and forwarded:
        return forwarded.split(",")[-1].strip()      # the proxy appends the address it saw last
    return peer


def client_mac(ip: str | None) -> str | None:
    """MAC for a same-LAN client from `ip neigh`, or None (loopback, routed client, or not in the table)."""
    try:
        if ip is None or ipaddress.ip_address(ip).is_loopback:
            return None
        out = subprocess.run(["ip", "-j", "neigh", "show", ip], capture_output=True, text=True, timeout=1).stdout
        for entry in json.loads(out or "[]"):
            if entry.get("lladdr"):
                return entry["lladdr"].lower()
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass
    return None


def who(request: Request) -> tuple[str | None, str | None]:
    """(ip, mac) of the client, for audit entries."""
    ip = client_ip(request)
    return ip, client_mac(ip)
