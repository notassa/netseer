"""NetSeer Details (Information page): facts about the box NetSeer runs on, read from /proc, /sys and local tools.

Nothing here needs root or leaves the machine (Ollama is asked on localhost).
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import httpx

from netseer.src.config import app_config, get_setting
from netseer.src.engine.live import interfaces


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def cpu_percent(proc: Path = Path("/proc"), wait: float = 0.2) -> float:
    """CPU busy % over `wait` seconds, from two /proc/stat samples."""
    def sample() -> tuple[int, int]:
        fields = [int(v) for v in _read(proc / "stat").split("\n", 1)[0].split()[1:]]
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)       # idle + iowait
        return sum(fields), idle
    total1, idle1 = sample()
    time.sleep(wait)
    total2, idle2 = sample()
    return round(100 * (1 - (idle2 - idle1) / max(total2 - total1, 1)), 1)


def memory(proc: Path = Path("/proc")) -> dict:
    """Total and used RAM in bytes (used = total − available)."""
    info = {k: int(v.split()[0]) * 1024 for k, v in
            (line.split(":", 1) for line in _read(proc / "meminfo").splitlines() if ":" in line)}
    total, available = info.get("MemTotal", 0), info.get("MemAvailable", 0)
    return {"total": total, "used": total - available}


def temperatures(sys_root: Path = Path("/sys")) -> list[dict]:
    """Every hwmon temperature: sensor, label and °C (CPU package/cores from coretemp, board from acpitz)."""
    out = []
    for hw in sorted((sys_root / "class" / "hwmon").glob("hwmon*")):
        sensor = _read(hw / "name").strip()
        for t in sorted(hw.glob("temp*_input")):
            raw = _read(t).strip()
            if raw.lstrip("-").isdigit():
                label = _read(t.with_name(t.name.replace("_input", "_label"))).strip() or t.name.split("_")[0]
                out.append({"sensor": sensor, "label": label, "celsius": int(raw) / 1000})
    return out


def addresses() -> dict[str, list[str]]:
    """IPv4/IPv6 addresses per interface (`ip -j addr`)."""
    try:
        data = json.loads(subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True).stdout or "[]")
    except (OSError, ValueError):
        return {}
    return {d["ifname"]: [f"{a['local']}/{a['prefixlen']}" for a in d.get("addr_info", [])] for d in data}


@lru_cache(maxsize=1)
def _static() -> dict:
    """Facts that do not change while NetSeer runs."""
    cpu = next((line.split(":", 1)[1].strip() for line in _read(Path("/proc/cpuinfo")).splitlines()
                if line.startswith("model name")), platform.processor())
    os_name = next((line.split("=", 1)[1].strip('"') for line in _read(Path("/etc/os-release")).splitlines()
                    if line.startswith("PRETTY_NAME=")), platform.system())
    try:
        suricata = subprocess.run([str(app_config("suricata_bin")), "-V"], capture_output=True, text=True,
                                  timeout=10).stdout.strip().replace("This is Suricata version ", "")
    except (OSError, subprocess.TimeoutExpired):
        suricata = ""
    return {"hostname": socket.gethostname(), "os": os_name, "kernel": platform.release(), "cpu": cpu,
            "cores": os.cpu_count(), "python": platform.python_version(), "suricata": suricata}


def _ollama(conn) -> str:
    try:
        version = httpx.get(f"{str(app_config('ollama_url')).rstrip('/')}/api/version", timeout=1).json()["version"]
        return f"{version} · model {get_setting(conn, 'llm_model')}"
    except (httpx.HTTPError, KeyError, ValueError):
        return "not reachable"


def snapshot(conn, data_dir: Path, db_path: Path) -> dict:
    """Everything the NetSeer Details tab shows; `usage` holds the numbers that change (refreshed every 5 s)."""
    boot = time.time() - float((_read(Path("/proc/uptime")).split() or ["0"])[0])
    ips = addresses()
    nics = [n | {"addresses": ips.get(n["name"], [])} for n in interfaces()]
    return _static() | {
        "up_since": datetime.fromtimestamp(boot, timezone.utc).isoformat(timespec="seconds"),
        "ollama": _ollama(conn),
        "db_bytes": sum(p.stat().st_size for p in Path(db_path).parent.glob(Path(db_path).name + "*")),
        "nics": nics,
        "usage": usage(data_dir),
    }


def usage(data_dir: Path) -> dict:
    """CPU %, load, RAM, disk and temperatures now."""
    disk = shutil.disk_usage(next(p for p in (Path(data_dir), *Path(data_dir).parents) if p.exists()))
    return {"cpu_percent": cpu_percent(), "load": [round(x, 2) for x in os.getloadavg()], "memory": memory(),
            "disk": {"total": disk.total, "used": disk.used}, "temperatures": temperatures()}
