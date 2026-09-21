"""Is anybody there? TCP and ICMP probes, and the TTL of a reply.

ICMP goes through the operating system's own `ping` (no raw sockets, no root).
The address is validated first and passed as a list, never through a shell,
and a value that is not an IP address never reaches the command line.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time

from ..config import DISCOVERY_PORTS
from ..log import logger
from ..net import Cancelled, SLICE, parse_ip, tcp_state

try:  # scapy is optional: it enables raw-ICMP TTL probing
    from scapy.all import ICMP, IP, conf as scapy_conf, sr1

    scapy_conf.verb = 0
    HAVE_SCAPY = True
except Exception:  # pragma: no cover - depends on the environment
    HAVE_SCAPY = False


def tcp_ping(ip: str, ports=DISCOVERY_PORTS, timeout: float = 0.6, cancel=None) -> bool:
    """A host is up if any port accepts the connection or answers with RST."""
    for port in ports:
        if tcp_state(ip, port, timeout, cancel) in ("open", "closed"):
            return True
    return False


def ping_cmd(ip: str, wait: int = 1) -> list:
    """The `ping` command line for one echo request to `ip` (IPv4 or IPv6)."""
    obj = parse_ip(ip)
    if obj is None:
        raise ValueError(f"not an IP address: {ip!r}")
    v6 = obj.version == 6
    if sys.platform.startswith("win"):
        return ["ping", *(["-6"] if v6 else []), "-n", "1", "-w", str(wait * 1000), str(ip)]
    if sys.platform == "darwin":  # macOS: -W is in milliseconds; IPv6 has its own binary
        return ["ping6" if v6 else "ping", "-c", "1", *([] if v6 else ["-W", str(wait * 1000)]), str(ip)]
    return ["ping", *(["-6"] if v6 else []), "-c", "1", "-W", str(wait), str(ip)]


def _run(cmd: list, timeout: float, cancel=None, capture: bool = False):
    """Run a command without a shell; stop it early when `cancel` is set. -> (returncode, stdout)."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, text=True)
    except OSError:
        return None, ""
    end = time.monotonic() + timeout
    while True:
        try:
            out, _ = proc.communicate(timeout=SLICE)
            return proc.returncode, out or ""
        except subprocess.TimeoutExpired:
            if time.monotonic() >= end or (cancel is not None and cancel.is_set()):
                proc.kill()
                proc.communicate()
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
                return None, ""


def icmp_ping(ip: str, cancel=None) -> bool:
    """Ping through the OS `ping` binary. False if it is missing or gets no reply."""
    if not shutil.which("ping") or parse_ip(ip) is None:
        return False
    code, _ = _run(ping_cmd(ip), 3.0, cancel)
    return code == 0


def get_ttl(ip: str, cancel=None):
    """TTL (hop limit) of an echo reply, or None. Scapy when available, else `ping`."""
    if HAVE_SCAPY and parse_ip(ip) is not None and ":" not in ip:
        try:
            pkt = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=0)
            if pkt is not None:
                return int(pkt.ttl)
        except Exception as exc:  # noqa: BLE001 - raw sockets may be refused
            logger.debug("scapy ICMP probe failed: %s", exc)
    if shutil.which("ping") and parse_ip(ip) is not None:
        _, out = _run(ping_cmd(ip), 3.0, cancel, capture=True)
        m = re.search(r"(?:ttl|hlim)[=:\s]*(\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None
