"""Finding devices on the local network through ARP / neighbour tables.

Two ways in, both optional:

* scapy (when installed and allowed to use raw sockets) broadcasts real ARP
  requests and is the most reliable;
* the neighbour cache: one empty UDP datagram per address makes the operating
  system resolve it with ARP (or NDP for IPv6), and the answers are then read
  from /proc/net/arp, `ip neigh` or `arp -a`. No root needed.

Neither is complete by itself (lost packets, sleeping devices, isolated Wi-Fi
clients), so `discover_hosts` treats ARP as a fast first pass and probes the
addresses that did not answer by TCP and ICMP as well.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from ..log import logger
from ..net import Cancelled, parse_ip, sleep_cancellable
from .mac import normalize_mac

try:
    from scapy.all import ARP, Ether, conf as scapy_conf, srp

    scapy_conf.verb = 0
    HAVE_SCAPY = True
except Exception:  # pragma: no cover - depends on the environment
    HAVE_SCAPY = False

_MAC = r"[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}"
_V4 = re.compile(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:dev\s+\S+\s+lladdr\s+|at\s+|\S+\s+\S+\s+)?(" + _MAC + ")")
_V6 = re.compile(r"^\s*([0-9a-fA-F:]*:[0-9a-fA-F:]*)(?:%\S+)?\s+dev\s+\S+\s+lladdr\s+(" + _MAC + ")")


def parse_arp_table(text: str) -> dict:
    """{ip: mac} from /proc/net/arp, `ip neigh` (IPv4 and IPv6), or `arp -a` (Windows, macOS, BSD)."""
    table = {}
    for line in text.splitlines():
        m = _V4.search(line) or _V6.search(line)
        if not m:
            continue
        ip, mac = m.group(1), normalize_mac(m.group(2))
        obj = parse_ip(ip)
        if mac and obj is not None and not obj.is_multicast:
            table[str(obj)] = mac
    return table


def _command(cmd: list, timeout: float = 5.0) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("%s failed: %s", cmd[0], exc)
        return ""


def read_arp_table() -> dict:
    """The operating system's neighbour cache: which hardware address answers for each IP."""
    if sys.platform.startswith("linux"):
        table = {}
        try:
            table.update(parse_arp_table(Path("/proc/net/arp").read_text()))
        except OSError:
            table.update(parse_arp_table(_command(["ip", "-4", "neigh", "show"])))
        table.update(parse_arp_table(_command(["ip", "-6", "neigh", "show"])))
        return table
    return parse_arp_table(_command(["arp", "-a"], 10.0))


def nudge(ips, limit: int = 1 << 16) -> int:
    """Send one empty UDP datagram to every address so the OS resolves it with ARP/NDP.

    Nothing is expected back; live hosts simply appear in the neighbour cache.
    Returns how many addresses were nudged.
    """
    socks = {}
    sent = 0
    try:
        for ip in ips:
            if sent >= limit:
                break
            family = socket.AF_INET6 if ":" in str(ip) else socket.AF_INET
            sock = socks.get(family)
            if sock is None:
                try:
                    sock = socks[family] = socket.socket(family, socket.SOCK_DGRAM)
                    sock.setblocking(False)
                except OSError:
                    continue
            try:
                sock.sendto(b"", (str(ip), 9))
                sent += 1
            except OSError:
                pass
    finally:
        for sock in socks.values():
            sock.close()
    return sent


def nudge_arp(network: str, limit: int = 1024) -> None:
    """Nudge every host address of a network (compat wrapper around `nudge`)."""
    nudge((str(h) for h in ipaddress.ip_network(network, strict=False).hosts()), limit)


def wait_for_neighbors(settle: float = 2.5, cancel=None) -> dict:
    """Read the neighbour table until it stops growing (or `settle` seconds pass)."""
    end = time.monotonic() + settle
    last, stable, table = -1, 0, {}
    while True:
        table = read_arp_table()
        stable = stable + 1 if len(table) == last else 0
        last = len(table)
        if stable >= 2 or time.monotonic() >= end:
            return table
        if not sleep_cancellable(0.3, cancel):
            return table


def neighbor_sweep(targets, settle: float = 2.5, cancel=None) -> dict:
    """{ip: mac} for the devices among `targets` (a network string or an iterable of
    addresses) that answered ARP/NDP after a nudge."""
    if isinstance(targets, str):
        net = ipaddress.ip_network(targets, strict=False)
        wanted, ips = None, (str(h) for h in net.hosts())

        def in_scope(ip):
            obj = parse_ip(ip)
            return obj is not None and obj.version == net.version and obj in net
    else:
        wanted = {str(parse_ip(ip)) for ip in targets if parse_ip(ip)}
        ips = sorted(wanted)

        def in_scope(ip):
            return ip in wanted
    nudge(ips)
    table = wait_for_neighbors(settle, cancel)
    return {ip: mac for ip, mac in table.items() if in_scope(ip)}


def scapy_arp_scan(ips: list, timeout: int = 2, cancel=None):
    """ARP discovery through scapy. Returns {ip: mac}, or None if it cannot run here."""
    if not HAVE_SCAPY:
        return None
    found = {}
    try:
        for start in range(0, len(ips), 512):
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips[start:start + 512]),
                              timeout=timeout, retry=1, verbose=0)
            found.update({rcv.psrc: rcv.hwsrc for _, rcv in answered})
    except PermissionError:
        raise
    except Cancelled:
        raise
    except Exception as exc:  # noqa: BLE001 - scapy raises many kinds of errors
        logger.debug("scapy ARP scan failed: %s", exc)
        return None
    return found
