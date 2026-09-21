"""Host discovery: who is up?

Order of work for a scan target:

1. ARP (only when every address is a private IPv4 one): scapy if it can run,
   otherwise the operating system's neighbour cache. This is fast and also
   gives the MAC address.
2. Whatever ARP did not find is probed by ICMP and TCP. ARP results are
   never trusted to be complete (packet loss, sleeping devices), so the
   remaining addresses always get this second chance; if ARP found nothing
   at all, every address does.
3. Hosts found by ICMP/TCP get their MAC from the neighbour cache afterwards.
"""
from __future__ import annotations

from ..config import DISCOVERY_PORTS
from ..i18n import t
from ..log import Diagnostics, log
from ..net import parse_ip
from ..scanning.scheduler import imap
from .arp import HAVE_SCAPY, neighbor_sweep, parse_arp_table, read_arp_table, scapy_arp_scan
from .mac import mac_is_local, mac_vendor, normalize_mac
from .ping import get_ttl, icmp_ping, tcp_ping

__all__ = ["HAVE_SCAPY", "discover_hosts", "get_ttl", "icmp_ping", "is_local", "mac_is_local", "mac_vendor",
           "neighbor_sweep", "normalize_mac", "parse_arp_table", "read_arp_table", "scapy_arp_scan", "tcp_ping"]

FALLBACK_LIMIT = 4096   # most addresses re-probed after an incomplete ARP pass


def is_local(ip: str) -> bool:
    """A private (or link-local) IPv4 address that could be on our own network."""
    addr = parse_ip(ip)
    return bool(addr and addr.version == 4 and (addr.is_private or addr.is_link_local)
                and not addr.is_loopback)


def discover_hosts(ips, workers: int = 100, probe_ports=DISCOVERY_PORTS, use_arp: bool = True,
                   on_host=None, on_progress=None, cancel=None, diagnostics=None,
                   timeout: float = 0.6, fallback: bool = True) -> dict:
    """{ip: {"mac": ..., "method": ...}} for the live hosts among `ips`.

    Optional hooks: on_host(ip, info) for every live host as soon as it is
    known, on_progress(done, total) while sweeping, and a `cancel` event.
    """
    diagnostics = diagnostics if diagnostics is not None else Diagnostics()
    targets = ips if hasattr(ips, "__len__") else list(ips)
    total = len(targets)
    found = {}
    done = 0

    def add(ip, info):
        if ip not in found:
            found[ip] = info
            if on_host:
                on_host(ip, info)

    def progress(n):
        nonlocal done
        done = n
        if on_progress:
            on_progress(min(done, total), total)

    def probe(addresses, ports, per_port_timeout):
        base = done
        count = 0
        for ip, alive in imap(lambda ip: icmp_ping(ip, cancel) or tcp_ping(ip, ports, per_port_timeout, cancel),
                              addresses, workers, cancel, diagnostics):
            count += 1
            if alive:
                add(ip, {"mac": None, "method": "ICMP/TCP"})
            progress(base + count)

    arp_first = use_arp and total > 0 and all(is_local(ip) for ip in targets)
    if arp_first:
        log(t("arp_start", n=total))
        table = None
        if HAVE_SCAPY:
            try:
                table = scapy_arp_scan(list(targets), cancel=cancel)
            except PermissionError:
                log(t("arp_permission"))
        if table is None:
            table = neighbor_sweep(targets, cancel=cancel)
        for ip, mac in table.items():
            add(ip, {"mac": mac, "method": "ARP"})
        by_arp = len(found)
        missing = [ip for ip in targets if ip not in found]
        progress(total - len(missing))
        if not missing or (cancel is not None and cancel.is_set()):
            pass
        elif not found:
            log(t("probe_start", n=len(missing)))
            probe(missing, probe_ports, timeout)
        elif fallback and len(missing) <= FALLBACK_LIMIT:
            probe(missing, tuple(probe_ports)[:4], min(timeout, 0.4))
            if len(found) > by_arp:
                diagnostics.warn("arp_incomplete", t("w_arp_incomplete", arp=by_arp, total=total,
                                                     extra=len(found) - by_arp))
    else:
        log(t("probe_start", n=total))
        probe(targets, probe_ports, timeout)

    lacking = [ip for ip, info in found.items() if not info.get("mac") and is_local(ip)]
    if lacking and not (cancel is not None and cancel.is_set()):
        table = read_arp_table()  # probing filled the OS cache: use it to name the devices
        for ip in lacking:
            if table.get(ip):
                found[ip]["mac"] = table[ip]
    progress(total)
    log(t("found", n=len(found)))
    return found
