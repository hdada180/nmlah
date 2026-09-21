"""The scan pipeline, shared by the command line and the 3D interface.

    Targets -> Discovery -> bounded scheduler -> TCP / UDP scanning
            -> service fingerprinting -> OS fingerprinting -> findings

Every open-port probe, UDP probe and per-host wrap-up is a job on one
scheduler, so there is a single global concurrency limit, a per-host limit,
an optional rate limit and probe budget, and one cancel event that stops
everything within a fraction of a second. Hosts are scanned side by side
(one job from each host in turn) and each host is wrapped up as soon as its
own jobs are done, so results stream out instead of arriving at the end.
"""
from __future__ import annotations

import functools
import socket
import sys
import threading
import time
import uuid
from datetime import datetime

from .config import DISCOVERY_PORTS, ScanOptions, __version__
from .discovery import discover_hosts, get_ttl, mac_vendor
from .discovery.arp import HAVE_SCAPY
from .findings import assess_host, summarize_findings
from .i18n import current_lang, t, use_lang
from .log import Diagnostics, log, logger
from .net import ip_sort_key
from .os_detection import OSGuess, guess_os_detailed, os_display, syn_fingerprint
from .scanning.scheduler import Job, ProbeBudget, RateLimiter, Scheduler, is_failure
from .scanning.tcp import round_robin, scan_port
from .scanning.udp import scan_udp_port
from .targets import format_ports

PROGRESS_INTERVAL = 0.1   # seconds between progress events (keeps the event stream light)


class _HostState:
    """What the dispatcher knows about one host while its jobs are running."""

    def __init__(self, ip: str, info: dict, remaining: int):
        self.ip, self.info, self.remaining = ip, info, remaining
        self.tcp, self.udp = [], []
        self.finalizing = False


def run_scan(target: str, ips, ports: list, *, no_ping: bool = False, no_os: bool = False,
             no_banner: bool = False, threads: int = 150, timeout: float = 0.7, emit=None, cancel=None,
             per_host: int = 100, rate: float = 0.0, max_probes: int = 0, intensity: int = 5,
             udp_ports=(), udp_timeout: float = 1.0, udp_rate: float = 200.0, lang=None,
             diagnostics=None):
    """Discover hosts, scan their ports, fingerprint services and OS, assess findings.

    Returns (hosts, meta). `emit(event: dict)` receives live progress events (phase,
    progress, host, host_start, port, host_done) and `cancel` is a threading.Event that
    stops the scan early. `meta["discovered"]` is the number of live hosts found.
    """
    options = ScanOptions.checked(
        no_ping=no_ping, no_os=no_os, no_banner=no_banner, threads=threads, timeout=timeout, per_host=per_host,
        rate=rate, max_probes=max_probes, intensity=intensity, udp_ports=tuple(udp_ports or ()),
        udp_timeout=udp_timeout, udp_rate=udp_rate, lang=lang or current_lang())
    with use_lang(options.lang):
        return _run(target, ips, list(ports), options, emit, cancel, diagnostics)


def _run(target, ips, ports, opts: ScanOptions, emit, cancel, diagnostics):
    def send(event):
        if emit is not None:
            emit(event)

    cancel = cancel if cancel is not None else threading.Event()
    diagnostics = diagnostics if diagnostics is not None else Diagnostics()
    budget = ProbeBudget(opts.max_probes)
    started = time.monotonic()
    total_addresses = len(ips) if hasattr(ips, "__len__") else sum(1 for _ in ips)
    logger.debug("scan %s: %d address(es), %d TCP port(s), %d UDP port(s), threads=%d per_host=%d timeout=%s intensity=%d",
                 target, total_addresses, len(ports), len(opts.udp_ports), opts.threads, opts.per_host, opts.timeout,
                 opts.intensity)

    # -- discovery ------------------------------------------------------------
    send({"type": "phase", "phase": "discovery", "total": total_addresses})
    if opts.no_ping:
        log(t("skip_discovery", n=total_addresses))
        hosts_map = {ip: {"mac": None, "method": "skipped"} for ip in ips}
        for ip, info in hosts_map.items():
            send({"type": "host", "ip": ip, "mac": None, "method": info["method"]})
    else:
        probe_ports = sorted(set(DISCOVERY_PORTS) | set(ports[:15]))
        last = [0.0]

        def on_progress(done, total):
            now = time.monotonic()
            if done >= total or now - last[0] >= PROGRESS_INTERVAL:
                last[0] = now
                send({"type": "progress", "phase": "discovery", "done": done, "total": total})

        hosts_map = discover_hosts(
            ips, workers=opts.threads, probe_ports=probe_ports, cancel=cancel, on_progress=on_progress,
            diagnostics=diagnostics, timeout=min(opts.timeout, 0.8),
            on_host=lambda ip, info: send({"type": "host", "ip": ip, "mac": info.get("mac"),
                                           "method": info.get("method")}))

    # -- scanning ---------------------------------------------------------------
    hosts = []
    if not hosts_map:
        log(t("no_hosts"))
    elif not cancel.is_set():
        try:
            hosts = _scan_hosts(hosts_map, ports, opts, budget, cancel, diagnostics, send)
        except KeyboardInterrupt:
            cancel.set()
            log(t("interrupted"))

    logger.debug("scan %s finished: %d host(s) found, %d probe(s) used, cancelled=%s", target, len(hosts_map),
                 budget.used, cancel.is_set())
    if budget.exhausted:
        log(t("budget_hit"))
        diagnostics.warn("budget", f"probe budget of {opts.max_probes} reached; results are incomplete")
    hosts.sort(key=lambda h: ip_sort_key(h["ip"]))
    meta = {
        "scan_id": str(uuid.uuid4()),
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": time.monotonic() - started,
        "ports_scanned": len(ports),
        "udp_ports_scanned": len(opts.udp_ports),
        "discovered": len(hosts_map),
        "cancelled": cancel.is_set(),
        "findings": summarize_findings(hosts),
        "warnings": diagnostics.as_list(),
        "probes_used": budget.used,
        "options": {"threads": opts.threads, "per_host": opts.per_host, "timeout": opts.timeout,
                    "rate": opts.rate, "max_probes": opts.max_probes, "intensity": opts.intensity,
                    "no_ping": opts.no_ping, "no_os": opts.no_os, "no_banner": opts.no_banner,
                    "udp": bool(opts.udp_ports), "udp_timeout": opts.udp_timeout, "udp_rate": opts.udp_rate},
        "capabilities": {"scapy": bool(HAVE_SCAPY), "ipv6": bool(socket.has_ipv6), "platform": sys.platform,
                         "version": __version__},
    }
    return hosts, meta


def _scan_hosts(hosts_map: dict, ports: list, opts: ScanOptions, budget, cancel, diagnostics, send) -> list:
    order = sorted(hosts_map, key=ip_sort_key)
    per_host_jobs = len(ports) + len(opts.udp_ports)
    log(t("port_count", n=len(ports)))
    if opts.udp_ports:
        log(t("udp_start", n=len(opts.udp_ports), rate=f"{opts.udp_rate:g}"))
    send({"type": "phase", "phase": "ports", "total": len(order), "ports": len(ports)})

    scheduler = Scheduler(opts.threads, per_key=opts.per_host, cancel=cancel, diagnostics=diagnostics)
    tcp_limiter = RateLimiter(opts.rate) if opts.rate else None
    udp_limiter = RateLimiter(opts.udp_rate)
    states = {ip: _HostState(ip, hosts_map[ip], per_host_jobs) for ip in order}
    started_hosts = [0]
    total_jobs = len(order) * per_host_jobs
    progress = {"done": 0, "last": 0.0}

    def host_jobs(ip):
        started_hosts[0] += 1
        log(t("scanning", ip=ip))
        send({"type": "host_start", "ip": ip, "index": started_hosts[0], "total": len(order)})
        for port in ports:
            yield Job(ip, functools.partial(scan_port, ip, port, opts.timeout, not opts.no_banner, cancel,
                                            budget, opts.intensity, diagnostics),
                      arg=port, kind="tcp", limiter=tcp_limiter)
        for port in opts.udp_ports:
            yield Job(ip, functools.partial(scan_udp_port, ip, port, opts.udp_timeout, cancel, budget, 1, diagnostics),
                      arg=port, kind="udp", limiter=udp_limiter)

    def finalize(state: _HostState):
        ttl = None
        if opts.no_os:
            guess, text = OSGuess(), t("os_skipped")
        else:
            ttl = get_ttl(state.ip, cancel)
            syn = syn_fingerprint(state.ip, state.tcp[0]["port"], opts.timeout) if state.tcp else None
            vendor = mac_vendor(state.info.get("mac"))
            guess = guess_os_detailed(ttl, state.tcp + state.udp, syn, vendor)
            text = os_display(guess, ttl)
        host = {
            "ip": state.ip, "mac": state.info.get("mac"), "discovery": state.info.get("method"),
            "os_guess": text, "ttl": ttl, "os": guess.as_dict(),
            "open_ports": sorted(state.tcp + [p for p in state.udp if p["state"] == "open"],
                                 key=lambda p: (p["proto"] != "tcp", p["port"])),
            "udp_unconfirmed": [{"port": p["port"], "state": p["state"]} for p in state.udp if p["state"] != "open"],
            "scanned": {"tcp": format_ports(ports), "udp": format_ports(opts.udp_ports)},
            "vendor": mac_vendor(state.info.get("mac")),
        }
        host["findings"] = assess_host(host)
        return host

    def bump():
        progress["done"] += 1
        now = time.monotonic()
        if progress["done"] >= total_jobs or now - progress["last"] >= PROGRESS_INTERVAL:
            progress["last"] = now
            send({"type": "progress", "phase": "ports", "done": progress["done"], "total": total_jobs})

    finished = []
    jobs = round_robin(host_jobs(ip) for ip in order)
    for job, result in scheduler.results(jobs):
        state = states[job.key]
        if job.kind == "final":
            if not is_failure(result):
                finished.append(result)
                send({"type": "host_done", "host": result})
                log(t("host_done", n=len(result["open_ports"]), os=result["os_guess"]))
            continue
        bump()
        if not is_failure(result) and result:
            (state.tcp if job.kind == "tcp" else state.udp).append(result)
            if result["state"] == "open":
                send({"type": "port", "ip": state.ip, **result})
        state.remaining -= 1
        if state.remaining == 0 and not state.finalizing and not cancel.is_set():
            state.finalizing = True
            scheduler.add(Job(state.ip, functools.partial(finalize, state), kind="final"))
    return finished
