"""TCP connect scanning, banner grabbing and service detection for one port."""
from __future__ import annotations

import collections

from ..config import DEFAULT_INTENSITY
from ..fingerprint import Probe, detection_fields, identify, port_guess, service_name
from ..fingerprint.base import BudgetExhausted
from ..fingerprint.rules import one_line
from ..log import logger
from ..net import Cancelled, Conn, ScanTimeout, tcp_connect
from .scheduler import Job, Scheduler, is_failure

# ports whose services speak first, and may take a moment to do it
SERVER_FIRST = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 2222, 2323, 3306, 5900, 5901}


def read_banner(conn: Conn, port: int, wait=None, limit: int = 256) -> bytes:
    """What the server says on its own right after the connection (b'' if it stays silent)."""
    wait = wait if wait is not None else (1.5 if port in SERVER_FIRST else 0.5)
    try:
        first = conn.recv(limit, wait)
    except Cancelled:
        raise
    except OSError:  # silence (ScanTimeout) or a reset
        return b""
    if first and len(first) < limit and not first.endswith(b"\n"):
        first += conn.read(limit - len(first), 0.05)
    return first


def scan_port(ip: str, port: int, timeout: float = 0.7, grab: bool = True, cancel=None,
              budget=None, intensity: int = DEFAULT_INTENSITY, diagnostics=None):
    """Try one TCP port. Returns the port record if it is open, else None.

    With `grab` the server's greeting is read and the service is identified
    (product, version, TLS...). Without it the service name is only a guess
    from the port number, and the record says so (`heuristic`).
    """
    if budget is not None and not budget.take():
        return None
    try:
        sock = tcp_connect(ip, port, timeout, cancel)
    except (ConnectionRefusedError, ScanTimeout):
        return None
    except Cancelled:
        raise
    except OSError as exc:
        logger.debug("connect %s:%s failed: %s", ip, port, exc)
        return None
    raw = b""
    with Conn(sock, cancel) as conn:
        if grab:
            raw = read_banner(conn, port)
    record = {"port": port, "proto": "tcp", "state": "open", "service": service_name(port),
              "banner": one_line(raw)}
    found = None
    if grab and intensity > 0:
        try:
            found = identify(Probe(ip, port, max(timeout, 1.0), cancel, budget, raw), intensity, diagnostics)
        except BudgetExhausted:
            if diagnostics is not None:
                diagnostics.warn("budget", "probe budget exhausted during service detection")
    if found is not None:
        record.update(detection_fields(found, port))
        record["banner"] = record.get("banner") or one_line(raw)
    else:
        record.update(detection_fields(port_guess(port), port))
        record.pop("evidence", None)
    return record


def scan_host_ports(ip: str, ports, workers: int = 150, timeout: float = 0.7, grab: bool = True,
                    on_port=None, on_progress=None, cancel=None, budget=None, intensity: int = DEFAULT_INTENSITY,
                    diagnostics=None) -> list:
    """Scan `ports` on one host. Optional hooks: on_port(result) for every open port as it
    is found, on_progress(done, total), and a `cancel` event. Ports are fed to a bounded pool
    lazily, so 65,535 ports never mean 65,535 queued tasks."""
    ports = list(ports)
    found, done = [], 0
    scheduler = Scheduler(workers, cancel=cancel, diagnostics=diagnostics)
    jobs = (Job(ip, lambda p=p: scan_port(ip, p, timeout, grab, cancel, budget, intensity, diagnostics), arg=p)
            for p in ports)
    for _, result in scheduler.results(jobs):
        done += 1
        if not is_failure(result) and result:
            found.append(result)
            if on_port:
                on_port(result)
        if on_progress:
            on_progress(done, len(ports))
    return sorted(found, key=lambda r: r["port"])


def round_robin(iterables):
    """Yield one item from each iterable in turn, so hosts are scanned side by side
    rather than one after another. Uses memory proportional to the number of hosts only."""
    live = collections.deque(iter(i) for i in iterables)
    while live:
        it = live.popleft()
        try:
            item = next(it)
        except StopIteration:
            continue
        live.append(it)
        yield item
