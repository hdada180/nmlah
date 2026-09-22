"""The bounded scheduler, cancellation, hostile responses and monotonic clocks."""
import importlib
import socket
import threading
import time
from pathlib import Path

import pytest

import nemla
from nemla import net
from nemla.scanning import scheduler as sched
from nemla.scanning.scheduler import Job, ProbeBudget, RateLimiter, Scheduler

from conftest import wait_until

ROOT = Path(nemla.__file__).resolve().parent
nemla_log = importlib.import_module("nemla.log")   # `nemla.log` itself is the log() function, as in Nemla 1


# --------------------------------------------------------------------------
# bounded submission: 65,535 ports must not mean 65,535 futures
# --------------------------------------------------------------------------

def test_jobs_are_pulled_lazily_and_memory_stays_bounded():
    pulled = [0]
    peak_ahead = [0]

    def source():
        for i in range(65535):
            pulled[0] += 1
            yield Job("h", lambda: None, arg=i)

    scheduler = Scheduler(workers=8, per_key=8)
    finished = 0
    for _ in scheduler.results(source()):
        finished += 1
        peak_ahead[0] = max(peak_ahead[0], pulled[0] - finished)
    assert finished == 65535
    assert peak_ahead[0] <= 8 + scheduler.window + 8      # workers + the small look-ahead window


def test_workers_never_exceed_the_global_limit():
    lock, active, peak = threading.Lock(), [0], [0]

    def work():
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.01)
        with lock:
            active[0] -= 1

    jobs = (Job(i % 5, work) for i in range(120))
    done = sum(1 for _ in Scheduler(workers=6, per_key=6).results(jobs))
    assert done == 120 and peak[0] <= 6


def test_per_host_limit_is_enforced_even_with_a_single_host():
    lock, active, peak = threading.Lock(), {"a": 0, "b": 0}, {"a": 0, "b": 0}

    def work(key):
        def run():
            with lock:
                active[key] += 1
                peak[key] = max(peak[key], active[key])
            time.sleep(0.01)
            with lock:
                active[key] -= 1
        return run

    jobs = [Job("a", work("a")) for _ in range(40)] + [Job("b", work("b")) for _ in range(40)]
    for _ in Scheduler(workers=20, per_key=3).results(jobs):
        pass
    assert peak["a"] <= 3 and peak["b"] <= 3 and peak["a"] >= 1


def test_a_busy_host_does_not_starve_the_others():
    order = []
    jobs = [Job("slow", lambda: (time.sleep(0.05), order.append("slow"))) for _ in range(6)]
    jobs += [Job("fast", lambda: order.append("fast")) for _ in range(6)]
    list(Scheduler(workers=4, per_key=1).results(jobs))
    assert order.index("fast") < len(order) - 1 and "fast" in order[:6]


def test_scan_host_ports_reports_progress_and_open_ports_in_order(tcp_server, closed_port):
    """scan_host_ports itself - the single-host convenience wrapper other code calls the scheduler directly
    instead of - was only ever referenced by a public-names test, never actually called."""
    from nemla.scanning.tcp import scan_host_ports
    first = tcp_server(lambda c: c.close())
    second = tcp_server(lambda c: (c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n"), c.close()))
    ports = sorted([closed_port, second, first])          # deliberately out of "open" order
    seen_ports, progress = [], []
    found = scan_host_ports("127.0.0.1", ports, workers=4, timeout=0.4, grab=True,
                            on_port=lambda r: seen_ports.append(r["port"]),
                            on_progress=lambda done, total: progress.append((done, total)))
    assert [r["port"] for r in found] == sorted([first, second])       # open only, sorted by port number
    assert sorted(seen_ports) == sorted([first, second])
    assert progress[-1] == (len(ports), len(ports)) and len(progress) == len(ports)


def test_a_failing_job_never_stops_the_scan_and_is_counted():
    diagnostics = nemla.Diagnostics()

    def boom():
        raise RuntimeError("hostile banner crashed the parser")

    jobs = [Job("h", boom), Job("h", lambda: 42), Job("h", boom)]
    results = [r for _, r in Scheduler(2, diagnostics=diagnostics).results(jobs)]
    assert 42 in results and sum(sched.is_failure(r) for r in results) == 2
    assert diagnostics.as_list()[0]["code"] == "job_error" and diagnostics.as_list()[0]["count"] == 2


def test_follow_up_jobs_run_before_the_rest():
    scheduler = Scheduler(workers=1)
    seen = []

    def gen():
        for i in range(3):
            yield Job("h", lambda i=i: seen.append(("main", i)), arg=i)

    for job, _ in scheduler.results(gen()):
        if job.arg == 0:
            scheduler.add(Job("h", lambda: seen.append(("follow", 0))))
    assert ("follow", 0) in seen and seen.index(("follow", 0)) == 1


def test_imap_is_a_bounded_generator_and_skips_failures():
    def half(n):
        if n == 3:
            raise ValueError
        return n * 2
    assert dict(sched.imap(half, range(6), 3)) == {0: 0, 1: 2, 2: 4, 4: 8, 5: 10}


# --------------------------------------------------------------------------
# cancellation
# --------------------------------------------------------------------------

def test_cancel_stops_sleeping_jobs_within_a_fraction_of_a_second():
    cancel = threading.Event()

    def sleeper():
        net.sleep_cancellable(30, cancel)

    threading.Timer(0.2, cancel.set).start()
    started = time.monotonic()
    list(Scheduler(4, cancel=cancel).results(Job("h", sleeper) for _ in range(500)))
    assert time.monotonic() - started < 2.0


def test_cancel_interrupts_a_connection_that_never_completes():
    """wait_io polls the cancel event every SLICE, whatever the socket is doing."""
    a, b = socket.socketpair()
    cancel = threading.Event()
    threading.Timer(0.15, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(net.Cancelled):
        net.wait_io(a, True, False, time.monotonic() + 30, cancel)
    assert time.monotonic() - started < 1.0
    a.close()
    b.close()


def test_silent_server_read_is_bounded_by_the_deadline(tcp_server):
    port = tcp_server(lambda conn: time.sleep(5))           # accepts, never speaks
    conn = net.open_conn("127.0.0.1", port, 1.0)
    started = time.monotonic()
    with pytest.raises(net.ScanTimeout):
        conn.recv(10, 0.3)
    assert time.monotonic() - started < 1.0
    assert conn.read(10, 0.2) == b""
    conn.close()


def test_engine_scan_can_be_cancelled_mid_flight(tcp_server):
    ports = [tcp_server(lambda conn: time.sleep(5)) for _ in range(6)]   # every port accepts and stalls
    cancel = threading.Event()
    result = {}

    def run():
        result["out"] = nemla.run_scan("127.0.0.1", ["127.0.0.1"], ports, no_ping=True, no_os=True,
                                       threads=6, timeout=1.0, cancel=cancel)

    thread = threading.Thread(target=run)
    thread.start()
    time.sleep(0.4)
    started = time.monotonic()
    cancel.set()
    thread.join(5)
    assert not thread.is_alive() and time.monotonic() - started < 3.0
    hosts, meta = result["out"]
    assert meta["cancelled"] is True and hosts == []            # a half-scanned host proves nothing


# --------------------------------------------------------------------------
# rate limit and probe budget
# --------------------------------------------------------------------------

def test_rate_limiter_paces_acquisitions():
    limiter = RateLimiter(50, burst=1)
    started = time.monotonic()
    for _ in range(11):
        assert limiter.acquire()
    elapsed = time.monotonic() - started
    assert 0.15 <= elapsed < 1.5                                # ~10 waits of 20 ms
    assert RateLimiter(0).acquire() is True                     # zero means unlimited


def test_rate_limiter_stops_waiting_when_cancelled():
    limiter = RateLimiter(0.5, burst=1)
    limiter.acquire()
    cancel = threading.Event()
    threading.Timer(0.1, cancel.set).start()
    started = time.monotonic()
    assert limiter.acquire(cancel) is False
    assert time.monotonic() - started < 1.0


def test_probe_budget_is_a_hard_cap(tcp_server, closed_port):
    port = tcp_server(lambda conn: conn.close())
    budget = ProbeBudget(3)
    found = [nemla.scan_port("127.0.0.1", port, 0.5, grab=False, budget=budget) for _ in range(6)]
    assert sum(r is not None for r in found) == 3
    assert budget.used == 3 and budget.exhausted


def test_engine_reports_an_exhausted_budget_as_a_warning(tcp_server):
    ports = [tcp_server(lambda conn: conn.close()) for _ in range(5)]
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], ports, no_ping=True, no_os=True, no_banner=True,
                                 max_probes=2, timeout=0.5)
    assert meta["probes_used"] == 2
    assert any(w["code"] == "budget" for w in meta["warnings"])
    assert sum(len(h["open_ports"]) for h in hosts) == 2


def test_engine_rate_limit_slows_the_scan(tcp_server):
    ports = [tcp_server(lambda conn: conn.close()) for _ in range(8)]
    started = time.monotonic()
    nemla.run_scan("127.0.0.1", ["127.0.0.1"], ports, no_ping=True, no_os=True, no_banner=True,
                   rate=20, timeout=0.5)
    assert time.monotonic() - started >= 0.25                   # 8 attempts at 20/s


# --------------------------------------------------------------------------
# hostile responses: size, time, control characters
# --------------------------------------------------------------------------

def test_a_server_that_never_stops_sending_is_cut_off_by_size(tcp_server):
    def flood(conn):
        try:
            while True:
                conn.sendall(b"A" * 65536)
        except OSError:
            pass

    port = tcp_server(flood)
    conn = net.open_conn("127.0.0.1", port, 1.0)
    data = conn.read(limit=10 ** 9, timeout=2.0)                # the caller asks for far too much
    assert len(data) <= conn.max_bytes == 64 * 1024
    assert conn.received <= conn.max_bytes
    conn.close()


def test_a_slow_drip_server_is_cut_off_by_time(tcp_server):
    def drip(conn):
        try:
            for _ in range(200):
                conn.sendall(b"x")
                time.sleep(0.05)
        except OSError:
            pass

    port = tcp_server(drip)
    conn = net.open_conn("127.0.0.1", port, 1.0)
    started = time.monotonic()
    data = conn.read(limit=10_000, timeout=0.5)
    assert time.monotonic() - started < 1.5 and 1 <= len(data) < 100
    conn.close()


def test_detection_survives_a_malicious_http_server(tcp_server):
    def evil(conn):
        conn.recv(4096)
        headers = b"".join(b"X-%d: %s\r\n" % (i, b"A" * 500) for i in range(5000))
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nServer: \x1b[31mnginx\x1b]0;pwned\x07/1.2 \xe2\x80\xaeevil\r\n"
                         + headers + b"\r\n<title>" + b"T" * 100000 + b"</title>")
        except OSError:
            pass
        conn.close()

    port = tcp_server(evil)
    started = time.monotonic()
    info = nemla.detect_service("127.0.0.1", port, b"", "", 1.0)
    assert time.monotonic() - started < 5
    text = " ".join(str(v) for v in info.values())
    assert "\x1b" not in text and "\x07" not in text and "\u202e" not in text
    assert len(info.get("title", "")) <= 80 and len(info.get("banner", "")) <= 120


def test_clean_text_removes_terminal_escapes_and_bidi_tricks():
    dirty = "ok\x1b[31mred\x1b[0m\x07\r\nnew\u202eline\u2066x\x00"
    cleaned = net.clean_text(dirty)
    assert all(ch.isprintable() for ch in cleaned) and cleaned.startswith("ok") and cleaned.endswith("x")
    assert "\x1b" not in cleaned and "\u202e" not in cleaned and "\n" not in cleaned
    assert len(net.clean_text("a" * 1000, 50)) == 50
    assert net.clean_text(b"\xff\xfeabc") .endswith("abc")


def test_log_lines_cannot_carry_terminal_escapes(capsys):
    nemla.log("banner said \x1b[2J\x1b]0;evil\x07 hello\r\nfake line")
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and out.count("\n") == 1


def test_log_survives_a_console_that_refuses_to_print(monkeypatch):
    """The desktop launcher runs with no console at all on some platforms: log() must not crash the scan over it."""
    import builtins

    def refuses(*a, **k):
        raise OSError("no console")
    monkeypatch.setattr(builtins, "print", refuses)
    nemla.log("this must not raise")             # no assertion needed beyond "did not raise"


def test_enable_debug_sends_the_debug_log_to_stderr_exactly_once(capsys):
    for handler in list(nemla_log.logger.handlers):
        if getattr(handler, "_nemla_debug", False):
            nemla_log.logger.removeHandler(handler)
    saved_level = nemla_log.logger.level
    try:
        nemla_log.enable_debug()
        nemla_log.enable_debug()                 # calling it again must not add a second handler
        debug_handlers = [h for h in nemla_log.logger.handlers if getattr(h, "_nemla_debug", False)]
        assert len(debug_handlers) == 1 and nemla_log.logger.level == nemla_log.logging.DEBUG
        nemla_log.logger.debug("a debug line")
        assert "a debug line" in capsys.readouterr().err
    finally:
        for handler in list(nemla_log.logger.handlers):
            if getattr(handler, "_nemla_debug", False):
                nemla_log.logger.removeHandler(handler)
        nemla_log.logger.setLevel(saved_level)


# --------------------------------------------------------------------------
# time.monotonic for every timeout, diagnostics instead of silent excepts
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["net.py", "scanning/scheduler.py", "scanning/tcp.py", "scanning/udp.py",
                                  "discovery/__init__.py", "discovery/arp.py", "discovery/ping.py", "engine.py",
                                  "fingerprint/base.py"])
def test_timeouts_use_the_monotonic_clock(path):
    source = (ROOT / path).read_text(encoding="utf-8")
    assert "time.time()" not in source, f"{path} must use time.monotonic() for timeouts"


def test_no_silent_exception_swallowing_left():
    offenders = []
    for path in [*ROOT.rglob("*.py"), ROOT.parent / "nemla_ui" / "server.py"]:
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith("except Exception") and i + 1 < len(lines) and lines[i + 1].strip() == "pass":
                offenders.append(f"{path.name}:{i + 1}")
    assert offenders == []


def test_diagnostics_dedupe_and_cap():
    d = nemla_log.Diagnostics(limit=3)
    for _ in range(5):
        d.warn("a", "same")
    for i in range(10):
        d.warn("b", f"different {i}")
    items = d.as_list()
    assert len(items) == 3 and items[0]["count"] == 5 and len(d) >= 5


def test_a_detector_that_crashes_is_reported_not_raised(tcp_server, monkeypatch):
    from nemla.fingerprint import REGISTRY, http

    def broken(self, probe):
        raise ZeroDivisionError

    monkeypatch.setattr(http.Http, "probe", broken)
    port = tcp_server(lambda conn: conn.close())
    diagnostics = nemla.Diagnostics()
    assert nemla.detect_service("127.0.0.1", port, b"", "", 0.5, diagnostics=diagnostics) is not None
    assert any(w["code"] == "detector_error" and "http" in w["message"] for w in diagnostics.as_list())
    assert REGISTRY
    assert wait_until(lambda: True)
