"""Port-scan benchmark against a controlled loopback target (never a real or public address).

    python -m benchmarks.bench_scan                            # 100, 1,000, 10,000 and 65,535 ports
    python -m benchmarks.bench_scan --sizes 100,1000 --threads 400 --json results.json
    python -m benchmarks.bench_scan --skip-cancel

For every size it reports the execution time, the peak memory of that scan (each size runs in a fresh process, so
the peak is its own), the most connections open at once (`peak_inflight` of the scheduler, and the same seen from
the target's side), the longest scheduler queue and the number of open ports found (which must equal the number of
listeners: a fast scan that misses ports is not a fast scan). Then it measures how long a cancel takes to stop
a scan: once during a rate-limited scan and once while connections hang on a silent service.

The target is one selector thread serving a few listeners on 127.0.0.1 (benchmarks/targets.py); the other ports
are closed. On Linux a closed loopback port answers at once, on Windows it takes about two seconds, so the big
sizes are much slower there: raise --threads (up to 2000) or expect to wait.
"""
import argparse
import itertools
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from .common import peak_memory_mb, table
from .targets import LocalTarget

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIZES = (100, 1000, 10000, 65535)
OPEN_LISTENERS = 20


def port_list(size: int, open_ports: list) -> list:
    """`size` distinct ports: the open ones plus 1, 2, 3... (skipping any that clash)."""
    ports = set(open_ports)
    candidate = 1
    while len(ports) < size:
        ports.add(candidate)
        candidate += 1
    return sorted(ports)


def scan_once(size: int, threads: int, timeout: float) -> dict:
    import nemla

    with LocalTarget() as target:
        behaviours = itertools.islice(itertools.cycle(("banner", "http", "close")), OPEN_LISTENERS)
        open_ports = [target.listen("127.0.0.1", 0, behaviour) for behaviour in behaviours]
        ports = port_list(size, open_ports)
        started = time.monotonic()
        hosts, meta = nemla.run_scan("bench", ["127.0.0.1"], ports, no_ping=True, no_os=True, threads=threads,
                                     per_host=min(threads, 1000), timeout=timeout)
        seconds = time.monotonic() - started
        found = len(hosts[0]["open_ports"]) if hosts else 0
        return {"ports": len(ports), "seconds": round(seconds, 2), "ports_per_second": round(len(ports) / max(seconds, 1e-9)),
                "peak_memory_mb": peak_memory_mb(), "threads": threads,
                "peak_active_connections": meta["scheduler"].get("peak_inflight", 0),
                "target_peak_connections": target.peak, "peak_queue": meta["scheduler"].get("peak_queued", 0),
                "open_found": found, "open_expected": OPEN_LISTENERS, "probes": meta["probes_used"]}


def cancel_latency(scenario: str, threads: int) -> dict:
    """Seconds between setting the cancel event and the scan returning."""
    import nemla

    cancel = threading.Event()
    mark: dict = {}
    with LocalTarget() as target:
        if scenario == "rate_limited":            # 20,000 ports at 2,000 connections/s would take 10 s: cancel after 1 s
            open_ports = [target.listen("127.0.0.1", 0, "banner") for _ in range(5)]
            ports, options, delay = port_list(20000, open_ports), {"rate": 2000.0, "timeout": 0.5}, 1.0
        else:                                     # "hung": 100 silent services and a 20 s read timeout
            ports = [target.listen("127.0.0.1", 0, "silent") for _ in range(100)]
            options, delay = {"timeout": 20.0}, 1.0

        def stopper():
            time.sleep(delay)
            mark["at"] = time.monotonic()
            cancel.set()

        threading.Thread(target=stopper, daemon=True).start()
        started = time.monotonic()
        _, meta = nemla.run_scan("bench", ["127.0.0.1"], ports, no_ping=True, no_os=True, threads=threads,
                                 per_host=min(threads, 1000), cancel=cancel, **options)
        finished = time.monotonic()
    late = "at" in mark
    return {"scenario": scenario, "cancelled": meta["cancelled"], "ran_seconds": round(finished - started, 2),
            "cancel_latency_s": round(finished - mark["at"], 3) if late else None,
            "connections_open_at_cancel": meta["scheduler"].get("peak_inflight", 0)}


def worker(args) -> None:
    if args.cancel_scenario:
        result = cancel_latency(args.cancel_scenario, args.threads)
    else:
        result = scan_once(args.worker, args.threads, args.timeout)
    print("RESULT " + json.dumps(result))


def in_fresh_process(*extra) -> dict:
    command = [sys.executable, "-m", "benchmarks.bench_scan", *extra]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", errors="replace", timeout=3600, check=False)
    for line in reversed(done.stdout.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError(f"benchmark worker failed ({done.returncode}): {done.stderr[-400:]}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Nemla port-scan benchmark (loopback only)")
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)), help="port counts to scan, comma separated")
    parser.add_argument("--threads", type=int, default=400)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--json", help="also write the results to this file")
    parser.add_argument("--skip-cancel", action="store_true", help="do not measure cancellation latency")
    parser.add_argument("--worker", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--cancel-scenario", choices=("rate_limited", "hung"), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker or args.cancel_scenario:
        worker(args)
        return 0

    sizes = [int(part) for part in args.sizes.split(",") if part.strip()]
    print(f"Python {sys.version.split()[0]} on {sys.platform}, {args.threads} threads, timeout {args.timeout}s\n")
    scans = []
    for size in sizes:
        scans.append(in_fresh_process("--worker", str(size), "--threads", str(args.threads), "--timeout", str(args.timeout)))
        print(f"  {size:>6} ports: {scans[-1]['seconds']}s", flush=True)
    print("\n" + table(scans, [("ports", "ports"), ("seconds", "seconds"), ("ports/s", "ports_per_second"),
                               ("peak memory MB", "peak_memory_mb"), ("peak connections", "peak_active_connections"),
                               ("target peak", "target_peak_connections"), ("peak queue", "peak_queue"),
                               ("open found", "open_found"), ("listeners", "open_expected")]))
    cancels = []
    if not args.skip_cancel:
        for scenario in ("rate_limited", "hung"):
            cancels.append(in_fresh_process("--cancel-scenario", scenario, "--threads", str(args.threads)))
        print("\n" + table(cancels, [("cancel scenario", "scenario"), ("cancelled", "cancelled"), ("ran (s)", "ran_seconds"),
                                     ("cancel latency (s)", "cancel_latency_s"),
                                     ("connections open", "connections_open_at_cancel")]))
    if args.json:
        Path(args.json).write_text(json.dumps({"python": sys.version.split()[0], "platform": sys.platform, "scans": scans,
                                               "cancel": cancels}, indent=2), encoding="utf-8")
    # more than the listeners is fine (the machine's own services on well-known ports), fewer is a missed port
    wrong = [s for s in scans if s["open_found"] < s["open_expected"]]
    if wrong:
        print("\nFAILED: the scan missed open ports:", wrong)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
