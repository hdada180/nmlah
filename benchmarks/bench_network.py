"""Many-hosts benchmark: 10, 50 and 100 synthetic hosts on loopback (127.0.x.y), some of them broken on purpose.

    python -m benchmarks.bench_network                       # 10, 50 and 100 hosts
    python -m benchmarks.bench_network --hosts 10,50 --threads 400 --json results.json

Every host offers an SSH banner and an HTTP page, and has two closed ports. A handful are not healthy, to prove that
one bad target never stops or spoils the scan:

    reset    accepts, then drops every connection with a TCP reset
    hung     accepts and never says a word (banner grabs and probes have to time out)
    crash    a healthy host whose last step (OS guess and findings) raises an exception
    closed   nothing listens at all

Reported per size: duration, peak memory, connections open at once, the longest scheduler queue, jobs that failed or were
cancelled, how many hosts came back with all their ports, and whether every broken host is accounted for.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from .common import peak_memory_mb, table
from .targets import LocalTarget

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HOSTS = (10, 50, 100)


def address(index: int) -> str:
    return f"127.0.{index // 250 + 1}.{index % 250 + 1}"


def free_ports(count: int) -> list:
    """Ports that nothing listens on right now (they are closed again straight away)."""
    import socket
    socks = []
    for _ in range(count):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def scan_network(hosts: int, threads: int = 400, timeout: float = 0.5, crash_ip=None) -> dict:
    """One scan of `hosts` synthetic hosts. Returns the measurements and the verdicts (see the module text)."""
    import nemla
    from nemla import engine

    ssh_port, http_port, closed_a, closed_b = free_ports(4)
    plan = {}
    with LocalTarget() as target:
        for index in range(hosts):
            ip = address(index)
            kind = {0: "reset", 1: "hung", 2: "crash", 3: "closed"}.get(index, "healthy") if hosts >= 10 else "healthy"
            plan[ip] = kind
            behaviours = {"reset": ("reset", "reset"), "hung": ("silent", "silent"),
                          "closed": (None, None)}.get(kind, ("banner", "http"))
            for port, behaviour in zip((ssh_port, http_port), behaviours):
                if behaviour:
                    target.listen(ip, port, behaviour)
        crash = crash_ip or next((ip for ip, kind in plan.items() if kind == "crash"), None)
        real = engine.assess_host

        def assess(host):
            if host["ip"] == crash:
                raise RuntimeError("injected failure while assessing this host")
            return real(host)

        engine.assess_host = assess
        try:
            started = time.monotonic()
            found, meta = nemla.run_scan("bench-network", list(plan), [ssh_port, http_port, closed_a, closed_b], no_ping=True,
                                         no_os=True, threads=threads, per_host=8, timeout=timeout, intensity=3)
            seconds = time.monotonic() - started
        finally:
            engine.assess_host = real
        by_ip = {h["ip"]: h for h in found}
        ok = [ip for ip, kind in plan.items() if kind == "healthy"]
        stats = meta["scheduler"]
        return {
            "hosts": hosts, "seconds": round(seconds, 2), "peak_memory_mb": peak_memory_mb(), "threads": threads,
            "peak_active_connections": stats.get("peak_inflight", 0), "peak_queue": stats.get("peak_queued", 0),
            "failed_jobs": stats.get("failed", 0), "cancelled_jobs": stats.get("cancelled", 0),
            "target_peak_connections": target.peak,
            "hosts_returned": len(found),
            "healthy_complete": sum(1 for ip in ok if ip in by_ip and len(by_ip[ip]["open_ports"]) == 2),
            "healthy_expected": len(ok),
            "broken_accounted_for": all(ip in by_ip for ip, kind in plan.items() if kind != "healthy"),
            "crash_host_partial": bool(crash and crash in by_ip and by_ip[crash]["findings"] == []
                                       and len(by_ip[crash]["open_ports"]) == 2),
            "warnings": [w["code"] for w in meta["warnings"]],
            "plan": {kind: [ip for ip, k in plan.items() if k == kind] for kind in ("reset", "hung", "crash", "closed")},
        }


def in_fresh_process(hosts: int, threads: int, timeout: float) -> dict:
    command = [sys.executable, "-m", "benchmarks.bench_network", "--worker", str(hosts), "--threads", str(threads),
               "--timeout", str(timeout)]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, encoding="utf-8", errors="replace", timeout=3600, check=False)
    for line in reversed(done.stdout.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise RuntimeError(f"benchmark worker failed ({done.returncode}): {done.stderr[-400:]}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Nemla many-hosts benchmark (loopback only)")
    parser.add_argument("--hosts", default=",".join(map(str, DEFAULT_HOSTS)), help="host counts, comma separated")
    parser.add_argument("--threads", type=int, default=400)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--json", help="also write the results to this file")
    parser.add_argument("--worker", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        print("RESULT " + json.dumps(scan_network(args.worker, args.threads, args.timeout)))
        return 0

    print(f"Python {sys.version.split()[0]} on {sys.platform}, {args.threads} threads, timeout {args.timeout}s\n")
    runs = []
    for count in (int(part) for part in args.hosts.split(",") if part.strip()):
        runs.append(in_fresh_process(count, args.threads, args.timeout))
        print(f"  {count:>4} hosts: {runs[-1]['seconds']}s", flush=True)
    print("\n" + table(runs, [("hosts", "hosts"), ("seconds", "seconds"), ("peak memory MB", "peak_memory_mb"),
                              ("peak connections", "peak_active_connections"), ("peak queue", "peak_queue"),
                              ("failed jobs", "failed_jobs"), ("hosts back", "hosts_returned"),
                              ("healthy complete", "healthy_complete"), ("of", "healthy_expected"),
                              ("broken all reported", "broken_accounted_for"),
                              ("crash host kept its ports", "crash_host_partial")]))
    if args.json:
        report = {"python": sys.version.split()[0], "platform": sys.platform, "runs": runs}
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    bad = [r for r in runs if r["healthy_complete"] != r["healthy_expected"] or not r["broken_accounted_for"]]
    if bad:
        print("\nFAILED: a broken host stopped or spoiled the scan:", bad)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
