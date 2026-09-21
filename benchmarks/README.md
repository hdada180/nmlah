# Benchmarks

Reproducible, dependency-free, and **loopback only**: the target is a few sockets served by one selector thread
(`benchmarks/targets.py`), never a real or public address.

```bash
python -m benchmarks.bench_scan                                  # 100, 1,000, 10,000, 65,535 ports; then two cancellation scenarios
python -m benchmarks.bench_scan --sizes 100,1000 --threads 400 --json results.json
python -m benchmarks.bench_network                               # 10, 50, 100 hosts (127.0.x.y), some broken on purpose
```

Each size runs in a fresh process, so **peak memory** (resident set: `ru_maxrss` on Linux/macOS, `PeakWorkingSetSize` on Windows) is
that scan's own.

| column | meaning |
|---|---|
| seconds / ports per second | wall-clock time of `run_scan` |
| peak connections | most jobs in flight at once (`Scheduler.stats["peak_inflight"]`): open connection attempts |
| target peak | the most connections the target had open at once (only open ports count: closed ports are refused) |
| peak queue | longest waiting line: jobs pulled from the source but held back by a busy host (`peak_queued`) |
| open found / listeners | must be at least the number of listeners; more is the machine's own services |
| cancel latency | seconds from `cancel.set()` to `run_scan` returning, during a rate-limited scan and while connections hang on a silent service |

`bench_network` scans 10 / 50 / 100 hosts that each offer an SSH banner and an HTTP page and have two closed ports; four are broken:
one resets every connection, one accepts and says nothing, one crashes in its last step (OS guess and findings), one has nothing
listening. It reports how many healthy hosts came back complete and whether every broken host is still accounted for; the exit code
is non-zero if not.

Notes for reading the numbers: on Linux a closed loopback port answers at once; on Windows it takes about two seconds, so the large
sizes are slower there unless you raise `--threads` (at most 2,000). The CI `benchmark` job runs both scripts on Ubuntu, publishes
the tables in the job summary, uploads the JSON, and fails on gross regressions (65,535 ports under 120 s, under 400 MB, a cancel
under a second, no healthy host lost). Results are machine-specific and are not committed (`benchmarks/results/` is ignored).

## What the benchmarks found (and what was done)

* Compared with 1.2.0 on the same machine and target, **port scanning itself is not slower** (1,000 ports, banners off: 0.67 s vs 0.68 s).
  A default 2.0 scan of 1,000 ports took 7.6 s against 0.68 s because service identification (new in 2.0) asks silent open ports a dozen
  protocol questions, one timeout each: 12 probes = 6 s on one silent port. Identification now gives up on a port that ignored four
  general-purpose probes (about 3 s), except at intensity 7+; the detectors that belong to the port always run first.
* A reply that merely starts with `S` or `N` (an `SSH-2.0-...` banner) was identified as PostgreSQL. PostgreSQL answers the SSL request
  with exactly one byte; the detector now requires that.
* A host whose last step failed used to vanish from the report; it now keeps its open ports and a `host_incomplete` warning.
