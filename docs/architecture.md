# Nemla architecture

Nemla 2 is a package (`nemla/`) with one module per job, plus the local web interface (`nemla_ui/`). `nemla.py` in the repository root is only a launcher, and `nemla/__init__.py` re-exports the names the old single file had, so `import nemla; nemla.parse_targets(...)` keeps working.

```
                +-----------+        +-------------+        +-------------------------+
 -t 10.0.0.0/24 | targets   |  ips   | discovery/  | hosts  | scanning/scheduler      |
 -p 1-1024  --> | (lazy     | -----> | arp, ping   | -----> | global + per-host limits|
 --udp          |  spans)   |        | + fallback  |        | rate limit, budget      |
                +-----------+        +-------------+        +-----------+-------------+
                                                                        | jobs
                        +-----------------------------+-----------------+----------------+
                        | scanning/tcp   scanning/udp |                                  |
                        |   connect, banner           |  one job per (host, port)        |
                        +--------------+--------------+                                  |
                                       | open port                                       |
                                 +-----v------+   +---------------+   +---------+   +----v-----+
                                 | fingerprint|-->| os_detection  |-->| findings|-->| reports/ |
                                 | plugins    |   | (per host)    |   | + i18n  |   | history  |
                                 +------------+   +---------------+   +---------+   +----------+
```

`engine.run_scan()` ties the stages together for the command line and the interface. Each host is finished (OS guess, findings, `host_done` event) as soon as its own jobs are done, so results stream out while other hosts are still being scanned.

## Modules

| Module | Responsibility |
| --- | --- |
| `config.py` | Constants, hard limits, `ScanOptions.checked()` (every user-supplied number is validated here) |
| `net.py` | Cancellable connects, bounded reads (`Conn`), UDP exchange, address helpers (`is_external`, zones), `clean_text` |
| `targets.py` | Target and port expressions to lazy `TargetSet` spans (IPv4/IPv6), `format_ports` |
| `discovery/` | `arp.py` (Scapy or the neighbour cache, adaptive settle), `ping.py` (ICMP through the OS, TCP), `mac.py`, and `discover_hosts` with the ARP-then-fallback logic |
| `scanning/scheduler.py` | `Scheduler` (bounded, fair, cancellable), `RateLimiter`, `ProbeBudget` |
| `scanning/tcp.py`, `udp.py` | One port: connect + banner + identify; one UDP port with its probe and state |
| `fingerprint/` | `base.py` (`Detector`, `Detection`, `Probe`), one module per protocol, `tls.py`, `x509.py` (own DER reader), `rules.py` (banner signatures), `__init__.py` (`identify`) |
| `os_detection.py` | Weighted votes from TTL, SYN-ACK shape, banners, ports, protocol facts, NIC maker |
| `findings.py` | Evidence-based findings and their localisation |
| `reports/` | `html.py`, `data.py` (JSON, CSV), `markdown.py`, `sarif.py`, `common.py` (escaping) |
| `history.py`, `diff.py` | Saved scans (UUID ids, atomic private files) and comparison |
| `guard.py` | Decoy ports, unknown devices, ARP changes with confidence and evidence |
| `i18n.py`, `_strings_base.py`, `strings_extra.py` | English, Arabic and Hebrew texts, the language of the current thread |
| `log.py` | Console output, debug logging, `Diagnostics` (non-fatal problems that end up in the report) |
| `cli.py`, `main.py`, `__main__.py` | Argument parsing and commands (`--diff`, `--watch`, `--guard`, ...) |

## The scheduler

`Scheduler.results(jobs)` is a generator. It pulls jobs from an iterable **only as workers free up** (plus a small look-ahead window), so 65,535 ports on thousands of hosts never become 65,535 futures. It enforces:

- a **global** limit (`--threads`) and a **per-key** limit (`--per-host`, the key is the host);
- an optional **rate limiter** (token bucket) carried by a job, for TCP attempts and UDP packets;
- a **probe budget** (`ProbeBudget`) that scanning and detection both charge;
- **cancellation**: nothing new starts once the event is set, and running jobs poll it through the cancellable helpers in `net.py` (every wait is a `select` of 0.1 s), so Stop and Ctrl+C take effect almost immediately;
- **failure isolation**: a job that raises is counted in `Diagnostics` and yields a `JobFailed`; the scan goes on.

Jobs of different hosts are interleaved (`round_robin`), and the consumer can add follow-up jobs (`Scheduler.add`); the engine uses that to run each host's wrap-up job when its last port job is done.

## Data model

A scan returns `(hosts, meta)`.

```jsonc
// host
{ "ip": "10.0.0.5", "mac": "...", "vendor": "...", "discovery": "ARP",
  "os_guess": "Ubuntu Linux (TTL=64)",                 // 1.x text, kept
  "os": { "family": "linux", "name": "Ubuntu Linux", "confidence": 0.74, "label": "high",
          "heuristic": false, "evidence": ["TTL 64 (started at 64): Unix-like", "SSH on port 22 names Ubuntu Linux"] },
  "ttl": 64,
  "open_ports": [ { "port": 22, "proto": "tcp", "state": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_9.6p1 ...",
                    "detected": "ssh", "product": "OpenSSH", "version": "9.6p1",
                    "confidence": 0.95, "heuristic": false, "method": "banner", "evidence": "...",
                    "os_hint": "Ubuntu Linux", "details": { "protocol": "2.0", "weak_algorithms": [] } } ],
  "udp_unconfirmed": [ { "port": 123, "state": "open|filtered" } ],
  "scanned": { "tcp": "1-1024", "udp": "53,123" },      // what was actually looked at
  "findings": [ { "id": "redis_open", "severity": "high", "title": "...", "description": "...", "evidence": "...",
                  "host": "10.0.0.5", "port": 6379, "proto": "tcp", "remediation": "...", "confidence": 0.97, "params": {} } ] }

// meta
{ "scan_id": "<uuid4>", "target": "...", "scan_time": "...", "duration": 3.2, "ports_scanned": 1024,
  "udp_ports_scanned": 2, "discovered": 12, "cancelled": false, "findings": { "high": 1, "medium": 2, "low": 0, "info": 5 },
  "warnings": [ { "code": "arp_incomplete", "message": "...", "count": 1 } ], "options": { ... }, "capabilities": { ... } }
```

`method` is `banner` (the server named itself), `protocol` (a well-formed protocol reply) or `port` (the port number only, always `heuristic: true`). Records from older scans lack `detected`, `confidence` and `proto`; every consumer treats missing fields as "TCP, identified by port".

Events for the interface (`emit`): `phase`, `progress`, `host`, `host_start`, `port`, `host_done`, `log`, `done`, `error`.

## Adding a protocol (a detector plugin)

Create `nemla/fingerprint/myproto.py`:

```python
from ..net import clean_text
from .base import CONFIDENCE, Detection, Detector, Probe, register


@register
class MyProto(Detector):
    name = "myproto"          # canonical key stored in the port record (`detected`)
    label = "MyProto"         # what the UI shows
    ports = (7777,)           # probed first on these ports
    rarity = 4                # 1 = always try ... 9 = only at --intensity 9 on other ports
    tls_capable = False       # True if it may run inside a TLS tunnel

    def passive(self, probe: Probe):
        """Recognise a greeting the server sent on its own (probe.banner). Return a Detection or None."""

    def probe(self, probe: Probe):
        """Ask one harmless question. Use probe.ask(b"...") or `with probe.connect() as conn:`."""
        reply = probe.ask(b"HELLO\r\n")
        if not reply.startswith(b"MYPROTO "):
            return None
        version = clean_text(reply[8:20], 20)
        return Detection("myproto", "MyProto", "MyProto", version, CONFIDENCE["exact"], "protocol",
                         "answered HELLO", "MYPROTO " + version, "", False, {"some_fact": True})

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        """Optional: learn more once `passive` recognised the service."""
        return detection
```

Then add `myproto` to the import line in `fingerprint/__init__.py`. Rules for detectors: send only harmless questions (never log in, never change state); read through `probe.ask`/`probe.connect()` (they are budgeted, cancellable and size-capped); pass every string from the network through `clean_text`; keep confidence honest (`CONFIDENCE["port"]` is for guesses). A detector that raises is caught, counted in the warnings and never stops the scan. Test it with a throw-away server (see `tests/test_fingerprint.py`).

## Adding a finding

1. Raise it in `findings.assess_host` from **observed** facts (`details`, `tls`, `auth`...). Pass `evidence` (what was seen) and `confidence`. Use `_sev(base, confidence)` when the fact may rest on a port number alone.
2. Add three texts to `strings_extra.py` for every language: `f_<id>` (the title, may use `{port}` and your params), `fd_<id>` (why it matters), `fr_<id>` (what to do). A test refuses missing or mismatching translations. The interface picks them up through `/api/strings`.
3. Add a test that shows the finding appears with the evidence and does **not** appear without it.

## Internationalisation

`i18n.t(key, lang=None, **values)` looks in the language of the current thread (`use_lang`, a `contextvars` value set by `run_scan(lang=...)`), then the process default (`--lang`), then English. Nothing switches a global while a scan runs, so a report in Hebrew can be rendered while a scan in Arabic is running. Reports take `lang=` explicitly. `nemla._LANG = "ar"` still works through a property on the package.

## Security invariants

These hold everywhere and are tested (`tests/test_scheduler_and_net.py`, `test_guard_discovery_hardening.py`, `test_server_security.py`, `test_reports_and_findings.py`):

1. Every timeout uses `time.monotonic()`.
2. Every read from the network is bounded in size and time and cleaned with `clean_text` before it is stored or shown.
3. No `shell=True`, `eval`, `exec`, pickle or `mktemp`; subprocesses get lists, and `ping` only validated addresses.
4. No silent `except Exception: pass`: unexpected errors are logged at debug level and, when they affect a scan, counted in `meta["warnings"]`.
5. Files that others may read later (history, reports, guard state) are written to a temporary file and renamed into place.
6. Anything user-supplied that sizes a loop (ports, targets, threads, rates, JSON depth) is bounded before it is used.
7. The local server trusts nothing: token, `Host`, `Origin`, `Sec-Fetch-Site`, body size, connection and stream ceilings, and a CSP.
