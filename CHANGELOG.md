# Changelog

All notable changes to Nemla are documented here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `v2.0.0` is the first tagged release; entries before it
are reconstructed from the git history rather than pinned to a release date.

## [Unreleased]

### Added
- **Fleet mode**: a controller and enrolled agents for several networks you are authorised to scan, from the command line
  (`nemla controller ...`, `nemla agent ...`), a JSON API and one page in the browser. See [docs/fleet.md](docs/fleet.md).
  It is reconnaissance only and built so that it cannot become remote control: the agent's scope is set on the agent and
  the controller can neither widen it nor skip the agent's own re-check; enrollment is local, with a single-use token that
  expires after 15 minutes; a job is validated data (literal addresses, ports, a short list of scan options) that only ever
  reaches Nemla's own scan function, and a test scans the package for anything that could run text or start a process;
  agents connect out over TLS 1.2+ and verify a pinned certificate fingerprint before sending anything; revocation is
  immediate on both sides and stops a scan in progress; every action is written to an append-only audit trail that refuses
  the action if it cannot be written and never holds a secret. Limits: 50 agents, one job at a time per agent, jobs held in
  the controller's memory. Not included, on purpose: remote commands, file transfer, updates, plugins pushed to agents,
  Guard control, a controller-managed scope.
- The Fleet page (`nemla_ui/web/fleet.*`): agents, queueing a scan, two-step revoke, jobs with results and what changed since
  the previous scan of the same target, and the audit trail. English and Arabic (right-to-left) and a phone layout. The
  Arabic text is machine-written and has not been reviewed by a native speaker.
- `TargetSet.contains_all()`, span arithmetic that says whether every address of one target expression lies inside another
  (IPv4 and IPv6, scoped addresses included); it is what the scope check is built on.
- CI proves what ships, not only the source tree: a `package` job (`compileall`, `python -m build`, `twine check --strict`,
  and `.github/scripts/check_dist.py`, which compares the wheel and the sdist with the source tree: nothing missing,
  nothing extra, one version) and an `installed` job that installs the wheel alone into a clean virtual environment
  (Python 3.8-3.14 on Linux, 3.8 and 3.13 on Windows) and runs `.github/scripts/smoke_installed.py` from outside the
  checkout: package location, one version everywhere, every module importing in a fresh interpreter, a real scan in
  every report format, and the web page and its security checks.
- `MANIFEST.in`, so the sdist carries the tests, the docs, the changelog and the source-checkout launcher, and no caches.
- Trove classifiers for Python 3.8 to 3.14, the versions CI actually tests.
- A test that every module imports as the first import of a fresh interpreter, and one that the version is written in
  exactly one place.
- `nemla 192.168.1.10` as a plain, positional way to give a target; `nemla ui`, `nemla guard`,
  `nemla watch TARGET [EVERY]` and `nemla diff OLD NEW` as one-word equivalents of the flags they stand for.
  `-t TARGET` and every 1.x flag still work exactly as before.
- `-p all` for every TCP port (1-65535), alongside the existing `N`, `N,M` and `N-M` forms.
- `SECURITY.md`: how to report a vulnerability in Nemla itself, and what is and is not in scope.
- `coverage` as a `[dev]` extra, with `[tool.coverage.*]` configuration in `pyproject.toml`, so measuring test
  coverage is a documented, repeatable command (`python -m coverage run -m pytest -q && python -m coverage report -m`)
  instead of a one-off.
- A broader, IEEE-registry-sourced table of MAC vendor prefixes in `nemla/discovery/mac.py` (73 entries, up from
  14), covering networking equipment, computers and phones, smart-home devices, and printers/cameras, not just
  virtualization platforms.

### Changed
- The version is written once, in `nemla/config.py`; `pyproject.toml` now reads it (`dynamic = ["version"]`) instead of
  repeating it, and the packages are found automatically (`[tool.setuptools.packages.find]`) instead of listed by hand.
- **Scan output is now owner-only.** Reports (HTML, JSON, CSV, Markdown, SARIF), the Guard's alert log and state and the
  `--watch-log` change log are created `0600`, and folders Nemla creates `0700`, on POSIX systems; before, reports were
  `0644` and the alert and change logs took the process umask. If you serve reports to other users, `chmod` them.
  Windows is unchanged. The README already described these files as private.
- `nemla/discovery/arp.py`'s ARP/neighbour-table lookup now takes the longest matching MAC prefix regardless of
  table order, so a short platform prefix can never shadow a more specific vendor entry.

### Removed
- `nemla/fingerprint/rdp.py`'s `_tpkt_complete`: dead code, defined but never called anywhere in the file.

### Fixed
- `--watch` no longer stops for good when a round's report, history entry or `--watch-log` cannot be written (a full
  disk, a mistyped path): it says so and keeps watching.
- The Guard's state file was written through the predictable name `guard.tmp` and only restricted after its content was
  written; it now goes through a random, owner-only temporary file renamed into place, like the history.
- `nemla --install-launcher` failed after a normal `pip install`: it looked for a `nemla.py` file next to the
  package, which a pip install never creates. It now uses the installed `nemla` command when there is one, and
  only falls back to `python3 nemla.py` in a plain git checkout.
- `write_csv()` (the public function) wrote plain UTF-8, while `--csv` writes UTF-8 with a byte-order mark so that
  Excel opens non-ASCII text correctly; the two now produce the same file for the same data.
- The interface server could lose its `413 Payload Too Large` answer to a request body over 64 KB: it refused the
  body without reading it, then closed the connection while the client was still sending, and the resulting TCP
  reset could destroy the answer before the client read it (about one request in eight on Windows). It now
  answers with `Connection: close`, discards what the client is still sending (never kept, at most 1 MiB and 2
  seconds), and only then closes.

## [2.0.0] - 2026-09-21

### Added
- A real package architecture (`nemla/`) in place of the original single `nemla.py` file: targets, discovery, a
  bounded scheduler, TCP and UDP scanners, one detector plugin per protocol, OS detection, findings, reports,
  history and Guard as separate modules. `python3 nemla.py ...` and `import nemla` keep working.
- IPv6 support throughout: targets, scanning, discovery, reports, history and the interface. Large prefixes
  (a `/64` and above) are refused before a single address is expanded, never silently truncated.
- UDP scanning with honest states (`open`, `closed`, `open|filtered`, `unknown`), rate limited by a token bucket.
- Service fingerprinting as plugins: HTTP/HTTPS, SSH, FTP, SMTP, POP3, IMAP, DNS, Redis, Memcached, MySQL/MariaDB,
  PostgreSQL, RDP (NLA), SMB (SMBv1, signing), Telnet, VNC, plus TLS and certificate analysis with Nemla's own
  X.509 reader.
- Confidence and evidence on every service and OS result; a guess from the port number alone is labelled as one.
- An evidence-based findings engine: id, severity, title, description, evidence, host, port, remediation and
  confidence, localized in English, Arabic and Hebrew.
- Markdown and SARIF 2.1.0 report formats, alongside HTML, JSON and CSV.
- A bounded scheduler: a global concurrency limit, a per-host limit, an optional rate limit, a probe budget, and
  cancellation that takes effect within about a tenth of a second.
- `privileges.detect()` and a capability-gated `SynProbe`: raw-packet features (Scapy ARP, SYN/ACK fingerprinting)
  report why they are unavailable instead of failing silently or crashing a scan without root.
- Real CI: a Linux matrix (Python 3.8-3.14), Windows (3.8, 3.13), a `privileged` job (root, Scapy, a real veth
  pair), an `integration` job against real Samba and xrdp in Docker, and a `benchmark` job.

### Changed
- Security hardening across the local server, reports, history and the Linux launcher, each with a regression
  test: token-based auth, Host/Origin/Sec-Fetch-Site checks, a strict CSP, size and time limits everywhere
  network-supplied data is read, atomic private-permission file writes, path-traversal defenses, no shell
  anywhere.
- `http_plain` (a plain-HTTP finding) now needs proof that HTTPS was actually scanned and not found, not just
  that port 80 was scanned alone.

### Fixed
- Numerous CI-only bugs, each with a regression test: Windows `cp1252` stdout crashing `--help`; Linux-only test
  races from `127.0.0.x` being entirely local on Linux; `mypy` failing on `ctypes.windll` when type-checked from
  Linux; a PostgreSQL detector false-positive on any reply starting with `S` or `N`; Windows-with-Python-<3.11
  history entries losing their save order when two scans landed in the same ~15ms clock tick.

## [1.2.0] - 2026-09-21

### Added
- New README screenshots and a real, checked-in sample HTML report.

## [1.1.0] - 2026-09-20 and earlier

### Added
- Service detection, TLS certificate details, evidence-based findings, and a Hebrew README/interface.
- Guard mode: decoy ports, unknown-device detection, and ARP-change alerts.
- A small hand-picked MAC-vendor table (virtualization platforms, Raspberry Pi).
- Scan history, comparison between saved scans, and `--watch`.
- The 3D web interface and a Linux `.desktop` launcher.

[Unreleased]: https://github.com/hdada180/nmlah/compare/main...feature/v2-security-platform
[2.0.0]: https://github.com/hdada180/nmlah/releases/tag/v2.0.0
