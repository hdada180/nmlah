# Changelog

All notable changes to Nemla are documented here, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). `v2.0.0` is the first tagged release; entries before it
are reconstructed from the git history rather than pinned to a release date.

## [Unreleased]

### Added
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
- `nemla/discovery/arp.py`'s ARP/neighbour-table lookup now takes the longest matching MAC prefix regardless of
  table order, so a short platform prefix can never shadow a more specific vendor entry.

### Removed
- `nemla/fingerprint/rdp.py`'s `_tpkt_complete`: dead code, defined but never called anywhere in the file.

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
