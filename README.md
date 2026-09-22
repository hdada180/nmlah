# 🐜 Nemla — Lightweight Network Reconnaissance, Service Intelligence & Defensive Monitoring Platform

**Discover · Scan · Fingerprint · Assess · Report · Watch**

[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-orange)](LICENSE)
[![CI](https://github.com/hdada180/nmlah/actions/workflows/ci.yml/badge.svg)](https://github.com/hdada180/nmlah/actions/workflows/ci.yml)

**English** · [العربية](README.ar.md) · [עברית](README.he.md)

Nemla (Arabic: **نملة**, "ant") is a small network reconnaissance platform written in Python with **no required dependencies**. Point it at an IP (IPv4 or IPv6), a hostname, a range or a subnet and it finds live hosts, scans TCP and UDP ports, identifies the service behind every open port (product, version, TLS certificate, protocol details), estimates the operating system from several independent signals, and turns what it saw into **evidence-based findings** with a confidence level and a fix. It writes reports as **HTML, JSON, CSV, Markdown and SARIF**, remembers your scans and tells you what changed, and can guard a network against suspicious activity. Everything is available in **English, Arabic and Hebrew**, on the command line, in reports and in a 3D web interface.

![Nemla HTML report](docs/report-en.png)

> The screenshot is a scan of a local lab (`127.0.0.1`) running a few demo services. See [`nemla_report_sample.html`](nemla_report_sample.html) for the full report.

## What's new in 2.0

- **A real architecture.** The single 1,900-line `nemla.py` became the `nemla/` package: targets, discovery, a bounded scheduler, TCP and UDP scanners, one small plugin per protocol, OS detection, findings, reports, history and guard. `python3 nemla.py ...` and `import nemla` keep working. See [docs/architecture.md](docs/architecture.md).
- **Shorter commands.** `nemla 192.168.1.10` instead of `nemla -t 192.168.1.10`; `nemla watch`, `nemla diff`, `nemla guard` and `nemla ui` for the modes; `-p all` for every port. Every 1.x flag still works.
- **IPv6** everywhere (targets, scanning, discovery, reports, history, the interface).
- **UDP scanning** with honest states: `open`, `closed`, `open|filtered`, `unknown`, rate limited and safe.
- **Service fingerprinting as plugins:** HTTP/HTTPS, SSH (with the algorithms the server offers), FTP, SMTP, POP3, IMAP, DNS, Redis, Memcached, MySQL/MariaDB, PostgreSQL, RDP (NLA), SMB (SMBv1, signing), Telnet, VNC, plus TLS and certificate analysis with Nemla's own X.509 reader.
- **Confidence everywhere.** Every service and OS result carries a confidence and its evidence. A guess from a port number alone is labelled a guess.
- **A findings engine that shows its work:** id, severity, title, description, evidence, host, port, remediation and confidence, in three languages.
- **Reports:** executive summary, scan metadata, errors and warnings, plus Markdown and SARIF 2.1.0.
- **Correctness and speed:** validated options, a scheduler that never queues tens of thousands of tasks, per-host and global limits, rate limiting, a probe budget and cancellation that takes effect within a tenth of a second.
- **Security hardening** of the local server, reports, history and launcher, with a test for every fix. See [Security](#security).

## Why Nemla?

[nmap](https://nmap.org) is far more powerful, and you should use it for serious work. Nemla is for the moments when you want something smaller and more explanatory:

- **Zero setup**: standard library only (Scapy is optional). No compiled parts.
- **It explains itself.** Every finding says what was observed, how sure Nemla is and what to do.
- **Honest confidence.** Nemla never presents a heuristic as a fact.
- **A report you can hand to someone**: a readable dark-mode HTML page, or Markdown and SARIF for your tooling.
- **Arabic and Hebrew**: `--lang ar` or `--lang he` switches the CLI, the reports and the interface, right-to-left included.
- **Readable source**: plain Python, one small module per protocol. Good for learning how scanners work.

## Features

| Area | What Nemla does |
| --- | --- |
| Targets | IPv4, IPv6 (`2001:db8::/120`, `fe80::1%eth0`), host names (`getaddrinfo`), CIDR, ranges, several at once; generated lazily, so a million addresses cost no memory |
| Discovery | ARP (Scapy, or the OS neighbour cache without root), completed by ICMP and TCP probes for the addresses ARP missed |
| TCP | Concurrent connect scan through a bounded scheduler, banner grabbing, service identification |
| UDP | DNS, TFTP, RPCBind, NTP, NetBIOS, SNMP (default community), SSDP, mDNS, Memcached; paced by a token bucket |
| Services | Product, version, confidence, evidence and protocol facts (STARTTLS, NLA, SMB signing, weak SSH algorithms...) |
| TLS | Protocol, cipher, certificate subject, issuer, validity, signature algorithm, key type and size, self-signed, TLS 1.0/1.1 still accepted |
| OS | TTL, TCP SYN-ACK shape (Scapy + root), banners, open ports, protocol facts, NIC maker; the result has a confidence and evidence |
| Findings | Exposed administration and remote access, insecure and plaintext protocols, expired or weak certificates, weak TLS and SSH, default SNMP, open Redis/Memcached/Elasticsearch, SMBv1, RDP without NLA, open resolvers, admin consoles |
| Reports | HTML, JSON, CSV (formula-injection safe), Markdown, SARIF |
| History | UUID scan ids, atomic private files, comparison: new/removed hosts, opened/closed ports (TCP and UDP), service, version and OS changes, new and resolved findings |
| Guard | Decoy ports, unknown devices, ARP changes with a confidence and the evidence behind it |
| Interface | 3D colony map, live progress, inspector with confidence and evidence, history, diff, Guard status, English/Arabic/Hebrew |

## Install

```bash
git clone https://github.com/hdada180/nmlah.git
cd nmlah
python3 nemla.py --help        # on Windows: python nemla.py --help
```

Below, **`nemla` stands for `python3 nemla.py`** run from this folder (on Windows `python nemla.py`). If you install it as a command (see below) it really is the command `nemla`.

Optional, for ARP discovery and raw SYN fingerprinting (needs root):

```bash
pip install scapy        # or: pip install -r requirements.txt
```

You can also install it as a command: `pip install .` (or `pip install ".[arp]"`), then run `nemla 192.168.1.10` (or `python -m nemla 192.168.1.10`) from any folder.

## Quick start

Three commands are enough to start:

```bash
nemla                                  # opens the 3D interface: type a target and press Start scan
nemla 192.168.1.10                     # scan one host: common ports, services, OS guess, findings, a report
nemla 192.168.1.0/24                   # scan a whole network
```

The report is written to `nemla_report.html` in the current folder (`-o` changes that). Then add only what you need:

```bash
nemla 192.168.1.10 -p 22,80,443        # only these TCP ports (or 1-1000, or all)
nemla 192.168.1.10 --udp               # plus the common UDP ports
nemla 2001:db8::5,192.168.1.10-20      # IPv6, and several targets at once
nemla 192.168.1.10 --json scan.json    # also save JSON (--csv, --md and --sarif work the same way)
nemla 192.168.1.0/24 --rate 50 --max-probes 5000    # gentle: 50 connections per second, at most 5,000 probes
nemla 192.168.1.10 --lang ar           # Arabic interface and report (--lang he for Hebrew)
nemla 10.0.0.0/24 --fail-on high       # for CI: exit code 3 on any high finding
```

And the other modes are one word each:

```bash
nemla watch 192.168.1.0/24 15m         # scan again every 15 minutes and say what changed
nemla diff yesterday.json today.json   # what changed between two saved scans
nemla guard                            # watch this network for suspicious activity
nemla ui                               # the 3D interface (the same as running nemla with nothing)
```

The 1.x form keeps working: `nemla -t 192.168.1.10 --udp` is the same as `nemla 192.168.1.10 --udp`. The words `scan`, `ui`, `guard`, `watch` and `diff` are commands only as the first word; a host that is really called `ui` is scanned with `-t ui`.

`sudo` is only needed for Scapy (real ARP requests, raw ICMP, SYN fingerprinting): `sudo python3 nemla.py 192.168.1.0/24`. Without it Nemla reads the operating system's neighbour cache and falls back to the system `ping` and plain TCP connections.

## Options

| Option | Description |
| --- | --- |
| `TARGET` (or `-t TARGET`) | IP, hostname, CIDR, `10.0.0.1-50`, `10.0.0.1-10.0.0.50`, IPv6 (`2001:db8::/120`, `fe80::1%eth0`); several separated by commas. `nemla 192.168.1.10` and `nemla -t 192.168.1.10` are the same |
| `ui`, `guard`, `watch TARGET [EVERY]`, `diff OLD NEW`, `scan TARGET` | The first word of the command: short for `--ui`, `--guard`, `--watch EVERY -t TARGET` (every 15 minutes if EVERY is left out), `--diff OLD NEW` and a plain scan |
| `-4` / `-6` | Resolve names to IPv4 or IPv6 only (default: the first IPv4 address, else the first IPv6 one) |
| `--all-addresses` | Scan every address a name resolves to |
| `-p`, `--ports` | `22`, `22,80,443`, `1-1000`, `all` (every port, 1-65535) or a mix |
| `--top-ports` | Also scan the built-in list of common ports (the default when `-p` is omitted) |
| `--udp` | Also probe the common UDP ports |
| `--udp-ports LIST` | UDP ports to probe (implies `--udp`) |
| `--udp-timeout S` / `--udp-rate PPS` | Wait per UDP probe (default 1.0) / packets per second (default 200) |
| `-o`, `--output` | HTML report path (default `nemla_report.html`) |
| `--json`, `--csv`, `--md`, `--sarif FILE` | Also write the results in that format |
| `--no-ping` | Skip host discovery; treat every target as up |
| `--no-os` | Skip OS fingerprinting |
| `--no-banner` | Skip banner grabbing and service detection |
| `--intensity 0-9` | Service detection effort: 0 none, 5 default, 9 tries every protocol |
| `--threads N` | Global limit of concurrent probes (default 150, at most 2000) |
| `--per-host N` | Limit of concurrent probes on one host (default 100) |
| `--timeout S` | TCP connect timeout in seconds, greater than 0 (default 0.7) |
| `--rate PPS` | Limit TCP connection attempts per second (default unlimited) |
| `--max-probes N` | Stop after N connections/datagrams in total (default unlimited) |
| `--max-hosts N` | Refuse targets bigger than N addresses (default 1024, hard limit about a million) |
| `--fail-on LEVEL` | Exit with code 3 if any finding is at `low`, `medium` or `high` or above |
| `--watch INTERVAL` / `--watch-log FILE` | Scan again every `90s`, `15m`, `2h` and report changes |
| `--diff OLD.json NEW.json` / `--fail-on-change` | Compare two saved scans; exit 3 if something appeared |
| `--guard`, `--guard-ports`, `--guard-interval`, `--guard-log` | Defensive monitoring (see below) |
| `--lang en\|ar\|he` | Language of the CLI, reports and interface |
| `-v`, `--verbose` | Debug details on stderr |
| `--ui`, `--ui-port`, `--no-browser`, `--keep-alive` | The 3D interface |
| `--install-launcher` / `--uninstall-launcher` | Linux applications-menu entry |

Exit codes: `0` success, `1` an error (bad target, unwritable report), `2` bad arguments, `3` findings at or above `--fail-on` (or changes with `--fail-on-change`).

## How it works

```
Targets -> Discovery -> bounded scheduler -> TCP / UDP scanning
        -> service fingerprinting -> OS fingerprinting -> findings -> reports
```

1. **Targets** become integer spans that yield one address at a time (IPv4 and IPv6). Ports are parsed with every bound checked first.
2. **Discovery** uses ARP first on private IPv4 networks, then probes every address ARP did not answer with ICMP and TCP; hosts found that way get their MAC from the neighbour cache. ARP is never trusted to be complete, and a warning says when it was not.
3. **The scheduler** pulls jobs lazily, enforces the global and per-host limits, the rate limit and the probe budget, and stops everything within a tenth of a second when you press Stop or Ctrl+C. Hosts are scanned side by side and each is finished the moment its own jobs are done.
4. **Service fingerprinting** first reads what the server says on its own, then asks protocol-specific questions (one detector plugin per protocol), tries TLS where it is likely and looks inside the tunnel. Nothing logs in and nothing changes state.
5. **OS fingerprinting** adds weighted votes from TTL, the TCP SYN-ACK (window, options, DF), banners, open ports, protocol facts and the NIC maker, and keeps the evidence.
6. **Findings** are raised only for what was observed. A port number alone gives a lower-confidence finding, one severity step down, labelled as such.
7. **Reports** are rendered from the same data in any language.

### Confidence

Every service and OS result has a `confidence` (0 to 1) and a `heuristic` flag. A banner that names a product and version scores about 0.95, a protocol reply without a version about 0.85, a port number alone 0.3 (`heuristic: true`). OS guesses are capped at 0.70 when they rest on inference alone and 0.92 when a service named the OS itself, because banners can be edited by the host's owner. Nothing is ever reported as certain.

### Findings

Each finding has `id`, `severity`, `title`, `description`, `evidence`, `host`, `port`, `proto`, `remediation` and `confidence`. Examples:

| Finding | Raised when Nemla observed | Severity |
| --- | --- | --- |
| `telnet`, `ftp`, `mail_plain`, `smtp_plain_auth`, `basic_auth_plain` | a clear-text service or login on the wire | medium to high |
| `redis_open`, `memcached`, `es_open` | PING / `version` / `GET /` answered without authentication | high |
| `smb1`, `smb_signing` | an SMBv1 negotiation accepted; signing not required | high / medium |
| `rdp_no_nla`, `rdp_weak_security` | the RDP server accepted a session without NLA / with legacy security | medium / high |
| `tls_expired`, `tls_expiring`, `tls_not_yet_valid` | certificate dates | high / medium |
| `tls_old`, `tls_weak_sig`, `tls_weak_key`, `tls_selfsigned` | TLS 1.0/1.1 handshake completed; SHA-1/MD5 signature; RSA below 2048 bits; subject equals issuer | medium / low |
| `ssh_protocol1`, `ssh_weak_crypto` | SSH-1 banner; weak algorithms in the key-exchange proposal | high / medium / low |
| `snmp_default`, `tftp`, `udp_exposed` | SNMP answered to `public`; TFTP answered; a reflection-capable UDP service on a public address | medium to high |
| `dns_recursion` | the RA flag in a DNS answer (an open resolver is only possible) | low to medium |
| `admin_panel`, `remote`, `db`, `files` | an administration console, remote access, database or file sharing reachable | low to high |
| `http_plain` | plain HTTP **and** HTTPS ports were scanned and none serves TLS (never after scanning port 80 alone) | low |

Exposure on a public address (judged with `is_global`, so shared address space and documentation ranges do not count) is rated higher than on a private network. Findings describe exposure and weak configuration, not exploitable vulnerabilities: Nemla does not match versions against a CVE database and never tries to log in or exploit anything.

## Reports

`--json` is the full record (schema version 2) and is what history stores. It keeps every field of the 1.x output. The CSV keeps the 1.x columns first (`ip,mac,vendor,os_guess,ttl,port,service,banner,product,version`) and appends `proto,state,confidence,os_confidence`; cells that could run as spreadsheet formulas are neutralised. Markdown escapes everything that came from the network. SARIF 2.1.0 has one rule per finding id and one result per finding, with the host and port as location, for GitHub code scanning, DefectDojo and similar dashboards.

## What changed since last time

Nemla remembers your scans (the newest 60, in your Nemla data folder, each with a random UUID) and compares each new scan with the previous one of the same target: hosts that appeared or vanished, ports that opened or closed (TCP and UDP), services whose product, version or protocol changed, a different operating-system family, and findings that appeared or were resolved.

```bash
nemla 192.168.1.0/24 --json today.json
nemla diff yesterday.json today.json                   # add --fail-on-change for scheduled checks
nemla watch 192.168.1.0/24 15m --watch-log changes.jsonl
```

In the 3D interface open the **History** tab to reopen any saved scan on the map, see its comparison with the previous scan and export it in any format.

## Guard mode (defensive)

Nemla can also watch a network instead of scanning it:

- **Decoy ports.** Ports that no legitimate device has a reason to touch (2222, 2323, 5901, 8888 and 3307 by default). Whatever connects is probing your network.
- **Unknown devices.** The first check learns your devices by MAC address; a device that was not there before raises an alert (with its maker when known).
- **ARP changes.** An address that suddenly answers from a different device.

Guard alerts carry a **confidence and the evidence** behind it. A changed ARP binding is **not** proof of spoofing: a replaced network card, a DHCP change or a virtual machine looks the same, so Nemla weighs the gateway, how often the binding flips, whether the new address belongs to a known device and whether the old one still answers, and never goes above 0.85. Guard only watches: it never attacks back, never scans other machines and never changes your firewall (for a device you want to block it prints the exact command and leaves running it to you).

```bash
nemla guard
nemla guard --guard-log alerts.jsonl       # also append every alert to a file
```

## The 3D interface

Run Nemla with no arguments and it opens its own window: a 3D map of your network, a scan form, a live host list, an inspector and a history of saved scans.

![The Nemla 3D interface showing the demo colony](docs/ui-3d.png)

```bash
nemla            # opens the 3D interface (the same as: nemla ui)
```

- **Colony view:** this computer is the nest, hosts float around it, every open port orbits its host coloured by service type. Drag to orbit, scroll to zoom, click a host.
- **Live progress** with a single global progress bar, hosts finishing side by side.
- **Inspector:** OS guess with its confidence and evidence; every port with its confidence (a `~` marks a guess); every finding with *why it matters*, *how to fix it* and the evidence.
- **History and diff, Guard status and alerts with their evidence, export** (HTML, JSON, CSV, Markdown, SARIF).
- **English, Arabic and Hebrew**, right-to-left included, keyboard accessible.

### Add Nemla to the Linux applications menu

```bash
nemla --install-launcher     # menu entry, icon and a `nemla` command, all under ~/.local
nemla --uninstall-launcher
```

In a Chromium-family browser it opens as its own window, otherwise in your default browser; closing the window stops Nemla. Browsers refuse to start as root, so for ARP discovery run `sudo python3 nemla.py ui --no-browser` and open the printed address. Over SSH forward the port (`ssh -L PORT:127.0.0.1:PORT host`).

## Security

Nemla scans hostile networks and shows what strangers wrote, so it is hardened accordingly. Each item below has tests.

- **Local server:** listens on `127.0.0.1` only; a random per-launch token (header for writes, address for reads); `Host`, `Origin` and `Sec-Fetch-Site` checks (DNS rebinding, cross-site requests); body size cap; idle-connection timeouts; ceilings on connections and event streams; strict Content-Security-Policy; no traceback ever leaves the server; scan parameters are validated and clamped; the first scan needs consent.
- **Malicious banners and certificates:** every read is bounded in size and time; text from the network is stripped of control characters, terminal escapes and bidi overrides before it is logged or stored; the DER certificate parser is fuzz-tested and only ever raises one error type; the page renders with `textContent`, reports escape every field (HTML entities, CSV formula guard, Markdown entities).
- **Resource exhaustion:** hostile port ranges (`1-99999999999`) are refused before they are expanded; a million-address target is a few integers; the scheduler pulls jobs lazily; deeply nested JSON is refused; history files are size-capped.
- **File system:** history and report files are written to a temporary file and renamed into place (private permissions); ids are UUIDs validated before they touch a path; static files cannot leave the web folder.
- **Commands:** no shell anywhere; `ping` receives only validated addresses; the Linux launcher quotes every path.
- **Races:** the language of a scan is per thread (no global switching), counters are locked.
- **Unsafe deserialisation:** only `json.loads` on untrusted data; no pickle, eval or exec (a test scans the source for them).
- **SSRF:** probes never follow redirects or URLs found in banners; a target is only what you typed.

## What needs elevated privileges

Nothing you need for a normal scan. Connect scans, service and TLS fingerprinting, UDP probes, IPv6, reports, history, the
neighbour-cache sweep and the **Guard** all use ordinary sockets and run as a normal user on Linux and Windows. Two optional
extras craft packets themselves:

| Extra | Needs | Without it |
|---|---|---|
| TCP/IP stack fingerprinting (one SYN, read the SYN-ACK) | Scapy **and** raw-socket rights: root or `CAP_NET_RAW` on Linux/macOS, an elevated prompt with Npcap on Windows | The OS guess uses TTL, service banners, open ports and protocol facts. Confidence is lower and the report says why. |
| ARP requests sent by Scapy | the same | The operating system's neighbour cache is read after a gentle UDP nudge (works without root). |

Nemla finds this out once, says so in one translated line ("TCP/IP fingerprinting is off (it needs root or administrator
rights)..."), records it in the report's warnings and in `meta["capabilities"]`, and carries on. It never asks to be elevated
and never elevates itself; if the operating system refuses in the middle of a scan the extra switches itself off, once. What is
unavailable without them: the window, option-order and DF traits of a host's TCP stack, and Scapy's own ARP discovery. What
works with root is proven against a real kernel in CI (the `privileged` job). Details: [docs/privileges.md](docs/privileges.md).

## IPv6 and neighbour discovery

IPv6 targets are first-class: explicit addresses (`::1`, `2001:db8::5`, `[::1]`, `fe80::1%eth0`), small ranges and blocks, TCP
and UDP scans, reports, history and diff (IPv4 sorts first, IPv6 numerically after it). **Large prefixes are refused, never
expanded**: a `/64` is 2^64 addresses, so anything above the host limit (`--max-hosts`, never more than 1,048,576) is rejected
before a single address is built, and a `/108` is counted, not listed. Malformed input is a clear error, not a crash.

IPv6 has no broadcast and no ARP, so **an unknown IPv6 host on the LAN cannot be found by sweeping an address range** the way an
IPv4 host can: Nemla probes the addresses you give it (ICMP and TCP), it does not discover strangers. To find IPv6 neighbours
use your router's neighbour table or `ip -6 neigh`, then scan those addresses. ARP-based discovery and the Guard's ARP checks are
IPv4 only.

## Testing and benchmarks

```bash
python -m pytest                                   # the whole suite (about 1,200 tests, roughly three minutes)
python -m ruff check . && python -m mypy           # lint and types (CI checks Linux, Windows and macOS typing)
python -m benchmarks.bench_scan                    # 100 / 1,000 / 10,000 / 65,535 ports against a loopback target
python -m benchmarks.bench_network                 # 10 / 50 / 100 synthetic hosts, some broken on purpose
```

CI runs seven Python versions (3.8 to 3.14) on Ubuntu, two on Windows, and separate jobs for the tests that need more than a
laptop: `privileged` (root, Scapy, a veth pair and real ARP), `integration` (real Samba and xrdp in Docker,
[tests/integration/README.md](tests/integration/README.md)) and `benchmark`. Tests that need those are skipped elsewhere with
their reason printed, never silently. The layout of the 3D interface is tested in a real Chrome or Edge (a small standard-library
DevTools client, no dependencies) at 14 screen sizes in three languages.

Measured on one Windows 11 machine (Python 3.13, loopback target, 1,500 threads; `benchmarks/README.md` explains the columns):

| ports | seconds | peak memory | connections at once | scheduler queue |
|---|---|---|---|---|
| 100 | 1.6 | 39 MB | 100 | 0 |
| 1,000 | 7.6 | 109 MB | 1,000 | 0 |
| 10,000 | 11.8 | 114 MB | 1,000 | 6,000 |
| 65,535 | 37.0 | 120 MB | 1,000 | 6,000 |

Memory stays flat as the port count grows (jobs are pulled lazily). Cancelling stops a scan in about 0.1 s, even while
connections hang. Compared with 1.2.0 on the same machine, the port scanning itself is not slower (1,000 ports, banners off:
0.67 s in 2.0, 0.68 s in 1.2.0); what 2.0 adds is service identification, which asks open ports that stay silent about a
dozen protocol questions and waits a timeout for each (a default scan of those 1,000 ports took 7.6 s). That is the price of finding
RDP, SMB or Redis on any port, and you choose it: `--intensity 1` or `--no-banner` for 1.x speed, `--timeout` to shorten each wait.

## Limitations

- TCP is a connect scan (no SYN scan). UDP replies are only understood for the protocols above; `open|filtered` is common on UDP, and Linux rate-limits ICMP replies, so a fast scan of a Linux host reports many closed ports that way.
- Findings describe exposure and configuration, not exploitable vulnerabilities. There is no CVE matching.
- OS detection is an estimate from several weak signals. The TCP fingerprint needs Scapy and root and its shapes are the widely documented ones, not a full database.
- SMB and RDP probes follow the published protocols but were verified against test servers, not every real Windows version; treat their findings as leads to confirm.
- IPv6 discovery of unknown neighbours is not attempted: give explicit addresses or ranges.
- Firewalls that drop packets make hosts look down. Try `--no-ping` and a larger `--timeout`. On Windows a refused connection takes about two seconds to be reported.

## Responsible use

**Only scan systems and networks you own or have explicit written permission to test.** Unauthorized scanning may violate laws, provider terms and organizational policy. Nemla is a reconnaissance tool: it discovers and reports, it does not exploit anything. The only check near credentials is deliberately minimal: SNMP is asked once with the well-known community `public`, and no login of any kind is ever attempted. The author is not responsible for misuse.

## Upgrading from 1.x

`python3 nemla.py ...` and `import nemla` keep working, `-t TARGET` still works next to the new plain `TARGET`, and every option and output field of 1.x is still there (new fields were added). Changes you may notice: IPv6 targets are accepted; several targets can be given at once; scan ids are UUIDs (old timestamp ids still load); `history` and `guard` moved to `nemla.history` and `nemla.guard` (the `nemla_ui.*` names still resolve to the same modules); the `http_plain` finding needs proof that HTTPS was scanned; `--timeout 0` and other invalid numbers are now rejected.

## Development

```bash
pip install ".[dev]"        # or: pip install pytest pyflakes ruff mypy coverage
python -m pyflakes nemla nemla_ui nemla.py
python -m pytest -q
python -m coverage run -m pytest -q && python -m coverage report -m    # which lines the tests never touch
```

The tests run entirely against loopback with throw-away servers (TCP, UDP, TLS, IPv6 when available): every protocol detector, the scheduler and cancellation, hostile input, reports in every format, history and diff, the local server's security and the Guard. See [docs/architecture.md](docs/architecture.md) for how to add a detector or a finding.

Found a security bug rather than a regular one? See [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Roadmap

- [x] JSON and CSV output, English / Arabic / Hebrew, findings and `--fail-on`, Guard, history, `--diff` and `--watch`, 3D interface, Linux launcher
- [x] Architecture split, plugin detectors, IPv6, UDP, OS fingerprinting with confidence, Markdown and SARIF, bounded scheduler
- [ ] Full IEEE OUI registry for MAC vendors (today a curated table of about 70 common vendor and platform prefixes, taken from the IEEE list)
- [ ] Scan profiles and a config file
- [ ] Interactive HTML report (sorting, filtering)
- [ ] IPv6 neighbour discovery on the local link
- [ ] More UDP protocols and SNMPv3

## Contributing

Issues and pull requests are welcome. Please keep changes small, add a test, and keep the tool recon-only. When reporting a bug, include your OS, Python version, the command you ran and the error output (without private IPs or credentials).

## License

[MIT](LICENSE) © hdada180

---

If Nemla is useful to you, a ⭐ helps other people find it.
