# 🐜 Nemla — Network Reconnaissance Tool

**Discover · Scan · Fingerprint · Report**

[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-orange)](LICENSE)
[![CI](https://github.com/hdada180/nmlah/actions/workflows/ci.yml/badge.svg)](https://github.com/hdada180/nmlah/actions/workflows/ci.yml)

**English** · [العربية](README.ar.md)

Nemla (Arabic: **نملة**, "ant") is a small, dependency-free network reconnaissance tool written in Python. Point it at an IP, a hostname, a range or a subnet and it finds live hosts, scans TCP ports, grabs service banners, makes a best-guess at the operating system, and writes a clean **HTML report** (plus JSON and CSV for scripting). The interface and the report are available in **English and Arabic**.

![Nemla HTML report](docs/report-en.png)

> The screenshot is a scan of a local lab (`127.0.0.1`) running a few demo services. See [`nemla_report_sample.html`](nemla_report_sample.html) for the full report.

## Why Nemla?

[nmap](https://nmap.org) is far more powerful, and you should use it for serious work. Nemla is for the moments when you want something smaller:

- **Zero setup** — a single Python file, standard library only. Scapy is optional.
- **A report you can actually hand to someone** — a readable dark-mode HTML page, no XML converting.
- **Arabic-first option** — `--lang ar` switches the whole CLI and the report to Arabic (right-to-left).
- **Readable source** — one file you can read in an evening, which makes it good for learning how scanners work.

## The 3D interface

Run Nemla with no arguments and it opens its own window: a 3D map of your network, a scan form, a live host list and a host inspector. It is the same scanner as the command line, just easier to work with.

```bash
python3 nemla.py            # opens the 3D interface
```

- **The colony view.** This computer is the nest in the middle, every discovered host floats around it, and each open port orbits its host, coloured by service type (web, remote access, database, mail, files). Drag to orbit, scroll to zoom, click a host to inspect it.
- **Live.** Hosts and ports appear while the scan runs. Stop keeps the partial results.
- **Export.** HTML report, JSON or CSV from the Export button.
- **English and Arabic**, right-to-left included.
- **Try it without scanning.** "Watch a demo colony" replays a made-up network.
- **Standard library only.** The interface is a small local web server plus one page. There is nothing to install and it works offline.

### Add Nemla to the Linux applications menu

```bash
python3 nemla.py --install-launcher     # menu entry, icon and a `nemla` command, all under ~/.local
python3 nemla.py --uninstall-launcher   # removes them again
```

Then open **Nemla** from your applications menu (or type `nemla`). In a Chromium-family browser (Chrome, Chromium, Brave, Edge) it opens as its own window without browser chrome, otherwise in your default browser. Closing the window stops Nemla.

ARP discovery needs root, and browsers refuse to start as root, so for that case run `sudo python3 nemla.py --no-browser` and open the printed address in your browser. Over SSH, forward the port (`ssh -L PORT:127.0.0.1:PORT host`) and open the address locally.

### How it stays safe

The interface listens on `127.0.0.1` only. Every request needs a random token that exists only in the link Nemla opens, and the `Host` and `Origin` headers are checked, so other websites and other machines cannot start scans. Scanned text (banners, OS strings) is shown as plain text, never as HTML, and the page runs under a strict Content-Security-Policy. The first scan asks you to confirm that you own the network or may test it.

### Identity

Nemla has its own logo, colours and type: see [`docs/brand.html`](docs/brand.html). The logo files live in [`nemla_ui/web/brand/`](nemla_ui/web/brand/).

## Install

```bash
git clone https://github.com/hdada180/nmlah.git
cd nmlah
python3 nemla.py --help
```

Optional, for ARP discovery on local networks and raw-ICMP TTL probing:

```bash
pip install scapy        # or: pip install -r requirements.txt
```

You can also install it as a command: `pip install .` (or `pip install ".[arp]"`), then run `nemla -t ...`.

## Quick start

```bash
# a whole subnet, common ports
sudo python3 nemla.py -t 192.168.1.0/24

# one host, ports 1-1000
python3 nemla.py -t 192.168.1.10 -p 1-1000

# ranges: short form or full form
python3 nemla.py -t 192.168.1.1-50
python3 nemla.py -t 192.168.1.1-192.168.2.20

# specific ports + JSON and CSV output
python3 nemla.py -t 192.168.1.10 -p 22,80,443 --json scan.json --csv scan.csv

# Arabic interface and report
python3 nemla.py -t 192.168.1.10 --lang ar

# target blocks ping? skip discovery (like nmap -Pn)
python3 nemla.py -t 192.168.1.10 --no-ping
```

`sudo` is only needed for ARP discovery and raw-ICMP TTL probing through Scapy. Without it, Nemla falls back to the system `ping` and plain TCP connections.

## Options

| Option | Description |
| --- | --- |
| `-t`, `--target` | IP, hostname, CIDR (`10.0.0.0/24`), short range (`10.0.0.1-50`) or full range (`10.0.0.1-10.0.0.50`) |
| `-p`, `--ports` | `22`, `22,80,443`, `1-1000` or a mix |
| `--top-ports` | Also scan the built-in list of common ports (this is the default when `-p` is omitted) |
| `-o`, `--output` | HTML report path (default `nemla_report.html`) |
| `--json FILE` | Also write the results as JSON |
| `--csv FILE` | Also write the results as CSV |
| `--no-ping` | Skip host discovery; treat every target as up |
| `--no-os` | Skip OS fingerprinting |
| `--no-banner` | Skip banner grabbing |
| `--threads N` | Worker threads (default 150) |
| `--timeout S` | TCP connect timeout in seconds (default 0.7) |
| `--max-hosts N` | Refuse targets bigger than N addresses (default 1024) |
| `--lang en\|ar` | Language of the CLI, the report and the interface (default `en`) |
| `--version` | Print the version |
| `--ui` | Open the 3D interface (also what happens with no arguments) |
| `--ui-port PORT` | Port for the local interface server (default: any free port) |
| `--no-browser` | Start the interface server without opening a window |
| `--keep-alive` | Keep the server running after its window is closed |
| `--install-launcher` / `--uninstall-launcher` | Linux: add or remove the applications-menu entry |

## How it works

1. **Discovery** — ARP on local networks (needs Scapy + root). If ARP finds nothing, or the target isn't local, Nemla falls back to ICMP (system `ping`) and TCP probes. A TCP connection *refused* still proves the host is alive.
2. **Port scan** — concurrent TCP connect scan (`ThreadPoolExecutor`). Service names come from a built-in table with a fallback to the system services database.
3. **Banner grabbing** — Nemla listens first (SSH, FTP and SMTP greet you). If the port stays silent, it sends a harmless HTTP `HEAD`, but only on HTTP ports and ports with no known non-HTTP service. TLS ports are not probed.
4. **OS guess** — heuristic: TTL (≤64 Linux/Unix/macOS, ≤128 Windows, otherwise network device) refined by open ports (RDP/SMB, SSH). Treat it as an estimate.
5. **Report** — HTML (all scanned data is HTML-escaped, since banners come from untrusted hosts), plus optional JSON/CSV.

## Limitations

- IPv4 only, TCP connect scan only (no SYN/UDP scanning).
- OS detection is a TTL-and-ports heuristic, not real fingerprinting.
- Firewalls that drop packets will make hosts look down. Try `--no-ping` and a larger `--timeout`.

## Responsible use

**Only scan systems and networks you own or have explicit written permission to test.** Unauthorized scanning may violate laws, provider terms and organizational policy. Nemla is a reconnaissance tool: it discovers and reports, it does not exploit anything, and that is intentional. The author is not responsible for misuse.

## Development

```bash
pip install pytest
python -m pytest -q
```

The tests run entirely against `127.0.0.1` with throw-away local servers. They also cover the interface server (token, host and origin checks, event stream, reports) and the Linux launcher.

## Roadmap

- [x] JSON and CSV output
- [x] English / Arabic interface
- [x] Unit and end-to-end tests, CI
- [x] 3D interface, Linux applications-menu launcher and the Nemla identity
- [ ] Scan history inside the interface
- [ ] IPv6 support
- [ ] MAC vendor lookup
- [ ] Scan profiles and a config file
- [ ] Richer service detection (plugin-based)
- [ ] Interactive HTML report (sorting, filtering)

## Contributing

Issues and pull requests are welcome. Please keep changes small, add a test where it makes sense, and keep the tool recon-only. When reporting a bug, include your OS, Python version, the command you ran, and the error output (without private IPs or credentials).

## License

[MIT](LICENSE) © hdada180

---

If Nemla is useful to you, a ⭐ helps other people find it.
