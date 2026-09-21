# What needs elevated privileges

Nemla never needs root or administrator rights for a normal scan, and never asks for them. `nemla/privileges.py` finds out
once what this process may do with raw packets, and the rest of the program adapts.

## Works for any user (Linux and Windows)

TCP connect scans, service identification, TLS and certificate analysis, UDP probes, IPv6, reports (HTML, JSON, CSV, Markdown,
SARIF), history and diff, the web interface, and the **Guard** (decoy ports and the periodic neighbour-table sweep: it reads the
operating system's ARP/neighbour table, it does not capture packets, so it needs neither Scapy nor root).

## Optional extras that need Scapy and raw-socket rights

| Extra | Needs | Without it | Information you lose |
|---|---|---|---|
| TCP/IP stack fingerprinting | Scapy, and root / `CAP_NET_RAW` (Linux, macOS) or an elevated prompt with Npcap (Windows) | TTL, banners, open ports, protocol facts and the network card's maker still vote | window size, TCP option order and the DF bit of the SYN-ACK: a Windows-vs-Linux guess rests on fewer signals and its confidence is lower |
| Scapy ARP requests | the same | neighbour cache after a UDP nudge | hosts that answer neither ICMP nor TCP and are not yet in the cache |

## What Nemla does when they are not available

* The capability is detected once (`privileges.detect()`); nothing is sent to find out (a raw socket is opened and closed).
* A scan with OS detection on prints one line in the scan language, e.g. *TCP/IP fingerprinting is off (it needs root or
  administrator rights). The OS guess uses TTL, service banners and open ports only.*, adds a `syn_fingerprint_off` warning to the
  report and sets `meta["capabilities"]["syn_fingerprint"]` to `false` with the reason.
* If the operating system refuses in the middle of a scan (no Npcap, a locked-down container), the probe switches itself off, once,
  and says so in the same way. A problem with one host (unreachable network) does not switch it off.
* The web interface reports the same facts in `/api/info` (`capabilities`). Nothing crashes and nothing is retried in a loop.
* Nemla does not weaken the system to get raw sockets: no `setcap`, no sudo prompts, no changes to `sysctl` or firewalls.

## How this is tested

* `tests/test_privileges.py`: every path above, simulated (no Scapy, refused raw socket, refusal mid-scan, one bad host).
* `tests/test_privileged.py` (CI job `privileged`, run under `sudo` in a private network namespace with a veth pair): a real
  SYN-ACK is read correctly, the same scan run as the unprivileged user `nobody` degrades exactly as described, Scapy's ARP scan
  works, and the Guard reads real kernel neighbour entries (complete, incomplete, static, changed).

Run the privileged tests yourself (Linux, root, Scapy, iproute2):

```bash
sudo -E env "PATH=$PATH" NEMLA_PRIVILEGED=1 python -m pytest -m privileged tests/test_privileged.py -v
```
