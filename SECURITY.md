# Security Policy

Nemla is a network reconnaissance and defensive-monitoring tool. This document is about vulnerabilities **in Nemla
itself** — a bug that lets Nemla's own code be abused — not about what a scan finds on the network you point it at
(that belongs in a regular [issue](https://github.com/hdada180/nmlah/issues)).

## Supported versions

Nemla does not yet have a long-term-support branch: it is one actively developed line. Security fixes land on
`main` and the latest tagged release; older tags are not backported.

| Version | Supported |
| --- | --- |
| latest release / `main` | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

**Preferred: GitHub's private vulnerability reporting.** Open the
[Security tab](https://github.com/hdada180/nmlah/security) on this repository and use **"Report a vulnerability"**.
It reaches the maintainer directly and is not public until a fix is out.

If that option is not enabled when you look, open a normal issue that says only *"security report, please advise how
to reach you privately"* — no details, no proof-of-concept — and wait for a reply with a private channel, rather than
describing the issue in public.

Please **do not** open a public issue or pull request that describes an unpatched vulnerability, or post it anywhere
else, before a fix is available.

**What to include**, as far as you can:

- the affected file(s)/function(s) or endpoint
- the version or commit you tested
- steps to reproduce, or a minimal proof of concept
- what an attacker gains (the impact), not just that something looks wrong

**Response**: this is a one-person open-source project, maintained in spare time — there is no contractual SLA. In
good faith, expect an acknowledgement within about a week and a fix or a public response once one is ready. Slow is
not the same as ignored.

## What is in scope

Roughly: anything that lets data or code from **the network being scanned**, or from **the local web UI's HTTP
requests**, do something Nemla did not intend. Examples:

- a banner, certificate, hostname, or any other network-supplied value causing a crash, memory/CPU exhaustion, path
  traversal, log/report injection, or code execution
- a way to reach the local web server's `/api/*` endpoints, read a saved scan, or trigger a scan without the
  per-launch token, from a page that isn't Nemla's own (CSRF, DNS rebinding, XSS, CORS)
- unsafe deserialization, `eval`/`exec`/`pickle` reachable from untrusted input, or shell injection anywhere in the
  codebase
- a saved report (HTML/CSV/Markdown/SARIF) that executes something when opened, because a field from the network
  was not escaped
- history, report or launcher files written with unsafe permissions, or path handling that can escape the intended
  folder

Nemla's current defenses along these lines are documented in [README.md → Security](README.md#security); a report
that finds a hole in one of them, or a place the same discipline was missed, is exactly what this policy is for.

## What is out of scope

- Findings Nemla *reports* about a scanned network (an open Redis, a weak TLS config, SMBv1...) — that's the
  product working as intended, not a vulnerability in Nemla.
- Scanning or Guard-mode activity against a network you do not own or have permission to test. Nemla's
  [Responsible use](README.md#responsible-use) policy governs that, and it is on the person running the tool, not a
  bug to report here.
- Denial of service that requires an attacker who can already run arbitrary code on the machine Nemla is running on,
  or who already controls the local network stack Nemla trusts by design (e.g., someone who can already spoof ARP
  on your LAN can naturally confuse ARP-based discovery — that is a property of ARP, not a Nemla bug).
- Missing hardening flags on the *scanned* services Nemla reports about (that's a finding, see above).

## Credit

Reporters who want it are credited by name (or handle) in the fix's commit message and, once there is one, in
`CHANGELOG.md`. Say in your report whether you'd like that, and how to spell it.
