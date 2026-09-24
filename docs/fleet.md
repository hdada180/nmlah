# Fleet mode: one controller, several networks

Fleet mode is for one situation: **you are authorised to scan several networks** (your employer's, your clients') and want
to watch them from one place. Each network gets an **agent**, a Nemla process that runs *inside* that network. One
**controller** hands the agents scans to run and collects what they found. There is a command line, a JSON API and one
page in the browser.

```
   you ── nemla controller … / the Fleet page ──►  CONTROLLER  ◄── HTTPS, agent connects OUT ──  agent (site A)
        (loopback only, needs the operator key)   stores results   (TLS 1.2+, certificate pinned)  agent (site B)
```

Fleet mode is **reconnaissance only**. It is deliberately not a remote-administration tool: see [What it will never
do](#what-it-will-never-do).

## The rules that cannot be switched off

Each of these is a property of the code, not a setting, and each has a test (`tests/test_fleet_*.py`).

| Rule | What it means |
| --- | --- |
| **The network owner sets the scope** | An agent has a scope (addresses and CIDR blocks) written on *its own machine* when it is enrolled. The controller can only send jobs inside it, cannot widen it, and the agent checks every job against it again, on the resolved addresses, whatever the controller believed. |
| **Enrolling is local and explicit** | The controller makes a one-time token (valid 15 minutes, used once, stored only as a hash). Someone at the agent's machine runs `nemla agent enroll`. Nothing can be installed or enrolled remotely, and nothing can register itself. |
| **Jobs are data, never code** | A job is `target`, `ports` and a short list of scan options. Anything else is refused. Targets are literal addresses, CIDR blocks or ranges, never names. The agent's only action is Nemla's own scan function: no commands, scripts, plugins, file transfer or updates. A test scans the Fleet source for anything that could run text as code or start a process. |
| **Revocation is immediate, on both sides** | `controller revoke` makes every request from that agent fail and drops its queued jobs; a scan already running is told to stop and its result is discarded. `agent leave` deletes the credentials on the agent's machine. Both are audited. |
| **Everything is audited, and the audit fails closed** | Enrollments, dispatches (who, what target, what options), starts, results, revocations and every refusal are appended to a log. If the log cannot be written, the action is refused. Secrets and tokens are never written to it. |
| **The agent connects out, encrypted, to a pinned certificate** | No agent listens on anything. The controller refuses to listen beyond this machine without TLS; the agent refuses a controller whose certificate's SHA-256 differs from the one recorded at enrollment, and checks it **before** it sends a token, a secret or a result. |

## Try it on one machine (no TLS, loopback only)

```bash
nemla controller serve
```

It prints the port agents connect to and a link to the Fleet page. In a second terminal:

```bash
nemla controller enroll-token acme-hq
nemla agent enroll http://127.0.0.1:8443 --token PASTE_THE_TOKEN --scope 127.0.0.0/24
nemla agent run
```

And in a third:

```bash
nemla controller agents
nemla controller dispatch acme-hq 127.0.0.1 -p 22,80,443 --no-os
nemla controller jobs
nemla controller results acme-hq
nemla controller audit
nemla controller revoke acme-hq
```

`--data-dir DIR` on any command keeps the controller's files under `DIR/fleet` and the agent's under `DIR/agent`, which is
handy for trying several agents on one computer.

## A real deployment

### 1. A certificate for the controller

Agents pin the certificate itself, so it can be self-signed; there is no certificate authority to run and no host name to
match. One command (OpenSSL 1.1.1 or newer):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=nemla-controller" -keyout key.pem -out cert.pem
```

(In Git Bash on Windows, which rewrites an argument that starts with `/` into a file path, put `MSYS_NO_PATHCONV=1` in front;
PowerShell and Command Prompt need nothing.) Keep `key.pem` on the controller, readable only by its user. Agents do not check the expiry date (the pin is the trust
anchor), so a long lifetime is fine. **A new certificate has a new fingerprint and every agent will refuse it until it is
enrolled again**; renew on purpose, not by accident.

### 2. Run the controller

```bash
nemla controller serve --host 0.0.0.0 --port 8443 --tls-cert cert.pem --tls-key key.pem
```

It prints the certificate fingerprint (`sha256:…`). Without `--tls-cert` and `--tls-key` it will not listen on anything
but this machine. The page and the API for you, the operator, always stay on `127.0.0.1` (choose the port with
`--operator-port`); reach them over an SSH tunnel if the controller is elsewhere, and never publish that port.

### 3. Enroll an agent, on the agent's machine

```bash
nemla controller enroll-token paris-office                 # on the controller
nemla agent enroll https://controller.example:8443 --token TOKEN --scope 10.20.0.0/16 --pin sha256:FINGERPRINT
nemla agent run
```

`--scope` is the only place the scope is set, and it is *this machine's* decision. `--max-hosts` (default 1024) and
`--max-minutes` (default 60) are the agent's own ceilings for one job. `nemla agent status` shows what the agent is set up
to do; `nemla agent leave` removes its credentials. Run `nemla agent run` under your usual service manager: it retries with
a back-off when the controller is unreachable and ends by itself if it is revoked or the certificate changes.

## The Fleet page

`nemla controller serve` prints a link like `http://127.0.0.1:PORT/#k=…`. The part after `#k=` is the operator key; it never
leaves your browser (a fragment is not sent to the server), the page removes it from the address bar and keeps it for the
tab only. Anyone with that key can queue scans and revoke agents from this computer, so treat the link like a password.

The page lists the agents (status, scope, last seen), queues a scan (the controller refuses a target outside the agent's
scope and says so), revokes an agent (two clicks), shows each job with its result and **what changed since the previous scan of
the same target**, and shows the audit trail. **Add agent** makes a token and the exact `nemla agent enroll` command to run,
with the fingerprint filled in. English and Arabic; the Arabic text has not yet been reviewed by a native speaker (see
[translation-review.md](translation-review.md)).

## What is kept, and where

| Where | What | Notes |
| --- | --- | --- |
| `DATA/fleet/agents.json`, `enrollment.json` | Enrolled agents and pending tokens | Secrets and tokens are stored only as SHA-256 hashes |
| `DATA/fleet/operator.token` | The operator key | Owner-only |
| `DATA/fleet/audit.jsonl` | The audit trail | Append-only; rotated to a new, never-overwritten name when large |
| `DATA/fleet/agents/<id>/` | That agent's scans | The ordinary Nemla history, so comparisons, pruning and exports work as usual |
| `DATA/agent/agent.json` | The agent's credentials and its own scope | Owner-only: whoever can read it can impersonate the agent until it is revoked |
| `DATA/agent/audit.jsonl` | What this agent was asked, and what it refused | Separate from the controller's, so the two can be compared |

`DATA` is Nemla's usual data folder (or `--data-dir`). Files are created owner-only (`0600`, folders `0700`) on POSIX systems.

## Limits, so you can plan

- **50 agents** per controller (each long-polling agent holds a connection), **8 queued jobs** per agent, one job at a time per agent.
- A job is at most 4096 addresses (an agent's own limit is lower by default), 8 KiB of text; a result at most 32 MiB.
- A queued job that nobody collects expires after an hour; a collected job with no result expires after six hours.
- **Jobs are held in the controller's memory**: restarting it forgets queued and running jobs (finished scans and the audit
  trail are on disk). Agents reconnect by themselves.
- An agent is shown as *online* if it polled in the last 75 seconds.
- One controller, no failover.

## Threat model: what an attacker gets

| If the attacker has… | They can… | They cannot… |
| --- | --- | --- |
| **the controller's machine** | Queue scans inside each agent's own scope; read every stored scan (sensitive: protect this machine like the data it holds); revoke agents | Run a command or read a file on any agent, widen a scope, install anything, or make an agent talk to a different server |
| **an agent's `agent.json`** | Pose as that agent: collect jobs meant for it and send made-up results (treated as untrusted data: size-limited, stored under the controller's own target, shown as text) | Do anything else; revoking the agent cuts it off at once |
| **a token** (within 15 minutes, before the real agent uses it) | Enroll an agent of their own under that name, with a scope of their choosing | Reuse it, or get anything from the controller except what an enrolled agent gets. Pass tokens over a channel you trust |
| **the operator key** | Queue scans and revoke agents (loopback only, so they need to be on the controller's machine already) | Reach the agents' machines, or change an agent's scope |
| **the network between them** | See that an agent talks to the controller | Read or change anything (TLS 1.2+); impersonate the controller (pinned certificate, checked before anything is sent) |
| **a hostile agent (compromised machine)** | Send huge or malformed results | Exhaust the controller (bodies, uploads and connections are bounded) or inject markup into the page (text only) |

## What it will never do

Remote shell or command execution, file transfer, updating or installing anything on an agent, plugins pushed to agents,
controlling the Guard remotely, a scope managed from the controller, hiding from the person who owns the agent's machine, or
starting itself again after `agent leave`. If you need central control of scope, that changes who holds the authority to scan
and deserves a separate design and a separate conversation, not a flag.

## What has and has not been verified

The controller, the agent, the CLI and the page are covered by tests that use real sockets, real TLS with a pinned
certificate, and a real scan of a local listener. Every safety rule above was also checked by breaking it on purpose and
confirming a test fails. Windows is where they were run during development; the owner-only file permission checks are POSIX
tests that run on Linux in CI. The Arabic page text is machine-written and unreviewed.
