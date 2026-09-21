# Integration lab: real Samba and xrdp

SMB and RDP detection is unit tested against captured replies (`tests/test_fingerprint.py`); this lab checks it against **real
servers**. Nothing here needs the public Internet, credentials or secrets: Samba serves a read-only guest share, xrdp is only ever
asked to negotiate a connection, and nobody logs in.

## Run it (Docker)

```bash
docker compose -f tests/integration/docker-compose.yml up -d --build
NEMLA_INTEGRATION=1 python -m pytest -m integration tests/integration -v
docker compose -f tests/integration/docker-compose.yml down
```

The compose file starts six containers on `127.0.0.1` only:

| name | what | port |
|---|---|---|
| smb | Samba, SMB2/3, signing offered but not required (the default) | 14445 |
| smb-signing | Samba, `server signing = mandatory` | 14446 |
| smb1 | Samba with SMBv1 switched on (a throw-away container: never do this for real) | 14447 |
| rdp | xrdp, `security_layer=negotiate` | 13389 |
| rdp-legacy | xrdp, standard RDP security only (weak) | 13390 |
| rdp-tls | xrdp, TLS only (no NLA: xrdp has no CredSSP) | 13391 |

The CI job `integration` does exactly these three commands, so the documented procedure is the tested one. Without
`NEMLA_INTEGRATION=1` these tests are skipped and say why.

## What is verified

* **SMB**: detection, dialect, signing offered / required / off, SMBv1 on / off and the findings that follow (`smb_signing`, `smb1`),
  identification inside a full scan (on a non-standard port), timeouts and cancellation.
* **RDP**: detection and identification by protocol on a non-standard port, standard RDP security reported as weak, TLS-only reported as
  "NLA not required", timeouts and cancellation.
* **Damaged answers**: a proxy (`lab.ChaosProxy`) sits between Nemla and the real server and truncates the real reply at 13 offsets,
  flips a byte at 12-14 offsets, replaces the tail with garbage, delays it, or never forwards anything. The detectors must never crash,
  never invent facts from broken data, and stay within their timeouts; a scan that meets a broken server still reports the open port.

## Pointing the tests at your own machines

Set `NEMLA_LAB_SMB`, `NEMLA_LAB_SMB_SIGNING`, `NEMLA_LAB_SMB1`, `NEMLA_LAB_RDP`, `NEMLA_LAB_RDP_LEGACY` and `NEMLA_LAB_RDP_TLS` to
`host:port` (only machines you own or may test). Tests whose server is missing are skipped; the generic tests (detection, damaged
answers, timeouts, cancellation) run against whatever `NEMLA_LAB_SMB` / `NEMLA_LAB_RDP` point at, including a Windows machine:
for example `NEMLA_LAB_SMB=127.0.0.1:445` checks a Windows SMB server (dialect 3.0.2, signing required, SMBv1 off was seen this way).

## Checking NLA against Windows (manual: it needs a Windows machine)

xrdp cannot enforce NLA, so "NLA required" is unit tested against captured replies and checked by hand:

1. On a Windows machine or VM you own, enable Remote Desktop and leave *Require Network Level Authentication* ticked
   (Settings, System, Remote Desktop, Advanced settings).
2. `python nemla.py -t <its address> -p 3389 --no-ping` and open the report: the RDP row must say NLA is required and there must be no
   `rdp_no_nla` finding. Untick the option and scan again: `rdp_no_nla` must appear.
3. For RDP through a firewall you can also run the generic tests against it: `NEMLA_INTEGRATION=1 NEMLA_LAB_RDP=<address>:3389 python -m pytest
   -m integration tests/integration/test_rdp_integration.py -k "not legacy and not tls"`.

## What is not covered

Kerberos / NTLM authentication, share enumeration, anything after the negotiation (Nemla stops there on purpose), and SMB 3.1.1
negotiate contexts (Nemla offers dialects 2.0.2 to 3.0.2, so a server that supports 3.1.1 reports 3.0.2).
