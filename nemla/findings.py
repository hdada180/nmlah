"""The findings engine: what a scan result means, backed by evidence.

Every finding says what was observed (`evidence`), how sure Nemla is
(`confidence`), where (`host`, `port`, `proto`) and what to do (`remediation`).
A finding is only raised when the scan actually observed something: a
version banner, a protocol reply, a certificate field. A port number alone
gives a low-confidence finding one severity step lower, and is labelled as
such. Nothing here logs in, exploits or tests a vulnerability.

Findings are language-neutral (`id` + `params`); `render()` adds the
localized `title`, `description` and `remediation`.
"""
from __future__ import annotations

from .fingerprint.rules import OLD_TLS
from .i18n import t
from .net import is_external
from .targets import parse_ports

SEVERITIES = ("info", "low", "medium", "high")
SEV_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

_REMOTE_PORTS = {1723, 3389, 5900, 5901, 5902, 5985, 5986, 6000}
_DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 5984, 9042}
_FILE_PORTS = {111, 135, 139, 445, 2049}
_SENSITIVE = {2375: "Docker Engine API", 2379: "etcd", 4243: "Docker Engine API", 10250: "Kubelet API",
              8500: "Consul", 8161: "ActiveMQ console", 15672: "RabbitMQ management", 7001: "WebLogic",
              6443: "Kubernetes API", 9000: "Portainer / PHP-FPM", 5601: "Kibana"}
_AMPLIFIERS = {"ssdp": "SSDP", "ntp": "NTP", "memcached": "Memcached", "netbios-ns": "NetBIOS", "snmp": "SNMP",
               "dns": "DNS", "tftp": "TFTP", "rpcbind": "RPCBind"}
_CLEARTEXT_AUTH = {"PLAIN", "LOGIN"}


def _lower(severity: str) -> str:
    return SEVERITIES[max(0, SEV_RANK[severity] - 1)]


def _sev(base: str, confidence: float) -> str:
    """One step lower when the evidence is weak (a port number and nothing else)."""
    return _lower(base) if confidence < 0.6 else base


def _ports_scanned(spec) -> set:
    try:
        return set(parse_ports(spec)) if spec else set()
    except ValueError:
        return set()


def _confidence(port: dict, cap: float = 0.95) -> float:
    return min(cap, float(port.get("confidence", 0.5)))


def assess_host(host: dict) -> list:
    """The findings for one host record. Sorted by severity, then port."""
    ip = host["ip"]
    external = is_external(ip)
    scanned_tcp = _ports_scanned((host.get("scanned") or {}).get("tcp"))
    found = []

    def add(fid, severity, port=None, proto="tcp", confidence=0.9, evidence="", **params):
        found.append({"id": fid, "severity": severity, "host": ip, "port": port, "proto": proto,
                      "confidence": round(confidence, 2), "evidence": evidence, "params": params})

    ports = host.get("open_ports", [])
    web_plain, web_tls = [], False
    for p in ports:
        n, proto = p["port"], p.get("proto", "tcp")
        if p.get("state", "open") != "open":
            continue
        service, detected = p.get("service", ""), p.get("detected", "")
        tls = p.get("tls") or {}
        details = p.get("details") or {}
        # records without `detected` come from older scans (or --no-banner): what the service is
        # rests on the port number alone, which is worth less than a protocol reply
        by_port = "detected" not in p or bool(p.get("heuristic"))
        conf = (0.5 if "detected" in p else 0.8) if by_port else _confidence(p)
        where = f"{n}/{proto}"
        basis = "port number only: " if by_port else ""

        # -- exposure of risky services -------------------------------------
        if proto == "tcp":
            if detected == "telnet" or (n == 23 and by_port):
                add("telnet", _sev("high", conf), n, confidence=conf,
                    evidence=basis + (p.get("evidence") or f"Telnet on {where}"))
            elif detected == "ftp" or (n == 21 and by_port):
                base = "high" if external else "medium"
                if details.get("starttls"):
                    base = _lower(base)
                add("ftp", _sev(base, conf), n, confidence=conf,
                    evidence=basis + (p.get("evidence") or f"FTP on {where}")
                    + ("; AUTH TLS offered but clear-text login still accepted" if details.get("starttls") else ""))
            elif p.get("auth") == "none" and (detected == "redis" or (by_port and n == 6379)):
                add("redis_open", "high", n, confidence=max(conf, 0.9),
                    evidence="PING answered +PONG without a password")
            elif p.get("auth") == "none" and (detected == "memcached" or (by_port and n == 11211)):
                add("memcached", "high", n, confidence=max(conf, 0.9),
                    evidence="the `version` command was answered without authentication")
            elif p.get("auth") == "none" and (p.get("product") == "Elasticsearch" or (by_port and n == 9200)):
                add("es_open", "high", n, confidence=0.95, evidence="GET / returned cluster information without a login")
            elif n in _REMOTE_PORTS or detected in ("rdp", "vnc"):
                add("remote", _sev("high" if external else "medium", conf), n, confidence=conf,
                    evidence=basis + (p.get("evidence") or f"{service or 'remote access'} reachable on {where}"), service=service)
            elif n in _DB_PORTS or detected in ("mysql", "postgresql", "redis", "memcached"):
                add("db", _sev("high" if external else "medium", conf), n, confidence=conf,
                    evidence=basis + (p.get("evidence") or f"{service or 'database'} reachable on {where}"), service=service)
            elif n in _FILE_PORTS or detected == "smb":
                add("files", _sev("high" if external else "low", conf), n, confidence=conf,
                    evidence=basis + (p.get("evidence") or f"{service or 'file sharing'} reachable on {where}"), service=service)
            elif n in _SENSITIVE and by_port:
                add("sensitive_port", "high" if external else "low", n, confidence=0.4,
                    evidence=f"port {n} is usually {_SENSITIVE[n]}; the service was not confirmed", name=_SENSITIVE[n])
        elif detected in _AMPLIFIERS and external:
            add("udp_exposed", "medium", n, "udp", conf, f"{_AMPLIFIERS[detected]} answered from a public address",
                service=_AMPLIFIERS[detected])
        if proto == "udp" and detected == "memcached":
            add("memcached", "high", n, "udp", 0.97, "the `version` command was answered over UDP without authentication")
        if detected == "snmp":
            add("snmp_default", "high" if external else "medium", n, "udp", 0.95,
                'answered a read with the default community "public"')
        if detected == "tftp":
            add("tftp", "medium", n, "udp", 0.9, "answered a read request (TFTP has no authentication)")

        # -- protocol details ------------------------------------------------
        if detected == "ssh":
            protocol = str(details.get("protocol") or "")
            if protocol.startswith("1.") and protocol != "1.99":
                add("ssh_protocol1", "high", n, confidence=0.95,
                    evidence=f"banner announces protocol {protocol}", version=protocol)
            elif protocol == "1.99":
                add("ssh_protocol1", "medium", n, confidence=0.9,
                    evidence="banner announces protocol 1.99 (SSH-1 still accepted)", version=protocol)
            weak = details.get("weak_algorithms") or []
            if weak:
                strong = any(w.split(":", 1)[1] in ("none", "arcfour", "arcfour128", "arcfour256", "des-cbc") for w in weak)
                add("ssh_weak_crypto", "medium" if strong else "low", n, confidence=0.9,
                    evidence="offered in the server's key-exchange proposal: " + ", ".join(weak[:6]),
                    list=", ".join(w.split(":", 1)[1] for w in weak[:5]))
        if detected == "smb":
            if details.get("smb1"):
                add("smb1", "high", n, confidence=0.95, evidence="an SMBv1-only negotiation was accepted")
            if details.get("signing") in ("enabled", "disabled"):
                add("smb_signing", "medium", n, confidence=0.9,
                    evidence=f"SMB signing is {details['signing']} but not required")
        if detected == "rdp":
            if details.get("weak_security"):
                add("rdp_weak_security", "high", n, confidence=0.9, evidence=p.get("evidence", ""))
            elif details.get("nla") == "not required":
                add("rdp_no_nla", "medium", n, confidence=0.85, evidence=p.get("evidence", ""))
        if detected == "dns" and details.get("recursion_available") and proto == "tcp":
            add("dns_recursion", "medium" if external else "low", n, proto, 0.6,
                "the RA (recursion available) flag is set in the reply")
        if detected == "smtp" and not p.get("tls"):
            auth = {a.upper() for a in details.get("auth_mechanisms", [])}
            if auth & _CLEARTEXT_AUTH and details.get("starttls") is False:
                add("smtp_plain_auth", "medium", n, confidence=0.85,
                    evidence=f"AUTH {' '.join(sorted(auth & _CLEARTEXT_AUTH))} offered without STARTTLS")
            elif details.get("starttls") is False:
                add("smtp_no_starttls", "low", n, confidence=0.8, evidence="EHLO reply does not offer STARTTLS")
        if detected in ("pop3", "imap") and not p.get("tls") and details.get("starttls") is False:
            add("mail_plain", "medium", n, confidence=0.8,
                evidence=f"{service} without STARTTLS: passwords travel in clear text", service=service)

        # -- web -------------------------------------------------------------
        if p.get("status"):
            if tls or details.get("tls"):
                web_tls = True
            elif n != 9200:
                web_plain.append(p)
            if details.get("admin") or p.get("details", {}).get("admin"):
                add("admin_panel", "medium" if external else "low", n, confidence=0.75,
                    evidence=details.get("admin_evidence", ""), name=details["admin"])
            wa = (details.get("www_authenticate") or p.get("www_authenticate") or "").lower()
            if wa.startswith("basic") and not tls:
                add("basic_auth_plain", "high" if external else "medium", n, confidence=0.95,
                    evidence=f"HTTP {p['status']} with WWW-Authenticate: Basic over an unencrypted connection")

        # -- TLS -------------------------------------------------------------
        if tls:
            web_tls = web_tls or bool(p.get("status"))
            days = tls.get("days_left")
            if tls.get("expired") or (days is not None and days < 0):
                add("tls_expired", "high", n, confidence=0.98,
                    evidence=f"certificate notAfter {tls.get('not_after', '?')}", days=-(days or 0))
            elif days is not None and days < 30:
                add("tls_expiring", "medium", n, confidence=0.98,
                    evidence=f"certificate notAfter {tls.get('not_after', '?')}", days=days)
            if tls.get("not_yet_valid"):
                add("tls_not_yet_valid", "medium", n, confidence=0.9,
                    evidence=f"certificate notBefore {tls.get('not_before', '?')} is in the future")
            old = tls.get("legacy") or ([tls["version"]] if tls.get("version") in OLD_TLS else [])
            if old:
                add("tls_old", "medium", n, confidence=0.95,
                    evidence="handshake completed with " + ", ".join(old), version=", ".join(old))
            if tls.get("self_signed"):
                add("tls_selfsigned", "low", n, confidence=0.95, evidence="subject and issuer are identical")
            if tls.get("weak_sig"):
                add("tls_weak_sig", "medium", n, confidence=0.95,
                    evidence=f"signature algorithm {tls.get('sig_alg', '?')}", alg=tls.get("sig_alg", "?"))
            if tls.get("key_type") == "RSA" and 0 < int(tls.get("key_bits") or 0) < 2048:
                add("tls_weak_key", "medium", n, confidence=0.95,
                    evidence=f"RSA key of {tls['key_bits']} bits", bits=tls["key_bits"], keytype="RSA")
        if p.get("product") and p.get("version") and proto == "tcp":
            add("version", "info", n, confidence=conf, evidence=f"{p['product']} {p['version']}",
                product=p["product"], version=p["version"])

    # HTTP without HTTPS, but only when HTTPS was really looked for and not found
    if web_plain and not web_tls and ((443 in scanned_tcp) or (8443 in scanned_tcp)):
        p = web_plain[0]
        if not (p.get("details") or {}).get("redirects_to_https") and not str(p.get("location", "")).lower().startswith("https://"):
            checked = ", ".join(f"{x}/tcp" for x in (443, 8443) if x in scanned_tcp)
            add("http_plain", "low", p["port"], confidence=0.8,
                evidence=f"HTTP {p['status']} served without TLS; {checked} scanned and no TLS web service found")

    for f in found:
        render(f)
    return sorted(found, key=lambda f: (-SEV_RANK[f["severity"]], f["port"] or 0, f["proto"], f["id"]))


def render(finding: dict, lang=None) -> dict:
    """Fill (or refresh) title, description and remediation in `lang` (default: the active language)."""
    params = dict(finding.get("params") or {})
    params.setdefault("port", finding.get("port"))
    params.setdefault("host", finding.get("host"))
    fid = finding["id"]
    finding["title"] = t("f_" + fid, lang=lang, **params)
    finding["description"] = t("fd_" + fid, lang=lang, **params)
    finding["remediation"] = t("fr_" + fid, lang=lang, **params)
    return finding


def finding_text(finding: dict) -> str:
    """The one-line title of a finding in the active language."""
    params = dict(finding.get("params") or {})
    params.setdefault("port", finding.get("port"))
    return t("f_" + finding["id"], **params)


def localized(findings, lang=None) -> list:
    """Copies of `findings` rendered in `lang` (reports may use another language than the scan)."""
    return [render(dict(f), lang) for f in findings]


def summarize_findings(hosts: list) -> dict:
    counts = dict.fromkeys(SEVERITIES, 0)
    for host in hosts:
        for finding in host.get("findings", []):
            counts[finding["severity"]] += 1
    return counts
