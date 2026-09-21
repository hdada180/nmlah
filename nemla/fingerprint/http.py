"""HTTP and HTTPS: status, server product, page title, admin consoles, redirects.

Only one ordinary `GET /` is sent. Replies are read with a hard size and time
limit, headers are capped, and everything that reaches the report is cleaned.
"""
from __future__ import annotations

import re

from ..config import HTTP_PORTS, __version__
from ..net import clean_text
from .base import CONFIDENCE, Detection, Detector, Probe, register
from .rules import banner_os_hint, parse_banner

HTTP_LIMIT = 24 * 1024       # bytes of a response we are willing to read
MAX_HEADERS = 64

# (label, where to look, pattern): consoles that should not be reachable by everyone
_ADMIN = (
    ("phpMyAdmin", "title", r"phpMyAdmin"),
    ("Jenkins", "header", r"^x-jenkins$"),
    ("Grafana", "title", r"^Grafana"),
    ("Kibana", "title", r"Kibana"),
    ("Portainer", "title", r"Portainer"),
    ("Webmin", "server", r"MiniServ"),
    ("Proxmox VE", "title", r"Proxmox Virtual Environment"),
    ("Zabbix", "title", r"Zabbix"),
    ("Nagios", "title", r"Nagios"),
    ("RabbitMQ Management", "title", r"RabbitMQ Management"),
    ("Consul", "title", r"Consul by HashiCorp"),
    ("Traefik dashboard", "title", r"Traefik"),
    ("Adminer", "title", r"Adminer"),
    ("pgAdmin", "title", r"pgAdmin"),
    ("Cockpit", "title", r"Cockpit"),
    ("Apache Tomcat", "title", r"Apache Tomcat"),
    ("SonarQube", "title", r"SonarQube"),
    ("Router administration", "title", r"RouterOS|Router (?:Login|Admin)|OpenWrt|LuCI"),
)


def parse_http(data: bytes) -> dict:
    """Facts from an HTTP response, or {} if `data` is not one."""
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
    lines = re.split(r"\r?\n", head[:8192].decode("latin-1", "replace"))[:MAX_HEADERS]
    m = re.match(r"HTTP/(\d\.\d)\s+(\d{3})", lines[0]) if lines else None
    if not m:
        return {}
    out = {"status": int(m.group(2)), "status_line": clean_text(lines[0], 80)}
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()[:40]] = clean_text(value, 200)
    for key, label, limit in (("server", "server", 80), ("x-powered-by", "powered_by", 60),
                              ("location", "location", 120), ("www-authenticate", "www_authenticate", 100)):
        if headers.get(key):
            out[label] = headers[key][:limit]
    out["headers"] = headers
    page = body[:HTTP_LIMIT].decode("utf-8", "replace")
    title = re.search(r"<title[^>]{0,200}>(.{0,400}?)</title>", page, re.I | re.S)
    if title:
        out["title"] = clean_text(title.group(1), 80)
    version = re.search(r'"number"\s*:\s*"([\d.]+)"', page)
    if version and '"cluster_name"' in page:
        out["elasticsearch"] = version.group(1)
    return out


def admin_console(web: dict):
    """The name of an administration console the response shows, or None (with the evidence)."""
    for label, where, pattern in _ADMIN:
        if where == "title" and re.search(pattern, web.get("title", ""), re.I):
            return label, f"page title: {web['title']}"
        if where == "server" and re.search(pattern, web.get("server", ""), re.I):
            return label, f"Server: {web['server']}"
        if where == "header" and any(re.search(pattern, key) for key in web.get("headers", {})):
            return label, "response header " + next(k for k in web["headers"] if re.search(pattern, k))
    return None


@register
class Http(Detector):
    name = "http"
    label = "HTTP"
    ports = tuple(sorted(HTTP_PORTS | {9200, 3000, 5000, 8008, 9000, 9090}))
    rarity = 1
    tls_capable = True

    def probe(self, probe: Probe):
        request = (f"GET / HTTP/1.0\r\nHost: {probe.ip}\r\nUser-Agent: Nemla/{__version__}\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n").encode()
        data = probe.ask(request, HTTP_LIMIT, probe.timeout + 0.5,
                         until=lambda d: len(d) >= HTTP_LIMIT or b"</title>" in d.lower())
        return self.build(probe, parse_http(data)) if data.startswith(b"HTTP/") else None

    def build(self, probe: Probe, web: dict):
        if not web:
            return None
        server = web.get("server", "")
        product, version = parse_banner("Server: " + server) if server else (None, None)
        if product is None and server:
            m = re.match(r"([A-Za-z][\w.-]*)(?:/([\w.]+))?", server)
            product, version = (m.group(1), m.group(2)) if m else (None, None)
        extra = {k: web[k] for k in ("status", "title", "location", "powered_by", "www_authenticate")
                 if web.get(k)}
        if web.get("elasticsearch"):
            product, version = "Elasticsearch", web["elasticsearch"]
            extra["auth"] = "none" if web.get("status") == 200 else "required"
        admin = admin_console(web)
        if admin:
            extra["admin"], extra["admin_evidence"] = admin
        if (web.get("location") or "").lower().startswith("https://"):
            extra["redirects_to_https"] = True
        banner = web["status_line"] + (f" | Server: {server}" if server else "")
        confidence = CONFIDENCE["exact"] if product and version else CONFIDENCE["protocol"]
        return Detection(
            "http", "HTTPS" if probe.tls else "HTTP", product or "", version or "", confidence,
            "protocol", f"HTTP {web['status']} response", banner[:120],
            banner_os_hint(f"{server} {web.get('powered_by', '')}") or "", probe.tls, extra)
