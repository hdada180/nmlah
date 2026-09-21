"""Nemla (نملة) - lightweight network reconnaissance, service intelligence and defensive monitoring.

The package is split by job (see docs/architecture.md):

    targets      what to scan (IPv4/IPv6, ranges, names, ports)
    discovery/   who is up (ARP, ICMP, TCP)
    scanning/    the bounded scheduler, TCP connect scans, UDP probes
    fingerprint/ one small detector per protocol, TLS and certificate inspection
    os_detection operating-system guess with confidence and evidence
    findings     security findings backed by evidence
    reports/     HTML, JSON, CSV, Markdown, SARIF
    history/diff saved scans and what changed between them
    guard        defensive monitoring (decoy ports, unknown devices, ARP changes)
    engine       the pipeline that ties it together; cli/main are the command line

This module re-exports the public names that Nemla 1 had in the single file
`nemla.py`, so `import nemla; nemla.parse_targets(...)` keeps working.

Only scan systems and networks you own or have explicit permission to test.
"""
from __future__ import annotations

import socket
import sys
import time
import types

from . import i18n as _i18n
from . import log as _log
from .cli import (LOGO_GRADIENT, LOGO_LINES, alert_text, banner_text, build_parser, fancy_output_ok,  # noqa: F401
                  launch_ui, main, parse_interval, print_banner, run_diff, run_guard, run_watch, scan_inputs)
from .config import (COMMON_SERVICE_NAMES, DISCOVERY_PORTS, HTTP_PORTS, TLS_PORTS, TOP_PORTS, UDP_PORTS,  # noqa: F401
                     ScanOptions, __version__)
from .diff import diff_lines, diff_scans  # noqa: F401
from .discovery import HAVE_SCAPY, discover_hosts, get_ttl, icmp_ping, mac_vendor, tcp_ping  # noqa: F401
from .discovery.arp import parse_arp_table, read_arp_table  # noqa: F401
from .discovery.mac import _MAC_PREFIXES, mac_is_local  # noqa: F401
from .discovery.ping import ping_cmd as _ping_cmd  # noqa: F401
from .engine import run_scan  # noqa: F401
from .findings import (SEV_RANK, SEVERITIES, assess_host, finding_text, summarize_findings)  # noqa: F401
from .fingerprint import detect_service, identify, service_name  # noqa: F401
from .fingerprint.base import Detection, Detector, Probe  # noqa: F401
from .fingerprint.databases import mysql_greeting
from .fingerprint.rules import banner_os_hint, parse_banner  # noqa: F401
from .fingerprint.tls import inspect_tls
from .history import load as load_scan  # noqa: F401
from .i18n import RTL_LANGS, STRINGS, t  # noqa: F401
from .log import Diagnostics, log  # noqa: F401
from .net import clean_text, is_external as _is_external  # noqa: F401
from .os_detection import guess_os, guess_os_detailed  # noqa: F401
from .reports import (BRAND_MARK, HTML_TEMPLATE, csv_text, json_text, markdown_text, render_html,  # noqa: F401
                      sarif_text, write_csv, write_json)
from .scanning.scheduler import imap as _pool_map  # noqa: F401
from .scanning.tcp import scan_host_ports, scan_port  # noqa: F401
from .scanning.udp import scan_udp_port  # noqa: F401
from .targets import format_ports, iter_targets, parse_ports, parse_targets  # noqa: F401


def _mysql_product(raw: bytes):
    """(product, version) of a MySQL/MariaDB greeting packet, or (None, None). Kept from Nemla 1."""
    greeting = mysql_greeting(raw)
    return (greeting[0], greeting[1]) if greeting else (None, None)


def tls_probe(ip: str, port: int, timeout: float = 1.5, http: bool = False):
    """Handshake with a port. Returns (tls facts, extra) like Nemla 1; (None, {}) if it is not TLS.

    `extra["http"]` carries the web page details when `http` is true, and `extra["greeting"]`
    the mail greeting on the implicit-TLS mail ports."""
    from .fingerprint.http import parse_http
    probe = Probe(ip, port, timeout)
    info = inspect_tls(probe)
    if info is None:
        return None, {}
    extra = {}
    inner = probe.derive(tls=True)
    if http:
        data = inner.ask(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: Nemla\r\n\r\n", 8192)
        web = parse_http(data)
        if web:
            extra["http"] = {k: v for k, v in web.items() if k not in ("headers", "status_line")}
    elif port in (465, 993, 995):
        from .fingerprint.rules import one_line
        try:
            with inner.connect() as conn:
                extra["greeting"] = one_line(conn.read(256, 0.8, until=lambda d: d.endswith(b"\n")))
        except OSError:
            pass
    return info, extra


__all__ = [
    "alert_text",
    "assess_host",
    "banner_os_hint",
    "banner_text",
    "BRAND_MARK",
    "build_parser",
    "clean_text",
    "COMMON_SERVICE_NAMES",
    "csv_text",
    "detect_service",
    "Detection",
    "Detector",
    "Diagnostics",
    "diff_lines",
    "diff_scans",
    "discover_hosts",
    "DISCOVERY_PORTS",
    "fancy_output_ok",
    "finding_text",
    "format_ports",
    "get_ttl",
    "guess_os",
    "guess_os_detailed",
    "HAVE_SCAPY",
    "HTML_TEMPLATE",
    "HTTP_PORTS",
    "icmp_ping",
    "identify",
    "inspect_tls",
    "iter_targets",
    "json_text",
    "launch_ui",
    "load_scan",
    "log",
    "LOGO_GRADIENT",
    "LOGO_LINES",
    "mac_is_local",
    "mac_vendor",
    "main",
    "markdown_text",
    "mysql_greeting",
    "parse_arp_table",
    "parse_banner",
    "parse_interval",
    "parse_ports",
    "parse_targets",
    "print_banner",
    "Probe",
    "read_arp_table",
    "render_html",
    "RTL_LANGS",
    "run_diff",
    "run_guard",
    "run_scan",
    "run_watch",
    "sarif_text",
    "scan_host_ports",
    "scan_inputs",
    "scan_port",
    "scan_udp_port",
    "ScanOptions",
    "service_name",
    "SEV_RANK",
    "SEVERITIES",
    "socket",
    "STRINGS",
    "summarize_findings",
    "t",
    "tcp_ping",
    "time",
    "TLS_PORTS",
    "tls_probe",
    "TOP_PORTS",
    "UDP_PORTS",
    "write_csv",
    "write_json",
    "__version__",
    "_is_external",
    "_MAC_PREFIXES",
    "_mysql_product",
    "_ping_cmd",
    "_pool_map",
]


class _Facade(types.ModuleType):
    """Lets `nemla._LANG = 'ar'` and `nemla._LOG_SINK = ...` keep working: they live in i18n / log."""

    @property
    def _LANG(self):
        return _i18n._LANG

    @_LANG.setter
    def _LANG(self, value):
        _i18n._LANG = value

    @property
    def _LOG_SINK(self):
        return _log.get_sink()

    @_LOG_SINK.setter
    def _LOG_SINK(self, value):
        _log.set_sink(value)


sys.modules[__name__].__class__ = _Facade
