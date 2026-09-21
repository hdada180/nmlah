"""Banner signatures: product, version and operating-system hints.

A banner is text written by the remote machine, so a match is a *claim* the
host makes about itself, not proof. The detectors give such matches a
confidence below certainty and the OS engine treats them as evidence.
"""
from __future__ import annotations

import re

from ..net import clean_text

_VERSION_RULES = (
    (re.compile(r"SSH-[\d.]+-OpenSSH_([\w.]+)"), "OpenSSH"),
    (re.compile(r"SSH-[\d.]+-dropbear_([\w.]+)", re.I), "Dropbear"),
    (re.compile(r"SSH-[\d.]+-libssh[_-]([\w.]+)", re.I), "libssh"),
    (re.compile(r"SSH-[\d.]+-Cisco-([\d.]+)", re.I), "Cisco SSH"),
    (re.compile(r"SSH-[\d.]+-ROSSSH", re.I), "MikroTik RouterOS SSH"),
    (re.compile(r"SSH-[\d.]+-mod_sftp", re.I), "ProFTPD mod_sftp"),
    (re.compile(r"SSH-[\d.]+-(?:Bitvise|WinSSHD)[_ ]?([\d.]+)?", re.I), "Bitvise SSH"),
    (re.compile(r"Server:\s*nginx(?:/([\d.]+))?", re.I), "nginx"),
    (re.compile(r"Server:\s*openresty(?:/([\d.]+))?", re.I), "OpenResty"),
    (re.compile(r"Server:\s*Apache-Coyote(?:/([\d.]+))?", re.I), "Apache Tomcat (Coyote)"),
    (re.compile(r"Server:\s*Apache(?:/([\d.]+))?", re.I), "Apache httpd"),
    (re.compile(r"Server:\s*Microsoft-IIS(?:/([\d.]+))?", re.I), "Microsoft IIS"),
    (re.compile(r"Server:\s*Microsoft-HTTPAPI(?:/([\d.]+))?", re.I), "Microsoft HTTPAPI"),
    (re.compile(r"Server:\s*lighttpd(?:/([\d.]+))?", re.I), "lighttpd"),
    (re.compile(r"Server:\s*Jetty\(?([\d.]+)?", re.I), "Jetty"),
    (re.compile(r"Server:\s*Caddy", re.I), "Caddy"),
    (re.compile(r"Server:\s*Kestrel", re.I), "Kestrel"),
    (re.compile(r"Server:\s*(?:Werkzeug|gunicorn|uvicorn|Twisted|CherryPy|Tornado)(?:TornadoServer)?/?([\d.]+)?", re.I),
     "Python web server"),
    (re.compile(r"Server:\s*uhttpd", re.I), "uhttpd (OpenWrt)"),
    (re.compile(r"Server:\s*MiniServ(?:/([\d.]+))?", re.I), "Webmin (MiniServ)"),
    (re.compile(r"Server:\s*RomPager(?:/([\d.]+))?", re.I), "RomPager"),
    (re.compile(r"Server:\s*(?:mini_httpd|thttpd|Boa|GoAhead-Webs)(?:/([\d.]+))?", re.I), "embedded web server"),
    (re.compile(r"vsFTPd\s+([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD\s+([\d.]+[a-z]?)", re.I), "ProFTPD"),
    (re.compile(r"Pure-FTPd", re.I), "Pure-FTPd"),
    (re.compile(r"FileZilla Server(?: version)?\s*([\d.]+)?", re.I), "FileZilla Server"),
    (re.compile(r"Microsoft FTP Service", re.I), "Microsoft FTP"),
    (re.compile(r"Exim\s+([\d.]+)"), "Exim"),
    (re.compile(r"Sendmail\s+([\d./]+)"), "Sendmail"),
    (re.compile(r"Microsoft ESMTP MAIL Service(?:, Version:\s*([\d.]+))?", re.I), "Microsoft Exchange SMTP"),
    (re.compile(r"OpenSMTPD"), "OpenSMTPD"),
    (re.compile(r"Postfix"), "Postfix"),
    (re.compile(r"qmail", re.I), "qmail"),
    (re.compile(r"Dovecot"), "Dovecot"),
    (re.compile(r"Courier-IMAP|Courier POP3", re.I), "Courier"),
    (re.compile(r"^RFB (\d{3}\.\d{3})"), "VNC (RFB)"),
)

_OS_HINTS = (
    (re.compile(r"Ubuntu", re.I), "Ubuntu Linux"),
    (re.compile(r"Debian|Raspbian", re.I), "Debian Linux"),
    (re.compile(r"CentOS|Red Hat|RHEL|Fedora|Rocky|AlmaLinux|\.el\d", re.I), "Red Hat family Linux"),
    (re.compile(r"Alpine", re.I), "Alpine Linux"),
    (re.compile(r"OpenWrt|uhttpd", re.I), "OpenWrt Linux"),
    (re.compile(r"FreeBSD", re.I), "FreeBSD"),
    (re.compile(r"OpenBSD", re.I), "OpenBSD"),
    (re.compile(r"RouterOS|MikroTik", re.I), "MikroTik RouterOS"),
    (re.compile(r"Win32|Win64|Windows|Microsoft-IIS|Microsoft-HTTPAPI|Microsoft FTP|Microsoft ESMTP", re.I), "Windows"),
)

OLD_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def parse_banner(text: str):
    """(product, version) recognised in a banner, or (None, None)."""
    for rx, product in _VERSION_RULES:
        m = rx.search(text or "")
        if m:
            return product, (m.group(1) if rx.groups and m.group(1) else None)
    return None, None


def banner_os_hint(text: str):
    """The operating system a banner names ('Ubuntu Linux', 'Windows'...), or None."""
    for rx, label in _OS_HINTS:
        if rx.search(text or ""):
            return label
    return None


def printable(text, limit: int) -> str:
    return clean_text(text, limit)


def one_line(data: bytes, limit: int = 100) -> str:
    """The first printable line of a reply, for the banner column of a report."""
    lines = [clean_text(line, limit) for line in data.decode("utf-8", "replace").splitlines()]
    lines = [line for line in lines if line]
    return lines[0] if lines else ""
