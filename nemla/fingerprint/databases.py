"""Databases and caches: Redis, Memcached, MySQL/MariaDB, PostgreSQL.

Each one is identified by a single harmless question (PING, version, the
greeting the server sends by itself, an SSL request). Nothing logs in, reads
data or changes state.
"""
from __future__ import annotations

import re
import struct

from ..net import clean_text
from .base import CONFIDENCE, Detection, Detector, Probe, register
from .rules import banner_os_hint


@register
class Redis(Detector):
    name = "redis"
    label = "Redis"
    ports = (6379,)
    rarity = 3

    def probe(self, probe: Probe):
        pong = probe.ask(b"PING\r\n", 256)
        if pong.startswith(b"+PONG"):
            info = probe.ask(b"INFO server\r\n", 4096, until=lambda d: len(d) > 200 and d.endswith(b"\n"))
            version = re.search(rb"redis_version:([\d.]+)", info)
            system = re.search(rb"os:([^\r\n]{1,60})", info)
            os_text = clean_text(system.group(1), 60) if system else ""
            return Detection(
                "redis", "Redis", "Redis", version.group(1).decode() if version else "",
                CONFIDENCE["exact"] if version else CONFIDENCE["protocol"], "protocol",
                "PING answered +PONG without a password", "+PONG",
                banner_os_hint(os_text) or ("Linux" if os_text.startswith("Linux") else ""), probe.tls,
                {"auth": "none", **({"os": os_text} if os_text else {})})
        if re.match(rb"-(NOAUTH|DENIED|ERR[^\r\n]*(auth|permission|password))", pong, re.I):
            text = clean_text(pong, 80)
            return Detection("redis", "Redis", "Redis", "", CONFIDENCE["protocol"], "protocol",
                             f"PING refused: {text}", text, "", probe.tls, {"auth": "required"})
        return None


@register
class Memcached(Detector):
    name = "memcached"
    label = "Memcached"
    ports = (11211,)
    rarity = 3

    def probe(self, probe: Probe):
        reply = probe.ask(b"version\r\n", 256, until=lambda d: d.endswith(b"\n"))
        m = re.match(rb"VERSION ([\w.+-]{1,30})\r?\n", reply)
        if not m:
            return None
        version = m.group(1).decode()
        return Detection("memcached", "Memcached", "Memcached", version, CONFIDENCE["exact"], "protocol",
                         "version command answered without authentication", f"VERSION {version}", "",
                         probe.tls, {"auth": "none"})


def mysql_greeting(raw: bytes):
    """(product, version, ssl_support, os_hint) from a MySQL/MariaDB greeting packet, or None."""
    if len(raw) < 8 or raw[4] not in (10, 9):
        return None
    end = raw.find(b"\x00", 5)
    if end < 0 or end - 5 > 80:
        return None
    text = raw[5:end].decode("latin-1", "replace")
    m = re.match(r"(?:5\.5\.5-)?(\d+\.\d+\.\d+)", text)
    if not m:
        return None
    version = m.group(1)
    product = "MariaDB" if "mariadb" in text.lower() else "MySQL"
    if product == "MariaDB":
        maria = re.search(r"(\d+\.\d+\.\d+)-MariaDB", text, re.I)
        version = maria.group(1) if maria else version
    ssl_support = None
    caps_at = end + 1 + 4 + 8 + 1                     # thread id, salt part 1, filler
    if len(raw) >= caps_at + 2:
        ssl_support = bool(struct.unpack_from("<H", raw, caps_at)[0] & 0x0800)
    return product, version, ssl_support, banner_os_hint(text) or ""


@register
class MySql(Detector):
    name = "mysql"
    label = "MySQL"
    ports = (3306,)
    rarity = 2

    def passive(self, probe: Probe):
        raw = probe.banner
        greeting = mysql_greeting(raw)
        if greeting:
            product, version, ssl_support, os_hint = greeting
            extra = {} if ssl_support is None else {"ssl_support": ssl_support}
            return Detection("mysql", "MySQL", product, version, CONFIDENCE["exact"], "banner",
                             f"handshake v10, server {product} {version}", f"{product} {version}",
                             os_hint, False, extra)
        # an error packet as the very first thing (host blocked, too many connections)
        if len(raw) > 9 and raw[4] == 0xFF and re.search(rb"MySQL|MariaDB|not allowed to connect|max_connect_errors", raw):
            text = clean_text(raw[7:], 80)
            return Detection("mysql", "MySQL", "MySQL", "", CONFIDENCE["protocol"], "banner",
                             f"error packet: {text}", text, "", False, {"blocked": True})
        return None


@register
class Postgres(Detector):
    name = "postgresql"
    label = "PostgreSQL"
    ports = (5432,)
    rarity = 4

    def probe(self, probe: Probe):
        # PostgreSQL answers the SSL request with exactly one byte. Taking only the first byte of a longer reply made
        # every service that starts with S or N (an "SSH-2.0-..." banner, for one) look like PostgreSQL.
        answer = probe.ask(struct.pack("!II", 8, 80877103), 16)
        if answer not in (b"S", b"N"):
            return None
        ssl_support = answer == b"S"
        return Detection("postgresql", "PostgreSQL", "PostgreSQL", "", CONFIDENCE["protocol"], "protocol",
                         "answered the SSL request (" + ("SSL supported" if ssl_support else "no SSL") + ")",
                         "", "", False, {"ssl_support": ssl_support})
