"""DNS over TCP (and the message helpers the UDP scanner shares).

The question is a CHAOS-class `version.bind` TXT query with recursion NOT
requested. Any well-formed reply with our id proves a DNS server; the RA flag
tells whether it advertises recursion (an open resolver if reachable by
strangers), and the TXT answer, when there is one, names the software.
"""
from __future__ import annotations

import os
import re
import struct

from ..net import clean_text
from .base import CONFIDENCE, Detection, Detector, Probe, register


def build_query(name: str = "version.bind", qtype: int = 16, qclass: int = 3, ident=None,
                recursion: bool = False) -> bytes:
    """A DNS query message (no TCP length prefix)."""
    ident = int.from_bytes(os.urandom(2), "big") if ident is None else ident
    flags = 0x0100 if recursion else 0x0000
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label)
    return struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0) + question + b"\x00" + struct.pack("!HH", qtype, qclass)


def _skip_name(data: bytes, pos: int) -> int:
    for _ in range(64):
        if pos >= len(data):
            raise ValueError("truncated name")
        size = data[pos]
        if size == 0:
            return pos + 1
        if size & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + size
    raise ValueError("name too long")


def parse_response(data: bytes, ident=None) -> dict:
    """Facts from a DNS response, or {} if it is not one (or is not the answer to `ident`)."""
    if len(data) < 12:
        return {}
    rid, flags, qd, an = struct.unpack_from("!HHHH", data, 0)
    if not flags & 0x8000 or (ident is not None and rid != ident):
        return {}
    out = {"rcode": flags & 0xF, "recursion_available": bool(flags & 0x0080), "answers": an,
           "authoritative": bool(flags & 0x0400)}
    try:
        pos = 12
        for _ in range(min(qd, 4)):
            pos = _skip_name(data, pos) + 4
        for _ in range(min(an, 4)):
            pos = _skip_name(data, pos)
            rtype, _cls, _ttl, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if rtype == 16 and size > 1 and pos + size <= len(data):     # TXT
                out["version"] = clean_text(data[pos + 1:pos + 1 + min(data[pos], size - 1)], 80)
                break
            pos += size
    except (ValueError, struct.error):
        pass
    return out


def dns_product(text: str):
    """(product, version) from a version.bind answer."""
    for rx, product in ((r"^(\d+\.\d+[\w.+-]*)", "BIND"), (r"dnsmasq-([\w.]+)", "dnsmasq"),
                        (r"unbound ([\w.]+)", "Unbound"), (r"PowerDNS[^\d]*([\d.]+)", "PowerDNS"),
                        (r"Microsoft DNS ([\d.]+)", "Microsoft DNS")):
        m = re.search(rx, text or "", re.I)
        if m:
            return product, m.group(1)
    return None, None


def detection_from(facts: dict, tls: bool = False, transport: str = "tcp") -> Detection:
    product, version = dns_product(facts.get("version", ""))
    extra = {"recursion_available": facts["recursion_available"], "transport": transport}
    if facts.get("version"):
        extra["version_bind"] = facts["version"]
    return Detection("dns", "DNS", product or "", version or "",
                     CONFIDENCE["exact"] if version else CONFIDENCE["protocol"], "protocol",
                     "well-formed DNS response" + (" (recursion advertised)" if facts["recursion_available"] else ""),
                     facts.get("version", ""), "", tls, extra)


@register
class Dns(Detector):
    name = "dns"
    label = "DNS"
    ports = (53,)
    rarity = 4

    def probe(self, probe: Probe):
        ident = int.from_bytes(os.urandom(2), "big")
        query = build_query(ident=ident)
        data = probe.ask(struct.pack("!H", len(query)) + query, 2048,
                         until=lambda d: len(d) >= 2 and len(d) >= 2 + struct.unpack("!H", d[:2])[0])
        if len(data) < 14 or struct.unpack("!H", data[:2])[0] > 2046:
            return None
        facts = parse_response(data[2:], ident)
        return detection_from(facts, probe.tls) if facts else None
