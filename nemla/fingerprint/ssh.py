"""SSH: banner, protocol version and the algorithms the server offers.

The server's identification line is read, then our own is sent and the
server's key-exchange proposal (SSH_MSG_KEXINIT, sent unencrypted before any
authentication) is parsed to list the algorithms on offer. No login is ever
attempted.
"""
from __future__ import annotations

import re
import struct

from ..net import Cancelled, clean_text
from .base import CONFIDENCE, BudgetExhausted, Detection, Detector, Probe, register
from .rules import banner_os_hint, parse_banner

_BANNER = re.compile(rb"^SSH-(\d\.\d+)-([\x21-\x7e]{1,200})(?: ([\x20-\x7e]{0,200}))?", re.M)
MAX_PACKET = 32 * 1024

WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "gss-group1-sha1-*"}
WEAK_CIPHERS = {"3des-cbc", "blowfish-cbc", "cast128-cbc", "des-cbc", "arcfour", "arcfour128",
                "arcfour256", "rijndael-cbc@lysator.liu.se", "none"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com", "none"}
WEAK_HOSTKEYS = {"ssh-dss"}


def parse_kexinit(payload: bytes) -> dict:
    """The name-lists of an SSH_MSG_KEXINIT payload (starting at the message type byte)."""
    if len(payload) < 17 or payload[0] != 20:
        raise ValueError("not a KEXINIT")
    pos, lists = 17, []
    for _ in range(10):
        if pos + 4 > len(payload):
            raise ValueError("truncated")
        (size,) = struct.unpack_from("!I", payload, pos)
        pos += 4
        if size > 8192 or pos + size > len(payload):
            raise ValueError("bad name-list")
        lists.append(payload[pos:pos + size].decode("ascii", "replace").split(",") if size else [])
        pos += size
    names = ("kex", "host_key", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c",
             "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c")
    return dict(zip(names, lists))


def weak_algorithms(algorithms: dict) -> list:
    """The offered algorithms that are considered weak, as 'kind:name' strings."""
    weak = []
    for kind, bad, keys in (("kex", WEAK_KEX, ("kex",)), ("cipher", WEAK_CIPHERS, ("cipher_c2s", "cipher_s2c")),
                            ("mac", WEAK_MACS, ("mac_c2s", "mac_s2c")), ("hostkey", WEAK_HOSTKEYS, ("host_key",))):
        for key in keys:
            for name in algorithms.get(key, []):
                if name in bad and f"{kind}:{name}" not in weak:
                    weak.append(f"{kind}:{name}")
    return weak


@register
class Ssh(Detector):
    name = "ssh"
    label = "SSH"
    ports = (22, 2222)
    rarity = 1

    def passive(self, probe: Probe):
        m = _BANNER.match(probe.banner.lstrip())
        if not m:
            return None
        proto = m.group(1).decode()
        software = m.group(2).decode("ascii", "replace")
        comment = (m.group(3) or b"").decode("ascii", "replace")
        text = clean_text(f"SSH-{proto}-{software} {comment}".strip(), 100)
        product, version = parse_banner(text)
        if product is None:
            m2 = re.match(r"([A-Za-z][\w.-]*?)[_-]([\w.]+)", software)
            product, version = (m2.group(1), m2.group(2)) if m2 else (software[:30], None)
        extra = {"protocol": proto}
        return Detection("ssh", "SSH", product or "", version or "", CONFIDENCE["exact"] if version
                         else CONFIDENCE["protocol"], "banner", text, text,
                         banner_os_hint(text) or "", False, extra)

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        try:
            with probe.connect() as conn:
                conn.read(256, probe.timeout, until=lambda d: b"\n" in d)   # the server's banner
                conn.send(b"SSH-2.0-Nemla\r\n", probe.timeout)
                head = conn.read_exact(5, probe.timeout + 0.5)
                if len(head) < 5:
                    return detection
                (length,) = struct.unpack("!I", head[:4])
                if not 12 <= length <= MAX_PACKET:
                    return detection
                body = conn.read_exact(length - 1, probe.timeout + 0.5)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return detection
        padding = head[4]
        if len(body) < length - 1 or padding >= length:
            return detection
        try:
            algorithms = parse_kexinit(body[:length - 1 - padding])
        except ValueError:
            return detection
        detection.extra["host_keys"] = algorithms["host_key"][:8]
        weak = weak_algorithms(algorithms)
        if weak:
            detection.extra["weak_algorithms"] = weak[:12]
        return detection
