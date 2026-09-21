"""SMB: dialects, whether SMBv1 is still enabled and whether signing is required.

Two protocol negotiations are sent, the first thing any SMB client does:
an SMB1 negotiate that offers only "NT LM 0.12" (answered only by servers that
still speak SMBv1) and an SMB2 negotiate offering dialects 2.0.2 to 3.0.2. No
session is set up and no credentials are sent.
"""
from __future__ import annotations

import os
import struct

from ..net import Cancelled
from .base import CONFIDENCE, BudgetExhausted, Detection, Detector, Probe, register

DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02FF: "2.x"}


def _netbios(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def smb1_negotiate(dialects=("NT LM 0.12",)) -> bytes:
    """An SMB1 NEGOTIATE PROTOCOL request offering `dialects`."""
    header = (b"\xffSMB" + bytes([0x72]) + struct.pack("<IBHH8sHHHHH", 0, 0x18, 0xC853, 0, b"\x00" * 8,
                                                        0, 0xFFFF, 0xFEFF, 0, 0))
    names = b"".join(b"\x02" + d.encode("ascii") + b"\x00" for d in dialects)
    return _netbios(header + b"\x00" + struct.pack("<H", len(names)) + names)


def smb2_negotiate(dialects=(0x0202, 0x0210, 0x0300, 0x0302)) -> bytes:
    """An SMB2 NEGOTIATE request offering `dialects`."""
    header = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"\x00" * 16
    body = struct.pack("<HHHHI16s8s", 36, len(dialects), 1, 0, 0, os.urandom(16), b"\x00" * 8)
    return _netbios(header + body + b"".join(struct.pack("<H", d) for d in dialects))


def parse_smb1(data: bytes):
    """{'signing': ...} if `data` is a successful SMB1 negotiate reply for dialect 0, else None."""
    if len(data) < 40 or data[4:8] != b"\xffSMB" or data[8] != 0x72:
        return None
    if struct.unpack_from("<I", data, 9)[0] != 0 or struct.unpack_from("<H", data, 37)[0] != 0:
        return None
    mode = data[39]
    return {"signing": "required" if mode & 0x08 else "enabled" if mode & 0x04 else "disabled"}


def parse_smb2(data: bytes):
    """{'dialect': '3.0.2', 'signing': ...} for an SMB2 negotiate reply, else None."""
    if len(data) < 74 or data[4:8] != b"\xfeSMB" or struct.unpack_from("<I", data, 12)[0] != 0:
        return None
    mode, dialect = struct.unpack_from("<HH", data, 70)
    if dialect not in DIALECTS:
        return None
    return {"dialect": DIALECTS[dialect],
            "signing": "required" if mode & 0x02 else "enabled" if mode & 0x01 else "disabled"}


def _complete(data: bytes) -> bool:
    return len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], "big")


@register
class Smb(Detector):
    name = "smb"
    label = "SMB"
    ports = (445, 139)
    rarity = 4

    def _ask(self, probe: Probe, request: bytes) -> bytes:
        try:
            with probe.connect() as conn:
                conn.send(request, probe.timeout)
                return conn.read(1024, probe.timeout + 0.5, until=_complete)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return b""

    def probe(self, probe: Probe):
        v2 = parse_smb2(self._ask(probe, smb2_negotiate()))
        v1 = parse_smb1(self._ask(probe, smb1_negotiate()))
        if v1 is None and v2 is None:
            return None
        extra = {"smb1": v1 is not None}
        evidence = []
        if v2:
            extra.update(dialect=v2["dialect"], signing=v2["signing"])
            evidence.append(f"SMB2 negotiate accepted (dialect {v2['dialect']}, signing {v2['signing']})")
        if v1:
            extra.setdefault("signing", v1["signing"])
            evidence.append("SMBv1 negotiate accepted")
        return Detection("smb", "SMB", "SMB", v2["dialect"] if v2 else "1", CONFIDENCE["protocol"], "protocol",
                         "; ".join(evidence), "", "", False, extra)
