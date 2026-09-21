"""RDP: which security layers the server accepts (standard, TLS, NLA).

Two X.224 connection requests are sent, exactly as an RDP client does before
login: the first asks for legacy "standard RDP security" only, the second for
TLS only. What the server answers (a connection confirm naming the protocol,
or a negotiation failure code) shows whether Network Level Authentication is
enforced. No credentials are ever sent.
"""
from __future__ import annotations

import struct

from ..net import Cancelled
from .base import CONFIDENCE, BudgetExhausted, Detection, Detector, Probe, register

PROTOCOL_NAMES = {0: "standard RDP security", 1: "TLS", 2: "CredSSP (NLA)", 4: "RDSTLS", 8: "CredSSP with early user auth"}
FAILURE_NAMES = {1: "SSL required", 2: "SSL not allowed", 3: "SSL certificate not on server",
                 4: "inconsistent flags", 5: "NLA (CredSSP) required", 6: "SSL with user auth required"}


def connection_request(protocols: int) -> bytes:
    """A TPKT + X.224 connection request carrying an RDP negotiation request."""
    negotiation = struct.pack("<BBHI", 0x01, 0x00, 8, protocols)
    x224 = bytes([6 + len(negotiation), 0xE0, 0, 0, 0, 0, 0]) + negotiation
    return struct.pack("!BBH", 3, 0, 4 + len(x224)) + x224


def _tpkt_complete(data: bytes) -> bool:
    """True once a whole TPKT packet arrived (or the data cannot be one)."""
    if not data:
        return False
    if data[0] != 3:
        return True
    return len(data) >= 4 and len(data) >= struct.unpack("!H", data[2:4])[0]


def parse_confirm(data: bytes):
    """('ok', selected_protocol) | ('fail', code) | ('legacy', 0) | None if it is not an RDP reply."""
    if len(data) < 11 or data[0] != 3 or data[5] != 0xD0:
        return None
    if len(data) >= 19 and data[11] in (0x02, 0x03):
        value = struct.unpack_from("<I", data, 15)[0]
        return ("ok", value) if data[11] == 0x02 else ("fail", value)
    return ("legacy", 0)          # an old server that does not negotiate at all


@register
class Rdp(Detector):
    name = "rdp"
    label = "RDP"
    ports = (3389,)
    rarity = 4

    def _ask(self, probe: Probe, protocols: int):
        try:
            with probe.connect() as conn:
                conn.send(connection_request(protocols), probe.timeout)
                return parse_confirm(conn.read(64, probe.timeout, until=lambda d: len(d) >= 19 or d[:1] not in (b"", b"\x03")))
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return None

    def probe(self, probe: Probe):
        legacy = self._ask(probe, 0)
        if legacy is None:
            return None
        extra: dict = {}
        evidence: list = []
        if legacy[0] in ("ok", "legacy") and legacy[1] == 0:
            extra.update(nla="not required", weak_security=True)
            evidence.append("the server accepted legacy standard RDP security")
        else:
            code = legacy[1] if legacy[0] == "fail" else None
            if code == 5:
                extra["nla"] = "required"
                evidence.append("the server demands NLA (CredSSP)")
            else:
                second = self._ask(probe, 1)
                if second and second[0] == "ok" and second[1] == 1:
                    extra["nla"] = "not required"
                    evidence.append("the server accepted a TLS-only session without NLA")
                elif second and second[0] == "fail" and second[1] == 5:
                    extra["nla"] = "required"
                    evidence.append("the server demands NLA (CredSSP)")
                else:
                    extra["nla"] = "unknown"
                    evidence.append("the server rejected the TLS-only request"
                                    + (f" ({FAILURE_NAMES.get(second[1], second[1])})" if second and second[0] == "fail" else ""))
        return Detection("rdp", "RDP", "Microsoft RDP", "", CONFIDENCE["protocol"], "protocol",
                         "; ".join(evidence), "", "", False, extra)
