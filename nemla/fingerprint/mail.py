"""POP3 and IMAP: greeting, product and whether encryption is offered or required."""
from __future__ import annotations

import re

from ..net import Cancelled, clean_text
from .base import CONFIDENCE, BudgetExhausted, Detection, Detector, Probe, register
from .rules import banner_os_hint, parse_banner


@register
class Pop3(Detector):
    name = "pop3"
    label = "POP3"
    ports = (110, 995)
    rarity = 3
    tls_capable = True

    def passive(self, probe: Probe):
        text = clean_text(probe.banner[:200], 120)
        if not text.startswith("+OK") or "IMAP" in text.upper():
            return None
        if not re.search(r"POP3|Dovecot|Courier|Cyrus|mail|ready", text, re.I) and probe.port not in self.ports:
            return None
        product, version = parse_banner(text)
        return Detection("pop3", "POP3S" if probe.tls else "POP3", product or "", version or "",
                         CONFIDENCE["exact"] if version else CONFIDENCE["protocol"], "banner", text, text,
                         banner_os_hint(text) or "", probe.tls, {})

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        try:
            with probe.connect() as conn:
                conn.read(512, probe.timeout, until=lambda d: d.endswith(b"\n"))
                conn.send(b"CAPA\r\n", probe.timeout)
                reply = conn.read(2048, probe.timeout, until=lambda d: d.endswith(b".\r\n") or d.startswith(b"-ERR"))
                conn.send(b"QUIT\r\n", probe.timeout)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return detection
        if reply.startswith(b"+OK"):
            detection.extra["starttls"] = b"STLS" in reply.upper()
        return detection


@register
class Imap(Detector):
    name = "imap"
    label = "IMAP"
    ports = (143, 993)
    rarity = 3
    tls_capable = True

    def passive(self, probe: Probe):
        text = clean_text(probe.banner[:200], 120)
        if not text.startswith("* OK") or not re.search(r"IMAP|Dovecot|Courier|Cyrus", text, re.I):
            return None
        product, version = parse_banner(text)
        return Detection("imap", "IMAPS" if probe.tls else "IMAP", product or "", version or "",
                         CONFIDENCE["exact"] if version else CONFIDENCE["protocol"], "banner", text, text,
                         banner_os_hint(text) or "", probe.tls, {})

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        try:
            with probe.connect() as conn:
                conn.read(512, probe.timeout, until=lambda d: d.endswith(b"\n"))
                conn.send(b"a1 CAPABILITY\r\n", probe.timeout)
                reply = conn.read(2048, probe.timeout, until=lambda d: b"a1 OK" in d or b"a1 BAD" in d)
                conn.send(b"a2 LOGOUT\r\n", probe.timeout)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return detection
        upper = reply.upper()
        if b"CAPABILITY" in upper:
            detection.extra["starttls"] = b"STARTTLS" in upper
            detection.extra["login_disabled"] = b"LOGINDISABLED" in upper
        return detection
