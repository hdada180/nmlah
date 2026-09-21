"""SMTP: greeting, product and the extensions the server announces (STARTTLS, AUTH).

After the 220 greeting only EHLO and QUIT are sent. No mail is submitted and
no relaying is tried.
"""
from __future__ import annotations

import re

from ..net import Cancelled, clean_text
from .base import CONFIDENCE, BudgetExhausted, Detection, Detector, Probe, register
from .rules import banner_os_hint, parse_banner

_SMTP_WORDS = re.compile(r"SMTP|Postfix|Exim|Sendmail|qmail|OpenSMTPD|Haraka|Zimbra|MailEnable", re.I)


@register
class Smtp(Detector):
    name = "smtp"
    label = "SMTP"
    ports = (25, 465, 587, 2525)
    rarity = 2
    tls_capable = True

    def passive(self, probe: Probe):
        text = clean_text(probe.banner[:300], 120)
        if not text.startswith("220") or not _SMTP_WORDS.search(text):
            return None
        product, version = parse_banner(text)
        confidence = CONFIDENCE["exact"] if product and version else (
            CONFIDENCE["protocol"] if product or "SMTP" in text.upper() else CONFIDENCE["signature"])
        return Detection("smtp", "SMTPS" if probe.tls else "SMTP", product or "", version or "",
                         confidence, "banner", text, text, banner_os_hint(text) or "", probe.tls, {})

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        try:
            with probe.connect() as conn:
                conn.read(512, probe.timeout, until=lambda d: d.endswith(b"\n"))
                conn.send(b"EHLO nemla.local\r\n", probe.timeout)
                reply = conn.read(4096, probe.timeout,
                                  until=lambda d: re.search(rb"(?:^|\n)250 [^\n]*\n$", d) is not None
                                  or d.startswith((b"5", b"4")))
                conn.send(b"QUIT\r\n", probe.timeout)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return detection
        text = reply.decode("latin-1", "replace").upper()
        if text.startswith("250"):
            detection.extra["starttls"] = bool(re.search(r"\bSTARTTLS\b", text))
            auth = re.search(r"\bAUTH[ =]([A-Z0-9 _-]{1,80})", text)
            if auth:
                detection.extra["auth_mechanisms"] = auth.group(1).split()[:8]
            if not detection.product:
                m = re.search(r"250-?\S+ Hello|250[- ]([\w.-]{1,60})", text)
                detection.extra["ehlo_host"] = clean_text(m.group(1), 60) if m and m.group(1) else ""
        return detection
