"""FTP: greeting, product and whether encryption (AUTH TLS) is offered.

After the greeting only FEAT and SYST are sent (both allowed before login),
then QUIT. No login is attempted, anonymous or otherwise.
"""
from __future__ import annotations

import re

from ..net import Cancelled, clean_text
from .base import CONFIDENCE, BudgetExhausted, Detection, Detector, Probe, register
from .rules import banner_os_hint, parse_banner

_FTP_WORDS = re.compile(r"FTP|vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Serv-U|wu-", re.I)


def _reply_done(code: str):
    """`until` callback: a reply is complete when a line 'CODE ' (code and a space) arrived."""
    needle = re.compile(rb"(?:^|\n)" + code.encode() + rb"[ \r\n]")
    return lambda data: bool(needle.search(data)) or (data.endswith(b"\n") and not re.match(rb"\d{3}-", data))


@register
class Ftp(Detector):
    name = "ftp"
    label = "FTP"
    ports = (21,)
    rarity = 1

    def passive(self, probe: Probe):
        text = clean_text(probe.banner[:300], 120)
        if not text.startswith("220") or not _FTP_WORDS.search(text) or "SMTP" in text.upper():
            return None
        product, version = parse_banner(text)
        confidence = CONFIDENCE["exact"] if product and version else (
            CONFIDENCE["protocol"] if product else CONFIDENCE["signature"])
        return Detection("ftp", "FTP", product or "", version or "", confidence, "banner", text, text,
                         banner_os_hint(text) or "", False, {})

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        try:
            with probe.connect() as conn:
                conn.read(512, probe.timeout, until=_reply_done("220"))
                conn.send(b"FEAT\r\n", probe.timeout)
                features = conn.read(2048, probe.timeout, until=_reply_done("211"))
                conn.send(b"SYST\r\nQUIT\r\n", probe.timeout)
                system = conn.read(512, probe.timeout)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return detection
        text = features.decode("latin-1", "replace").upper()
        if text.startswith("211"):
            detection.extra["starttls"] = bool(re.search(r"\bAUTH (TLS|SSL)", text))
        m = re.search(rb"^215 ([^\r\n]{1,60})", system, re.M)
        if m:
            info = clean_text(m.group(1), 60)
            detection.extra["system"] = info
            hint = banner_os_hint(info) or ("Unix-like" if info.upper().startswith("UNIX") else "")
            detection.os_hint = detection.os_hint or hint
        return detection
