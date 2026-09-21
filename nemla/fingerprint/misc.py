"""Small banner-only services: Telnet and VNC."""
from __future__ import annotations

import re

from ..net import clean_text
from .base import CONFIDENCE, Detection, Detector, Probe, register

_IAC = 0xFF


@register
class Telnet(Detector):
    name = "telnet"
    label = "Telnet"
    ports = (23, 2323)
    rarity = 2

    def passive(self, probe: Probe):
        data = probe.banner
        negotiates = len(data) >= 3 and data[0] == _IAC and data[1] in (0xFB, 0xFC, 0xFD, 0xFE)
        prompt = re.search(rb"(?i)\b(login|username)\s*:\s*$", data.rstrip()[-40:] if data else b"")
        if not negotiates and not prompt:
            return None
        text = clean_text(re.sub(rb"\xff[\xfb-\xfe].", b"", data)[:100], 80)
        return Detection("telnet", "Telnet", "", "", CONFIDENCE["protocol"] if negotiates else CONFIDENCE["signature"],
                         "banner", text or "Telnet option negotiation", text or "Telnet", "", False,
                         {"cleartext": True})


@register
class Vnc(Detector):
    name = "vnc"
    label = "VNC"
    ports = (5900, 5901, 5902)
    rarity = 2

    def passive(self, probe: Probe):
        m = re.match(rb"RFB (\d{3}\.\d{3})\n", probe.banner)
        if not m:
            return None
        version = m.group(1).decode()
        text = f"RFB {version}"
        return Detection("vnc", "VNC", "VNC (RFB)", version, CONFIDENCE["exact"], "banner", text, text,
                         "", False, {})
