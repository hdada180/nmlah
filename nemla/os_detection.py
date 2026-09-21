"""Operating-system fingerprinting from several independent signals.

No single signal is trusted. Each one adds weighted votes for an OS family
and leaves a line of evidence:

* the TTL of a reply (only a coarse hint: 64 = Unix-like, 128 = Windows...)
* the TCP SYN-ACK: window size, option order, DF bit (needs Scapy and root)
* what services say about themselves (an SSH banner naming Ubuntu, IIS...)
* which ports are open (RDP, WinRM, SMB + MSRPC...)
* protocol fingerprints (SNMP sysDescr, RDP, FTP SYST...)
* the maker of the network card (a Raspberry Pi, a Docker bridge)

The result carries a confidence and its evidence. `heuristic` stays True
unless a service named the operating system itself, and even then confidence
never reaches 1: banners can be edited by the host's owner.
"""
from __future__ import annotations

import re
import errno
from dataclasses import dataclass, field

from . import privileges
from .i18n import t
from .log import logger

try:  # optional: raw SYN probing
    from scapy.all import IP, TCP, sr1
except Exception:  # pragma: no cover - depends on the environment
    IP = TCP = sr1 = None

FAMILIES = ("windows", "linux", "apple", "bsd", "network", "unix")

_FAMILY_NAMES = {
    "windows": "Windows", "linux": "Linux", "apple": "macOS / iOS", "bsd": "BSD",
    "network": "Network device", "unix": "Linux / Unix / macOS", "unknown": "Unknown",
}

# what a banner hint (see fingerprint/rules.py) says about the family
_HINT_FAMILY = (
    (re.compile(r"Ubuntu|Debian|Red Hat|Alpine|OpenWrt|Linux", re.I), "linux"),
    (re.compile(r"Windows", re.I), "windows"),
    (re.compile(r"FreeBSD|OpenBSD|NetBSD", re.I), "bsd"),
    (re.compile(r"macOS|Darwin|Mac OS", re.I), "apple"),
    (re.compile(r"RouterOS|MikroTik|Cisco|JunOS", re.I), "network"),
)

_IIS = {"10.0": "Windows 10 / Server 2016 or newer", "8.5": "Windows 8.1 / Server 2012 R2",
        "8.0": "Windows 8 / Server 2012", "7.5": "Windows 7 / Server 2008 R2",
        "7.0": "Windows Vista / Server 2008", "6.0": "Windows Server 2003"}

CAP_HEURISTIC = 0.70     # what inference alone can ever reach
CAP_REPORTED = 0.92      # what a host naming its own OS can reach


@dataclass
class OSGuess:
    family: str = "unknown"
    name: str = "Unknown"
    confidence: float = 0.0
    heuristic: bool = True
    evidence: list = field(default_factory=list)

    @property
    def label(self) -> str:
        return "high" if self.confidence >= 0.75 else "medium" if self.confidence >= 0.45 else "low"

    def as_dict(self) -> dict:
        return {"family": self.family, "name": self.name, "confidence": round(self.confidence, 2),
                "label": self.label, "heuristic": self.heuristic, "evidence": list(self.evidence)}


def initial_ttl(observed: int) -> int:
    """The TTL a packet started with, guessed from the one that arrived (32, 64, 128 or 255)."""
    for start in (32, 64, 128):
        if observed <= start:
            return start
    return 255


# ---------------------------------------------------------------------------
# TCP SYN-ACK signatures
# ---------------------------------------------------------------------------

def classify_syn_ack(window: int, options, df: bool = True, ttl=None) -> list:
    """Votes [(family, weight, evidence)] for the header of a SYN-ACK.

    The rules are the widely documented shapes of each stack's SYN-ACK, not an
    exhaustive database, so every weight is modest.
    """
    opts = [str(o) for o in options]
    head = opts[:3]
    shape = "/".join(opts) or "no options"
    seen = f"SYN-ACK window={window}, options={shape}, DF={'set' if df else 'clear'}"
    has_ts = "Timestamp" in opts
    votes = []
    if opts[:2] == ["MSS", "SAckOK"] and has_ts:
        votes.append(("linux", 0.55, seen + " (typical of Linux)"))
    elif head == ["MSS", "NOP", "WScale"] and "SAckOK" in opts and not has_ts:
        votes.append(("windows", 0.55, seen + " (typical of Windows)"))
    elif head == ["MSS", "NOP", "WScale"] and has_ts and "EOL" in opts:
        votes.append(("apple", 0.55, seen + " (typical of macOS/iOS)"))
    elif head == ["MSS", "NOP", "WScale"] and has_ts and window == 65535:
        votes.append(("bsd", 0.5, seen + " (typical of FreeBSD)"))
    elif opts == ["MSS"] or (opts[:1] == ["MSS"] and len(opts) <= 2 and window in (4128, 4096, 8192, 16384)):
        votes.append(("network", 0.4, seen + " (typical of routers and embedded stacks)"))
    if not df:
        votes.append(("network", 0.1, "DF bit clear on replies (typical of older or embedded stacks)"))
    return votes


def _refused(exc: BaseException) -> bool:
    """Does this error mean the system will not let us send raw packets at all (as opposed to one bad host)?"""
    if isinstance(exc, PermissionError) or (isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES)):
        return True
    return isinstance(exc, RuntimeError) or type(exc).__name__ == "Scapy_Exception"   # no Npcap/libpcap, no layer 2


class SynProbe:
    """Sends the fingerprinting SYN, when the system allows it.

    Without Scapy or raw-socket rights it is off from the start, and it switches itself off (once, and
    visibly, through `diagnostics`) if the system refuses mid-scan. Callers just get None and go on
    with TTL, banners and ports: a missing privilege never breaks or slows a scan.
    """

    def __init__(self, capabilities=None, diagnostics=None):
        caps = capabilities if capabilities is not None else privileges.detect()
        self.diagnostics = diagnostics
        self.reason = "" if caps.syn_fingerprint else caps.reasons.get("syn_fingerprint", "not available on this system")
        # a short code for the translated note: no_scapy, no_raw (rights), refused (the system said no mid-scan)
        self.code = "" if caps.syn_fingerprint else ("no_raw" if caps.scapy else "no_scapy")
        self.attempts = 0
        self.answers = 0

    @property
    def available(self) -> bool:
        return not self.reason

    def _switch_off(self, why: str) -> None:
        if not self.reason:
            self.reason, self.code = why, "refused"
            logger.info("TCP/IP fingerprinting switched off: %s", why)
            if self.diagnostics is not None:
                self.diagnostics.warn("syn_fingerprint_off", "TCP/IP fingerprinting is off: " + why)

    def __call__(self, ip: str, port: int, timeout: float = 1.0):
        """The SYN-ACK's traits as a dict, or None (unavailable, IPv6, no answer, not a SYN-ACK)."""
        if self.reason or sr1 is None or ":" in ip:
            return None
        self.attempts += 1
        try:
            options = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]
            reply = sr1(IP(dst=ip) / TCP(dport=port, flags="S", options=options), timeout=timeout, verbose=0)
            if reply is None or not reply.haslayer(TCP) or (int(reply[TCP].flags) & 0x12) != 0x12:
                return None
            self.answers += 1
            return {"window": int(reply[TCP].window), "options": [o[0] for o in reply[TCP].options],
                    "df": bool(int(reply[IP].flags) & 2), "ttl": int(reply[IP].ttl)}
        except Exception as exc:
            if _refused(exc):
                self._switch_off(f"{type(exc).__name__}: {exc}"[:200])
            else:
                logger.debug("SYN fingerprint of %s failed: %s", ip, exc)
            return None


def syn_fingerprint(ip: str, port: int, timeout: float = 1.0):
    """One-off SYN fingerprint (kept for the 1.x API): the traits dict, or None when unavailable or unanswered."""
    return SynProbe()(ip, port, timeout)


# ---------------------------------------------------------------------------
# Combining the signals
# ---------------------------------------------------------------------------

def _hint_family(text: str):
    for rx, family in _HINT_FAMILY:
        if rx.search(text or ""):
            return family
    return None


def guess_os_detailed(ttl=None, ports=(), tcp=None, vendor=None) -> OSGuess:
    """Combine every available signal into one guess with its confidence and evidence.

    ttl     observed TTL of a reply (or None)
    ports   open port records (with `port`, `proto`, `service`, `os_hint`, `product`, `version`...)
    tcp     the dict returned by syn_fingerprint(), or None
    vendor  the network card's maker, when known
    """
    scores = dict.fromkeys(FAMILIES, 0.0)
    evidence: list = []
    reported = False
    names: dict = {}

    def vote(family, weight, text, name=None):
        scores[family] += weight
        evidence.append(text)
        if name:
            names.setdefault(family, name)

    if ttl:
        start = initial_ttl(int(ttl))
        text = f"TTL {ttl} (started at {start})"
        if start == 64:
            vote("unix", 0.30, text + ": Unix-like")
        elif start == 128:
            vote("windows", 0.40, text + ": Windows")
        elif start == 255:
            vote("network", 0.35, text + ": routers, switches, Solaris")
        elif start == 32:
            vote("windows", 0.10, text + ": very old Windows or embedded")
    if tcp:
        for family, weight, text in classify_syn_ack(tcp.get("window", 0), tcp.get("options", []),
                                                     tcp.get("df", True), tcp.get("ttl")):
            vote(family, weight, text)

    open_ports = [p for p in ports if p.get("state", "open") == "open"]
    numbers = {(p["port"], p.get("proto", "tcp")) for p in open_ports}
    tcp_open = {n for n, proto in numbers if proto == "tcp"}
    hint_families = set()
    for p in open_ports:
        hint = p.get("os_hint") or ""
        family = _hint_family(hint)
        if family:
            label = f"{p.get('service') or 'service'} on port {p['port']} names {hint}"
            vote(family, 0.55 if family != "unix" else 0.3, label, hint)
            reported = True
            hint_families.add(family)
        product, version = p.get("product") or "", p.get("version") or ""
        if product == "Microsoft IIS" and version in _IIS:
            vote("windows", 0.15, f"IIS {version} is shipped with {_IIS[version]}", _IIS[version])
    if 3389 in tcp_open:
        vote("windows", 0.20, "port 3389 (RDP) is open")
    if 5985 in tcp_open or 5986 in tcp_open:
        vote("windows", 0.20, "WinRM is open (5985/5986)")
    if {135, 445} <= tcp_open or {135, 139} <= tcp_open:
        vote("windows", 0.20, "MSRPC (135) together with SMB is open")
    elif 445 in tcp_open or 139 in tcp_open:
        vote("windows", 0.06, "SMB is open (Samba on Unix looks the same)")
    if tcp_open & {548, 62078}:
        vote("apple", 0.20, "an Apple-specific port is open (AFP 548 / lockdown 62078)")
    if 22 in tcp_open and not scores["windows"]:
        vote("unix", 0.08, "SSH is open")
    for p in open_ports:
        if p.get("detected") == "netbios-ns":
            vote("windows", 0.10, "answers NetBIOS name queries (Samba does too)")
    if vendor:
        if "Raspberry Pi" in vendor:
            vote("linux", 0.30, f"the network card is made by {vendor} (usually Raspberry Pi OS)", "Linux (Raspberry Pi)")
        elif vendor.startswith("Docker"):
            vote("linux", 0.35, "Docker bridge MAC address (a container)", "Linux (container)")

    # generic Unix-like evidence supports each specific Unix family that already has its own
    for family in ("linux", "apple", "bsd"):
        if scores[family] > 0:
            scores[family] += 0.5 * scores["unix"]
    top = max(FAMILIES, key=lambda f: scores[f])
    if scores[top] <= 0:
        return OSGuess()
    others = sum(scores[f] for f in FAMILIES if f != top)
    share = scores[top] / (scores[top] + others)
    cap = CAP_REPORTED if reported and top in hint_families else CAP_HEURISTIC
    confidence = round(min(cap, scores[top]) * share, 2)
    name = names.get(top) or _FAMILY_NAMES[top]
    return OSGuess(top, name, confidence, not (reported and top in hint_families), evidence)


def os_display(guess: OSGuess, ttl=None) -> str:
    """The single-line text kept in `os_guess`: the name, and the TTL when known."""
    text = guess.name if guess.family != "unknown" else t("os_unknown")
    return f"{text} (TTL={ttl})" if ttl else text


def guess_os(ttl, open_ports: list) -> str:
    """Compatibility wrapper: the OS guess as one line of text."""
    return os_display(guess_os_detailed(ttl, open_ports))
