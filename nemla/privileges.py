"""What this process may do with raw packets, found out once and reported plainly.

Nemla never needs root or administrator rights for a normal scan: TCP connect scans, service
fingerprinting, TLS analysis, UDP probes, the neighbour-cache sweep and the Guard all use ordinary
sockets. Two optional extras craft packets themselves and need Scapy plus raw-socket rights
(root or CAP_NET_RAW on Linux/macOS, an elevated prompt with Npcap on Windows):

* TCP/IP stack fingerprinting: one hand-made SYN, then the shape of the SYN-ACK (window, options, DF)
* ARP requests sent by Scapy, instead of reading the operating system's neighbour cache

When they are not available Nemla says so and carries on with what it has (TTL, banners, open ports,
the neighbour cache). It never asks to be elevated and never tries to elevate itself.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
from dataclasses import dataclass, field

from .discovery.arp import HAVE_SCAPY
from .log import logger


def is_elevated() -> bool:
    """True when running as root (POSIX) or with an elevated token (Windows)."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return False


def raw_socket_allowed() -> tuple:
    """(True, "") if a raw socket can be opened here, else (False, why). Nothing is sent."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        return False, "the operating system refuses raw sockets to this user (needs root/CAP_NET_RAW or administrator rights)"
    except OSError as exc:
        return False, f"raw sockets are not available here ({exc.strerror or type(exc).__name__})"
    probe.close()
    return True, ""


@dataclass(frozen=True)
class Capabilities:
    scapy: bool                     # the Scapy library can be imported
    elevated: bool                  # running as root / administrator
    raw_socket: bool                # a raw socket can be opened
    syn_fingerprint: bool           # optional extra 1 can run
    arp_scan: bool                  # optional extra 2 can run
    reasons: dict = field(default_factory=dict)   # extra name -> why it is off (plain English)

    def as_dict(self) -> dict:
        return {"scapy": self.scapy, "elevated": self.elevated, "raw_socket": self.raw_socket,
                "syn_fingerprint": self.syn_fingerprint, "arp_scan": self.arp_scan, "reasons": dict(self.reasons)}


_cache: dict = {}
_lock = threading.Lock()


def detect(refresh: bool = False) -> Capabilities:
    """The raw-packet capabilities of this process (cached: they do not change while it runs)."""
    with _lock:
        if "found" in _cache and not refresh:
            return _cache["found"]
        elevated = is_elevated()
        allowed, why_not = raw_socket_allowed()
        reasons = {}
        if not HAVE_SCAPY:
            reasons["syn_fingerprint"] = reasons["arp_scan"] = "Scapy is not installed (pip install scapy)"
        elif not allowed:
            reasons["syn_fingerprint"] = reasons["arp_scan"] = why_not
        found = Capabilities(scapy=bool(HAVE_SCAPY), elevated=elevated, raw_socket=allowed,
                             syn_fingerprint=bool(HAVE_SCAPY and allowed), arp_scan=bool(HAVE_SCAPY and allowed),
                             reasons=reasons)
        logger.debug("capabilities: %s", found.as_dict())
        _cache["found"] = found
        return found
