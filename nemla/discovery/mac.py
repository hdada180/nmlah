"""Who made a network card: a small table of well-known prefixes."""
from __future__ import annotations

import re

# A small hand-picked list of prefixes for devices common on home and lab
# networks (virtual machines, containers, Raspberry Pi). It is NOT the full
# IEEE registry: an address that is not listed simply has no vendor shown.
# Each entry is (hex digits, name); the digits are the first octets of the MAC.
_MAC_PREFIXES = (
    ("000569", "VMware"),
    ("000C29", "VMware"),
    ("001C14", "VMware"),
    ("005056", "VMware"),
    ("080027", "Oracle VirtualBox"),
    ("001C42", "Parallels"),
    ("00155D", "Microsoft Hyper-V"),
    ("00163E", "Xen"),
    ("525400", "QEMU/KVM (libvirt)"),
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("D83ADD", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("0242", "Docker (bridge network)"),  # Docker derives the rest of the address from the IP
)


def mac_vendor(mac):
    """Name of the vendor or platform behind a MAC address, or None if unknown."""
    if not mac:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(digits) < 6:
        return None
    for prefix, name in _MAC_PREFIXES:
        if digits.startswith(prefix):
            return name
    return None


def normalize_mac(mac: str):
    """'a4-2B-b0-1c-9e-10' -> 'a4:2b:b0:1c:9e:10'; None for empty or multicast MACs."""
    parts = re.split(r"[:-]", str(mac).strip())
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if any(o > 255 for o in octets) or not any(octets) or octets[0] & 1:
        return None  # not a MAC, all zero (incomplete entry) or broadcast/multicast
    return ":".join(f"{o:02x}" for o in octets)


def mac_is_local(mac: str) -> bool:
    """True if the 'locally administered' bit is set in the first octet.

    Such an address was not necessarily assigned to a hardware maker: virtual
    machines, containers, and phones using a private Wi-Fi address per network
    all use them. It is a fact about the bits, not proof of anything.
    """
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    return len(digits) >= 2 and bool(int(digits[:2], 16) & 0x02)
