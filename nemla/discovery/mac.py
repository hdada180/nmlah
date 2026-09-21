"""Who made a network card: a curated table of well-known prefixes.

One representative block per vendor, picked from the IEEE public OUI registry (standards-oui.ieee.org/oui/oui.csv,
fetched 2026-09-22) so the hex digits are real assignments rather than a guess. This is deliberately not the full
registry (tens of thousands of rows, most of them irrelevant to a home or lab network, and most vendors hold many
blocks): an address that is not listed simply has no vendor shown, which is honest and cheap to keep working.
"""
from __future__ import annotations

import re

# Each entry is (hex digits, name); the digits are the first octets of the MAC, longest match wins (see
# _BY_LENGTH below), so a shorter prefix such as Docker's never shadows a more specific one that starts the same way.
_MAC_PREFIXES = (
    # virtualization and containers
    ("000569", "VMware"),
    ("000C29", "VMware"),
    ("001C14", "VMware"),
    ("005056", "VMware"),
    ("080027", "Oracle VirtualBox"),
    ("001C42", "Parallels"),
    ("00155D", "Microsoft Hyper-V"),
    ("00163E", "Xen"),
    ("525400", "QEMU/KVM (libvirt)"),
    ("0242", "Docker (bridge network)"),  # Docker derives the rest of the address from the IP
    # single-board computers and IoT platforms
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("D83ADD", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("D48AFC", "Espressif (ESP32/ESP8266)"),
    # networking equipment
    ("E80AB9", "Cisco"),
    ("9CE330", "Cisco Meraki"),
    ("F09FC2", "Ubiquiti"),
    ("34F716", "TP-Link"),
    ("405D82", "NETGEAR"),
    ("BC2228", "D-Link"),
    ("E4F27C", "Juniper Networks"),
    ("F80DA9", "Zyxel"),
    ("1402EC", "Hewlett Packard Enterprise"),
    # computers, mobile devices and their chip makers
    ("F0EE7A", "Apple"),
    ("641B2F", "Samsung"),
    ("E4C767", "Intel"),
    ("CCEB5E", "Xiaomi"),
    ("E00630", "Huawei"),
    ("002618", "ASUS"),
    ("D0431E", "Dell"),
    ("9C7BEF", "Hewlett-Packard"),
    ("644ED7", "HP Inc."),
    ("70F8AE", "Microsoft"),
    ("00E04C", "Realtek"),
    ("40F3B0", "Texas Instruments"),
    ("48C35A", "Lenovo"),
    ("5016F4", "Motorola Mobility"),
    ("ACC048", "OnePlus"),
    ("005043", "Marvell"),
    ("A0BD71", "Qualcomm"),
    ("000C43", "MediaTek"),
    ("48B02D", "Nvidia"),
    ("0000C0", "Western Digital"),
    ("38F0C8", "Logitech"),
    ("00620B", "Broadcom"),
    # smart-home, media and wearables
    ("AC800A", "Sony"),
    ("F46412", "Sony (PlayStation)"),
    ("AC5AF0", "LG Electronics"),
    ("842859", "Amazon (Echo/Kindle/Fire)"),
    ("60706C", "Google"),
    ("641666", "Nest (Google)"),
    ("7828CA", "Sonos"),
    ("D04D2C", "Roku"),
    ("54E019", "Ring (Amazon)"),
    ("601AC7", "Nintendo"),
    ("D8EC5E", "Belkin"),
    ("F051EA", "Fitbit"),
    ("C87B23", "Bose"),
    ("446132", "ecobee"),
    ("789C85", "August Home"),
    ("D03F27", "Wyze Labs"),
    # printers, cameras and office/industrial equipment
    ("9C934E", "Xerox"),
    ("84BA3B", "Canon"),
    ("B07C8E", "Brother Industries"),
    ("0C75D2", "Hikvision"),
    ("74C929", "Dahua"),
    ("9009D0", "Synology"),
    ("245EBE", "QNAP"),
    ("A4D73C", "Epson"),
    ("583879", "Ricoh"),
    ("004084", "Honeywell"),
    ("E8C1D7", "Philips"),
)
_BY_LENGTH = tuple(sorted(_MAC_PREFIXES, key=lambda item: -len(item[0])))


def mac_vendor(mac):
    """Name of the vendor or platform behind a MAC address, or None if unknown."""
    if not mac:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(digits) < 6:
        return None
    for prefix, name in _BY_LENGTH:
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
