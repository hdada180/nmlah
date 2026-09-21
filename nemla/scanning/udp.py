"""UDP reconnaissance: one small, protocol-correct probe per port, honest states.

UDP has no handshake, so a scan can only report what it saw:

* open           a well-formed answer came back
* closed         the host replied "port unreachable" (ICMP)
* open|filtered  silence: the port may be open and quiet, or a firewall drops
                 the probe. Linux also rate-limits its ICMP replies, so a fast
                 scan of a Linux host reports many closed ports this way.
* unknown        a local error stopped the probe (no route, no permission)

Probes are tiny requests for public information (a DNS `version.bind`, an NTP
time request, an SNMP `sysDescr` read with the well-known community "public",
an SSDP search, ...). Nothing is flooded: sending is paced by a token bucket
and never more than `retries + 1` datagrams go to one port.
"""
from __future__ import annotations

import os
import re
import socket
import struct

from ..config import DEFAULT_UDP_RATE, DEFAULT_UDP_TIMEOUT
from ..fingerprint import detection_fields
from ..fingerprint.base import CONFIDENCE, Detection
from ..fingerprint.dns import build_query, detection_from as dns_detection, parse_response as parse_dns
from ..fingerprint.rules import banner_os_hint
from ..log import logger
from ..net import clean_text, udp_exchange
from .scheduler import Job, RateLimiter, Scheduler, is_failure

_SNMP_SYSDESCR = bytes.fromhex("2b06010201010100")   # 1.3.6.1.2.1.1.1.0


# ---------------------------------------------------------------------------
# Probes: (payload, validator). A validator turns a reply into a Detection or None.
# ---------------------------------------------------------------------------

def _dns_probe(ip: str):
    ident = int.from_bytes(os.urandom(2), "big")
    query = build_query(ident=ident)

    def check(reply: bytes):
        facts = parse_dns(reply, ident)
        return dns_detection(facts, transport="udp") if facts else None
    return query, check


def _mdns_probe(ip: str):
    ident = int.from_bytes(os.urandom(2), "big")
    query = build_query("_services._dns-sd._udp.local", qtype=12, qclass=1, ident=ident, recursion=False)

    def check(reply: bytes):
        facts = parse_dns(reply, ident)
        if not facts:
            return None
        return Detection("mdns", "mDNS", "mDNS responder", "", CONFIDENCE["protocol"], "protocol",
                         "answered a multicast-DNS service query", "", "", False, {"transport": "udp"})
    return query, check


def _ntp_probe(ip: str):
    def check(reply: bytes):
        if len(reply) < 48 or reply[0] & 7 not in (4, 5):
            return None
        stratum, version = reply[1], (reply[0] >> 3) & 7
        return Detection("ntp", "NTP", "NTP", f"v{version}", CONFIDENCE["protocol"], "protocol",
                         f"NTP server answer, stratum {stratum}", "", "", False,
                         {"stratum": stratum, "ntp_version": version, "transport": "udp"})
    return b"\x1b" + b"\x00" * 47, check


def snmp_get_request(community: bytes = b"public", request_id: bytes = b"\x4e\x45\x4d\x4c") -> bytes:
    """An SNMPv1 GetRequest for sysDescr.0 (a public, read-only value)."""
    varbind = b"\x30\x0c\x06\x08" + _SNMP_SYSDESCR + b"\x05\x00"
    pdu_body = b"\x02\x04" + request_id + b"\x02\x01\x00\x02\x01\x00" + b"\x30" + bytes([len(varbind)]) + varbind
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    body = b"\x02\x01\x00" + b"\x04" + bytes([len(community)]) + community + pdu
    return b"\x30" + bytes([len(body)]) + body


def parse_snmp_response(reply: bytes, request_id: bytes = b"\x4e\x45\x4d\x4c"):
    """The sysDescr text of an SNMP GetResponse to our request, '' if it has none, None if it is not one."""
    if len(reply) < 12 or reply[0] != 0x30 or b"\xa2" not in reply[:40] or b"\x02\x04" + request_id not in reply:
        return None
    at = reply.find(_SNMP_SYSDESCR)
    if at < 0:
        return ""
    pos = at + len(_SNMP_SYSDESCR)
    if pos + 2 > len(reply) or reply[pos] != 0x04:
        return ""
    length, pos = reply[pos + 1], pos + 2
    if length & 0x80:                       # long-form length
        count = length & 0x7F
        if count == 0 or count > 2 or pos + count > len(reply):
            return ""
        length, pos = int.from_bytes(reply[pos:pos + count], "big"), pos + count
    return clean_text(reply[pos:pos + min(length, 400)], 160)


def _snmp_probe(ip: str):
    def check(reply: bytes):
        text = parse_snmp_response(reply)
        if text is None:
            return None
        os_hint = banner_os_hint(text) or ("Linux" if re.match(r"Linux\b", text) else "")
        return Detection("snmp", "SNMP", "SNMP agent", "", CONFIDENCE["exact"], "protocol",
                         'answered a read with the default community "public"', text, os_hint, False,
                         {"community": "public", "sysdescr": text, "transport": "udp"})
    return snmp_get_request(), check


def _ssdp_probe(ip: str):
    host = f"[{ip}]" if ":" in ip else ip
    request = (f'M-SEARCH * HTTP/1.1\r\nHOST: {host}:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\n'
               "ST: upnp:rootdevice\r\n\r\n").encode()

    def check(reply: bytes):
        if not reply.startswith(b"HTTP/1.1 200") and not reply.startswith(b"NOTIFY"):
            return None
        server = re.search(rb"(?im)^server:\s*([^\r\n]{1,120})", reply)
        text = clean_text(server.group(1), 100) if server else ""
        m = re.search(r"([A-Za-z][\w.-]*)/([\d.]+)\s*$", text)
        return Detection("ssdp", "SSDP", (m.group(1) if m else "UPnP"), (m.group(2) if m else ""),
                         CONFIDENCE["exact"] if m else CONFIDENCE["protocol"], "protocol",
                         "answered an SSDP search", text, banner_os_hint(text) or ("Linux" if text.startswith("Linux") else ""),
                         False, {"server": text, "transport": "udp"})
    return request, check


def _netbios_probe(ip: str):
    tid = int.from_bytes(os.urandom(2), "big")
    query = (struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
             + struct.pack("!HH", 0x21, 1))

    def check(reply: bytes):
        if len(reply) < 57 or struct.unpack_from("!H", reply, 0)[0] != tid or not reply[2] & 0x80:
            return None
        names = []
        count = reply[56]
        for i in range(min(count, 16)):
            entry = reply[57 + 18 * i:57 + 18 * (i + 1)]
            if len(entry) < 18:
                break
            names.append((clean_text(entry[:15].decode("latin-1"), 15), entry[15], struct.unpack("!H", entry[16:18])[0]))
        host = next((n for n, suffix, flags in names if suffix == 0x00 and not flags & 0x8000), "")
        group = next((n for n, suffix, flags in names if suffix == 0x00 and flags & 0x8000), "")
        return Detection("netbios-ns", "NetBIOS-NS", "NetBIOS name service", "", CONFIDENCE["protocol"], "protocol",
                         "answered a node-status query", host, "", False,
                         {"netbios_name": host, "workgroup": group, "transport": "udp"})
    return query, check


def _tftp_probe(ip: str):
    name = b"nemla-" + os.urandom(4).hex().encode()

    def check(reply: bytes):
        if len(reply) < 4 or struct.unpack("!H", reply[:2])[0] not in (3, 5):
            return None
        return Detection("tftp", "TFTP", "TFTP", "", CONFIDENCE["protocol"], "protocol",
                         "answered a read request for a file that does not exist", "", "", False,
                         {"transport": "udp"})
    return b"\x00\x01" + name + b"\x00octet\x00", check


def _rpcbind_probe(ip: str):
    xid = os.urandom(4)
    call = xid + struct.pack("!IIIIII", 0, 2, 100000, 2, 0, 0) + b"\x00" * 16

    def check(reply: bytes):
        if len(reply) < 24 or reply[:4] != xid or struct.unpack_from("!I", reply, 4)[0] != 1:
            return None
        return Detection("rpcbind", "RPCBind", "rpcbind", "", CONFIDENCE["protocol"], "protocol",
                         "answered an RPC null call", "", "", False, {"transport": "udp"})
    return call, check


def _memcached_probe(ip: str):
    def check(reply: bytes):
        m = re.search(rb"VERSION ([\w.+-]{1,30})", reply[8:])
        if len(reply) < 8 or not m:
            return None
        version = m.group(1).decode()
        return Detection("memcached", "Memcached", "Memcached", version, CONFIDENCE["exact"], "protocol",
                         "answered a version request over UDP", f"VERSION {version}", "", False,
                         {"auth": "none", "transport": "udp"})
    return struct.pack("!HHHH", 0x4E4D, 0, 1, 0) + b"version\r\n", check


UDP_PROBES = {
    53: _dns_probe, 69: _tftp_probe, 111: _rpcbind_probe, 123: _ntp_probe, 137: _netbios_probe,
    161: _snmp_probe, 1900: _ssdp_probe, 5353: _mdns_probe, 11211: _memcached_probe,
}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_udp_port(ip: str, port: int, timeout: float = DEFAULT_UDP_TIMEOUT, cancel=None,
                  budget=None, retries: int = 1, diagnostics=None):
    """Probe one UDP port. Returns a port record (state open, open|filtered or unknown), or None if closed."""
    if budget is not None and not budget.take():
        return None
    factory = UDP_PROBES.get(port)
    payload, check = factory(ip) if factory else (b"", None)
    state, reply = udp_exchange(ip, port, payload, timeout, cancel, retries)
    if state == "closed":
        return None
    record = {"port": port, "proto": "udp", "state": state, "service": service_name_udp(port), "banner": ""}
    if state == "open":
        found = None
        if check is not None:
            try:
                found = check(reply)
            except Exception as exc:
                logger.debug("UDP %s:%s reply check failed", ip, port, exc_info=True)
                if diagnostics is not None:
                    diagnostics.warn("detector_error", f"udp/{port}: {type(exc).__name__}")
        if found is not None:
            record.update(detection_fields(found, port))
            record["state"] = "open"
        else:
            record.update({"detected": "unknown", "confidence": 0.3, "heuristic": True, "method": "port",
                           "banner": f"{len(reply)}-byte reply"})
    else:
        record.update({"confidence": 0.3, "heuristic": True, "method": "port"})
    return record


UDP_NAMES = {53: "DNS", 69: "TFTP", 111: "RPCBind", 123: "NTP", 137: "NetBIOS-NS", 161: "SNMP", 500: "IKE",
             514: "Syslog", 1900: "SSDP", 5353: "mDNS", 11211: "Memcached"}


def service_name_udp(port: int) -> str:
    """A UDP service name guessed from the port number alone."""
    if port in UDP_NAMES:
        return UDP_NAMES[port]
    try:
        return socket.getservbyport(port, "udp")
    except OSError:
        return "unknown"


def scan_host_udp(ip: str, ports, workers: int = 32, timeout: float = DEFAULT_UDP_TIMEOUT, rate: float = DEFAULT_UDP_RATE,
                  cancel=None, budget=None, retries: int = 1, diagnostics=None) -> list:
    """UDP-scan `ports` of one host (rate limited). Returns the records that are not closed."""
    limiter = RateLimiter(rate)
    scheduler = Scheduler(workers, cancel=cancel, diagnostics=diagnostics)
    jobs = (Job(ip, (lambda p=p: scan_udp_port(ip, p, timeout, cancel, budget, retries, diagnostics)),
                arg=p, kind="udp", limiter=limiter) for p in ports)
    return sorted((r for _, r in scheduler.results(jobs) if not is_failure(r) and r), key=lambda r: r["port"])

