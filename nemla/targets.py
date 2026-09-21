"""Target and port expressions -> addresses and port lists (IPv4 and IPv6).

Addresses are never expanded into a list up front: a target is a handful of
integer spans that yield one address at a time, so `--max-hosts 1000000` costs
no more memory than `--max-hosts 10`.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import sys

from .config import MAX_HOSTS_HARD, MAX_TARGET_ITEMS, MAX_TARGET_SPEC
from .i18n import t
from .net import parse_ip, split_zone

_IPV4_RANGE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})-([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9]{1,3})")
_HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?")


class TargetSet:
    """The addresses of one target expression, generated on demand."""

    def __init__(self, spans, scoped=(), spec: str = ""):
        self._spans = list(spans)      # (version, first, last) integer spans, merged and sorted
        self._scoped = list(scoped)    # addresses with a zone id (fe80::1%eth0), kept as text
        self.spec = spec

    def count(self) -> int:
        """The number of addresses (an IPv6 /64 is 2**64, more than len() can express)."""
        return sum(last - first + 1 for _, first, last in self._spans) + len(self._scoped)

    def __len__(self) -> int:
        return min(self.count(), sys.maxsize)

    def __bool__(self) -> bool:
        return self.count() > 0

    def __iter__(self):
        for version, first, last in self._spans:
            make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
            for number in range(first, last + 1):
                yield str(make(number))
        yield from self._scoped

    def to_list(self) -> list:
        return list(self)

    def all_local(self, predicate) -> bool:
        return len(self) > 0 and all(predicate(ip) for ip in self)


def _merge(spans: list) -> list:
    """Sort spans and join the ones that touch or overlap, so no address repeats."""
    merged: list = []
    for version, first, last in sorted(spans):
        if merged and merged[-1][0] == version and first <= merged[-1][2] + 1:
            merged[-1] = (version, merged[-1][1], max(last, merged[-1][2]))
        else:
            merged.append((version, first, last))
    return merged


def _network_span(net) -> tuple:
    first, last = int(net.network_address), int(net.broadcast_address)
    if net.version == 4 and net.prefixlen <= 30:      # skip network and broadcast, like hosts()
        first, last = first + 1, last - 1
    elif net.version == 6 and net.prefixlen <= 126:   # skip the subnet-router anycast address
        first += 1
    return net.version, first, last


def resolve(name: str, family=None, all_addresses: bool = False) -> list:
    """Resolve a host name. By default one address: the first IPv4 one, else the first IPv6 one."""
    if not _HOSTNAME.fullmatch(name):
        raise ValueError(t("cannot_resolve", spec=name))
    af = {4: socket.AF_INET, 6: socket.AF_INET6}.get(family, socket.AF_UNSPEC)
    try:
        infos = socket.getaddrinfo(name, None, af, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise ValueError(t("cannot_resolve", spec=name)) from None
    found = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in found:
            found.append(addr)
    if not found:
        raise ValueError(t("cannot_resolve", spec=name))
    found.sort(key=lambda a: ":" in a)        # IPv4 first (sort is stable)
    return found if all_addresses else found[:1]


def _spans_for(item: str, family, all_addresses: bool):
    """(spans, scoped) for one comma-separated item of a target expression."""
    if item.startswith("[") and item.endswith("]"):
        item = item[1:-1]

    if "/" in item:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(t("bad_range", spec=item)) from None
        _check_family(net.version, family, item)
        return [_network_span(net)], []

    m = _IPV4_RANGE.fullmatch(item)
    if m:
        try:
            first = ipaddress.IPv4Address(m.group(1))
            end = m.group(2)
            last = ipaddress.IPv4Address(
                m.group(1).rsplit(".", 1)[0] + "." + end if "." not in end else end)
        except ValueError:
            raise ValueError(t("bad_range", spec=item)) from None
        _check_family(4, family, item)
        if last < first:
            raise ValueError(t("bad_range", spec=item))
        return [(4, int(first), int(last))], []

    if ":" in item and "-" in item and "%" not in item:      # IPv6 range a-b
        left, _, right = item.partition("-")
        try:
            low6, high6 = ipaddress.IPv6Address(left), ipaddress.IPv6Address(right)
        except ValueError:
            raise ValueError(t("bad_range", spec=item)) from None
        _check_family(6, family, item)
        if high6 < low6:
            raise ValueError(t("bad_range", spec=item))
        return [(6, int(low6), int(high6))], []

    addr = parse_ip(item)
    if addr is not None:
        _check_family(addr.version, family, item)
        if split_zone(item)[1]:
            return [], [str(addr) + "%" + split_zone(item)[1]]
        return [(addr.version, int(addr), int(addr))], []

    spans = []
    for text in resolve(item, family, all_addresses):
        obj = parse_ip(text)
        if split_zone(text)[1]:
            return [], [text]
        spans.append((obj.version, int(obj), int(obj)))
    return spans, []


def _check_family(version: int, family, item: str) -> None:
    if family and version != family:
        raise ValueError(t("bad_range", spec=item))


def iter_targets(spec, max_hosts: int = 1024, family=None, all_addresses: bool = False) -> TargetSet:
    """Parse a target expression into a lazy TargetSet.

    Items are separated by commas or spaces. Each item may be a single IPv4/IPv6
    address (fe80::1%eth0 too), a CIDR block (10.0.0.0/24, 2001:db8::/120), a
    range (10.0.0.1-50, 10.0.0.1-10.0.0.50, 2001:db8::1-2001:db8::9) or a host
    name. `family` (4 or 6) restricts the result; `all_addresses` keeps every
    address a name resolves to instead of just one.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError(t("bad_range", spec=spec if isinstance(spec, str) else "?"))
    if len(spec) > MAX_TARGET_SPEC or any(ord(ch) < 32 for ch in spec):
        raise ValueError(t("bad_range", spec=spec[:40].strip() + "..."))
    items = [i for i in re.split(r"[,\s]+", spec.strip()) if i]
    if not items or len(items) > MAX_TARGET_ITEMS:
        raise ValueError(t("bad_range", spec=spec[:40]))
    limit = min(max_hosts, MAX_HOSTS_HARD)
    spans, scoped = [], []
    for item in items:
        new_spans, new_scoped = _spans_for(item, family, all_addresses)
        spans += new_spans
        scoped += new_scoped
    targets = TargetSet(_merge(spans), dict.fromkeys(scoped), spec.strip())
    if targets.count() > limit:
        raise ValueError(t("too_many", n=targets.count(), limit=limit))
    if not targets:
        raise ValueError(t("bad_range", spec=spec.strip()))
    return targets


def parse_targets(spec: str, max_hosts: int = 1024, family=None, all_addresses: bool = False) -> list:
    """Like `iter_targets`, but as a plain list of address strings."""
    return iter_targets(spec, max_hosts, family, all_addresses).to_list()


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

_PORT_ITEM = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")


def parse_ports(spec: str) -> list:
    """'22', '22,80,443' or '1-1000' (and mixes) -> sorted, de-duplicated ports.

    Every bound is checked before a range is expanded, so a hostile '1-99999999999'
    is refused instead of eating memory.
    """
    if not isinstance(spec, str):
        raise ValueError("ports must be text such as 22,80,443 or 1-1000")
    if len(spec) > 20000:
        raise ValueError("the port list is too long")
    ports: set = set()
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        m = _PORT_ITEM.fullmatch(part)
        if not m:
            raise ValueError(f"'{part[:30]}' is not a port or a port range")
        low = int(m.group(1))
        high = int(m.group(2)) if m.group(2) else low
        if low < 1 or high > 65535:
            raise ValueError("ports must be between 1 and 65535")
        if low > high:
            raise ValueError(f"{part}: the range is backwards")
        ports.update(range(low, high + 1))
    if not ports:
        raise ValueError("empty port list")
    return sorted(ports)


def format_ports(ports) -> str:
    """[1, 2, 3, 8080] -> '1-3,8080' (a compact form for reports)."""
    ordered = sorted(set(ports))
    out, i = [], 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        out.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(out)
