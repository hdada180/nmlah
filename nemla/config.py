"""Constants, hard limits and validation of scan options.

Every number that a user (or the local web interface) can supply is checked
here, so the rest of the code can rely on sane values.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Ports and services
# ---------------------------------------------------------------------------

TOP_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1080, 1433, 1521, 1723, 2049, 3128, 3306, 3389, 5432, 5900,
    5985, 6000, 6379, 8000, 8080, 8081, 8443, 8888, 9200, 11211, 27017,
})

# UDP ports Nemla knows how to ask politely (see scanning/udp.py)
UDP_PORTS = (53, 69, 111, 123, 137, 161, 1900, 5353, 11211)

COMMON_SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3128: "Squid", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6000: "X11",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}

HTTP_PORTS = {80, 3128, 8000, 8080, 8081, 8888}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}
DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 135, 8080)

# ---------------------------------------------------------------------------
# Defaults and hard limits
# ---------------------------------------------------------------------------

DEFAULT_THREADS = 150
DEFAULT_TIMEOUT = 0.7
DEFAULT_MAX_HOSTS = 1024
DEFAULT_PER_HOST = 100
DEFAULT_INTENSITY = 5
DEFAULT_UDP_TIMEOUT = 1.0
DEFAULT_UDP_RATE = 200.0

MAX_THREADS = 2000
MAX_PER_HOST = 1000
MAX_TIMEOUT = 60.0
MAX_HOSTS_HARD = 1 << 20          # even with --max-hosts, never plan for more than ~1M addresses
MAX_TARGET_SPEC = 4096            # characters in one target expression
MAX_TARGET_ITEMS = 512            # comma-separated items in one target expression
MAX_RATE = 1_000_000.0

MAX_RESPONSE = 64 * 1024          # bytes read from one probe, ever
MAX_TEXT = 200                    # characters kept from any banner-like field


class OptionError(ValueError):
    """A scan option is outside its allowed range."""


def _number(value, name: str, kind=float):
    try:
        number = kind(value)
    except (TypeError, ValueError, OverflowError):
        raise OptionError(f"{name} must be a number") from None
    if isinstance(number, float) and not math.isfinite(number):
        raise OptionError(f"{name} must be a finite number")
    return number


def positive_float(value, name: str = "value", maximum: float = MAX_TIMEOUT) -> float:
    """A finite number greater than zero (a timeout, for instance)."""
    number = _number(value, name, float)
    if number <= 0:
        raise OptionError(f"{name} must be greater than 0")
    if number > maximum:
        raise OptionError(f"{name} must not be more than {maximum:g}")
    return number


def non_negative_float(value, name: str = "value", maximum: float = MAX_RATE) -> float:
    number = _number(value, name, float)
    if number < 0:
        raise OptionError(f"{name} must not be negative")
    if number > maximum:
        raise OptionError(f"{name} must not be more than {maximum:g}")
    return number


def bounded_int(value, name: str, low: int, high: int) -> int:
    number = _number(value, name, int)
    if not low <= number <= high:
        raise OptionError(f"{name} must be between {low} and {high}")
    return number


@dataclass
class ScanOptions:
    """Validated options of one scan. Build it with `ScanOptions.checked(...)`."""

    no_ping: bool = False
    no_os: bool = False
    no_banner: bool = False
    threads: int = DEFAULT_THREADS
    timeout: float = DEFAULT_TIMEOUT
    per_host: int = DEFAULT_PER_HOST
    rate: float = 0.0                  # TCP connection attempts per second, 0 = unlimited
    max_probes: int = 0                # total connection budget, 0 = unlimited
    intensity: int = DEFAULT_INTENSITY  # 0 = banner only ... 9 = try every protocol
    udp_ports: tuple = ()              # empty = no UDP scan
    udp_timeout: float = DEFAULT_UDP_TIMEOUT
    udp_rate: float = DEFAULT_UDP_RATE
    lang: str = "en"

    @classmethod
    def checked(cls, **kw) -> ScanOptions:
        opts = cls(**{k: v for k, v in kw.items() if v is not None})
        opts.threads = bounded_int(opts.threads, "threads", 1, MAX_THREADS)
        opts.per_host = bounded_int(opts.per_host, "per-host", 1, MAX_PER_HOST)
        opts.per_host = min(opts.per_host, opts.threads)
        opts.timeout = positive_float(opts.timeout, "timeout")
        opts.udp_timeout = positive_float(opts.udp_timeout, "udp-timeout")
        opts.rate = non_negative_float(opts.rate, "rate")
        opts.udp_rate = non_negative_float(opts.udp_rate, "udp-rate")
        opts.max_probes = bounded_int(opts.max_probes, "max-probes", 0, 10**12)
        opts.intensity = bounded_int(opts.intensity, "intensity", 0, 9)
        opts.udp_ports = tuple(sorted(set(opts.udp_ports or ())))
        return opts
