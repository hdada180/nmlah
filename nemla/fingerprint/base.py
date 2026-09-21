"""The detector interface: what a service fingerprint plugin looks like.

A detector is a small class that knows one protocol. It may

* recognise a banner the server sent on its own (`passive`),
* ask a protocol-specific question of its own (`probe`),
* look deeper once it has recognised the service (`refine`).

Detectors return a `Detection` with an honest confidence: a guess from the
port number alone is never presented as a fact (`method == "port"`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..net import Cancelled, Conn, open_conn


class BudgetExhausted(OSError):
    """The scan's connection budget is used up: no more probes."""


@dataclass
class Detection:
    service: str                     # canonical key: "http", "ssh", "redis"...
    label: str = ""                  # display name: "HTTP", "SSH"...
    product: str = ""
    version: str = ""
    confidence: float = 0.5          # 0..1, see CONFIDENCE
    method: str = "banner"           # banner | protocol | port
    evidence: str = ""               # short, cleaned, human-readable
    banner: str = ""                 # one-line banner for reports
    os_hint: str = ""
    tls: bool = False                # the service speaks inside TLS
    extra: dict = field(default_factory=dict)  # protocol facts: auth state, status code, title...

    def __post_init__(self):
        self.label = self.label or self.service.upper()

    @property
    def heuristic(self) -> bool:
        return self.method == "port"


# Confidence levels used by the detectors (kept in one place so they stay consistent)
CONFIDENCE = {
    "exact": 0.95,       # a reply that names the product and version
    "protocol": 0.85,    # a well-formed protocol-specific reply, no version
    "signature": 0.7,    # a banner that fits, but could be something else
    "port": 0.3,         # the port number and nothing else
}


class Probe:
    """Everything a detector may use to look at one open port: the address,
    the bytes the server sent first, and budgeted, cancellable connections."""

    def __init__(self, ip: str, port: int, timeout: float = 1.0, cancel=None, budget=None,
                 banner: bytes = b"", tls: bool = False, shared=None):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.cancel = cancel
        self.budget = budget
        self.banner = banner
        self.tls = tls
        self.shared = shared if shared is not None else {}   # results reused between detectors

    def derive(self, **changes) -> "Probe":
        data = dict(ip=self.ip, port=self.port, timeout=self.timeout, cancel=self.cancel,
                    budget=self.budget, banner=self.banner, tls=self.tls, shared=self.shared)
        data.update(changes)
        return Probe(**data)

    def connect(self, tls=None, timeout=None) -> Conn:
        """A new connection to the port (in TLS if this probe is). Counts against the budget."""
        if self.budget is not None and not self.budget.take():
            raise BudgetExhausted("probe budget exhausted")
        return open_conn(self.ip, self.port, timeout or self.timeout, self.cancel,
                         tls=self.tls if tls is None else tls)

    def ask(self, payload: bytes, limit: int = 4096, wait=None, until=None) -> bytes:
        """Connect, send `payload`, return the first reply ('' if the port does not answer)."""
        try:
            with self.connect() as conn:
                if payload:
                    conn.send(payload, self.timeout)
                return conn.read(limit, wait or self.timeout, until)
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            return b""


class Detector:
    """Base class of a service fingerprint plugin."""

    name = ""              # canonical service key
    label = ""             # display name
    ports = ()             # ports where this service usually lives (probed first there)
    rarity = 5             # 1 (always try) .. 9 (only at the highest intensity) on other ports
    tls_capable = False    # may run inside a TLS tunnel

    def passive(self, probe: Probe):
        """A Detection if `probe.banner` (sent by the server unasked) is this service."""
        return None

    def probe(self, probe: Probe):
        """Ask a protocol-specific question. A Detection if the answer is this service."""
        return None

    def refine(self, probe: Probe, detection: Detection) -> Detection:
        """Learn more about a service that `passive` already recognised."""
        return detection


REGISTRY: list = []


def register(cls):
    """Class decorator: add a detector to the registry (in import order)."""
    REGISTRY.append(cls())
    return cls
