"""Service fingerprinting: turn an open port into a named, versioned, scored service.

`identify()` runs the registered detectors in a sensible order:

1. a banner the server sent on its own is matched by every detector's
   `passive()` (SSH, FTP, SMTP, MySQL...), then `refine()` learns more;
2. otherwise detectors ask their own protocol questions: the ones that
   normally live on this port first, then the rest up to `intensity`;
3. TLS is tried where it is likely (443, 993...) or when nothing else
   answered, and the application detectors then run inside the tunnel.

A result that rests on the port number alone is marked heuristic and never
presented as confirmed. Adding a protocol means adding one detector module.
"""
from __future__ import annotations

import socket

from ..config import COMMON_SERVICE_NAMES, TLS_PORTS
from ..log import logger
from ..net import Cancelled, clean_text
from . import databases, dns, ftp, http, mail, misc, rdp, smb, smtp, ssh  # registers the detectors
from .base import CONFIDENCE, REGISTRY, BudgetExhausted, Detection, Detector, Probe, register
from .rules import OLD_TLS, banner_os_hint, one_line, parse_banner
from .tls import inspect_tls

__all__ = [
    "CONFIDENCE",
    "OLD_TLS",
    "REGISTRY",
    "BudgetExhausted",
    "Detection",
    "Detector",
    "Probe",
    "banner_os_hint",
    "databases",
    "detect_service",
    "detection_fields",
    "dns",
    "ftp",
    "http",
    "identify",
    "mail",
    "misc",
    "one_line",
    "parse_banner",
    "port_guess",
    "rdp",
    "register",
    "service_name",
    "smb",
    "smtp",
    "ssh",
]

HTTP_TLS_PORTS = {443, 8443}   # these never greet first, so do not wait for a banner there
INTENSITY_TLS_LEGACY = 4  # from this intensity on, TLS ports are also asked about TLS 1.0/1.1


def service_name(port: int) -> str:
    """A service name guessed from the port number alone."""
    if port in COMMON_SERVICE_NAMES:
        return COMMON_SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def port_guess(port: int) -> Detection:
    """The detection for a port nothing answered on: a labelled guess, not a fact."""
    name = service_name(port)
    return Detection(name.lower(), name, "", "", CONFIDENCE["port"] if name != "unknown" else 0.0, "port",
                     f"port number {port}", "", "", False, {})


def _candidates(port: int, intensity: int, tls: bool) -> list:
    """Detectors to try actively, most likely first."""
    chosen = [d for d in REGISTRY if (port in d.ports or d.rarity <= intensity) and (d.tls_capable or not tls)]
    return sorted(chosen, key=lambda d: (port not in d.ports, d.rarity))


def _run(detector: Detector, probe: Probe, diagnostics):
    try:
        return detector.probe(probe)
    except (Cancelled, BudgetExhausted):
        raise
    except Exception as exc:
        logger.debug("detector %s failed on %s:%s", detector.name, probe.ip, probe.port, exc_info=True)
        if diagnostics is not None:
            diagnostics.warn("detector_error", f"{detector.name}: {type(exc).__name__}")
        return None


def _passive(probe: Probe, intensity: int, diagnostics):
    """Match the banner the server volunteered; refine the first detector that recognises it."""
    if not probe.banner:
        return None
    for detector in REGISTRY:
        try:
            found = detector.passive(probe)
            if found is not None:
                return detector.refine(probe, found) if intensity >= 2 else found
        except (Cancelled, BudgetExhausted):
            raise
        except Exception as exc:
            logger.debug("detector %s failed on a banner", detector.name, exc_info=True)
            if diagnostics is not None:
                diagnostics.warn("detector_error", f"{detector.name}: {type(exc).__name__}")
    return None


def _active(probe: Probe, intensity: int, diagnostics, stage: str = "all"):
    """Try detectors actively. `early` = the ones for this port and the always-tried ones (rarity 1),
    `late` = the rest; the TLS attempt sits between the two so a TLS server is not asked a dozen
    plaintext questions first."""
    candidates = _candidates(probe.port, intensity, probe.tls)
    early = [d for d in candidates if probe.port in d.ports or d.rarity <= 1]
    chosen = {"early": early, "late": [d for d in candidates if d not in early], "all": candidates}[stage]
    for detector in chosen:
        found = _run(detector, probe, diagnostics)
        if found is not None:
            return found
    return None


def _inside_tls(probe: Probe, info: dict, intensity: int, diagnostics):
    """The application service running inside an already-verified TLS tunnel."""
    inner = probe.derive(tls=True, banner=b"")
    if probe.port not in HTTP_TLS_PORTS:
        try:                   # SMTPS / IMAPS / POP3S greet as soon as the tunnel is up
            with inner.connect() as conn:
                inner.banner = conn.read(512, min(probe.timeout, 0.6), until=lambda d: d.endswith(b"\n"))
        except (Cancelled, BudgetExhausted):
            raise
        except OSError:
            inner.banner = b""
    found = _passive(inner, intensity, diagnostics) or _active(inner, intensity, diagnostics)
    if found is None:
        found = Detection("tls", "TLS", "", "", CONFIDENCE["protocol"], "protocol",
                          f"TLS handshake succeeded ({info.get('version', '?')})", "", "", True, {})
    found.tls = True
    if found.label in ("HTTP", "SMTP", "IMAP", "POP3", "FTP"):
        found.label = {"HTTP": "HTTPS", "SMTP": "SMTPS", "IMAP": "IMAPS", "POP3": "POP3S", "FTP": "FTPS"}[found.label]
    elif found.service != "tls" and not found.label.endswith(("S", "TLS")):
        found.label += " (TLS)"
    found.extra["tls"] = info
    return found


def identify(probe: Probe, intensity: int = 5, diagnostics=None):
    """The best Detection for an open port, or None if nothing could be learned."""
    if intensity <= 0:
        return None
    found = _passive(probe, intensity, diagnostics)
    if found is not None:
        return found
    tls_likely = probe.port in TLS_PORTS
    if not tls_likely:
        found = _active(probe, intensity, diagnostics, "early")
        if found is not None:
            return found
    if tls_likely or (intensity >= 3 and not probe.banner):
        info = inspect_tls(probe, legacy=intensity >= INTENSITY_TLS_LEGACY)
        if info is not None:
            return _inside_tls(probe, info, intensity, diagnostics)
    return _active(probe, intensity, diagnostics, "all" if tls_likely else "late")


def detect_service(ip: str, port: int, raw: bytes = b"", banner: str = "", timeout: float = 1.0,
                   cancel=None, budget=None, intensity: int = 5, diagnostics=None) -> dict:
    """Best-effort service details for one open port, as a flat dict (product, version, tls, ...).

    Only ordinary identification probes are sent (a web GET, a TLS handshake, Redis PING, ...),
    never anything that logs in or changes state. Any failure just means less detail, so a
    detection bug can never break a scan.
    """
    probe = Probe(ip, port, timeout, cancel, budget, raw or b"")
    try:
        found = identify(probe, intensity, diagnostics)
    except BudgetExhausted:
        found = None
        if diagnostics is not None:
            diagnostics.warn("budget", "probe budget exhausted during service detection")
    return detection_fields(found, port) if found else {}


def detection_fields(found: Detection, port: int = 0) -> dict:
    """A Detection as the flat port record fields used by reports, the UI and history."""
    info = {"detected": found.service, "service": found.label, "confidence": round(found.confidence, 2),
            "heuristic": found.heuristic, "method": found.method}
    if found.evidence:
        info["evidence"] = clean_text(found.evidence, 160)
    if found.product:
        info["product"] = found.product
    if found.version:
        info["version"] = found.version
    if found.os_hint:
        info["os_hint"] = found.os_hint
    if found.banner:
        info["banner"] = clean_text(found.banner, 120)
    extra = dict(found.extra)
    tls = extra.pop("tls", None)
    if tls:
        info["tls"] = tls
    for key in ("auth", "status", "title", "location", "powered_by"):
        if key in extra:
            info[key] = extra.pop(key)
    if extra:
        info["details"] = extra
    return info
