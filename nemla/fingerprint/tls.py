"""TLS inspection: protocol, cipher, certificate facts, obsolete protocols.

The handshake accepts any certificate (we inspect servers, we do not trust
them). The certificate is read with Nemla's own DER parser, so nothing touches
the disk and no private standard-library helper is needed.
"""
from __future__ import annotations

import ssl
import time

from ..net import Cancelled, clean_text, open_conn, tls_context
from .base import BudgetExhausted, Probe
from .rules import OLD_TLS
from .x509 import X509Error, parse_certificate

_LEGACY = (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"))


def _day(epoch: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(epoch))


def certificate_facts(der: bytes) -> dict:
    """The certificate fields Nemla reports, from DER bytes (see x509.parse_certificate)."""
    try:
        cert = parse_certificate(der)
    except X509Error:
        return {"cert_error": "unreadable certificate"}
    now = time.time()
    days_left = int((cert["not_after"] - now) // 86400)
    facts = {
        "subject": clean_text(cert["subject"].get("commonName", ""), 80),
        "issuer": clean_text(cert["issuer"].get("organizationName") or cert["issuer"].get("commonName", ""), 80),
        "self_signed": cert["self_signed"],
        "not_before": _day(cert["not_before"]), "not_after": _day(cert["not_after"]),
        "days_left": days_left, "expired": cert["not_after"] < now,
        "not_yet_valid": cert["not_before"] > now,
        "sig_alg": cert["sig_alg"], "weak_sig": cert["weak_sig"],
        "key_type": cert["key_type"], "key_bits": cert["key_bits"],
    }
    if cert["san"]:
        facts["san"] = [clean_text(name, 60) for name in cert["san"][:6]]
    return facts


def _accepts(probe: Probe, low, high) -> bool:
    """True if the port completes a handshake restricted to one obsolete protocol version."""
    ctx = tls_context(low, high)
    if ctx.minimum_version != low or ctx.maximum_version != high:
        return False  # this OpenSSL build cannot even attempt that version
    try:
        open_conn(probe.ip, probe.port, probe.timeout, probe.cancel, tls=True, ctx=ctx).close()
        return True
    except (Cancelled, BudgetExhausted):
        raise
    except (OSError, ValueError):
        return False


def legacy_protocols(probe: Probe) -> list:
    """The obsolete protocol versions (TLSv1, TLSv1.1) the port still completes a handshake with."""
    accepted = []
    for label, attr in _LEGACY:
        version = getattr(ssl.TLSVersion, attr, None)
        if version is None:
            continue
        if probe.budget is not None and not probe.budget.take():
            break
        if _accepts(probe, version, version):
            accepted.append(label)
    return accepted


def inspect_tls(probe: Probe, legacy: bool = False):
    """Handshake with the port. Returns a dict of TLS facts, or None if it does not speak TLS.

    With `legacy=True` the port is also asked (two extra connections) whether it still
    accepts TLS 1.0 / 1.1, unless the negotiated version is already one of those.
    """
    try:
        conn = probe.connect(tls=True)
    except (Cancelled, BudgetExhausted):
        raise
    except (OSError, ValueError):
        return None
    with conn:
        sock = conn.sock
        info = {"version": sock.version() or "", "cipher": (sock.cipher() or ("",))[0]}
        try:
            der = sock.getpeercert(binary_form=True)
        except (ValueError, ssl.SSLError):
            der = None
    if der:
        info.update(certificate_facts(der))
    if legacy and info["version"] not in OLD_TLS:
        old = legacy_protocols(probe)
        if old:
            info["legacy"] = old
    elif info["version"] in OLD_TLS:
        info["legacy"] = [info["version"]]
    return info
