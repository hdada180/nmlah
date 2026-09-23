"""What travels between a Fleet controller and its agents: a job, a result, and nothing else.

A job is *data*: an address expression, a port list and a fixed set of scan options, checked against the same limits
as every other way of starting a scan. There is no field that can carry a command, a script, a file or a plugin, and
an unknown field is refused, never ignored. Fleet jobs name addresses, CIDR blocks and ranges only - never host
names - so that what was checked against an agent's scope is exactly what is scanned (a name can resolve to something
else a moment later).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets

from ..config import OptionError, ScanOptions
from ..net import parse_ip
from ..targets import _IPV4_RANGE, iter_targets, parse_ports

PROTOCOL = 1
MAX_JOB_BYTES = 8 * 1024
MAX_ENROLL_BYTES = 4 * 1024
MAX_RESULT_BYTES = 32 * 1024 * 1024        # the size history refuses to read back
MAX_AGENTS = 50                            # long-polling agents each hold a controller connection
MAX_QUEUED_PER_AGENT = 8
MAX_JOB_HOSTS = 4096                       # addresses per job; an agent may lower it, never raise it
MAX_TARGET = 1000                          # characters of a job's address expression
MAX_TEXT = 500

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
ID = re.compile(r"[0-9a-f]{8,32}")

JOB_STATES = ("queued", "sent", "running", "done", "failed", "cancelled", "expired")
RESULT_STATES = ("done", "failed", "cancelled")
_TRANSITIONS = {
    "queued": {"sent", "cancelled", "expired"},
    "sent": {"running", "done", "failed", "cancelled", "expired"},
    "running": {"done", "failed", "cancelled"},
}

_OPTION_KINDS = {"no_ping": bool, "no_os": bool, "no_banner": bool, "threads": int, "per_host": int, "max_probes": int,
                 "intensity": int, "timeout": float, "rate": float, "udp_timeout": float, "udp_rate": float}
JOB_KEYS = frozenset({"target", "ports", "options"})
RESULT_KEYS = frozenset({"job", "state", "meta", "hosts", "error"})


class ProtocolError(ValueError):
    """A message that is not valid Fleet protocol."""


class JobError(ProtocolError):
    """A job request that is malformed or outside the limits."""


def loads_strict(data: bytes, limit: int):
    """JSON from the wire: size-capped, UTF-8 only, no NaN/Infinity, and refusing absurd nesting."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > limit:
        raise ProtocolError("message too large or not bytes")

    def refuse(constant):
        raise ProtocolError(f"{constant} is not valid JSON")
    try:
        return json.loads(bytes(data).decode("utf-8"), parse_constant=refuse)
    except (ValueError, RecursionError):
        raise ProtocolError("not valid JSON") from None


# -- addresses -----------------------------------------------------------------------------------------------------

def _is_literal(item: str) -> bool:
    if parse_ip(item) is not None:
        return True
    if "/" in item:
        try:
            ipaddress.ip_network(item, strict=False)
            return True
        except ValueError:
            return False
    if _IPV4_RANGE.fullmatch(item):
        return True
    left, _, right = item.partition("-")
    try:
        ipaddress.IPv6Address(left)
        ipaddress.IPv6Address(right)
        return True
    except ValueError:
        return False


def require_literal_targets(spec) -> None:
    """Refuse an address expression that names a host (only addresses, CIDR blocks and ranges are allowed)."""
    if not isinstance(spec, str) or not spec.strip() or len(spec) > MAX_TARGET:
        raise JobError(f"the target must be text of 1 to {MAX_TARGET} characters")
    if any(ord(ch) < 32 for ch in spec):
        raise JobError("the target contains control characters")
    for item in (i for i in re.split(r"[,\s]+", spec.strip()) if i):
        text = item[1:-1] if item.startswith("[") and item.endswith("]") else item
        if not _is_literal(text):
            raise JobError("only addresses, CIDR blocks and ranges are accepted in a fleet job, not names: " + text[:40])


# -- jobs ----------------------------------------------------------------------------------------------------------

def _clean_options(raw) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise JobError("options must be an object")
    out: dict = {}
    for key, value in raw.items():
        if key == "udp_ports":
            if not isinstance(value, str):
                raise JobError("udp_ports must be a port list")
            try:
                parse_ports(value)
            except ValueError as err:
                raise JobError(f"udp_ports: {err}") from None
            out[key] = value
            continue
        kind = _OPTION_KINDS.get(key)
        if kind is None:
            raise JobError(f"unknown option {key!r}")
        if isinstance(value, bool) != (kind is bool) or not isinstance(value, (bool, int, float)):
            raise JobError(f"option {key} has the wrong type")
        if kind is int and not isinstance(value, (bool, int)):
            raise JobError(f"option {key} must be a whole number")
        out[key] = value
    try:
        ScanOptions.checked(**{k: v for k, v in out.items() if k != "udp_ports"})
    except OptionError as err:
        raise JobError(str(err)) from None
    return out


def validate_job(raw, max_hosts: int = MAX_JOB_HOSTS) -> dict:
    """The job request as a clean dict, or JobError. `max_hosts` is capped at MAX_JOB_HOSTS."""
    if not isinstance(raw, dict):
        raise JobError("a job is an object")
    unknown = set(raw) - JOB_KEYS
    if unknown:
        raise JobError("unknown job field(s): " + ", ".join(sorted(str(k)[:30] for k in unknown)))
    target, ports = raw.get("target"), raw.get("ports")
    require_literal_targets(target)
    if not isinstance(ports, str):
        raise JobError("ports must be text such as 22,80,443 or 1-1000")
    try:
        parse_ports(ports)
        iter_targets(target, min(max_hosts, MAX_JOB_HOSTS))
    except ValueError as err:
        raise JobError(str(err)) from None
    return {"target": str(target).strip(), "ports": ports.strip(), "options": _clean_options(raw.get("options"))}


def validate_result(raw) -> dict:
    """A result bundle from an agent: known fields only, sane types (its content is still untrusted text)."""
    if not isinstance(raw, dict):
        raise ProtocolError("a result is an object")
    unknown = set(raw) - RESULT_KEYS
    if unknown:
        raise ProtocolError("unknown result field(s)")
    job = raw.get("job")
    if not isinstance(job, str) or not ID.fullmatch(job):
        raise ProtocolError("a result names its job")
    if raw.get("state") not in RESULT_STATES:
        raise ProtocolError("a result has a state of done, failed or cancelled")
    meta, hosts, error = raw.get("meta", {}), raw.get("hosts", []), raw.get("error", "")
    if not isinstance(meta, dict) or not isinstance(hosts, list) or not isinstance(error, str):
        raise ProtocolError("meta, hosts and error have the wrong types")
    if any(not isinstance(h, dict) or not isinstance(h.get("ip"), str) for h in hosts):
        raise ProtocolError("every host of a result is an object with an ip")
    return {"job": job, "state": raw["state"], "meta": meta, "hosts": hosts, "error": error[:MAX_TEXT]}


def can_move(state: str, new: str) -> bool:
    """Whether a job may go from `state` to `new` (a finished job never moves again)."""
    return new in _TRANSITIONS.get(state, ())


# -- secrets and pins ----------------------------------------------------------------------------------------------

def new_id() -> str:
    return secrets.token_hex(8)


def new_secret() -> str:
    """256 random bits: an agent's secret, or an enrollment token."""
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    """What is stored instead of a secret. A plain hash is right for a value that is 256 random bits."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def secret_matches(secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), stored_hash)


def pin_of(der_certificate: bytes) -> str:
    """The pin of a certificate: its SHA-256 fingerprint, `sha256:` plus lowercase hex."""
    return "sha256:" + hashlib.sha256(der_certificate).hexdigest()


def normalize_pin(text: str) -> str:
    """'AA:BB:..' , 'sha256:aabb..' or a bare hex digest -> 'sha256:<lowercase hex>'; ProtocolError otherwise."""
    digest = str(text).strip().lower().replace("sha256:", "").replace(":", "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ProtocolError("a pin is the SHA-256 fingerprint of the controller's certificate (64 hex digits)")
    return "sha256:" + digest


def pins_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii", "replace"), b.encode("ascii", "replace"))
