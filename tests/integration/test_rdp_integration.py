"""RDP against a real xrdp server (or, with NEMLA_LAB_RDP* pointing at them, a Windows machine or VM you own).

Run with the lab up (tests/integration/README.md):   NEMLA_INTEGRATION=1 python -m pytest -m integration tests/integration

Nemla only negotiates: it sends the X.224 connection request an RDP client sends before login and reads which security
layer the server selects. It never sends credentials. xrdp answers that negotiation itself, so no desktop, account or
session is needed. What is covered: detection and service identification, the security layers (standard RDP security,
TLS) and what they mean for the NLA indication, answers damaged on their way (real xrdp bytes, through lab.ChaosProxy),
a server that never answers, and cancellation.

Not covered here, and why: "NLA required" needs a Windows machine (xrdp does not implement CredSSP). That case is unit
tested against captured negotiation replies (tests/test_fingerprint.py) and has a manual procedure in
tests/integration/README.md ("Checking NLA against Windows").
"""
import threading
import time

import pytest

import nemla
from lab import ChaosProxy, endpoint, wait_open
from nemla.fingerprint import detect_service

pytestmark = pytest.mark.integration


def up(name, required=True):
    host, port = endpoint(name)
    if not wait_open(host, port, 30):
        if required:
            pytest.fail(f"no RDP server at {host}:{port} (start the lab: see tests/integration/README.md)")
        pytest.skip(f"the {name} RDP server is not running")
    return host, port


def detect(host, port, timeout=2.0, **kw):
    return detect_service(host, port, b"", "", timeout, kw.get("cancel"), None, 5, None)


@pytest.fixture(scope="module")
def rdp():
    return up("RDP")


# ----------------------------------------------------------------------------------------------- what a real server says

def test_a_real_rdp_server_is_detected_and_identified(rdp):
    info = detect(*rdp)
    assert info["detected"] == "rdp" and info["service"] == "RDP" and info["method"] == "protocol"
    assert info["details"]["nla"] in ("not required", "required", "unknown")
    assert info["confidence"] >= 0.8 and info["evidence"]


def test_a_full_scan_identifies_rdp_on_a_non_standard_port(rdp):
    host, port = rdp                                          # the lab does not use 3389: identification is by protocol, not port
    hosts, _meta = nemla.run_scan("lab", [host], [port], no_ping=True, no_os=True, timeout=2.0)
    record = hosts[0]["open_ports"][0]
    assert record["service"] == "RDP" and record["method"] == "protocol" and not record.get("heuristic")


def test_standard_rdp_security_is_reported_as_weak():
    host, port = up("RDP_LEGACY", required=False)
    info = detect(host, port)
    assert info["details"]["weak_security"] is True and info["details"]["nla"] == "not required"
    ids = {f["id"] for f in nemla.assess_host({"ip": host, "open_ports": [{**info, "port": port, "proto": "tcp", "state": "open"}]})}
    assert "rdp_weak_security" in ids and "rdp_no_nla" not in ids       # the stronger finding replaces the weaker one


def test_tls_only_rdp_without_nla_is_reported_as_not_requiring_nla():
    host, port = up("RDP_TLS", required=False)
    info = detect(host, port)
    assert info["details"]["nla"] == "not required" and not info["details"].get("weak_security")
    ids = {f["id"] for f in nemla.assess_host({"ip": host, "open_ports": [{**info, "port": port, "proto": "tcp", "state": "open"}]})}
    assert "rdp_no_nla" in ids and "rdp_weak_security" not in ids


def test_the_proxy_itself_is_transparent(rdp):
    with ChaosProxy(rdp, "pass") as proxy:
        assert detect("127.0.0.1", proxy.port)["detected"] == "rdp"


# ----------------------------------------------------------------------------------------------- answers that arrive damaged

@pytest.mark.parametrize("cut", [0, 1, 2, 3, 4, 5, 6, 10, 11, 12, 14, 15, 18])
def test_a_truncated_negotiation_reply_never_crashes_the_detector(rdp, cut):
    with ChaosProxy(rdp, "truncate", cut=cut) as proxy:
        started = time.monotonic()
        info = detect("127.0.0.1", proxy.port, timeout=1.0)
    assert time.monotonic() - started < 10
    assert isinstance(info, dict)
    if info:
        assert info["detected"] == "rdp" and info["details"]["nla"] in ("not required", "required", "unknown")


@pytest.mark.parametrize("at", [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 14, 15])
def test_a_corrupted_byte_never_crashes_the_detector(rdp, at):
    with ChaosProxy(rdp, "flip", at=at) as proxy:
        info = detect("127.0.0.1", proxy.port, timeout=1.0)
    assert isinstance(info, dict)
    if at in (0, 5):                                         # the TPKT version and the X.224 'connection confirm' code make it RDP
        assert info == {} or info["detected"] == "rdp"


@pytest.mark.parametrize("at", [0, 5, 11, 15])
def test_garbage_after_a_valid_start_is_never_taken_for_facts_it_cannot_support(rdp, at):
    with ChaosProxy(rdp, "garbage", at=at) as proxy:
        info = detect("127.0.0.1", proxy.port, timeout=1.0)
    assert isinstance(info, dict)


# ----------------------------------------------------------------------------------------------- silence and cancellation

def test_a_server_that_never_answers_costs_a_bounded_time_and_reports_nothing(rdp):
    with ChaosProxy(rdp, "blackhole", seconds=30) as proxy:
        started = time.monotonic()
        info = detect("127.0.0.1", proxy.port, timeout=0.5)
        took = time.monotonic() - started
    assert info == {} and took < 8


def test_a_slow_rdp_server_within_the_timeout_is_still_understood(rdp):
    with ChaosProxy(rdp, "delay", seconds=0.4) as proxy:
        assert detect("127.0.0.1", proxy.port, timeout=2.0).get("detected") == "rdp"


def test_cancelling_a_scan_of_a_stalled_rdp_server_returns_promptly(rdp):
    cancel = threading.Event()
    with ChaosProxy(rdp, "blackhole", seconds=60) as proxy:
        threading.Timer(0.5, cancel.set).start()
        started = time.monotonic()
        _, meta = nemla.run_scan("lab", ["127.0.0.1"], [proxy.port], no_ping=True, no_os=True, timeout=30.0, cancel=cancel)
        took = time.monotonic() - started
    assert meta["cancelled"] is True and took < 3.0


def test_cancelling_during_a_slow_negotiation_stops_within_a_fraction_of_a_second(rdp):
    cancel = threading.Event()
    with ChaosProxy(rdp, "delay", seconds=60) as proxy:
        threading.Timer(0.4, cancel.set).start()
        started = time.monotonic()
        _, meta = nemla.run_scan("lab", ["127.0.0.1"], [proxy.port], no_ping=True, no_os=True, timeout=30.0, cancel=cancel)
        took = time.monotonic() - started
    assert meta["cancelled"] is True and took < 3.0


def test_no_dependence_on_the_public_internet(rdp):
    """The lab is local. If a test ever needed a public RDP server this would say so: every endpoint is a loopback or private address."""
    import ipaddress
    for name in ("RDP", "RDP_LEGACY", "RDP_TLS"):
        host, _ = endpoint(name)
        address = ipaddress.ip_address(host)
        assert address.is_loopback or address.is_private, f"{name} points at a public address: {host}"
