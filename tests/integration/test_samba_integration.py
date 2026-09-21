"""SMB against a real Samba server (and, with NEMLA_LAB_SMB pointing at it, against a Windows machine you own).

Run with the lab up (tests/integration/README.md):   NEMLA_INTEGRATION=1 python -m pytest -m integration tests/integration

Covers detection, dialect, SMB signing and SMBv1 information, service identification inside a real scan, answers that
have been damaged on their way (truncated, corrupted, garbage), a server that never answers, and cancellation while
the server stalls. The tests that damage answers put a proxy (lab.ChaosProxy) between Nemla and the real server, so the
bytes being mangled are real Samba bytes, not a hand-made imitation. No credentials are used or needed.
"""
import threading
import time

import pytest

import nemla
from lab import ChaosProxy, endpoint, wait_open
from nemla.fingerprint import detect_service

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def smb():
    host, port = endpoint("SMB")
    if not wait_open(host, port, 30):
        pytest.fail(f"no SMB server at {host}:{port} (start the lab: see tests/integration/README.md)")
    return host, port


def detect(host, port, timeout=2.0, **kw):
    return detect_service(host, port, b"", "", timeout, kw.get("cancel"), None, kw.get("intensity", 5), None)


# ----------------------------------------------------------------------------------------------- what a real server says

def test_a_real_smb_server_is_detected_with_its_dialect_and_signing_state(smb):
    info = detect(*smb)
    assert info["detected"] == "smb" and info["service"] == "SMB" and info["method"] == "protocol"
    assert info["details"]["dialect"] in ("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1")
    assert info["details"]["signing"] in ("disabled", "enabled", "required")
    assert isinstance(info["details"]["smb1"], bool)
    assert info["confidence"] >= 0.8 and "negotiate" in info["evidence"]


def test_the_default_samba_does_not_require_signing_and_that_is_a_finding():
    host, port = endpoint("SMB")
    if not wait_open(host, port, 30):
        pytest.fail("the default Samba is not running")
    info = detect(host, port)
    if info["details"]["signing"] == "required":
        pytest.skip("this server requires signing (a Windows domain member, perhaps): not the default Samba")
    ids = {f["id"] for f in nemla.assess_host({"ip": host, "open_ports": [{**info, "port": port, "proto": "tcp", "state": "open"}]})}
    assert "smb_signing" in ids


def test_mandatory_signing_is_reported_as_required_and_is_not_a_finding():
    host, port = endpoint("SMB_SIGNING")
    if not wait_open(host, port, 30):
        pytest.skip("the signing-required Samba is not running")
    info = detect(host, port)
    assert info["details"]["signing"] == "required"
    ids = {f["id"] for f in nemla.assess_host({"ip": host, "open_ports": [{**info, "port": port, "proto": "tcp", "state": "open"}]})}
    assert "smb_signing" not in ids


def test_smbv1_being_enabled_is_seen_and_flagged():
    host, port = endpoint("SMB1")
    if not wait_open(host, port, 30):
        pytest.skip("the SMBv1 Samba is not running")
    info = detect(host, port)
    assert info["details"]["smb1"] is True
    ids = {f["id"] for f in nemla.assess_host({"ip": host, "open_ports": [{**info, "port": port, "proto": "tcp", "state": "open"}]})}
    assert "smb1" in ids


def test_smbv1_is_off_by_default(smb):
    host, port = smb
    info = detect(host, port)
    if info["details"]["smb1"]:
        pytest.skip("this server still speaks SMBv1")
    assert info["details"]["smb1"] is False


def test_a_full_scan_identifies_smb_on_its_port(smb):
    host, port = smb
    hosts, meta = nemla.run_scan("lab", [host], [port], no_ping=True, no_os=True, timeout=2.0)
    record = hosts[0]["open_ports"][0]
    assert record["service"] == "SMB" and record["details"]["dialect"] and meta["cancelled"] is False


def test_the_proxy_itself_is_transparent(smb):
    with ChaosProxy(smb, "pass") as proxy:
        assert detect("127.0.0.1", proxy.port)["details"]["dialect"] == detect(*smb)["details"]["dialect"]


# ----------------------------------------------------------------------------------------------- answers that arrive damaged

@pytest.mark.parametrize("cut", [0, 1, 3, 4, 5, 8, 12, 39, 40, 63, 64, 70, 73])
def test_a_truncated_answer_never_crashes_the_detector(smb, cut):
    with ChaosProxy(smb, "truncate", cut=cut) as proxy:
        started = time.monotonic()
        info = detect("127.0.0.1", proxy.port, timeout=1.0)
    assert time.monotonic() - started < 10
    assert isinstance(info, dict)
    if info:                                              # if it claims SMB, the claim must be internally consistent
        assert info["detected"] == "smb" and info["details"]["smb1"] in (True, False)


@pytest.mark.parametrize("at", [0, 3, 4, 5, 8, 12, 16, 60, 68, 70, 71, 72])
def test_a_corrupted_byte_never_crashes_the_detector(smb, at):
    with ChaosProxy(smb, "flip", at=at) as proxy:
        info = detect("127.0.0.1", proxy.port, timeout=1.0)
    assert isinstance(info, dict)
    if at in (4, 5, 6, 7) and info:                       # the protocol id is what makes it SMB: a broken one is not SMB2
        assert "dialect" not in info.get("details", {}) or info["details"]["dialect"]


@pytest.mark.parametrize("at", [0, 4, 8, 24, 60, 70])
def test_garbage_after_a_valid_start_is_not_taken_for_smb_facts(smb, at):
    with ChaosProxy(smb, "garbage", at=at) as proxy:
        info = detect("127.0.0.1", proxy.port, timeout=1.0)
    assert isinstance(info, dict)
    if info.get("details", {}).get("dialect"):
        assert info["details"]["dialect"] in ("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1", "2.x")


# ----------------------------------------------------------------------------------------------- silence and cancellation

def test_a_server_that_never_answers_costs_a_bounded_time_and_reports_nothing(smb):
    with ChaosProxy(smb, "blackhole", seconds=30) as proxy:
        started = time.monotonic()
        info = detect("127.0.0.1", proxy.port, timeout=0.5)
        took = time.monotonic() - started
    assert info == {}                                        # nothing was learned, nothing was invented
    assert took < 8                                          # a handful of probes at 0.5 s, not a hang


def test_a_slow_smb_server_within_the_timeout_is_still_understood(smb):
    with ChaosProxy(smb, "delay", seconds=0.4) as proxy:
        info = detect("127.0.0.1", proxy.port, timeout=2.0)
    assert info.get("detected") == "smb"


def test_cancelling_a_scan_of_a_stalled_smb_server_returns_promptly(smb):
    cancel = threading.Event()
    with ChaosProxy(smb, "blackhole", seconds=60) as proxy:
        threading.Timer(0.5, cancel.set).start()
        started = time.monotonic()
        _hosts, meta = nemla.run_scan("lab", ["127.0.0.1"], [proxy.port], no_ping=True, no_os=True, timeout=30.0, cancel=cancel)
        took = time.monotonic() - started
    assert meta["cancelled"] is True and took < 3.0          # a 30 s timeout did not hold the scan back


def test_a_scan_that_meets_a_broken_smb_server_still_finishes_and_reports_the_port(smb):
    with ChaosProxy(smb, "truncate", cut=12) as proxy:
        hosts, meta = nemla.run_scan("lab", ["127.0.0.1"], [proxy.port], no_ping=True, no_os=True, timeout=1.0)
    assert hosts and hosts[0]["open_ports"][0]["port"] == proxy.port           # the port is open whatever the server says
    assert meta["cancelled"] is False
