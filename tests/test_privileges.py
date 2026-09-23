"""Raw-packet features are optional: no root, no Scapy, a refusing OS, must never break or slow a scan.

The privileged half (real Scapy, real raw sockets, real SYN-ACKs) lives in test_privileged.py and runs
in the `privileged` CI job. Here everything is simulated, so it runs everywhere.
"""
import errno
import socket
import types

import pytest

import nemla
from nemla import engine, os_detection, privileges
from nemla.discovery import arp
from nemla.log import Diagnostics
from nemla.os_detection import SynProbe


@pytest.fixture(autouse=True)
def fresh_capabilities():
    """Every test starts (and leaves) with a fresh capability probe."""
    saved = dict(privileges._cache)
    privileges._cache.clear()
    yield
    privileges._cache.clear()
    privileges._cache.update(saved)


def caps(scapy=True, raw=True, elevated=False):
    reasons = {}
    if not scapy:
        reasons["syn_fingerprint"] = reasons["arp_scan"] = "Scapy is not installed (pip install scapy)"
    elif not raw:
        reasons["syn_fingerprint"] = reasons["arp_scan"] = "the operating system refuses raw sockets to this user"
    return privileges.Capabilities(scapy=scapy, elevated=elevated, raw_socket=raw, syn_fingerprint=scapy and raw,
                                   arp_scan=scapy and raw, reasons=reasons)


# ----------------------------------------------------------------------------------------------- detection

def test_detect_reports_the_real_state_without_sending_anything():
    found = privileges.detect(refresh=True)
    assert found is privileges.detect()                       # cached
    assert found.syn_fingerprint == (found.scapy and found.raw_socket)
    if not found.syn_fingerprint:
        assert found.reasons["syn_fingerprint"]               # always says why
    assert set(found.as_dict()) >= {"scapy", "elevated", "raw_socket", "syn_fingerprint", "arp_scan", "reasons"}


def test_no_scapy_means_no_raw_features_and_says_so(monkeypatch):
    monkeypatch.setattr(privileges, "HAVE_SCAPY", False)
    found = privileges.detect(refresh=True)
    assert not found.syn_fingerprint and not found.arp_scan and "Scapy" in found.reasons["syn_fingerprint"]


def test_a_refused_raw_socket_turns_the_features_off(monkeypatch):
    def refuse(*args, **kwargs):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(privileges, "HAVE_SCAPY", True)
    monkeypatch.setattr(privileges.socket, "socket", refuse)
    allowed, why = privileges.raw_socket_allowed()
    assert allowed is False and "root" in why and "administrator" in why
    found = privileges.detect(refresh=True)
    assert found.scapy and not found.raw_socket and not found.syn_fingerprint and "root" in found.reasons["syn_fingerprint"]


def test_other_socket_errors_are_reported_not_raised(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError(errno.EAFNOSUPPORT, "Address family not supported")

    monkeypatch.setattr(privileges.socket, "socket", broken)
    allowed, why = privileges.raw_socket_allowed()
    assert allowed is False and "not available" in why


def test_a_raw_socket_that_opens_is_closed_again(monkeypatch):
    closed = []

    class Fake:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(privileges.socket, "socket", lambda *a, **k: Fake())
    assert privileges.raw_socket_allowed() == (True, "")
    assert closed == [True]


# ----------------------------------------------------------------------------------------------- the probe

class FakeLayer:
    def __init__(self, **values):
        self.__dict__.update(values)

    def __truediv__(self, other):
        return self


class FakeIP(FakeLayer):
    pass


class FakeTCP(FakeLayer):
    pass


class FakeReply:
    def __init__(self, flags=0x12):
        self.layers = {FakeTCP: FakeLayer(flags=flags, window=64240,
                                          options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 2)), ("NOP", None), ("WScale", 7)]),
                       FakeIP: FakeLayer(flags=2, ttl=64)}

    def haslayer(self, cls):
        return cls in self.layers

    def __getitem__(self, cls):
        return self.layers[cls]


@pytest.fixture()
def fake_scapy(monkeypatch):
    """Scapy's sr1 replaced by a recorder; behaviour is set through `state`."""
    state = {"calls": [], "reply": FakeReply(), "error": None, "refreshed": 0}
    monkeypatch.setattr(os_detection, "refresh_scapy", lambda: state.update(refreshed=state["refreshed"] + 1))

    def sr1(packet, timeout=1.0, verbose=0):
        state["calls"].append(packet)
        if state["error"] is not None:
            raise state["error"]
        return state["reply"]

    monkeypatch.setattr(os_detection, "sr1", sr1)
    monkeypatch.setattr(os_detection, "IP", FakeIP)
    monkeypatch.setattr(os_detection, "TCP", FakeTCP)
    return state


def test_a_probe_that_may_run_returns_the_synack_traits(fake_scapy):
    probe = SynProbe(caps())
    assert probe.available and probe.code == ""
    assert probe("10.0.0.5", 80) == {"window": 64240, "options": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
                                     "df": True, "ttl": 64}
    assert probe.attempts == 1 and probe.answers == 1


def test_a_probe_without_rights_never_touches_scapy(fake_scapy):
    diagnostics = Diagnostics()
    probe = SynProbe(caps(raw=False), diagnostics)
    assert not probe.available and probe.code == "no_raw" and "refuses raw sockets" in probe.reason
    assert probe("10.0.0.5", 80) is None
    assert fake_scapy["calls"] == [] and fake_scapy["refreshed"] == 0


def test_a_probe_that_may_run_makes_scapy_re_read_its_routes_first(fake_scapy):
    """Scapy reads interfaces and routes at import time; the privileged CI job builds its network afterwards."""
    SynProbe(caps())
    assert fake_scapy["refreshed"] == 1


class FakeTable:
    def __init__(self, calls, name, error=None):
        self.calls, self.name, self.error = calls, name, error

    def _do(self):
        self.calls.append(self.name)
        if self.error is not None:
            raise self.error

    reload = resync = _do


def test_refreshing_scapy_reloads_interfaces_and_routes(monkeypatch):
    calls = []
    monkeypatch.setattr(arp, "HAVE_SCAPY", True)
    monkeypatch.setattr(arp, "scapy_conf", types.SimpleNamespace(ifaces=FakeTable(calls, "ifaces"), route=FakeTable(calls, "route")),
                        raising=False)
    arp.refresh_scapy()
    assert calls == ["ifaces", "route"]


def test_a_refresh_that_fails_is_harmless_and_does_not_skip_the_other_step(monkeypatch):
    calls = []
    monkeypatch.setattr(arp, "HAVE_SCAPY", True)
    monkeypatch.setattr(arp, "scapy_conf", types.SimpleNamespace(ifaces=FakeTable(calls, "ifaces", RuntimeError("no")),
                                                                 route=FakeTable(calls, "route")), raising=False)
    arp.refresh_scapy()
    assert calls == ["ifaces", "route"]


def test_refreshing_without_scapy_does_nothing(monkeypatch):
    monkeypatch.setattr(arp, "HAVE_SCAPY", False)
    arp.refresh_scapy()


def test_a_probe_without_scapy_has_its_own_reason(fake_scapy):
    probe = SynProbe(caps(scapy=False))
    assert probe.code == "no_scapy" and probe("10.0.0.5", 80) is None and fake_scapy["calls"] == []


def test_ipv6_and_unanswered_and_non_synack_are_quietly_none(fake_scapy):
    probe = SynProbe(caps())
    assert probe("::1", 80) is None and fake_scapy["calls"] == []            # IPv6 is not fingerprinted
    fake_scapy["reply"] = None                                                 # a filtered port: no answer
    assert probe("10.0.0.5", 80) is None
    fake_scapy["reply"] = FakeReply(flags=0x14)                                # RST/ACK: closed port
    assert probe("10.0.0.5", 80) is None
    assert probe.available                                                     # none of that is a reason to stop


@pytest.mark.parametrize("error", [PermissionError(errno.EPERM, "Operation not permitted"),
                                   OSError(errno.EACCES, "Permission denied"),
                                   RuntimeError("Sniffing and sending packets is not available at layer 2: no libpcap")])
def test_when_the_system_refuses_mid_scan_the_probe_switches_off_once_and_visibly(fake_scapy, error):
    diagnostics = Diagnostics()
    probe = SynProbe(caps(), diagnostics)
    fake_scapy["error"] = error
    assert probe("10.0.0.5", 80) is None
    assert not probe.available and probe.code == "refused"
    assert probe("10.0.0.6", 80) is None and probe("10.0.0.7", 80) is None
    assert len(fake_scapy["calls"]) == 1                                       # it did not keep hammering a closed door
    warnings = diagnostics.as_list()
    assert [w["code"] for w in warnings] == ["syn_fingerprint_off"] and "off" in warnings[0]["message"]


def test_a_problem_with_one_host_does_not_switch_the_probe_off(fake_scapy):
    probe = SynProbe(caps(), Diagnostics())
    for error in (OSError(errno.ENETUNREACH, "Network is unreachable"), ValueError("bad packet")):
        fake_scapy["error"] = error
        assert probe("10.0.0.5", 80) is None
    assert probe.available
    fake_scapy["error"] = None
    assert probe("10.0.0.5", 80)["ttl"] == 64                                   # and it still works afterwards


def test_the_one_off_helper_keeps_working_without_scapy(monkeypatch):
    monkeypatch.setattr(privileges, "detect", lambda refresh=False: caps(scapy=False))
    assert os_detection.syn_fingerprint("127.0.0.1", 80) is None and os_detection.syn_fingerprint("::1", 80) is None


# ----------------------------------------------------------------------------------------------- whole scans

def run(monkeypatch, capabilities, **options):
    monkeypatch.setattr(privileges, "detect", lambda refresh=False: capabilities)
    monkeypatch.setattr(engine, "get_ttl", lambda ip, cancel=None: 128)
    return nemla.run_scan("127.0.0.1", ["127.0.0.1"], [1], no_ping=True, timeout=0.3, **options)


@pytest.mark.parametrize("capabilities, code", [(caps(scapy=False), "no_scapy"), (caps(raw=False), "no_raw")])
def test_a_scan_without_raw_packets_still_guesses_the_os_and_says_why(monkeypatch, capsys, capabilities, code):
    hosts, meta = run(monkeypatch, capabilities)
    assert hosts and hosts[0]["ttl"] == 128 and "Windows" in hosts[0]["os_guess"]        # the TTL still speaks
    assert meta["capabilities"]["syn_fingerprint"] is False and meta["capabilities"]["syn_fingerprint_reason"]
    assert meta["capabilities"]["raw_socket"] == capabilities.raw_socket
    assert [w["code"] for w in meta["warnings"] if w["code"] == "syn_fingerprint_off"] == ["syn_fingerprint_off"]
    assert nemla.t("cap_syn_off_" + code) in capsys.readouterr().out                    # one clear line in the log


@pytest.mark.parametrize("lang", ["ar", "he"])
def test_the_capability_note_is_translated(monkeypatch, capsys, lang):
    run(monkeypatch, caps(raw=False), lang=lang)
    text = capsys.readouterr().out
    assert nemla.t("cap_syn_off_no_raw", lang=lang) in text and nemla.t("cap_syn_off_no_raw", lang="en") not in text


def test_no_os_detection_means_no_capability_noise(monkeypatch, capsys):
    hosts, meta = run(monkeypatch, caps(raw=False), no_os=True)
    assert hosts and "syn_fingerprint_off" not in [w["code"] for w in meta["warnings"]]
    assert meta["capabilities"]["syn_fingerprint"] is False and meta["capabilities"]["syn_fingerprint_reason"] == ""
    assert "fingerprinting is off" not in capsys.readouterr().out


def test_a_scan_with_working_raw_packets_uses_them(monkeypatch, fake_scapy, tcp_server):
    port = tcp_server(lambda c: c.close())
    monkeypatch.setattr(privileges, "detect", lambda refresh=False: caps())
    monkeypatch.setattr(engine, "get_ttl", lambda ip, cancel=None: 64)
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_ping=True, timeout=0.5)
    assert meta["capabilities"]["syn_fingerprint"] is True and len(fake_scapy["calls"]) == 1
    assert any("SYN" in line or "window" in line for line in hosts[0]["os"]["evidence"])


def test_a_refusal_during_a_scan_is_reported_and_the_scan_finishes(monkeypatch, fake_scapy, tcp_server):
    ports = [tcp_server(lambda c: c.close()) for _ in range(3)]
    fake_scapy["error"] = PermissionError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(privileges, "detect", lambda refresh=False: caps())
    monkeypatch.setattr(engine, "get_ttl", lambda ip, cancel=None: 64)
    hosts, meta = nemla.run_scan("127.0.0.1-2", ["127.0.0.1", "127.0.0.2"], ports, no_ping=True, timeout=0.5)
    assert len(hosts) == 2 and meta["capabilities"]["syn_fingerprint"] is False       # switched off along the way
    assert "refused" in meta["capabilities"]["syn_fingerprint_reason"] or "Permission" in meta["capabilities"]["syn_fingerprint_reason"]
    assert [w["code"] for w in meta["warnings"] if w["code"] == "syn_fingerprint_off"] == ["syn_fingerprint_off"]


def test_the_ui_reports_capabilities_to_the_page(tmp_path):
    from nemla_ui import server
    app = server.App(nemla, data_dir=tmp_path)
    info = app.info()
    assert info["capabilities"]["syn_fingerprint"] == privileges.detect().syn_fingerprint
    assert isinstance(info["root"], bool) and info["root"] == privileges.is_elevated()


def test_elevation_check_never_raises():
    assert isinstance(privileges.is_elevated(), bool)
    assert socket.AF_INET is not None

def test_elevation_on_posix_is_the_effective_user_id(monkeypatch):
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 0, raising=False)
    assert privileges.is_elevated() is True
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 1000, raising=False)
    assert privileges.is_elevated() is False


def test_elevation_on_windows_asks_the_shell_and_survives_it_failing(monkeypatch):
    monkeypatch.delattr(privileges.os, "geteuid", raising=False)
    monkeypatch.setattr(privileges.sys, "platform", "win32")
    shell = types.SimpleNamespace(IsUserAnAdmin=lambda: 1)
    monkeypatch.setitem(privileges.sys.modules, "ctypes", types.SimpleNamespace(windll=types.SimpleNamespace(shell32=shell)))
    assert privileges.is_elevated() is True
    monkeypatch.setitem(privileges.sys.modules, "ctypes", types.SimpleNamespace())          # no windll at all
    assert privileges.is_elevated() is False


def test_elevation_on_an_unknown_system_is_false(monkeypatch):
    monkeypatch.delattr(privileges.os, "geteuid", raising=False)
    monkeypatch.setattr(privileges.sys, "platform", "plan9")
    assert privileges.is_elevated() is False
