"""The Guard, judged on what it must do when the network or the machine is not cooperative.

Covers: malformed and incomplete ARP data, legitimate hardware-address changes, how much a change proves
(never certainty, never 'spoofing' from a change alone), and that every limit of the watch is visible:
no network, unreadable neighbour table, a crashing or empty sweep, refused decoy ports. None of it needs
Scapy, root or a real network. (The real-kernel version is in test_privileged.py.)
"""
import json
import logging
import os
import socket
import time

import pytest

import nemla
from nemla import cli, guard, privileges
from nemla.discovery.arp import parse_arp_table
from conftest import wait_until as wait_for

GW, A, B, X = "192.168.1.1", "192.168.1.20", "192.168.1.21", "192.168.1.99"
M_GW, M_A, M_B, M_X = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03", "aa:bb:cc:00:00:99"
M_VM = "52:54:00:12:34:56"                     # locally administered: a virtual machine, a container, a private Wi-Fi address


def learned(table, gateway=GW):
    state = guard.new_state()
    guard.evaluate_sweep(table, state, gateway)
    return state


def change(state, table, gateway=GW):
    alerts = guard.evaluate_sweep(table, state, gateway)
    return [a for a in alerts if a["kind"] == "arp_change"]


# ------------------------------------------------------------------------------ malformed and incomplete data

@pytest.mark.parametrize("bad", [
    {"not-an-ip": M_A}, {"": M_A}, {"192.168.1.300": M_A}, {A: "zz:zz"}, {A: ""}, {A: None}, {A: 12345},
    {A: "00:00:00:00:00:00"}, {A: "ff:ff:ff:ff:ff:ff"}, {"224.0.0.251": M_A}, {"0.0.0.0": M_A}, {None: M_A}, {A: "aa:bb:cc"}])
def test_a_malformed_entry_is_dropped_never_fatal(bad):
    clean, dropped = guard.sanitize_table(bad)
    assert clean == {} and dropped == 1
    assert guard.evaluate_sweep(bad, guard.new_state(), GW) == []            # and a sweep of only garbage learns nothing


@pytest.mark.parametrize("junk", [None, [], "table", 42, [(A, M_A)]])
def test_a_table_of_the_wrong_type_is_an_empty_table(junk):
    assert guard.sanitize_table(junk) == ({}, 0)
    assert guard.evaluate_sweep(junk, guard.new_state(), GW) == []


def test_good_entries_survive_next_to_bad_ones_and_are_normalised():
    clean, dropped = guard.sanitize_table({A: "AA:BB:CC:00:00:02", "junk": M_B, "fe80::1": "AA-BB-CC-00-00-05", X: "0:0:0:0:0:0"})
    assert clean == {A: M_A, "fe80::1": "aa:bb:cc:00:00:05"} and dropped == 2


def test_a_mixed_ipv4_ipv6_table_is_judged_without_crashing():
    """IPv4 and IPv6 addresses cannot be compared with < : sorting them used to raise TypeError."""
    state = guard.new_state()
    alerts = guard.evaluate_sweep({GW: M_GW, "fe80::1": M_A, "2001:db8::5": M_B}, state, GW)
    assert [a["kind"] for a in alerts] == ["baseline"] and alerts[0]["detail"]["devices"] == 3
    assert [a["kind"] for a in guard.evaluate_sweep({GW: M_GW, "fe80::1": M_A, "2001:db8::5": M_B, X: M_X}, state, GW)] == ["new_device"]


def test_incomplete_and_failed_neighbours_never_look_like_devices():
    linux_proc = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                  f"{GW}      0x1         0x2         {M_GW}     *        eth0\n"
                  "192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0\n")
    ip_neigh = (f"{A} dev eth0 lladdr {M_A} REACHABLE\n192.168.1.51 dev eth0  FAILED\n192.168.1.52 dev eth0  INCOMPLETE\n"
                "192.168.1.53 dev eth0 lladdr 00:00:00:00:00:00 NOARP\n")
    macos = "? (192.168.1.60) at (incomplete) on en0 ifscope [ethernet]\n? (192.168.1.61) at aa:bb:cc:00:00:61 on en0 ifscope [ethernet]\n"
    windows = "  192.168.1.70          ff-ff-ff-ff-ff-ff     static\n  224.0.0.22            01-00-5e-00-00-16     static\n"
    assert parse_arp_table(linux_proc) == {GW: M_GW}
    assert parse_arp_table(ip_neigh) == {A: M_A}
    assert parse_arp_table(macos) == {"192.168.1.61": "aa:bb:cc:00:00:61"}
    assert parse_arp_table(windows) == {}
    state = guard.new_state()                                                  # and the Guard, fed the raw text
    guard.evaluate_sweep(parse_arp_table(linux_proc + ip_neigh), state, GW)
    assert set(state["bindings"]) == {GW, A}


@pytest.mark.parametrize("text", ["", "\n\n", "garbage", "\x00\xff" * 50, "192.168.1.1", "aa:bb:cc:dd:ee:ff", "1.2.3.4 at (incomplete)" * 100,
                                  "192.168.1.1 dev eth0 lladdr " + "aa:" * 500])
def test_garbage_output_from_the_arp_tool_parses_to_nothing_or_less(text):
    assert isinstance(parse_arp_table(text), dict)


# ------------------------------------------------------------------------------ what a changed address does and does not prove

def test_a_replaced_network_card_is_a_weak_signal_and_says_why():
    state = learned({GW: M_GW, A: M_A})
    (alert,) = change(state, {GW: M_GW, A: M_X})
    assert alert["confidence"] <= 0.30 and alert["severity"] == "medium" and alert["detail"]["gateway"] is False
    assert any("no longer answers anywhere" in line for line in alert["evidence"])          # the old card is gone: a replacement is plausible


def test_the_same_device_getting_a_new_address_is_weaker_still_than_a_stranger():
    state = learned({GW: M_GW, A: M_A, B: M_B})
    (stranger,) = change(state, {GW: M_GW, A: M_X, B: M_B})
    state = learned({GW: M_GW, A: M_A, B: M_B})
    (moved,) = change(state, {GW: M_GW, A: M_B, B: M_B})                  # .20 now answers with .21's hardware address
    assert moved["confidence"] < stranger["confidence"]
    assert any("trusted device" in line for line in moved["evidence"])


def test_a_locally_administered_address_is_explained_not_condemned():
    state = learned({GW: M_GW, A: M_A})
    (alert,) = change(state, {GW: M_GW, A: M_VM})
    assert any("locally administered" in line for line in alert["evidence"]) and alert["confidence"] < 0.5


def test_a_change_never_reaches_certainty_however_often_it_repeats():
    state = learned({GW: M_GW, A: M_A})
    confidences = []
    for i in range(12):
        (alert,) = change(state, {GW: M_GW, A: (M_X if i % 2 == 0 else M_A)})
        confidences.append(alert["confidence"])
    assert confidences[0] < confidences[-1] <= 0.85 and max(confidences) < 1.0
    state = learned({GW: M_GW})
    (gateway,) = change(state, {GW: M_X})
    assert gateway["severity"] == "high" and 0.5 <= gateway["confidence"] <= 0.85


def test_no_alert_calls_a_change_spoofing_on_its_own():
    """The alert kind and every sentence that describes it stay hedged, in every language."""
    state = learned({GW: M_GW, A: M_A})
    (alert,) = change(state, {GW: M_GW, A: M_X})
    assert alert["kind"] == "arp_change"                                                          # not "arp_spoofing"
    for lang in ("en", "ar", "he"):
        with_lang = {"lang": lang}
        text = nemla.t("g_arp_change", ip=A, old_mac=M_A, new_mac=M_X, **with_lang)
        gateway_text = nemla.t("g_arp_gateway", ip=GW, old_mac=M_GW, new_mac=M_X, **with_lang)
        assert "ARP" in text and "ARP" in gateway_text
    assert "can be ARP spoofing, but" in nemla.t("g_arp_change", ip=A, old_mac=M_A, new_mac=M_X, lang="en")
    assert "possible sign" in nemla.t("g_arp_gateway", ip=GW, old_mac=M_GW, new_mac=M_X, lang="en")


def test_the_confidence_labels_follow_the_numbers():
    assert cli.alert_confidence({"confidence": 0.85}) == "high confidence"
    assert cli.alert_confidence({"confidence": 0.5}) == "medium confidence"
    assert cli.alert_confidence({"confidence": 0.3}) == "low confidence"


def test_an_unknown_device_is_reported_with_its_evidence_and_only_once():
    state = learned({GW: M_GW, A: M_A})
    (alert,) = guard.evaluate_sweep({GW: M_GW, A: M_A, X: M_X}, state, GW)
    assert alert["kind"] == "new_device" and alert["confidence"] == 0.9
    assert any("not in the trusted baseline of 2 device" in line for line in alert["evidence"])
    assert guard.evaluate_sweep({GW: M_GW, A: M_A, X: M_X}, state, GW) == []


# ------------------------------------------------------------------------------ visible limits

def notices(log):
    return [a for a in log.alerts if a["kind"] == "guard_notice"]


def codes(log):
    return [a["detail"]["code"] for a in notices(log)]


def make(log=None, **kw):
    log = log or guard.AlertLog()
    kw.setdefault("ports", [])
    kw.setdefault("gateway", GW)
    return log, guard.Guard(log, **kw)


def test_no_network_is_announced_once_and_the_decoys_still_work():
    log, watcher = make(ports=[0], host="127.0.0.1", network=None, interval=60)
    try:
        status = watcher.start()
        watcher.start()                                                        # starting twice does not repeat it
        assert codes(log) == ["no_network"] and status["notices"] == ["no_network"] and status["decoys"]
        assert notices(log)[0]["severity"] == "info" and notices(log)[0]["src_ip"] is None
        with socket.create_connection(("127.0.0.1", status["decoys"][0]), timeout=3):
            pass
        wait_for(lambda: any(a["kind"] == "tripwire" for a in log.alerts) or watcher.ignore_local)
    finally:
        watcher.stop()


def test_tripwire_only_mode_is_not_a_problem():
    log, watcher = make(ports=[0], host="127.0.0.1", network=None, interval=0)
    try:
        watcher.start()
        assert notices(log) == []                                             # asked for no sweeps: nothing to warn about
    finally:
        watcher.stop()


def test_an_unreadable_neighbour_table_is_announced(monkeypatch):
    monkeypatch.setattr(guard, "neighbor_table_status", lambda: (False, "the arp command"))
    monkeypatch.setattr(guard, "arp_sweep", lambda network, *a, **k: {})
    log, watcher = make(network="10.0.0.0/24", interval=3600)
    try:
        status = watcher.start()
        assert codes(log) == ["neighbor_table_unreadable"]
        assert notices(log)[0]["evidence"] == ["missing: the arp command"]
        assert status["capabilities"]["neighbor_table"] is False and status["capabilities"]["neighbor_table_missing"] == "the arp command"
    finally:
        watcher.stop()


def test_a_crashing_sweep_is_announced_once_however_often_it_repeats():
    def broken():
        raise RuntimeError("neighbour table unreadable")

    log, watcher = make(network="10.0.0.0/24", interval=0.02, sweep=broken)
    try:
        watcher.start()
        wait_for(lambda: watcher.errors >= 5)
    finally:
        watcher.stop()
    assert watcher.errors >= 5 and codes(log) == ["sweep_failed"]                # five failures, one notice
    assert "RuntimeError: neighbour table unreadable" in watcher.status()["last_error"]
    assert notices(log)[0]["evidence"] == ["RuntimeError: neighbour table unreadable"]


def test_different_failures_each_get_their_own_notice_up_to_a_limit():
    log, watcher = make(network="10.0.0.0/24", interval=0)
    for i in range(guard.MAX_NOTICES + 10):
        watcher.notice("sweep_failed", key=f"error {i}", evidence=[f"error {i}"])
    assert len(notices(log)) == guard.MAX_NOTICES                               # a broken system cannot flood the alert list


def test_a_network_that_shows_nobody_is_announced_after_three_empty_sweeps():
    log, watcher = make(network="10.0.0.0/24", interval=0, sweep=dict)
    watcher.sweep_once()
    watcher.sweep_once()
    assert codes(log) == []
    watcher.sweep_once()
    watcher.sweep_once()
    assert codes(log) == ["sweep_empty"] and notices(log)[0]["detail"]["count"] == 3


def test_one_sweep_that_sees_someone_resets_the_empty_count():
    tables = [{}, {}, {GW: M_GW}, {}, {}]
    log, watcher = make(network="10.0.0.0/24", interval=0, sweep=lambda: tables.pop(0))
    for _ in range(5):
        watcher.sweep_once()
    assert codes(log) == []


def test_garbage_in_a_sweep_is_counted_and_the_rest_is_still_judged():
    log, watcher = make(network="10.0.0.0/24", interval=0,
                        sweep=lambda: {GW: M_GW, "junk": M_A, A: "00:00:00:00:00:00", B: M_B})
    watcher.sweep_once()
    assert codes(log) == ["bad_entries"] and notices(log)[0]["detail"]["count"] == 2
    assert set(watcher.state["bindings"]) == {GW, B} and any(a["kind"] == "baseline" for a in log.alerts)


def test_the_guard_needs_neither_scapy_nor_privileges(monkeypatch):
    monkeypatch.setattr(privileges, "detect", lambda refresh=False: privileges.Capabilities(
        scapy=False, elevated=False, raw_socket=False, syn_fingerprint=False, arp_scan=False, reasons={}))
    monkeypatch.setattr(privileges, "is_elevated", lambda: False)
    log, watcher = make(ports=[0], host="127.0.0.1", network="10.0.0.0/24", interval=0, sweep=lambda: {GW: M_GW, A: M_A})
    try:
        status = watcher.start()
        watcher.sweep_once()
        assert status["decoys"] and status["capabilities"]["needs_elevation"] is False and status["capabilities"]["elevated"] is False
        assert any(a["kind"] == "baseline" for a in log.alerts) and not notices(log)
    finally:
        watcher.stop()


def test_a_decoy_port_the_system_refuses_is_reported_and_the_others_still_listen(monkeypatch):
    real_bind = socket.socket.bind
    refused = {"count": 0}

    class Refusing(socket.socket):
        def bind(self, address):
            if refused["count"] == 0:
                refused["count"] += 1
                raise PermissionError(13, "Permission denied")
            return real_bind(self, address)

    monkeypatch.setattr(guard.socket, "socket", Refusing)
    _log, watcher = make(ports=[7, 0], host="127.0.0.1", network=None, interval=0)
    try:
        status = watcher.start()
        assert status["failed"] == {7: "Permission denied"} and len(status["decoys"]) == 1
    finally:
        watcher.stop()


def test_no_usable_interface_means_loopback_and_no_gateway_never_an_exception(monkeypatch):
    class Offline:
        def __init__(self, *a, **k):
            pass

        def connect(self, address):
            raise OSError(101, "Network is unreachable")

        def getsockname(self):
            return ("0.0.0.0", 0)

        def close(self):
            pass

    monkeypatch.setattr(guard.socket, "socket", Offline)
    assert guard.local_network_hint() == ("127.0.0.1", "127.0.0.1")
    monkeypatch.setattr(guard.Path, "read_text", lambda self, *a, **k: (_ for _ in ()).throw(OSError("no routing table")))
    monkeypatch.setattr(guard.sys, "platform", "linux")
    assert guard.default_gateway() is None


def test_guard_notices_read_well_in_every_language():
    for lang in ("en", "ar", "he"):
        for code, detail in (("no_network", {}), ("neighbor_table_unreadable", {}), ("sweep_failed", {}),
                             ("sweep_empty", {"count": 3}), ("bad_entries", {"count": 2})):
            text = nemla.t("g_notice_" + code, lang=lang, **detail)
            assert text and not text.startswith("g_notice_") and "{" not in text, (lang, code)
    alert = {"kind": "guard_notice", "severity": "info", "src_ip": None, "mac": None, "detail": {"code": "sweep_empty", "count": 3}}
    with nemla.i18n.use_lang("en"):
        assert "last 3 network checks" in cli.alert_text(alert)
    with nemla.i18n.use_lang("ar"):
        assert "3" in cli.alert_text(alert) and "ARP" in cli.alert_text(alert)


def test_the_alert_stream_carries_notices_to_the_json_lines_file(tmp_path):
    path = tmp_path / "alerts.jsonl"
    _log, watcher = make(guard.AlertLog(path), network=None, interval=60)
    try:
        watcher.start()
    finally:
        watcher.stop()
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    assert any('"guard_notice"' in line and '"no_network"' in line for line in lines)


def test_the_page_can_render_every_notice_code():
    """app.js picks the sentence by code; every code the Guard can raise needs a sentence in every language."""
    from pathlib import Path
    source = (Path(__file__).resolve().parent.parent / "nemla_ui" / "web" / "i18n.js").read_text(encoding="utf-8")
    for code in ("no_network", "neighbor_table_unreadable", "sweep_failed", "sweep_empty", "bad_entries"):
        assert source.count(f"'guard.t.notice.{code}'") == 3, code
    assert source.count("'guard.k.guard_notice'") == 3



# ------------------------------------------------------------------------------ the plumbing around the judging

def test_the_alert_file_is_rotated_when_it_grows_too_large(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "LOG_LIMIT", 10)
    path = tmp_path / "alerts.jsonl"
    log = guard.AlertLog(path)
    log.add({"kind": "one"})
    log.add({"kind": "two"})          # the first line alone is already over the limit: moved aside, a fresh file starts
    assert [json.loads(line)["kind"] for line in path.read_text(encoding="utf-8").splitlines()] == ["two"]
    old = (tmp_path / "alerts.jsonl.1").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["kind"] for line in old] == ["one"]


def test_an_unwritable_alert_file_never_stops_the_watch(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a folder is needed", encoding="utf-8")
    log = guard.AlertLog(blocker / "alerts.jsonl")
    added = log.add({"kind": "x"})
    assert log.since(0) == [added]     # still in memory for the live view


class _FakeConn:
    """A decoy connection whose peer misbehaves in one chosen way."""

    def __init__(self, fail_send=False, fail_recv=False, fail_close=False):
        self.fail_send, self.fail_recv, self.fail_close = fail_send, fail_recv, fail_close

    def settimeout(self, seconds):
        pass

    def sendall(self, data):
        if self.fail_send:
            raise OSError("peer vanished")

    def recv(self, size):
        if self.fail_recv:
            raise OSError("connection reset")
        return b"hello"

    def close(self):
        if self.fail_close:
            raise OSError("already closed")


@pytest.mark.parametrize("failure, seen", [({}, b"hello"), ({"fail_recv": True}, b""), ({"fail_send": True}, b""),
                                           ({"fail_close": True}, b"hello")])
def test_a_decoy_connection_that_misbehaves_is_still_reported_and_its_slot_freed(failure, seen):
    hits = []
    wire = guard.Tripwire([], lambda *args: hits.append(args), max_clients=1)
    assert wire._slots.acquire(blocking=False)
    wire._serve(_FakeConn(**failure), ("10.0.0.9", 4444), 22)      # port 22 has a banner, so a send is attempted
    assert hits == [("10.0.0.9", 4444, 22, seen)]
    assert wire._slots.acquire(blocking=False)                      # released, not leaked


def test_a_flood_beyond_the_client_limit_is_dropped_not_served():
    hits = []
    wire = guard.Tripwire([0], lambda *args: hits.append(args), host="127.0.0.1", max_clients=1)
    ports, failed = wire.start()
    try:
        assert ports and not failed
        assert wire._slots.acquire(blocking=False)                  # the only slot is busy
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=3) as client:
            client.settimeout(3)
            try:
                assert client.recv(16) == b""                       # closed at once, without a word
            except ConnectionResetError:
                pass
        time.sleep(0.3)
        assert hits == []
    finally:
        wire.stop()


def test_stopping_the_tripwire_survives_a_socket_that_will_not_close():
    class Stubborn:
        def close(self):
            raise OSError("cannot close")

    wire = guard.Tripwire([], lambda *args: None)
    wire._socks = [Stubborn()]
    wire.stop()
    assert wire._socks == []


def test_arp_sweep_hands_the_network_to_the_neighbour_sweep(monkeypatch):
    seen = []
    monkeypatch.setattr(guard, "neighbor_sweep", lambda network, settle, cancel: seen.append((network, settle)) or {A: M_A})
    assert guard.arp_sweep("192.168.1.0/24", 0.1) == {A: M_A}
    assert seen == [("192.168.1.0/24", 0.1)]


LINUX_ROUTES = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t0100000A\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"      # a default route with no gateway flag
                "short\n"
                "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"    # the real one: 192.168.1.1
                "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")


class _Done:
    def __init__(self, stdout):
        self.stdout = stdout


def test_the_linux_default_gateway_is_read_from_the_routing_table(monkeypatch):
    monkeypatch.setattr(guard.sys, "platform", "linux")
    monkeypatch.setattr(guard.Path, "read_text", lambda self, *a, **k: LINUX_ROUTES)
    assert guard.default_gateway() == "192.168.1.1"
    monkeypatch.setattr(guard.Path, "read_text", lambda self, *a, **k: LINUX_ROUTES.splitlines()[0] + "\n")
    assert guard.default_gateway() is None                           # a table with no default route at all


@pytest.mark.parametrize("output, expected", [
    ("Active Routes:\n  0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25\n", "192.168.1.1"),
    ("Active Routes:\n  10.0.0.0      255.0.0.0      On-link      10.0.0.5     281\n", None)])
def test_the_windows_default_gateway_is_read_from_the_route_tool(monkeypatch, output, expected):
    monkeypatch.setattr(guard.sys, "platform", "win32")
    monkeypatch.setattr(guard.subprocess, "run", lambda *args, **kwargs: _Done(output))
    assert guard.default_gateway() == expected


@pytest.mark.parametrize("output, expected", [
    ("   route to: default\ndestination: default\n    gateway: 10.1.1.1\n  interface: en0\n", "10.1.1.1"),
    ("route: writing to routing socket: not in table\n", None)])
def test_the_macos_default_gateway_is_read_from_the_route_tool(monkeypatch, output, expected):
    monkeypatch.setattr(guard.sys, "platform", "darwin")
    monkeypatch.setattr(guard.subprocess, "run", lambda *args, **kwargs: _Done(output))
    assert guard.default_gateway() == expected


def test_own_addresses_survive_a_machine_that_can_neither_name_nor_route_itself(monkeypatch):
    class Offline:
        def __init__(self, *args, **kwargs):
            pass

        def connect(self, address):
            raise OSError(101, "Network is unreachable")

        def close(self):
            pass

    monkeypatch.setattr(guard.socket, "gethostbyname_ex", lambda name: (_ for _ in ()).throw(OSError("no such host")))
    monkeypatch.setattr(guard.socket, "socket", Offline)
    assert guard.own_addresses() == {"127.0.0.1"}


def test_the_guard_state_is_saved_even_where_chmod_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no chmod")))
    path = tmp_path / "guard.json"
    guard.save_state(path, guard.new_state())
    assert json.loads(path.read_text(encoding="utf-8"))["learning"] is True


def test_a_state_file_that_cannot_be_written_is_a_warning_not_a_crash(tmp_path, caplog):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a folder is needed", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="nemla"):
        guard.save_state(blocker / "guard.json", guard.new_state())
    assert any("could not save the guard state" in record.message for record in caplog.records)


def test_a_changed_vendor_is_evidence_of_an_address_change():
    vendors = {M_A: "Cisco Systems", M_B: "Apple"}
    confidence, evidence = guard.arp_change_assessment(A, M_A, M_B, {A: M_B}, guard.new_state(), False,
                                                       vendor_lookup=vendors.get)
    assert "vendor changed from Cisco Systems to Apple" in evidence
    assert 0.10 <= confidence <= 0.85


def test_guard_block_gives_commands_for_an_ordinary_address_and_refuses_the_gateway():
    monitor = guard.Guard(guard.AlertLog(), ports=[], network=None, gateway=GW, sweep=dict)
    assert monitor.block(B)["ip"] == B
    with pytest.raises(guard.ProtectedAddress):
        monitor.block(GW)


def test_decoys_bind_with_address_reuse_on_systems_other_than_windows(monkeypatch):
    monkeypatch.setattr(guard.sys, "platform", "linux")
    wire = guard.Tripwire([0], lambda *args: None, host="127.0.0.1")
    ports, failed = wire.start()
    try:
        assert ports and not failed
    finally:
        wire.stop()

posix_only = pytest.mark.skipif(os.name != "posix", reason="owner-only permissions and symbolic links are checked on POSIX")


@posix_only
def test_the_alert_log_and_its_new_folder_are_owner_only(tmp_path):
    log = guard.AlertLog(tmp_path / "fresh" / "alerts.jsonl")
    log.add({"kind": "tripwire", "src_ip": "203.0.113.9"})
    assert oct((tmp_path / "fresh" / "alerts.jsonl").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "fresh").stat().st_mode & 0o777) == "0o700"


def test_the_guard_state_is_replaced_atomically_and_leaves_no_temporary_file(tmp_path):
    path = tmp_path / "data" / "guard.json"
    state = guard.new_state()
    guard.save_state(path, state)
    state["learning"] = False
    guard.save_state(path, state)
    assert json.loads(path.read_text(encoding="utf-8"))["learning"] is False
    assert [p.name for p in path.parent.iterdir()] == ["guard.json"]
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600" and oct(path.parent.stat().st_mode & 0o777) == "0o700"


@posix_only
def test_a_link_planted_at_the_old_temporary_name_is_never_followed(tmp_path):
    """The state used to go through the predictable name guard.tmp, which anyone who could write to the folder could
    turn into a link to a file of the owner's. The temporary name is random now."""
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    (tmp_path / "guard.tmp").symlink_to(victim)
    guard.save_state(tmp_path / "guard.json", guard.new_state())
    assert victim.read_text(encoding="utf-8") == "precious"

def test_the_decoy_accept_loop_ends_when_its_socket_is_closed():
    """Deterministic version of what stop() causes in the background thread: accept() fails, the loop returns."""
    class Closed:
        def accept(self):
            raise OSError("the listening socket was closed")

    wire = guard.Tripwire([], lambda *args: None)
    assert wire._accept(Closed(), 2222) is None
