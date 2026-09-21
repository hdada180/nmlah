import http.client
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

import nemla
from nemla_ui import guard, server

GW, A, B, X = "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.99"
MAC_GW, MAC_A, MAC_B, MAC_X = ("a4:2b:b0:1c:9e:10", "dc:a6:32:5e:11:07", "3c:52:82:aa:04:9d", "de:ad:be:ef:00:01")


# --------------------------------------------------------------------------
# reading the network
# --------------------------------------------------------------------------

LINUX_ARP = """IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         A4:2B:B0:1C:9E:10     *        wlan0
10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        wlan0
"""
IP_NEIGH = """10.0.0.1 dev wlan0 lladdr a4:2b:b0:1c:9e:10 REACHABLE
10.0.0.9 dev wlan0  FAILED
fe80::1 dev wlan0 lladdr a4:2b:b0:1c:9e:10 router STALE
"""
WINDOWS_ARP = """
Interface: 10.0.0.11 --- 0x7
  Internet Address      Physical Address      Type
  10.0.0.1              a4-2b-b0-1c-9e-10     dynamic
  10.0.0.255            ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
MAC_OS_ARP = """? (10.0.0.1) at a4:2b:b0:1c:9e:10 on en0 ifscope [ethernet]
? (10.0.0.5) at 0:1a:2b:3:4:5 on en0 ifscope [ethernet]
? (10.0.0.7) at (incomplete) on en0 ifscope [ethernet]
"""


@pytest.mark.parametrize("text, expected", [
    (LINUX_ARP, {"10.0.0.1": "a4:2b:b0:1c:9e:10"}),
    (IP_NEIGH, {"10.0.0.1": "a4:2b:b0:1c:9e:10", "fe80::1": "a4:2b:b0:1c:9e:10"}),  # IPv6 neighbours count too
    (WINDOWS_ARP, {"10.0.0.1": "a4:2b:b0:1c:9e:10"}),
    (MAC_OS_ARP, {"10.0.0.1": "a4:2b:b0:1c:9e:10", "10.0.0.5": "00:1a:2b:03:04:05"}),
    ("", {}),
    ("999.1.1.1 dev x lladdr a4:2b:b0:1c:9e:10", {}),
])
def test_parse_arp_table(text, expected):
    assert guard.parse_arp_table(text) == expected


@pytest.mark.parametrize("mac, expected", [
    ("A4-2B-b0-1c-9e-10", "a4:2b:b0:1c:9e:10"), ("0:1a:2b:3:4:5", "00:1a:2b:03:04:05"),
    ("00:00:00:00:00:00", None), ("ff:ff:ff:ff:ff:ff", None), ("01:00:5e:00:00:16", None),
    ("nonsense", None), ("a4:2b:b0:1c:9e", None)])
def test_normalize_mac(mac, expected):
    assert guard.normalize_mac(mac) == expected


# --------------------------------------------------------------------------
# judging a sweep
# --------------------------------------------------------------------------

def kinds(alerts):
    return [(a["kind"], a["severity"]) for a in alerts]


def test_first_sweep_only_learns():
    state = guard.new_state()
    assert guard.evaluate_sweep({}, state, GW) == []
    assert state["learning"] is True  # nothing seen yet, keep learning
    alerts = guard.evaluate_sweep({GW: MAC_GW, A: MAC_A}, state, GW)
    assert kinds(alerts) == [("baseline", "info")] and alerts[0]["detail"]["devices"] == 2
    assert state["learning"] is False and set(state["devices"]) == {MAC_GW, MAC_A}


def test_unknown_device_is_reported_once():
    state = guard.new_state()
    guard.evaluate_sweep({GW: MAC_GW, A: MAC_A}, state, GW)
    alerts = guard.evaluate_sweep({GW: MAC_GW, A: MAC_A, X: MAC_X}, state, GW)
    assert kinds(alerts) == [("new_device", "medium")]
    assert alerts[0]["src_ip"] == X and alerts[0]["mac"] == MAC_X
    assert guard.evaluate_sweep({GW: MAC_GW, A: MAC_A, X: MAC_X}, state, GW) == []


def test_known_device_changing_address_is_not_an_alert():
    state = guard.new_state()
    guard.evaluate_sweep({A: MAC_A}, state, GW)
    assert guard.evaluate_sweep({B: MAC_A}, state, GW) == []  # same hardware, new DHCP lease


@pytest.mark.parametrize("mac, expected", [
    ("52:54:00:12:34:56", True), ("02:42:ac:11:00:02", True), ("aa:bb:cc:dd:ee:ff", True),
    ("dc:a6:32:5e:11:07", False), ("08:00:27:11:22:33", False), ("00:0c:29:ab:cd:ef", False),
    ("", False), (None, False), ("z", False)])
def test_mac_is_local(mac, expected):
    assert guard.mac_is_local(mac) is expected


def test_new_device_alert_says_whether_the_address_is_locally_administered():
    state = guard.new_state()
    guard.evaluate_sweep({GW: MAC_GW}, state, GW)
    alerts = guard.evaluate_sweep({GW: MAC_GW, A: "52:54:00:12:34:56", B: MAC_B}, state, GW)
    assert {a["mac"]: a["detail"]["local"] for a in alerts} == {"52:54:00:12:34:56": True, MAC_B: False}


def test_guard_names_the_vendor_of_new_devices_only():
    log = guard.AlertLog()
    sweeps = [{GW: MAC_GW}, {GW: MAC_GW, A: "b8:27:eb:11:22:33", X: MAC_X}]
    g = guard.Guard(log, ports=[], network=None, gateway=GW, sweep=lambda: sweeps.pop(0),
                    vendor_lookup=lambda mac: "Raspberry Pi Foundation" if mac.startswith("b8:27:eb") else None)
    g.sweep_once()
    alerts = g.sweep_once()
    assert {a["mac"]: a["detail"].get("vendor") for a in alerts} == {
        "b8:27:eb:11:22:33": "Raspberry Pi Foundation", MAC_X: None}


def test_arp_binding_change_on_the_gateway_is_high():
    state = guard.new_state()
    guard.evaluate_sweep({GW: MAC_GW, A: MAC_A}, state, GW)
    alerts = guard.evaluate_sweep({GW: MAC_A, A: MAC_A}, state, GW)
    change = next(a for a in alerts if a["kind"] == "arp_change")
    assert change["severity"] == "high" and change["detail"]["gateway"] is True
    assert (change["detail"]["old_mac"], change["detail"]["new_mac"]) == (MAC_GW, MAC_A)
    assert ("arp_dup", "high") in kinds(alerts)  # one MAC now answers for the gateway and another IP
    assert guard.evaluate_sweep({GW: MAC_A, A: MAC_A}, state, GW) == []  # and only once


def test_arp_binding_change_elsewhere_is_medium():
    state = guard.new_state()
    guard.evaluate_sweep({GW: MAC_GW, A: MAC_A}, state, GW)
    alerts = guard.evaluate_sweep({GW: MAC_GW, A: MAC_X}, state, GW)
    assert ("arp_change", "medium") in kinds(alerts) and ("new_device", "medium") in kinds(alerts)


def test_several_addresses_for_one_mac_are_fine_without_the_gateway():
    state = guard.new_state()
    guard.evaluate_sweep({GW: MAC_GW}, state, GW)
    alerts = guard.evaluate_sweep({GW: MAC_GW, A: MAC_A, B: MAC_A}, state, GW)
    assert kinds(alerts) == [("new_device", "medium")]  # once for the hardware, no spoofing alarm


# --------------------------------------------------------------------------
# alerts and state on disk
# --------------------------------------------------------------------------

def test_alert_log_is_bounded_and_written_as_json_lines(tmp_path):
    path = tmp_path / "sub" / "alerts.jsonl"
    log = guard.AlertLog(path, limit=3)
    for i in range(5):
        log.add({"kind": "tripwire", "severity": "high", "src_ip": f"10.0.0.{i}"})
    assert [a["id"] for a in log.alerts] == [3, 4, 5]
    assert [a["id"] for a in log.since(3)] == [4, 5]
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5 and json.loads(lines[-1])["src_ip"] == "10.0.0.4"


def test_alert_log_wait_wakes_up_on_new_alert():
    log = guard.AlertLog()
    threading.Timer(0.1, lambda: log.add({"kind": "x", "severity": "info"})).start()
    started = time.time()
    assert [a["id"] for a in log.wait(0, 3)] == [1] and time.time() - started < 2
    assert log.wait(1, 0.1) == []


def test_state_survives_a_restart_and_trust_works(tmp_path):
    path = tmp_path / "guard.json"
    sweeps = [{GW: MAC_GW, A: MAC_A}, {GW: MAC_GW, A: MAC_A, X: MAC_X}]
    log = guard.AlertLog()
    first = guard.Guard(log, ports=[], network=None, state_path=path, gateway=GW, sweep=lambda: sweeps.pop(0))
    assert kinds(first.sweep_once()) == [("baseline", "info")]
    assert kinds(first.sweep_once()) == [("new_device", "medium")]

    again = guard.Guard(guard.AlertLog(), ports=[], network=None, state_path=path, gateway=GW,
                        sweep=lambda: {GW: MAC_GW, A: MAC_A, X: MAC_X})
    assert again.sweep_once() == []  # already knows all three, and X was already reported
    assert again.status()["unknown"] == 1 and again.status()["trusted"] == 2
    assert again.trust("DE-AD-BE-EF-00-01") is True
    assert again.status()["unknown"] == 0 and again.status()["trusted"] == 3
    assert again.trust("not a mac") is False and again.trust("") is False
    assert guard.load_state(path)["devices"].keys() >= {MAC_X}


def test_damaged_state_file_starts_fresh(tmp_path):
    path = tmp_path / "guard.json"
    path.write_text("{ not json", encoding="utf-8")
    assert guard.load_state(path) == guard.new_state()
    assert guard.load_state(tmp_path / "missing.json") == guard.new_state()


# --------------------------------------------------------------------------
# tripwires
# --------------------------------------------------------------------------

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def poke(port, payload=b"", read=False):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
        if payload:
            s.sendall(payload)
        if read:
            s.settimeout(1)
            try:
                return s.recv(200)
            except OSError:
                return b""
    return b""


def make_guard(**kw):
    log = guard.AlertLog()
    g = guard.Guard(log, ports=kw.pop("ports", [0]), host="127.0.0.1", network=None,
                    ignore_local=False, gateway=GW, **kw)
    return log, g


def test_tripwire_alerts_with_the_source_and_what_it_sent():
    log, g = make_guard()
    port = g.start()["decoys"][0]
    try:
        poke(port, b"GET /admin HTTP/1.1\r\n")
        alerts = log.wait(0, 3)
    finally:
        g.stop()
    assert len(alerts) == 1
    alert = alerts[0]
    assert (alert["kind"], alert["severity"], alert["src_ip"], alert["port"]) == ("tripwire", "high", "127.0.0.1", port)
    assert alert["detail"]["count"] == 1 and "GET /admin" in alert["detail"]["sample"]


def test_tripwire_escalates_instead_of_flooding():
    log, g = make_guard()
    port = g.start()["decoys"][0]
    try:
        for _ in range(12):
            poke(port)
        deadline = time.time() + 5
        while len(log.alerts) < 2 and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
    finally:
        g.stop()
    assert [a["detail"]["count"] for a in log.alerts] == [1, 10]


def test_tripwire_speaks_like_the_service_it_imitates(monkeypatch):
    port = free_port()
    monkeypatch.setitem(guard._BANNERS, port, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
    _log, g = make_guard(ports=[port])
    g.start()
    try:
        assert poke(port, read=True).startswith(b"SSH-2.0-OpenSSH")
    finally:
        g.stop()


def test_own_and_trusted_addresses_are_ignored():
    log = guard.AlertLog()
    quiet = guard.Guard(log, ports=[0], host="127.0.0.1", network=None, gateway=GW)  # ignore_local defaults on
    port = quiet.start()["decoys"][0]
    try:
        poke(port)
        time.sleep(0.4)
        assert log.alerts == []
        quiet.ignore_local = False
        quiet.trusted_ips = {"127.0.0.1"}
        poke(port)
        time.sleep(0.4)
        assert log.alerts == []
    finally:
        quiet.stop()


def test_a_busy_port_is_reported_not_fatal():
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    busy = taken.getsockname()[1]
    _log, g = make_guard(ports=[busy, 0])
    try:
        status = g.start()
        assert busy in status["failed"] and len(status["decoys"]) == 1
    finally:
        g.stop()
        taken.close()


def test_stopping_closes_the_decoys():
    _log, g = make_guard()
    port = g.start()["decoys"][0]
    g.stop()
    time.sleep(0.6)
    with pytest.raises(OSError):
        poke(port)
    assert g.status()["running"] is False


def test_a_crashing_handler_does_not_kill_the_decoy():
    hits = []

    def handler(src, sport, dport, data):
        hits.append(dport)
        raise RuntimeError("boom")

    wire = guard.Tripwire([0], handler, host="127.0.0.1")
    listening, _ = wire.start()
    try:
        poke(listening[0])
        poke(listening[0])
        deadline = time.time() + 3
        while len(hits) < 2 and time.time() < deadline:
            time.sleep(0.05)
    finally:
        wire.stop()
    assert len(hits) == 2


# --------------------------------------------------------------------------
# responding
# --------------------------------------------------------------------------

def test_block_commands_for_linux_and_windows():
    linux = guard.block_commands("203.0.113.9", platform="linux")
    assert linux["options"][0]["commands"] == ["sudo iptables -I INPUT -s 203.0.113.9 -j DROP"]
    assert linux["options"][0]["undo"] == ["sudo iptables -D INPUT -s 203.0.113.9 -j DROP"]
    assert linux["options"][1]["name"] == "ufw"
    win = guard.block_commands("203.0.113.9", platform="win32")
    assert 'remoteip=203.0.113.9' in win["options"][0]["commands"][0]
    with pytest.raises(ValueError):
        guard.block_commands("203.0.113.9", platform="darwin")


@pytest.mark.parametrize("ip", ["10.0.0.1", "10.0.0.11", "127.0.0.1", "224.0.0.1", "0.0.0.0", "169.254.1.1"])
def test_protected_addresses_are_never_blocked(ip):
    with pytest.raises(guard.ProtectedAddress):
        guard.block_commands(ip, gateway="10.0.0.1", own={"10.0.0.11"}, platform="linux")


@pytest.mark.parametrize("ip", ["", "abc", "1.2.3.4; rm -rf /", "1.2.3.4 -j ACCEPT", "::1", "2001:db8::1", "1.2.3"])
def test_block_commands_reject_anything_that_is_not_an_ipv4_address(ip):
    with pytest.raises(ValueError):
        guard.block_commands(ip, platform="linux")


# --------------------------------------------------------------------------
# through the interface server
# --------------------------------------------------------------------------

@pytest.fixture()
def gui(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    app.guard_host = "127.0.0.1"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(app))
    port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, port
    app.finished.set()
    if app.guard:
        app.guard.stop()
    httpd.shutdown()
    httpd.server_close()


def api(port, app, path, method="GET", body=None, token=True):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"X-Nemla-Token": app.token} if token else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, "/api/" + path, body=json.dumps(body) if body is not None else None, headers=headers)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res.status, (json.loads(data) if data else None)


def test_guard_api_needs_the_token(gui):
    app, port = gui
    assert api(port, app, "guard/status", token=False)[0] == 401
    assert api(port, app, "guard/start", "POST", {}, token=False)[0] == 401


def test_start_watch_and_stop_over_the_api(gui):
    app, port = gui
    assert api(port, app, "guard/status") == (200, {"running": False})
    status, data = api(port, app, "guard/start", "POST", {"ports": [0], "interval": 0})
    assert status == 200 and data["running"] and len(data["decoys"]) == 1
    decoy = data["decoys"][0]
    assert api(port, app, "info")[1]["guard"]["running"] is True

    app.guard.ignore_local = False  # the test itself connects from this computer
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", f"/api/guard/events?k={app.token}")
    stream = conn.getresponse()
    assert stream.status == 200
    poke(decoy, b"hello")
    line = b""
    while not line.startswith(b"data: "):
        line = stream.readline()
    alert = json.loads(line[6:])
    conn.close()
    assert (alert["kind"], alert["src_ip"], alert["port"]) == ("tripwire", "127.0.0.1", decoy)

    assert api(port, app, "guard/stop", "POST", {})[1]["running"] is False
    time.sleep(0.6)
    with pytest.raises(OSError):
        poke(decoy)


def test_guard_start_validates_ports(gui):
    app, port = gui
    for bad in ([70000], ["abc"], list(range(1, 20)), [-1]):
        assert api(port, app, "guard/start", "POST", {"ports": bad, "interval": 0})[0] == 400
    assert api(port, app, "guard/status")[1]["running"] is False


def test_guard_ports_can_be_given_as_text(gui):
    app, port = gui
    status, data = api(port, app, "guard/start", "POST", {"ports": "0, 0", "interval": 0})
    assert status == 200 and len(data["decoys"]) == 2


def test_block_and_trust_endpoints(gui):
    app, port = gui
    status, data = api(port, app, "guard/block?ip=203.0.113.9")
    assert status == 200 and data["options"]
    assert api(port, app, "guard/block?ip=127.0.0.1")[0] == 409
    assert api(port, app, "guard/block?ip=1.2.3.4;reboot")[0] == 400
    assert api(port, app, "guard/trust", "POST", {"mac": MAC_X})[0] == 400  # guard is not running yet
    api(port, app, "guard/start", "POST", {"ports": [0], "interval": 0})
    app.guard.state["unknown"][MAC_X] = {"ip": X, "first_seen": 1}
    assert api(port, app, "guard/trust", "POST", {"mac": MAC_X}) == (200, {"ok": True})
    assert MAC_X in app.guard.state["devices"]
    assert api(port, app, "guard/trust", "POST", {"mac": "junk"})[0] == 400


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

@pytest.mark.parametrize("lang, marker", [("en", "decoy"), ("ar", "الطُّعم"), ("he", "הפיתיון")])
def test_alert_sentences_in_every_language(lang, marker):
    nemla._LANG = lang
    try:
        text = nemla.alert_text({"kind": "tripwire", "severity": "high", "src_ip": "10.0.0.9",
                                 "detail": {"count": 3, "ports": [2222, 2323]}})
    finally:
        nemla._LANG = "en"
    assert marker in text and "10.0.0.9" in text and "2222, 2323" in text


def test_every_alert_kind_has_a_sentence():
    samples = [
        {"kind": "new_device", "src_ip": X, "mac": MAC_X},
        {"kind": "arp_change", "src_ip": A, "detail": {"old_mac": MAC_A, "new_mac": MAC_X}},
        {"kind": "arp_change", "src_ip": GW, "detail": {"old_mac": MAC_GW, "new_mac": MAC_X, "gateway": True}},
        {"kind": "arp_dup", "src_ip": GW, "mac": MAC_X, "detail": {"ips": [GW, A]}},
        {"kind": "baseline", "detail": {"devices": 4}}]
    for lang in nemla.STRINGS:
        nemla._LANG = lang
        try:
            for sample in samples:
                text = nemla.alert_text(sample)
                assert text and "{" not in text
        finally:
            nemla._LANG = "en"


def test_new_device_sentence_names_the_vendor_or_explains_local_addresses():
    base = {"kind": "new_device", "src_ip": X, "mac": MAC_X}
    for lang in nemla.STRINGS:
        nemla._LANG = lang
        try:
            plain = nemla.alert_text({**base, "detail": {}})
            vendor = nemla.alert_text({**base, "detail": {"vendor": "VMware", "local": True}})
            local = nemla.alert_text({**base, "detail": {"local": True}})
            note = nemla.t("g_new_device_local")
        finally:
            nemla._LANG = "en"
        assert "VMware" in vendor and vendor.startswith(plain)
        assert note not in vendor  # a named maker replaces the generic note
        assert local == plain + note and "VMware" not in local


def test_guard_command_rejects_bad_ports(capsys):
    assert nemla.main(["--guard", "--guard-ports", "abc"]) == 1


def test_guard_command_prints_alerts_and_stops_on_ctrl_c(monkeypatch, capsys, tmp_path):
    class FakeGuard:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return {"decoys": [2222], "failed": {2323: "in use"}}

        def block(self, ip):
            return guard.block_commands(ip, platform="linux")

        def stop(self):
            print("fake stopped")

    calls = []

    def fake_wait(self, after, timeout):
        calls.append(after)
        if len(calls) == 1:
            return [{"id": 1, "kind": "tripwire", "severity": "high", "src_ip": "203.0.113.9",
                     "detail": {"count": 1, "ports": [2222]}}]
        raise KeyboardInterrupt

    monkeypatch.setattr(guard, "Guard", FakeGuard)
    monkeypatch.setattr(guard.AlertLog, "wait", fake_wait)
    assert nemla.main(["--guard", "--guard-log", str(tmp_path / "a.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.9 connected to decoy port(s) 2222" in out and "[High]" in out
    assert "sudo iptables -I INPUT -s 203.0.113.9 -j DROP" in out
    assert "Could not open decoy port 2323" in out and "Guard stopped." in out
