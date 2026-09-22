"""UDP reconnaissance (states, probes, rate limit) and IPv6 support."""
import errno
import socket
import struct
import time

import pytest

import nemla
from nemla import net
from nemla.fingerprint import dns
from nemla.scanning import udp

from conftest import needs_ipv6
from test_fingerprint import dns_reply


def use_probe(monkeypatch, port, factory):
    """Real services live on well-known ports; the tests run theirs on free ones."""
    monkeypatch.setitem(udp.UDP_PROBES, port, factory)


# --------------------------------------------------------------------------
# reply builders for the fake servers
# --------------------------------------------------------------------------

def snmp_reply(request, text=b"Linux router 5.15.0 #1 SMP"):
    request_id = request[request.index(b"\x02\x04") + 2:request.index(b"\x02\x04") + 6]
    oid = bytes.fromhex("2b06010201010100")
    varbind = b"\x30" + bytes([len(oid) + 2 + 2 + len(text)]) + b"\x06\x08" + oid + b"\x04" + bytes([len(text)]) + text
    varbinds = b"\x30" + bytes([len(varbind)]) + varbind
    pdu_body = b"\x02\x04" + request_id + b"\x02\x01\x00\x02\x01\x00" + varbinds
    pdu = b"\xa2" + bytes([len(pdu_body)]) + pdu_body
    body = b"\x02\x01\x00\x04\x06public" + pdu
    return b"\x30" + bytes([len(body)]) + body


def netbios_reply(request):
    names = [(b"LABBOX         ", 0x00, 0x0400), (b"WORKGROUP      ", 0x00, 0x8400)]
    answer = request[:2] + struct.pack("!HHHHH", 0x8400, 0, 1, 0, 0) + request[12:12 + 34] + struct.pack("!HHIH", 0x21, 1, 0, 1 + 18 * len(names) + 6)
    body = bytes([len(names)]) + b"".join(n + bytes([s]) + struct.pack("!H", f) for n, s, f in names) + b"\x00" * 6
    return answer + body


# --------------------------------------------------------------------------
# protocols
# --------------------------------------------------------------------------

def test_dns_over_udp(udp_server, monkeypatch):
    port = udp_server(lambda data, addr, sock: dns_reply(data))
    use_probe(monkeypatch, port, udp._dns_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert rec["state"] == "open" and rec["proto"] == "udp" and rec["detected"] == "dns"
    assert rec["product"] == "BIND" and rec["details"]["recursion_available"] is True and rec["details"]["transport"] == "udp"
    assert rec["confidence"] >= 0.9 and rec["heuristic"] is False


def test_ntp(udp_server, monkeypatch):
    port = udp_server(lambda data, addr, sock: bytes([0x24, 2]) + b"\x00" * 46 if len(data) == 48 else None)
    use_probe(monkeypatch, port, udp._ntp_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert rec["detected"] == "ntp" and rec["details"]["stratum"] == 2 and rec["details"]["ntp_version"] == 4


def test_snmp_default_community_is_a_finding(udp_server, monkeypatch):
    port = udp_server(lambda data, addr, sock: snmp_reply(data) if b"public" in data else None)
    use_probe(monkeypatch, port, udp._snmp_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert rec["detected"] == "snmp" and rec["details"]["community"] == "public" and "Linux router" in rec["details"]["sysdescr"]
    assert rec["os_hint"] == "Linux"
    found = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{**rec, "port": 161}]})}
    assert found["snmp_default"]["severity"] == "medium"
    assert {f["id"]: f for f in nemla.assess_host({"ip": "8.8.8.8", "open_ports": [{**rec, "port": 161}]})}["snmp_default"]["severity"] == "high"


def test_snmp_request_is_well_formed_and_parser_is_strict():
    request = udp.snmp_get_request()
    assert request[0] == 0x30 and request[1] == len(request) - 2 and b"public" in request
    assert udp.parse_snmp_response(snmp_reply(request)).startswith("Linux router")
    assert udp.parse_snmp_response(b"") is None and udp.parse_snmp_response(b"\x30\x03\x02\x01\x00") is None
    assert udp.parse_snmp_response(snmp_reply(request)[:30]) in (None, "")            # truncated: never raises
    other = udp.snmp_get_request(request_id=b"\x00\x00\x00\x01")
    assert udp.parse_snmp_response(snmp_reply(other)) is None                        # someone else's answer


def test_ssdp_netbios_tftp_rpcbind_memcached(udp_server, monkeypatch):
    port = udp_server(lambda d, a, s: b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nSERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r\n\r\n")
    use_probe(monkeypatch, port, udp._ssdp_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert (rec["detected"], rec["product"], rec["version"]) == ("ssdp", "MiniUPnPd", "2.1") and rec["os_hint"] == "Linux"

    port = udp_server(lambda d, a, s: netbios_reply(d))
    use_probe(monkeypatch, port, udp._netbios_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert rec["detected"] == "netbios-ns" and rec["details"]["netbios_name"] == "LABBOX" and rec["details"]["workgroup"] == "WORKGROUP"

    port = udp_server(lambda d, a, s: b"\x00\x05\x00\x01File not found\x00")
    use_probe(monkeypatch, port, udp._tftp_probe)
    assert udp.scan_udp_port("127.0.0.1", port, 1.0)["detected"] == "tftp"

    port = udp_server(lambda d, a, s: d[:4] + struct.pack("!II", 1, 0) + b"\x00" * 20)
    use_probe(monkeypatch, port, udp._rpcbind_probe)
    assert udp.scan_udp_port("127.0.0.1", port, 1.0)["detected"] == "rpcbind"

    port = udp_server(lambda d, a, s: d[:8] + b"VERSION 1.6.9\r\n")
    use_probe(monkeypatch, port, udp._memcached_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert rec["detected"] == "memcached" and rec["version"] == "1.6.9"
    found = {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{**rec, "port": 11211}]})}
    assert "memcached" in found


def test_mdns(udp_server, monkeypatch):
    port = udp_server(lambda d, a, s: dns_reply(d))
    use_probe(monkeypatch, port, udp._mdns_probe)
    assert udp.scan_udp_port("127.0.0.1", port, 1.0)["detected"] == "mdns"


def test_snmp_response_without_an_octet_string_tag_is_empty():
    request_id = b"\x4e\x45\x4d\x4c"
    reply = b"\x30\x00\xa2\x02\x04" + request_id + udp._SNMP_SYSDESCR + b"\x05\x00"   # 0x05 (NULL), not 0x04 (OCTET STRING)
    assert udp.parse_snmp_response(reply, request_id) == ""


def test_snmp_response_with_a_long_form_length_is_parsed():
    request_id = b"\x4e\x45\x4d\x4c"
    reply = b"\x30\x00\xa2\x02\x04" + request_id + udp._SNMP_SYSDESCR + b"\x04\x81\x05hello"
    assert udp.parse_snmp_response(reply, request_id) == "hello"


@pytest.mark.parametrize("indicator, rest", [
    (b"\x80", b""),                 # count 0 (the reserved "indefinite length" form, refused outright)
    (b"\x83", b"\x00\x00\x00"),     # count 3: this parser only ever follows 1 or 2 length octets
    (b"\x82", b"\x00"),             # count 2, but only 1 octet actually follows: truncated
])
def test_snmp_response_with_an_unusable_long_form_length_is_empty(indicator, rest):
    request_id = b"\x4e\x45\x4d\x4c"
    reply = b"\x30\x00\xa2\x02\x04" + request_id + udp._SNMP_SYSDESCR + b"\x04" + indicator + rest
    assert udp.parse_snmp_response(reply, request_id) == ""


def test_each_probe_rejects_a_reply_that_does_not_validate(udp_server, monkeypatch):
    """The happy path for each of these is already covered elsewhere; this is what happens when a UDP service on
    that port answers, but not with anything the probe recognises - a real possibility since UDP has no handshake
    to rule out talking to the wrong protocol."""
    fixed_cases = [
        (udp._mdns_probe, lambda d, a, s: b"\x01\x02"),                             # not even DNS-shaped
        (udp._ntp_probe, lambda d, a, s: b"\x00" * 10),                             # too short for an NTP header
        (udp._ssdp_probe, lambda d, a, s: b"not an HTTP or NOTIFY response line"),
        (udp._netbios_probe, lambda d, a, s: b"\x00" * 10),                         # too short for a name table
        (udp._tftp_probe, lambda d, a, s: struct.pack("!H", 99) + b"junk"),         # neither DATA (3) nor ERROR (5)
        (udp._rpcbind_probe, lambda d, a, s: b"\x00\x00\x00\x00" + struct.pack("!I", 1) + b"\x00" * 16),  # wrong xid
        (udp._memcached_probe, lambda d, a, s: b"12345678ERROR\r\n"),               # no VERSION line
        (udp._snmp_probe, lambda d, a, s: b"not snmp at all"),
    ]
    for factory, handler in fixed_cases:
        port = udp_server(handler)
        use_probe(monkeypatch, port, factory)
        rec = udp.scan_udp_port("127.0.0.1", port, 0.3)
        assert rec["state"] == "open" and rec["detected"] == "unknown", factory.__name__


def test_netbios_stops_at_the_first_entry_a_hostile_reply_cannot_fill(udp_server, monkeypatch):
    """The name table claims 2 entries but only has data for 1: parsing stops there instead of reading past the
    end of the reply, and the entry that WAS complete is still used rather than discarding everything."""
    def handler(request, addr, sock):
        tid = request[:2]
        header = tid + struct.pack("!HHHHH", 0x8400, 0, 1, 0, 0) + request[12:12 + 34] + struct.pack("!HHIH", 0x21, 1, 0, 0)
        one_entry = b"A" * 15 + b"\x00" + struct.pack("!H", 0)
        return header + bytes([2]) + one_entry + b"short"      # 5 bytes left where the 2nd 18-byte entry should be
    port = udp_server(handler)
    use_probe(monkeypatch, port, udp._netbios_probe)
    rec = udp.scan_udp_port("127.0.0.1", port, 0.3)
    assert rec["detected"] == "netbios-ns" and rec["details"]["netbios_name"] == "AAAAAAAAAAAAAAA"


def test_scan_udp_port_respects_the_probe_budget():
    from nemla.scanning.scheduler import ProbeBudget
    budget = ProbeBudget(1)
    assert budget.take()                              # use up the one unit this probe is allowed
    assert udp.scan_udp_port("127.0.0.1", 12345, 0.2, budget=budget) is None


def test_scan_udp_port_survives_a_check_function_that_crashes(udp_server, monkeypatch):
    diagnostics = nemla.Diagnostics()
    port = udp_server(lambda d, a, s: b"anything")

    def hostile(ip):
        def check(reply):
            raise RuntimeError("hostile reply crashed the parser")
        return b"probe", check
    use_probe(monkeypatch, port, hostile)
    rec = udp.scan_udp_port("127.0.0.1", port, 0.3, diagnostics=diagnostics)
    assert rec["state"] == "open" and rec["detected"] == "unknown"
    assert diagnostics.as_list()[0]["code"] == "detector_error"


# --------------------------------------------------------------------------
# the four states
# --------------------------------------------------------------------------

def test_open_state_even_when_the_reply_is_not_the_expected_protocol(udp_server):
    port = udp_server(lambda d, a, s: b"\x01\x02\x03 who knows")
    rec = udp.scan_udp_port("127.0.0.1", port, 1.0)
    assert rec["state"] == "open" and rec["heuristic"] is True and rec["confidence"] <= 0.3


def test_silence_is_open_or_filtered_and_says_so(udp_server):
    port = udp_server(lambda d, a, s: None)
    rec = udp.scan_udp_port("127.0.0.1", port, 0.2, retries=1)
    assert rec["state"] == "open|filtered" and rec["heuristic"] is True


def test_a_closed_port_is_reported_as_closed(monkeypatch):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    state, reply = net.udp_exchange("127.0.0.1", port, b"x", 1.0)
    if state == "open|filtered":
        pytest.skip("this system does not send ICMP port-unreachable to loopback")
    assert (state, reply) == ("closed", b"")
    assert udp.scan_udp_port("127.0.0.1", port, 1.0) is None


def test_local_errors_give_the_unknown_state(monkeypatch):
    class Broken:
        def setblocking(self, flag): pass
        def connect(self, addr): pass
        def send(self, data): raise OSError(errno.ENETUNREACH, "Network is unreachable")
        def close(self): pass

    monkeypatch.setattr(net.socket, "socket", lambda *a, **k: Broken())
    assert net.udp_exchange("203.0.113.9", 53, b"x", 0.2) == ("unknown", b"")


def test_the_scan_udp_record_lists_states_per_host(udp_server, monkeypatch):
    answering = udp_server(lambda d, a, s: dns_reply(d))
    quiet = udp_server(lambda d, a, s: None)
    use_probe(monkeypatch, answering, udp._dns_probe)
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [1], no_ping=True, no_os=True, timeout=0.3,
                                 udp_ports=[answering, quiet], udp_timeout=0.2)
    host = hosts[0]
    assert meta["udp_ports_scanned"] == 2 and host["scanned"]["udp"]
    assert [p["port"] for p in host["open_ports"] if p["proto"] == "udp"] == [answering]
    assert [p["port"] for p in host["udp_unconfirmed"]] == [quiet] and host["udp_unconfirmed"][0]["state"] == "open|filtered"


def test_udp_is_paced_by_the_rate_limit():
    ports = []
    for _ in range(8):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        s.close()
    started = time.monotonic()
    udp.scan_host_udp("127.0.0.1", ports, timeout=0.05, rate=10, retries=0)
    assert time.monotonic() - started >= 0.6              # 8 packets at 10 per second


def test_udp_probe_budget_and_defaults():
    assert set(udp.UDP_PROBES) >= {53, 69, 111, 123, 137, 161, 1900, 5353, 11211}
    assert set(nemla.UDP_PORTS) <= set(udp.UDP_PROBES)
    assert udp.service_name_udp(161) == "SNMP" and udp.service_name_udp(53) == "DNS"


def test_udp_cli_flags(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(nemla.cli, "run_scan", lambda *a, **k: seen.update(k) or ([], {"discovered": 0}))
    nemla.main(["-t", "127.0.0.1", "--udp", "-o", str(tmp_path / "r.html")])
    assert tuple(seen["udp_ports"]) == nemla.UDP_PORTS
    nemla.main(["-t", "127.0.0.1", "--udp-ports", "53,123", "--udp-rate", "5", "-o", str(tmp_path / "r.html")])
    assert tuple(seen["udp_ports"]) == (53, 123) and seen["udp_rate"] == 5.0
    nemla.main(["-t", "127.0.0.1", "-o", str(tmp_path / "r.html")])
    assert tuple(seen["udp_ports"]) == ()


# --------------------------------------------------------------------------
# IPv6
# --------------------------------------------------------------------------

@needs_ipv6
def test_scan_a_port_over_ipv6(tcp_server):
    port = tcp_server(lambda c: (c.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"), time.sleep(0.2), c.close()),
                      host="::1", family=socket.AF_INET6)
    rec = nemla.scan_port("::1", port, 1.0)
    assert rec["product"] == "OpenSSH" and rec["state"] == "open"


@needs_ipv6
def test_full_scan_report_and_history_for_an_ipv6_host(tcp_server, tmp_path):
    port = tcp_server(lambda c: (c.sendall(b"220 (vsFTPd 3.0.5)\r\n"), time.sleep(0.2), c.close()),
                      host="::1", family=socket.AF_INET6)
    hosts, meta = nemla.run_scan("::1", ["::1"], [port], no_ping=True, timeout=1.0)
    assert hosts[0]["ip"] == "::1" and hosts[0]["open_ports"][0]["product"] == "vsftpd"
    assert "::1" in nemla.render_html(meta, hosts) and '"ip": "::1"' in nemla.json_text(meta, hosts)
    from nemla import history
    scan_id = history.save(tmp_path, nemla, meta, hosts)
    assert history.load(tmp_path, scan_id)["hosts"][0]["ip"] == "::1"
    assert nemla.diff_scans(hosts, hosts)["summary"]["changed"] is False


@needs_ipv6
def test_discovery_tcp_ping_and_ping_command_for_ipv6(tcp_server):
    port = tcp_server(lambda c: c.close(), host="::1", family=socket.AF_INET6)
    assert nemla.tcp_ping("::1", ports=(port,), timeout=1.0) is True
    found = nemla.discover_hosts(["::1"], probe_ports=(port,), use_arp=False, timeout=1.0)
    assert "::1" in found
    cmd = nemla._ping_cmd("::1")
    assert "-6" in cmd or cmd[0] == "ping6"


def test_ipv6_ping_command_shapes(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    assert nemla._ping_cmd("::1")[:2] == ["ping", "-6"]
    assert nemla._ping_cmd("10.0.0.1")[:2] == ["ping", "-c"]
    monkeypatch.setattr("sys.platform", "win32")
    assert nemla._ping_cmd("::1")[:2] == ["ping", "-6"]
    monkeypatch.setattr("sys.platform", "darwin")
    assert nemla._ping_cmd("::1")[0] == "ping6"


@pytest.mark.parametrize("bad", ["-f", "--help", "; reboot", "10.0.0.1 -c 9", "$(id)", "", "1.2.3", "localhost"])
def test_ping_never_receives_something_that_is_not_an_ip_address(bad):
    with pytest.raises(ValueError):
        nemla._ping_cmd(bad)
    assert nemla.icmp_ping(bad) is False


def test_ipv6_in_the_ui_helpers():
    import re
    from pathlib import Path
    js = (Path(nemla.__file__).resolve().parent.parent / "nemla_ui" / "web" / "app.js").read_bytes().decode("utf-8", "replace")
    assert not re.search(r"ip\.split\('\.'\)\.reduce", js), "sorting must not assume dotted IPv4"
    assert dns.build_query() and net.is_external("2001:4860:4860::8888")
