"""IPv6, end to end and at the edges: explicit targets, malformed input, prefix limits (a /64 is never expanded),
mixed IPv4/IPv6 sorting, reports, history and diff, and what discovery does (and does not) do for IPv6.

What IPv6 discovery cannot do is documented in the README ("IPv6 and neighbour discovery"): there is no broadcast in
IPv6, so an unknown IPv6 host on the LAN cannot be found by sweeping an address range the way IPv4 can. Give explicit
addresses (or a small range) and Nemla scans them; ARP-based discovery is IPv4 only.
"""
import time
import tracemalloc

import pytest

import nemla
from conftest import needs_ipv6
from nemla import history, net, targets

# ----------------------------------------------------------------------------------------------- malformed input

MALFORMED = [
    "::1::2", ":::1", "1:2:3:4:5:6:7:8:9", "gggg::1", "12345::1", "[::1", "::1]", "[::1]]", "[[::1]]", "::1/", "::1/abc", "::1/-1",
    "2001:db8::/129", "2001:db8::/999999999999999999999", "fe80::1%", "fe80::1%%eth0", "fe80::1% eth0", "fe80::1%" + "a" * 5000,
    "::1-", "-::1", "::2-::1", "::1-2001:db8::1-::3", "::ffff:999.1.1.1", "::1.2.3", "1::2::3::4", "٢٠٠١:db8::1",
    "2001:db8::1\x00", "2001:db8::1\n2001:db8::2", "::1;reboot", "::1 -c 9", "0x20010db8::1", ":", "::::", "1:", ":1",
]


@pytest.mark.parametrize("spec", MALFORMED)
def test_a_malformed_ipv6_target_is_a_clear_error_never_a_crash_or_a_hang(spec):
    started = time.monotonic()
    with pytest.raises(ValueError):
        nemla.parse_targets(spec)
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize("spec, expected", [
    ("::1", ["::1"]), ("0:0:0:0:0:0:0:1", ["::1"]), ("[::1]", ["::1"]), ("2001:DB8::A", ["2001:db8::a"]),
    ("2001:db8:0:0:0:0:0:1", ["2001:db8::1"]), ("fe80::1%eth0", ["fe80::1%eth0"]), ("fe80::1%12", ["fe80::1%12"]),
    ("fe80::1%br-1a2b", ["fe80::1%br-1a2b"]),
])
def test_valid_ipv6_forms_are_normalised(spec, expected):
    assert nemla.parse_targets(spec) == expected


def test_an_ipv4_mapped_address_is_one_ipv6_address_in_one_spelling():
    (only,) = nemla.parse_targets("::ffff:1.2.3.4")
    assert only in ("::ffff:1.2.3.4", "::ffff:102:304")                                        # Python's spelling varies by version


# ----------------------------------------------------------------------------------------------- prefixes are never expanded

@pytest.mark.parametrize("prefix", ["::/0", "2001:db8::/16", "2001:db8::/32", "2001:db8::/48", "2001:db8::/56", "2001:db8::/64",
                                    "2001:db8::/96", "2001:db8::/104", "fe80::/10", "ff02::/16", "2001:db8::/1"])
@pytest.mark.parametrize("limit", [1024, 65536, 10**9, None])
def test_a_large_ipv6_prefix_is_refused_at_once_whatever_the_limit(prefix, limit):
    """2**64 addresses do not fit in memory or in a lifetime: refused before anything is built, even with a huge --max-hosts."""
    tracemalloc.start()
    started = time.monotonic()
    try:
        with pytest.raises(ValueError):
            if limit is None:
                nemla.parse_targets(prefix)
            else:
                nemla.parse_targets(prefix, max_hosts=limit)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert time.monotonic() - started < 0.5 and peak < 2 * 1024 * 1024


def test_the_expansion_limit_is_strict_at_the_boundary():
    # /120: 256 addresses; IPv6 has no broadcast address, only the subnet-router anycast (the first) is left out
    assert len(nemla.parse_targets("2001:db8::/120", max_hosts=256)) == 255
    assert len(nemla.parse_targets("2001:db8::/120", max_hosts=256, all_addresses=True)) == 255
    with pytest.raises(ValueError):
        nemla.parse_targets("2001:db8::/120", max_hosts=100)                                # 255 > 100
    with pytest.raises(ValueError):
        nemla.parse_targets("2001:db8::/119", max_hosts=256)                                # 511 > 256
    with pytest.raises(ValueError):
        nemla.parse_targets("2001:db8::1-2001:db8::ffff", max_hosts=1000)                   # a range is counted before it is walked


def test_the_hard_ceiling_holds_even_when_the_caller_asks_for_more():
    with pytest.raises(ValueError):
        nemla.parse_targets("2001:db8::/64", max_hosts=2**80)
    assert targets.MAX_HOSTS_HARD <= 1 << 20


def test_a_big_but_allowed_ipv6_block_is_counted_lazily_not_built():
    tracemalloc.start()
    try:
        source = targets.iter_targets("2001:db8::/108", max_hosts=1 << 20)                   # 1,048,575 hosts
        assert len(source) == (1 << 20) - 1
        first = next(iter(source))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert first == "2001:db8::1" and peak < 4 * 1024 * 1024                                 # nothing like a million strings


def test_many_prefixes_in_one_target_list_are_still_bounded():
    with pytest.raises(ValueError):
        nemla.parse_targets(",".join(f"2001:db8:{i:x}::/120" for i in range(600)))            # over the item limit
    with pytest.raises(ValueError):
        nemla.parse_targets(",".join(f"2001:db8:{i:x}::/112" for i in range(64)), max_hosts=1024)   # 64 x 65,534 hosts


# ----------------------------------------------------------------------------------------------- families and sorting

def test_family_switches_pick_and_refuse_the_right_addresses():
    assert nemla.parse_targets("127.0.0.1, ::1") == ["127.0.0.1", "::1"]
    with pytest.raises(ValueError):
        nemla.parse_targets("127.0.0.1, ::1", family=6)                                     # -6 refuses the IPv4 item, it does not skip it
    with pytest.raises(ValueError):
        nemla.parse_targets("::1", family=4)
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.1", family=6)


def test_sorting_puts_ipv4_first_then_ipv6_numerically_and_never_raises():
    ips = ["2001:db8::10", "::1", "10.0.0.10", "fe80::1%eth0", "2001:db8::2", "10.0.0.9", "0:0:0:0:0:0:0:2", "9.9.9.9", "fe80::1"]
    ordered = sorted(ips, key=net.ip_sort_key)
    assert ordered[:3] == ["9.9.9.9", "10.0.0.9", "10.0.0.10"]                                # IPv4 first, numerically
    v6 = ordered[3:]
    assert v6.index("::1") < v6.index("0:0:0:0:0:0:0:2") < v6.index("2001:db8::2") < v6.index("2001:db8::10")
    assert sorted(ips, key=net.ip_sort_key) == sorted(sorted(ips, reverse=True), key=net.ip_sort_key)     # a total order, whatever the input order
    assert net.ip_sort_key("not an ip") is not None                                           # garbage sorts, it does not crash


# ----------------------------------------------------------------------------------------------- scan, report, history, diff

def scan_record(ip, port=80):
    return {"ip": ip, "mac": None, "discovery": "skipped", "os_guess": "Linux", "ttl": 64,
            "os": {"name": "Linux", "family": "linux", "confidence": 0.6, "label": "Linux", "heuristic": True, "evidence": []},
            "vendor": None, "scanned": {"tcp": str(port), "udp": ""}, "udp_unconfirmed": [], "findings": [],
            "open_ports": [{"port": port, "proto": "tcp", "state": "open", "service": "HTTP", "banner": "", "product": "nginx",
                            "version": "1.24", "confidence": 0.9, "heuristic": False}]}


META = {"target": "mixed", "scan_time": "2026-09-21 10:00:00", "duration": 1.0, "ports_scanned": 1, "discovered": 3,
        "cancelled": False, "findings": {"high": 0, "medium": 0, "low": 0, "info": 0}, "warnings": [], "capabilities": {}}
MIXED = ["2001:db8::10", "192.168.1.5", "fe80::1%eth0", "10.0.0.9", "::1"]


def test_every_report_format_handles_mixed_ipv4_and_ipv6_hosts():
    hosts = [scan_record(ip) for ip in MIXED]
    import json
    assert json.loads(nemla.sarif_text(META, hosts))["version"] == "2.1.0"                    # (its results carry only findings)
    for render in (nemla.render_html, nemla.markdown_text, nemla.json_text):
        text = render(META, hosts)
        for ip in MIXED:
            assert ip in text or ip.replace(":", "\\:") in text or ip.split("%")[0] in text, (render.__name__, ip)
    csv = nemla.csv_text(hosts)
    assert all(ip in csv for ip in MIXED)


def test_history_and_diff_work_for_ipv6_and_mixed_hosts(tmp_path):
    before = [scan_record(ip) for ip in MIXED[:3]]
    after = [scan_record(ip) for ip in MIXED[:3]] + [scan_record("2001:db8::99"), scan_record("10.0.0.9", 8080)]
    first = history.save(tmp_path, nemla, dict(META), before)
    second = history.save(tmp_path, nemla, dict(META), after)
    assert history.load(tmp_path, first)["hosts"][0]["ip"] in MIXED
    assert history.previous_for(tmp_path, "mixed", second) == first
    diff = nemla.diff_scans(history.load(tmp_path, first)["hosts"], history.load(tmp_path, second)["hosts"])
    assert diff["new_hosts"] == ["10.0.0.9", "2001:db8::99"]                                  # IPv4 first, then IPv6
    assert diff["summary"]["new_hosts"] == 2 and diff["summary"]["worse"] is True
    text = "\n".join(nemla.diff_lines(diff))
    assert "2001:db8::99" in text and "10.0.0.9" in text


def test_a_scan_id_or_ip_can_never_reach_the_file_system_through_ipv6_text(tmp_path):
    for hostile in ("::1/../../x", "fe80::1%../../../etc", "..\\..\\x", "2001:db8::1\x00.json"):
        assert history.valid_id(hostile) is False
        assert history.load(tmp_path, hostile) is None


@needs_ipv6
def test_scanning_several_explicit_ipv6_ports_and_the_summary(tcp_server):
    import socket
    ports = [tcp_server(lambda c: (c.sendall(b"SSH-2.0-OpenSSH_9.6p1\r\n"), c.close()), host="::1", family=socket.AF_INET6),
             tcp_server(lambda c: c.close(), host="::1", family=socket.AF_INET6)]
    hosts, meta = nemla.run_scan("::1", ["::1"], [*ports, 1], no_ping=True, no_os=True, timeout=1.0)
    assert [p["port"] for p in hosts[0]["open_ports"]] == sorted(ports)
    assert meta["capabilities"]["ipv6"] is True and meta["discovered"] == 1


@needs_ipv6
def test_localhost_resolves_to_ipv6_when_asked():
    try:
        found = nemla.parse_targets("localhost", family=6)
    except ValueError:
        pytest.skip("this machine's localhost has no IPv6 address")
    assert "::1" in found


# ----------------------------------------------------------------------------------------------- discovery limits

def test_arp_discovery_is_never_attempted_for_ipv6_targets(monkeypatch):
    """There is no ARP for IPv6 and no broadcast sweep: IPv6 hosts are probed one by one (ICMP/TCP), or taken as given."""
    from nemla import discovery
    called = []
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda *a, **k: called.append("sweep") or {})
    monkeypatch.setattr(discovery, "scapy_arp_scan", lambda *a, **k: called.append("scapy") or {})
    monkeypatch.setattr(discovery, "icmp_ping", lambda ip, cancel=None: False)
    monkeypatch.setattr(discovery, "tcp_ping", lambda *a, **k: False)
    found = discovery.discover_hosts(["2001:db8::1", "2001:db8::2"], probe_ports=(80,), timeout=0.1)
    assert found == {} and called == []


def test_the_documentation_states_the_ipv6_discovery_limit():
    from pathlib import Path
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    assert "IPv6 and neighbour discovery" in readme and "cannot be found" in readme
