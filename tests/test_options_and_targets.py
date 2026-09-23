"""Option validation, target and port parsing (IPv4, IPv6, hostile input)."""
import ipaddress
import time

import pytest

import nemla
from nemla import config, net, targets


# --------------------------------------------------------------------------
# option validation: --timeout, --threads, --max-hosts ...
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["0", "-1", "-0.5", "nan", "inf", "-inf", "abc", "", "1e999", "61"])
def test_cli_rejects_bad_timeouts(value, capsys):
    with pytest.raises(SystemExit) as exit_info:
        nemla.main(["-t", "127.0.0.1", "--timeout", value])
    assert exit_info.value.code == 2
    assert "timeout" in capsys.readouterr().err


@pytest.mark.parametrize("flag, value", [
    ("--threads", "0"), ("--threads", "-4"), ("--threads", "99999"), ("--threads", "x"),
    ("--max-hosts", "0"), ("--max-hosts", "-1"), ("--per-host", "0"), ("--intensity", "10"),
    ("--intensity", "-1"), ("--rate", "-5"), ("--rate", "nan"), ("--udp-timeout", "0"), ("--udp-rate", "-1"),
    ("--max-probes", "-1"),
])
def test_cli_rejects_out_of_range_numbers(flag, value):
    with pytest.raises(SystemExit) as exit_info:
        nemla.main(["-t", "127.0.0.1", flag, value])
    assert exit_info.value.code == 2


def test_cli_accepts_the_edges():
    args = nemla.build_parser().parse_args(["-t", "x", "--timeout", "0.001", "--threads", "1", "--max-hosts", "1",
                                            "--intensity", "0", "--rate", "0"])
    assert (args.timeout, args.threads, args.max_hosts, args.intensity, args.rate) == (0.001, 1, 1, 0, 0.0)


def test_scan_options_validate_for_library_callers():
    with pytest.raises(config.OptionError):
        config.ScanOptions.checked(timeout=0)
    with pytest.raises(config.OptionError):
        config.ScanOptions.checked(timeout=float("nan"))
    with pytest.raises(config.OptionError):
        config.ScanOptions.checked(threads=0)
    with pytest.raises(ValueError):                       # OptionError is a ValueError
        nemla.run_scan("127.0.0.1", ["127.0.0.1"], [80], timeout=-1)
    ok = config.ScanOptions.checked(threads=10, per_host=500)
    assert ok.per_host == 10                             # never more per host than in total


# --------------------------------------------------------------------------
# targets
# --------------------------------------------------------------------------

def test_ipv4_forms_still_work():
    assert nemla.parse_targets("10.0.0.7") == ["10.0.0.7"]
    assert nemla.parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert nemla.parse_targets("10.0.0.7/32") == ["10.0.0.7"]
    assert nemla.parse_targets("10.0.0.6/31") == ["10.0.0.6", "10.0.0.7"]
    assert nemla.parse_targets("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert nemla.parse_targets("10.0.0.254-10.0.1.1") == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]


def test_several_targets_are_merged_without_duplicates():
    assert nemla.parse_targets("10.0.0.1-3, 10.0.0.2, 10.0.0.9") == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"]
    assert nemla.parse_targets("10.0.0.0/30 10.0.0.1-2") == ["10.0.0.1", "10.0.0.2"]


def test_ipv6_targets():
    assert nemla.parse_targets("::1") == ["::1"]
    assert nemla.parse_targets("[2001:db8::5]") == ["2001:db8::5"]
    assert nemla.parse_targets("2001:db8::/126") == ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    assert nemla.parse_targets("2001:db8::1-2001:db8::3") == ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    assert nemla.parse_targets("::1, 127.0.0.1") == ["127.0.0.1", "::1"]         # IPv4 first, then IPv6
    assert nemla.parse_targets("fe80::1%eth0") == ["fe80::1%eth0"]


def test_family_filter():
    with pytest.raises(ValueError):
        nemla.parse_targets("::1", family=4)
    with pytest.raises(ValueError):
        nemla.parse_targets("127.0.0.1", family=6)
    assert nemla.parse_targets("localhost", family=4)[0].startswith("127.")


def test_names_resolve_with_getaddrinfo():
    result = nemla.parse_targets("localhost")
    assert len(result) == 1 and net.parse_ip(result[0]) is not None
    both = nemla.parse_targets("localhost", all_addresses=True)
    assert set(result) <= set(both)


@pytest.mark.parametrize("bad", [
    "", "   ", ",,,", "10.0.0.9-10.0.0.1", "10.0.0.1-", "999.1.1.1", "10.0.0.0/33", "10.0.0.1/abc",
    "10.0.0.1; rm -rf /", "$(reboot)", "-oX", "--help", "host name", "a\x00b", "a\nb", "no.such.host.invalid",
    "2001:db8::9-2001:db8::1", "x" * 5000,
])
def test_hostile_or_broken_targets_are_refused(bad):
    with pytest.raises(ValueError):
        nemla.parse_targets(bad)


def test_max_hosts_is_checked_before_anything_is_built():
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.0/16", max_hosts=1024)
    with pytest.raises(ValueError):
        nemla.parse_targets("2001:db8::/64", max_hosts=1024)          # 2**64 addresses: refused at once
    started = time.monotonic()
    big = nemla.iter_targets("10.0.0.0/12", max_hosts=2_000_000)
    assert len(big) == 2 ** 20 - 2                                     # counted, not expanded
    assert time.monotonic() - started < 0.5
    first = next(iter(big))
    assert first == "10.0.0.1"


def test_target_set_is_lazy_and_reiterable():
    ts = nemla.iter_targets("192.168.0.0/24")
    assert len(ts) == 254 and list(ts)[:2] == ["192.168.0.1", "192.168.0.2"]
    assert list(ts) == list(ts)


def test_hard_limit_wins_over_max_hosts():
    with pytest.raises(ValueError):
        nemla.iter_targets("10.0.0.0/8", max_hosts=10 ** 12)      # ~16.7 million addresses: never planned for


# --------------------------------------------------------------------------
# ports
# --------------------------------------------------------------------------

def test_ports_forms():
    assert nemla.parse_ports("22") == [22]
    assert nemla.parse_ports("80, 22 ,443,22") == [22, 80, 443]
    assert nemla.parse_ports("1-3,8080") == [1, 2, 3, 8080]
    assert nemla.parse_ports("1 2 3") == [1, 2, 3]
    assert len(nemla.parse_ports("1-65535")) == 65535


@pytest.mark.parametrize("bad", ["", " , ", "0", "65536", "70000", "abc", "22-", "-22", "5-1", "1-99999999999",
                                 "1e3", "22;23", "1..5", "0-10", "١٢٣"])
def test_bad_ports_are_refused(bad):
    with pytest.raises(ValueError):
        nemla.parse_ports(bad)


def test_port_range_bomb_is_refused_quickly():
    started = time.monotonic()
    with pytest.raises(ValueError):
        nemla.parse_ports("1-999999999999999")
    with pytest.raises(ValueError):
        nemla.parse_ports("1-70000")
    assert time.monotonic() - started < 0.2


def test_format_ports_round_trip():
    assert targets.format_ports([1, 2, 3, 8080, 5]) == "1-3,5,8080"
    assert nemla.parse_ports(targets.format_ports(range(1, 1025))) == list(range(1, 1025))
    assert targets.format_ports([]) == ""


# --------------------------------------------------------------------------
# "is this address on the public internet?" (is_global based)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("ip, expected", [
    ("8.8.8.8", True), ("1.1.1.1", True), ("2001:4860:4860::8888", True), ("::ffff:8.8.8.8", True),
    ("10.1.2.3", False), ("172.16.0.1", False), ("192.168.1.1", False), ("127.0.0.1", False), ("::1", False),
    ("169.254.1.1", False), ("fe80::1", False), ("fc00::1", False), ("fd12:3456::1", False),
    ("100.64.0.1", False),            # carrier-grade NAT space is not the public internet
    ("192.0.2.1", False), ("198.51.100.7", False), ("203.0.113.9", False), ("2001:db8::1", False),  # documentation
    ("224.0.0.1", False), ("ff02::1", False), ("0.0.0.0", False), ("255.255.255.255", False),
    ("::ffff:10.0.0.1", False), ("fe80::1%eth0", False),
    ("not an ip", False), ("", False), ("999.1.1.1", False),
])
def test_is_external(ip, expected):
    assert net.is_external(ip) is expected


def test_is_external_is_used_for_severity():
    def host(ip):
        return {"ip": ip, "open_ports": [{"port": 21, "service": "FTP", "banner": ""}]}
    assert nemla.assess_host(host("100.64.0.9"))[0]["severity"] == "medium"     # CGNAT: not public
    assert nemla.assess_host(host("8.8.8.8"))[0]["severity"] == "high"
    assert nemla.assess_host(host("::1"))[0]["severity"] == "medium"


def test_addresses_sort_numerically_and_by_family():
    ips = ["10.0.0.10", "10.0.0.9", "::1", "2001:db8::2", "9.9.9.9"]
    assert sorted(ips, key=net.ip_sort_key) == ["9.9.9.9", "10.0.0.9", "10.0.0.10", "::1", "2001:db8::2"]


def test_sockaddr_for_both_families():
    assert net.sockaddr("10.0.0.1", 80) == ("10.0.0.1", 80)
    assert net.sockaddr("::1", 80) == ("::1", 80, 0, 0)
    assert net.sockaddr("fe80::1%3", 80) == ("fe80::1", 80, 0, 3)
    with pytest.raises(ValueError):
        net.sockaddr("fe80::1%no-such-interface-xyz", 80)
    assert net.af_of("::1") != net.af_of("127.0.0.1")
    assert ipaddress.ip_address(net.split_zone("fe80::1%eth0")[0]).version == 6

def test_all_local_asks_the_predicate_about_every_address():
    targets = nemla.iter_targets("10.0.0.1-3")
    assert targets.all_local(lambda ip: ip.startswith("10.")) is True
    assert targets.all_local(lambda ip: ip != "10.0.0.2") is False


def test_a_name_that_resolves_to_nothing_is_refused(monkeypatch):
    from nemla import targets
    monkeypatch.setattr(targets.socket, "getaddrinfo", lambda *args, **kwargs: [])
    with pytest.raises(ValueError):
        targets.resolve("empty.example")


def test_a_range_whose_end_is_not_an_address_is_refused():
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.1-999")


def test_a_name_that_resolves_to_a_scoped_address_keeps_its_zone(monkeypatch):
    from nemla import targets
    monkeypatch.setattr(targets, "resolve", lambda *args, **kwargs: ["fe80::1%eth0"])
    assert nemla.parse_targets("printer") == ["fe80::1%eth0"]


def test_a_target_expression_that_yields_nothing_is_refused_even_if_every_item_parsed(monkeypatch):
    from nemla import targets
    monkeypatch.setattr(targets, "_spans_for", lambda item, family, all_addresses: ([], []))
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.1")


@pytest.mark.parametrize("spec", [None, 22, ["22"], "1," * 10001])
def test_a_port_spec_that_is_not_text_or_is_absurdly_long_is_refused(spec):
    with pytest.raises(ValueError):
        nemla.parse_ports(spec)
