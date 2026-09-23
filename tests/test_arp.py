"""Unit-level coverage of nemla.discovery.arp: the branches its callers usually stub out.

Guard and discover_hosts tests (tests/test_guard_discovery_hardening.py) monkeypatch neighbor_sweep,
read_arp_table and wait_for_neighbors wholesale, so the real implementations of those functions - and the
platform branching, subprocess failures and safety limits inside them - were never actually exercised. These
tests call the real functions.

The logic around Scapy (which interface is chosen, batching, cancellation, what happens when the scan is refused
or fails) is tested here against a fake Scapy. Not coverable on a machine without Scapy: the import-time lines that
set HAVE_SCAPY = True, and Scapy's real packet send/receive. Those are exercised for real, with root and a live
network, by the `privileged` CI job
(tests/test_privileged.py::test_scapy_arp_scan_works_as_root_and_is_refused_without and its neighbours).
"""
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from nemla.discovery import arp

# --------------------------------------------------------------------------
# _command: subprocess failures must never crash discovery
# --------------------------------------------------------------------------


def test_command_returns_the_output(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout="10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff\n"))
    assert "10.0.0.1" in arp._command(["ip", "neigh"])


@pytest.mark.parametrize("error", [
    FileNotFoundError("no such file: ip"),               # the command is not installed
    subprocess.TimeoutExpired(cmd=["ip"], timeout=5.0),   # it hung
    PermissionError("not permitted"),
])
def test_command_swallows_a_failing_subprocess_and_returns_nothing(monkeypatch, error):
    def raises(*a, **k):
        raise error
    monkeypatch.setattr(subprocess, "run", raises)
    assert arp._command(["ip", "neigh"]) == ""


# --------------------------------------------------------------------------
# neighbor_table_status: both platform branches, both outcomes
# --------------------------------------------------------------------------


def test_linux_status_true_when_proc_net_arp_exists(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "exists", lambda self: True)
    assert arp.neighbor_table_status() == (True, "")


def test_linux_status_true_when_only_the_ip_command_is_available(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/ip" if name == "ip" else None)
    assert arp.neighbor_table_status() == (True, "")


def test_linux_status_false_when_neither_exists(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    ok, missing = arp.neighbor_table_status()
    assert ok is False and "ip" in missing


def test_non_linux_status_follows_the_arp_command(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(shutil, "which", lambda name: r"C:\Windows\System32\arp.exe" if name == "arp" else None)
    assert arp.neighbor_table_status() == (True, "")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    ok, missing = arp.neighbor_table_status()
    assert ok is False and "arp" in missing


# --------------------------------------------------------------------------
# read_arp_table: the Linux branch (this machine is not Linux)
# --------------------------------------------------------------------------


def test_read_arp_table_on_linux_prefers_proc_net_arp_for_ipv4(monkeypatch):
    """IPv4 comes from /proc/net/arp when it is readable, never a subprocess; IPv6 neighbours are never in that
    file, so `ip -6 neigh show` still runs unconditionally (checked on its own below)."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "read_text", lambda self: "10.0.0.5     0x1   0x2   aa:bb:cc:dd:ee:ff  *  eth0\n")
    v6_calls = []

    def fake_command(cmd, timeout=5.0):
        assert cmd == ["ip", "-6", "neigh", "show"]      # the only subprocess call this scenario should make
        v6_calls.append(cmd)
        return ""
    monkeypatch.setattr(arp, "_command", fake_command)
    table = arp.read_arp_table()
    assert table == {"10.0.0.5": "aa:bb:cc:dd:ee:ff"} and len(v6_calls) == 1


def test_read_arp_table_on_linux_falls_back_to_ip_neigh_when_proc_is_unreadable(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    def no_proc(self):
        raise OSError("no such file")
    monkeypatch.setattr(Path, "read_text", no_proc)
    calls = []

    def fake_command(cmd, timeout=5.0):
        calls.append(cmd)
        if cmd[1] == "-4":
            return "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        return "fe80::1 dev eth0 lladdr aa:22:33:44:55:66 REACHABLE\n"
    monkeypatch.setattr(arp, "_command", fake_command)
    table = arp.read_arp_table()
    assert table == {"10.0.0.5": "aa:bb:cc:dd:ee:ff", "fe80::1": "aa:22:33:44:55:66"}
    assert [c[:2] for c in calls] == [["ip", "-4"], ["ip", "-6"]]     # both address families, in order


def test_read_arp_table_off_linux_uses_arp_a(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(arp, "_command", lambda cmd, timeout=5.0: "? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0\n" if cmd == ["arp", "-a"] else "")
    assert arp.read_arp_table() == {"10.0.0.5": "aa:bb:cc:dd:ee:ff"}


# --------------------------------------------------------------------------
# nudge: the resource limit and a socket that refuses to open
# --------------------------------------------------------------------------


def test_nudge_stops_at_the_limit_instead_of_sending_forever():
    sent = arp.nudge((f"10.0.{n // 256}.{n % 256}" for n in range(10_000)), limit=25)
    assert sent == 25


def test_nudge_skips_a_family_whose_socket_cannot_be_created(monkeypatch):
    real_socket = socket.socket

    def picky(family, kind):
        if family == socket.AF_INET6:
            raise OSError("no IPv6 stack")
        return real_socket(family, kind)
    monkeypatch.setattr(socket, "socket", picky)
    # the IPv6 address is silently skipped (no socket to send it on); the IPv4 one still gets through
    assert arp.nudge(["::1", "127.0.0.1"]) == 1


def test_nudge_arp_wrapper_reaches_every_host_of_the_network(monkeypatch):
    seen = []
    monkeypatch.setattr(arp, "nudge", lambda ips, limit=1024: seen.extend(ips) or len(seen))
    arp.nudge_arp("10.0.0.0/30", limit=1024)
    assert sorted(seen) == ["10.0.0.1", "10.0.0.2"]        # a /30 has exactly two usable host addresses


# --------------------------------------------------------------------------
# wait_for_neighbors: cancellation cuts the wait short
# --------------------------------------------------------------------------


def test_wait_for_neighbors_returns_early_when_cancelled(monkeypatch):
    monkeypatch.setattr(arp, "read_arp_table", lambda: {"10.0.0.5": "aa:bb:cc:dd:ee:ff"})
    cancel = threading.Event()
    cancel.set()
    started = time.monotonic()
    table = arp.wait_for_neighbors(settle=5.0, cancel=cancel)
    assert table == {"10.0.0.5": "aa:bb:cc:dd:ee:ff"} and time.monotonic() - started < 1.0


# --------------------------------------------------------------------------
# neighbor_sweep: real function, both calling conventions (every caller stubs this out)
# --------------------------------------------------------------------------


def test_neighbor_sweep_with_a_network_string_keeps_only_in_scope_answers(monkeypatch):
    nudged = []
    monkeypatch.setattr(arp, "nudge", nudged.extend)
    # the table has one address inside the /30 and one wildly outside it (a stray ARP entry from elsewhere)
    monkeypatch.setattr(arp, "wait_for_neighbors", lambda settle, cancel: {"10.0.0.1": "aa:bb:cc:dd:ee:01", "192.168.1.1": "aa:bb:cc:dd:ee:02"})
    found = arp.neighbor_sweep("10.0.0.0/30", settle=0.1)
    assert found == {"10.0.0.1": "aa:bb:cc:dd:ee:01"}
    assert sorted(nudged) == ["10.0.0.1", "10.0.0.2"]


def test_neighbor_sweep_with_explicit_targets_keeps_only_the_ones_asked_for(monkeypatch):
    monkeypatch.setattr(arp, "nudge", lambda ips: None)
    monkeypatch.setattr(arp, "wait_for_neighbors", lambda settle, cancel: {"10.0.0.5": "aa:bb:cc:dd:ee:01", "10.0.0.6": "aa:bb:cc:dd:ee:02"})
    found = arp.neighbor_sweep(["10.0.0.5", "not an ip"], settle=0.1)
    assert found == {"10.0.0.5": "aa:bb:cc:dd:ee:01"}       # 10.0.0.6 was never asked for; the junk address is just ignored


def test_neighbor_sweep_targets_can_be_any_iterable_not_just_a_list(monkeypatch):
    monkeypatch.setattr(arp, "nudge", lambda ips: None)
    monkeypatch.setattr(arp, "wait_for_neighbors", lambda settle, cancel: {"10.0.0.5": "aa:bb:cc:dd:ee:01"})
    found = arp.neighbor_sweep(iter(["10.0.0.5"]), settle=0.1)
    assert found == {"10.0.0.5": "aa:bb:cc:dd:ee:01"}

def test_normalize_mac_refuses_six_groups_that_are_not_hex():
    from nemla.discovery import mac
    assert mac.normalize_mac("zz:11:22:33:44:55") is None

# --------------------------------------------------------------------------
# scapy_arp_scan: our logic around Scapy, against a fake Scapy
# --------------------------------------------------------------------------

class _Layer:
    """Ether(...) / ARP(...) with the fields kept, so the fake srp can see what was asked."""

    def __init__(self, **fields):
        self.fields = fields

    def __truediv__(self, other):
        return _Layer(**{**self.fields, **other.fields})


def fake_scapy(monkeypatch, answers=None, route=("eth9", "0.0.0.0", "10.0.0.1"), error=None):
    """Install a fake Scapy into arp; returns the list of (addresses asked about, srp options) it received."""
    import types
    sent = []

    def srp(packet, timeout, retry, verbose, **options):
        asked = packet.fields["pdst"]
        sent.append((asked, options))
        if error is not None:
            raise error
        replies = [(None, types.SimpleNamespace(psrc=ip, hwsrc=mac)) for ip, mac in (answers or {}).items() if ip in asked]
        return replies, []

    def find_route(ip):
        if isinstance(route, Exception):
            raise route
        return route

    monkeypatch.setattr(arp, "HAVE_SCAPY", True)
    monkeypatch.setattr(arp, "srp", srp, raising=False)
    monkeypatch.setattr(arp, "Ether", _Layer, raising=False)
    monkeypatch.setattr(arp, "ARP", _Layer, raising=False)
    monkeypatch.setattr(arp, "scapy_conf", types.SimpleNamespace(route=types.SimpleNamespace(route=find_route)), raising=False)
    monkeypatch.setattr(arp, "refresh_scapy", lambda: None)
    return sent


def test_the_scapy_arp_scan_says_it_cannot_run_without_scapy(monkeypatch):
    monkeypatch.setattr(arp, "HAVE_SCAPY", False)
    assert arp.scapy_arp_scan(["10.0.0.5"]) is None


def test_the_scapy_arp_scan_returns_who_answered_through_the_interface_that_reaches_the_targets(monkeypatch):
    sent = fake_scapy(monkeypatch, answers={"10.0.0.5": "aa:bb:cc:00:00:05"})
    assert arp.scapy_arp_scan(["10.0.0.5", "10.0.0.6"]) == {"10.0.0.5": "aa:bb:cc:00:00:05"}
    assert sent == [(["10.0.0.5", "10.0.0.6"], {"iface": "eth9"})]


def test_the_scapy_arp_scan_asks_about_at_most_512_addresses_at_a_time(monkeypatch):
    sent = fake_scapy(monkeypatch)
    ips = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(1100)]
    assert arp.scapy_arp_scan(ips) == {}
    assert [len(asked) for asked, _ in sent] == [512, 512, 76]


def test_the_scapy_arp_scan_still_runs_when_no_interface_can_be_chosen(monkeypatch):
    sent = fake_scapy(monkeypatch, route=OSError("no route"), answers={"10.0.0.5": "aa:bb:cc:00:00:05"})
    assert arp.scapy_arp_scan(["10.0.0.5"]) == {"10.0.0.5": "aa:bb:cc:00:00:05"}
    assert sent[0][1] == {}                              # left to Scapy's own default


def test_the_scapy_arp_scan_stops_when_cancelled(monkeypatch):
    from nemla.net import Cancelled
    sent = fake_scapy(monkeypatch)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(Cancelled):
        arp.scapy_arp_scan(["10.0.0.5"], cancel=cancel)
    assert sent == []


def test_the_scapy_arp_scan_lets_a_refusal_reach_the_caller(monkeypatch):
    fake_scapy(monkeypatch, error=PermissionError("Operation not permitted"))
    with pytest.raises(PermissionError):
        arp.scapy_arp_scan(["10.0.0.5"])


def test_the_scapy_arp_scan_reports_any_other_failure_as_unavailable(monkeypatch):
    fake_scapy(monkeypatch, error=RuntimeError("libpcap exploded"))
    assert arp.scapy_arp_scan(["10.0.0.5"]) is None
