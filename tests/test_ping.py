"""Unit-level coverage of nemla.discovery.ping: the branches discover_hosts/engine tests stub out.

get_ttl's Scapy branch is tested against a fake Scapy (a reply, no reply, a failure). Not coverable on a machine
without Scapy: the import-time lines that set HAVE_SCAPY = True, and Scapy's real ICMP probe (the `privileged` CI job).
The ping-command fallback path of get_ttl (no Scapy) is also exercised against a real localhost ping elsewhere in
the suite.
"""
import subprocess
import threading

import pytest

from nemla import net
from nemla.discovery import ping


def test_tcp_ping_is_false_when_no_port_answers(monkeypatch):
    monkeypatch.setattr(ping, "tcp_state", lambda ip, port, timeout, cancel: "filtered")
    assert ping.tcp_ping("10.0.0.5", ports=(80, 443)) is False


def test_tcp_ping_is_true_the_moment_one_port_answers(monkeypatch):
    seen = []

    def state(ip, port, timeout, cancel):
        seen.append(port)
        return "closed" if port == 443 else "filtered"
    monkeypatch.setattr(ping, "tcp_state", state)
    assert ping.tcp_ping("10.0.0.5", ports=(80, 443, 8080)) is True
    assert seen == [80, 443]                                         # stopped as soon as 443 answered


# --------------------------------------------------------------------------
# _run: the command wrapper behind icmp_ping and get_ttl's fallback
# --------------------------------------------------------------------------


class FakeProc:
    """A subprocess.Popen stand-in whose communicate() always times out until kill() is called."""

    def __init__(self):
        self.killed = False

    def communicate(self, timeout=None):
        if timeout is None:            # the final, blocking call _run makes right after kill()
            return "", ""
        raise subprocess.TimeoutExpired(cmd="ping", timeout=timeout)

    def kill(self):
        self.killed = True


def test_run_returns_none_when_the_command_cannot_even_start(monkeypatch):
    def raise_oserror(*a, **k):
        raise OSError("no such file")
    monkeypatch.setattr(subprocess, "Popen", raise_oserror)
    assert ping._run(["definitely-not-a-real-binary"], timeout=1.0) == (None, "")


def test_run_kills_and_gives_up_after_its_own_timeout(monkeypatch):
    proc = FakeProc()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    code, out = ping._run(["ping", "10.0.0.5"], timeout=0.05)
    assert (code, out) == (None, "") and proc.killed is True


def test_run_kills_and_raises_cancelled_when_the_cancel_event_is_set(monkeypatch):
    proc = FakeProc()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(net.Cancelled):
        ping._run(["ping", "10.0.0.5"], timeout=5.0, cancel=cancel)
    assert proc.killed is True

# --------------------------------------------------------------------------
# get_ttl: the Scapy branch, against a fake Scapy
# --------------------------------------------------------------------------

class _Layer:
    def __init__(self, *args, **kwargs):
        pass

    def __truediv__(self, other):
        return self


def fake_scapy(monkeypatch, sr1):
    monkeypatch.setattr(ping, "HAVE_SCAPY", True)
    monkeypatch.setattr(ping, "sr1", sr1, raising=False)
    monkeypatch.setattr(ping, "IP", _Layer, raising=False)
    monkeypatch.setattr(ping, "ICMP", _Layer, raising=False)


def test_get_ttl_reads_the_ttl_of_a_scapy_echo_reply(monkeypatch):
    import types
    fake_scapy(monkeypatch, lambda packet, timeout, verbose: types.SimpleNamespace(ttl=57))
    assert ping.get_ttl("10.0.0.5") == 57


@pytest.mark.parametrize("scapy_result", ["no reply", "crash"])
def test_get_ttl_falls_back_to_the_ping_command_when_scapy_gets_nothing(monkeypatch, scapy_result):
    def sr1(packet, timeout, verbose):
        if scapy_result == "crash":
            raise OSError("no raw socket")
        return None
    fake_scapy(monkeypatch, sr1)
    monkeypatch.setattr(ping.shutil, "which", lambda name: "/bin/ping")
    monkeypatch.setattr(ping, "_run", lambda command, seconds, cancel, capture=False: (0, "64 bytes from 10.0.0.5: ttl=113 time=1 ms"))
    assert ping.get_ttl("10.0.0.5") == 113
