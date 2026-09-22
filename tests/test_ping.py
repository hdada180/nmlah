"""Unit-level coverage of nemla.discovery.ping: the branches discover_hosts/engine tests stub out.

Not covered here, and not coverable on this machine: the real Scapy ICMP probe inside get_ttl (Scapy is not
installed). The ping-command fallback path of get_ttl (no Scapy) is already exercised against a real localhost
ping elsewhere in the suite.
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
