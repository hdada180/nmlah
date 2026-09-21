"""The raw-packet features and the Guard against a real Linux kernel: real Scapy, real SYN-ACKs, real ARP.

Needs root, Scapy and iproute2 (`ip`), so it only runs where NEMLA_PRIVILEGED=1 is set: the `privileged` CI job does
that under sudo. It builds a private network for itself (a network namespace joined to the host by a veth pair,
10.77.0.1 <-> 10.77.0.2), so nothing outside the machine is touched and nothing is left behind:

    sudo -E env "PATH=$PATH" NEMLA_PRIVILEGED=1 python -m pytest -m privileged tests/test_privileged.py -v

What it shows that the simulated tests (test_privileges.py, test_guard_validation.py) cannot: that a genuine SYN-ACK
is read correctly, that an unprivileged process degrades exactly as described, that ARP entries the kernel creates
(complete, incomplete, static, changed) are read and judged correctly by the Guard, and that Scapy's own ARP scan
works. Everything degrades gracefully without root; this file is where "with root" is proven.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

import nemla
from conftest import wait_until
from nemla import discovery, guard, privileges
from nemla.discovery.arp import read_arp_table
from nemla.os_detection import SynProbe

pytestmark = pytest.mark.privileged

HOST_IF, NS_IF = "nlh0", "nlp0"
HOST_IP, NS_IP = "10.77.0.1", "10.77.0.2"
HTTP_PORT, SSH_PORT = 8080, 2222
ROOT = Path(__file__).resolve().parent.parent

SERVER = textwrap.dedent("""
    import socket, threading, time
    def serve(port, greeting=b"", reply=b""):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("10.77.0.2", port)); s.listen(64)
        def one(c):
            try:
                c.settimeout(2)
                if greeting: c.sendall(greeting)
                if reply:
                    c.recv(2048); c.sendall(reply)
                else:
                    time.sleep(0.3)
            except OSError:
                pass
            finally:
                c.close()
        while True:
            c, _ = s.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    web = b"HTTP/1.1 200 OK\\r\\nServer: nginx/1.24.0\\r\\nContent-Length: 27\\r\\nConnection: close\\r\\n\\r\\n<html><title>Lab</title></html>"
    threading.Thread(target=serve, args=(8080, b"", web), daemon=True).start()
    serve(2222, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\\r\\n")
""")


def ip(*args, check=True):
    return subprocess.run(["ip", *args], capture_output=True, encoding="utf-8", check=check)


def mac_of(device, namespace=None):
    command = ["-n", namespace, "-o", "link", "show", device] if namespace else ["-o", "link", "show", device]
    line = ip(*command).stdout
    return line.split("link/ether")[1].split()[0]


def can_do_it():
    if os.name != "posix" or os.geteuid() != 0:
        return "not root"
    if not shutil.which("ip"):
        return "no iproute2 (`ip`)"
    if not privileges.detect(refresh=True).scapy:
        return "Scapy is not installed"
    return None


@pytest.fixture(scope="module")
def lab():
    missing = can_do_it()
    if missing:
        pytest.fail(f"the privileged tests cannot run here: {missing}")
    namespace = f"nemla{os.getpid()}"
    ip("netns", "add", namespace)
    server = None
    try:
        ip("link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF)
        ip("link", "set", NS_IF, "netns", namespace)
        ip("addr", "add", f"{HOST_IP}/24", "dev", HOST_IF)
        ip("link", "set", HOST_IF, "up")
        ip("-n", namespace, "addr", "add", f"{NS_IP}/24", "dev", NS_IF)
        ip("-n", namespace, "link", "set", NS_IF, "up")
        ip("-n", namespace, "link", "set", "lo", "up")
        server = subprocess.Popen(["ip", "netns", "exec", namespace, sys.executable, "-c", SERVER])
        assert wait_until(lambda: _reachable(HTTP_PORT) and _reachable(SSH_PORT), timeout=15), "the lab server did not start"
        yield {"namespace": namespace, "ns_mac": mac_of(NS_IF, namespace), "host_mac": mac_of(HOST_IF)}
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
        ip("link", "del", HOST_IF, check=False)
        ip("netns", "del", namespace, check=False)


def _reachable(port):
    try:
        socket.create_connection((NS_IP, port), timeout=1).close()
        return True
    except OSError:
        return False


# ----------------------------------------------------------------------------------------------- capabilities and the SYN-ACK

def test_as_root_with_scapy_every_raw_feature_is_available(lab):
    caps = privileges.detect(refresh=True)
    assert caps.elevated and caps.scapy and caps.raw_socket and caps.syn_fingerprint and caps.arp_scan
    assert caps.reasons == {}


def test_a_real_synack_is_read_correctly(lab):
    probe = SynProbe()
    assert probe.available
    traits = probe(NS_IP, HTTP_PORT, timeout=3.0)
    assert traits is not None and probe.answers == 1
    assert traits["window"] > 0 and "MSS" in traits["options"] and traits["ttl"] == 64      # a Linux stack, one hop (the veth)
    assert isinstance(traits["df"], bool)
    assert probe(NS_IP, 9, timeout=1.0) is None and probe.available                        # a closed port: RST, no SYN-ACK, no harm


def test_a_scan_fingerprints_the_real_stack_and_reports_that_it_did(lab):
    hosts, meta = nemla.run_scan("lab", [NS_IP], [HTTP_PORT, SSH_PORT, 9], no_ping=True, timeout=1.0)
    host = hosts[0]
    assert meta["capabilities"]["syn_fingerprint"] is True and meta["capabilities"]["elevated"] is True
    assert host["os"]["family"] in ("linux", "unix")
    assert any("SYN-ACK" in line or "window" in line for line in host["os"]["evidence"])
    assert {p["port"] for p in host["open_ports"]} == {HTTP_PORT, SSH_PORT}
    assert next(p for p in host["open_ports"] if p["port"] == SSH_PORT)["product"] == "OpenSSH"


# ----------------------------------------------------------------------------------------------- the same scan without rights

CHILD = textwrap.dedent("""
    import json, sys
    sys.path.insert(0, sys.argv[1])
    import nemla
    from nemla import privileges
    caps = privileges.detect(refresh=True)
    hosts, meta = nemla.run_scan("lab", ["10.77.0.2"], [8080], no_ping=True, timeout=1.0)
    print("RESULT " + json.dumps({"caps": caps.as_dict(), "meta_caps": meta["capabilities"], "warnings": [w["code"] for w in meta["warnings"]],
                                  "os": hosts[0]["os"]["family"], "os_guess": hosts[0]["os_guess"], "open": [p["port"] for p in hosts[0]["open_ports"]]}))
""")


def test_without_root_the_same_scan_degrades_exactly_as_documented(lab):
    """The package is copied where the unprivileged user `nobody` can read it, and a scan runs as that user."""
    import pwd
    try:
        nobody = pwd.getpwnam("nobody")
    except KeyError:
        pytest.skip("no `nobody` user on this system")
    target = Path(tempfile.mkdtemp(prefix="nemla-nobody-"))
    try:
        shutil.copytree(ROOT / "nemla", target / "nemla", ignore=shutil.ignore_patterns("__pycache__"))
        for folder in [target, *target.rglob("*")]:
            folder.chmod(0o755 if folder.is_dir() else 0o644)
        done = subprocess.run([sys.executable, "-c", CHILD, str(target)], capture_output=True, encoding="utf-8",
                              user=nobody.pw_uid, group=nobody.pw_gid, cwd="/", timeout=120, check=False)
    finally:
        shutil.rmtree(target, ignore_errors=True)
    assert done.returncode == 0, done.stderr[-800:]
    result = json.loads(next(line for line in done.stdout.splitlines() if line.startswith("RESULT "))[7:])
    assert result["caps"]["elevated"] is False and result["caps"]["raw_socket"] is False and result["caps"]["syn_fingerprint"] is False
    assert any(word in result["caps"]["reasons"]["syn_fingerprint"] for word in ("root", "raw sockets", "Scapy"))
    assert result["meta_caps"]["syn_fingerprint"] is False and "syn_fingerprint_off" in result["warnings"]
    assert result["open"] == [8080] and result["os"] != ""                                    # the scan still worked, the OS guess used the TTL


def test_scapy_arp_scan_works_as_root_and_is_refused_without(lab):
    assert discovery.scapy_arp_scan([NS_IP], timeout=2) == {NS_IP: lab["ns_mac"]}


# ----------------------------------------------------------------------------------------------- the Guard on a real kernel

def touch(ip_address=NS_IP):
    """Make the kernel (re)learn the neighbour: any traffic will do."""
    subprocess.run(["ping", "-c", "1", "-W", "1", ip_address], capture_output=True, check=False)


def real_sweep():
    """The neighbour entries of the lab network, as the Guard's own sweep would read them."""
    touch()
    table = read_arp_table()
    return {addr: mac for addr, mac in table.items() if addr.startswith("10.77.0.")}


def test_the_kernels_arp_table_is_read_and_incomplete_entries_never_become_devices(lab):
    touch()
    for phantom in ("10.77.0.3", "10.77.0.4"):                                            # nobody there: FAILED / INCOMPLETE entries
        subprocess.run(["ping", "-c", "1", "-W", "1", phantom], capture_output=True, check=False)
    raw = ip("neigh", "show", "dev", HOST_IF).stdout
    assert NS_IP in raw
    table = real_sweep()
    assert table == {NS_IP: lab["ns_mac"]}                                                # only the real one, with its real address


def test_a_new_static_neighbour_is_an_unknown_device_and_a_changed_address_is_a_weak_signal(lab):
    log = guard.AlertLog()
    watcher = guard.Guard(log, ports=[], network="10.77.0.0/24", interval=0, sweep=real_sweep, gateway=None)
    watcher.sweep_once()                                                                  # learn: the baseline
    assert [a["kind"] for a in log.alerts] == ["baseline"] and watcher.status()["trusted"] == 1

    ip("neigh", "replace", "10.77.0.50", "lladdr", "02:11:22:33:44:55", "dev", HOST_IF, "nud", "permanent")
    try:
        watcher.sweep_once()
        newcomer = [a for a in log.alerts if a["kind"] == "new_device"]
        assert len(newcomer) == 1 and newcomer[0]["src_ip"] == "10.77.0.50" and newcomer[0]["mac"] == "02:11:22:33:44:55"
        assert newcomer[0]["detail"]["local"] is True                                     # 02:... is locally administered

        ip("-n", lab["namespace"], "link", "set", NS_IF, "address", "02:aa:bb:cc:dd:ee")   # the lab host "changes its network card"
        ip("neigh", "flush", "dev", HOST_IF, check=False)
        ip("neigh", "replace", "10.77.0.50", "lladdr", "02:11:22:33:44:55", "dev", HOST_IF, "nud", "permanent")
        assert wait_until(lambda: real_sweep().get(NS_IP) == "02:aa:bb:cc:dd:ee", timeout=10)
        watcher.sweep_once()
        changes = [a for a in log.alerts if a["kind"] == "arp_change"]
        assert len(changes) == 1 and changes[0]["src_ip"] == NS_IP
        assert changes[0]["detail"] == {"old_mac": lab["ns_mac"], "new_mac": "02:aa:bb:cc:dd:ee", "gateway": False}
        assert changes[0]["confidence"] <= 0.30 and changes[0]["severity"] == "medium"        # a change alone is a weak signal
        assert any("locally administered" in line for line in changes[0]["evidence"])
        assert "spoof" not in json.dumps(changes[0]).lower()                                   # and no alert calls it spoofing
    finally:
        ip("-n", lab["namespace"], "link", "set", NS_IF, "address", lab["ns_mac"], check=False)
        ip("neigh", "del", "10.77.0.50", "dev", HOST_IF, check=False)


def test_the_guards_own_sweep_finds_the_lab_host_through_the_real_kernel(lab):
    table = guard.arp_sweep("10.77.0.0/24", settle=2.0)
    assert lab["ns_mac"] in table.values() or NS_IP in table


def test_the_guard_reports_a_network_it_cannot_see_instead_of_pretending(lab):
    log = guard.AlertLog()
    watcher = guard.Guard(log, ports=[], network="10.99.0.0/24", interval=0, gateway=None)     # no interface has this network
    for _ in range(guard.EMPTY_SWEEPS_BEFORE_NOTICE):
        watcher.sweep_once()
    assert [a["detail"]["code"] for a in log.alerts if a["kind"] == "guard_notice"] == ["sweep_empty"]
