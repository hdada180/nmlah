"""Guard mode: watch a network for suspicious activity. Defensive only.

Three signals, none of which needs root or third-party code:

* tripwires: decoy ports that nothing legitimate should ever touch; any
  connection is a strong sign that something is probing the network;
* unknown devices: a hardware (MAC) address that was not there before;
* ARP changes: an address that suddenly belongs to a different device,
  the classic trace of ARP spoofing.

Guard only observes and alerts. It never attacks back, never touches other
machines, and never changes a firewall by itself: for blocking it prints the
exact commands and leaves running them to you.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

DEFAULT_DECOYS = (2222, 2323, 5901, 8888, 3307)
MAX_ALERTS = 500
LOG_LIMIT = 5 * 1024 * 1024

# What a decoy says when someone connects. Deception only: no login is ever accepted.
_BANNERS = {
    22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    23: b"\xff\xfb\x01\xff\xfb\x03login: ",
    2323: b"\xff\xfb\x01\xff\xfb\x03login: ",
    5900: b"RFB 003.008\n",
    5901: b"RFB 003.008\n",
    80: b"HTTP/1.1 401 Unauthorized\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    8080: b"HTTP/1.1 401 Unauthorized\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    8888: b"HTTP/1.1 401 Unauthorized\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
}


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "nemla"


def _printable(data: bytes, limit: int = 60) -> str:
    return "".join(ch if ch.isprintable() else "." for ch in data.decode("latin-1"))[:limit]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class AlertLog:
    """Newest alerts in memory (for the live view) plus a JSON-lines file."""

    def __init__(self, path=None, limit: int = MAX_ALERTS):
        self.path = Path(path) if path else None
        self.limit = limit
        self.alerts = []
        self.cond = threading.Condition()
        self._seq = 0

    def add(self, alert: dict) -> dict:
        alert = dict(alert)
        alert.setdefault("time", time.time())
        with self.cond:
            self._seq += 1
            alert["id"] = self._seq
            self.alerts.append(alert)
            del self.alerts[:-self.limit]
            self.cond.notify_all()
        self._write(alert)
        return alert

    def since(self, after_id: int) -> list:
        with self.cond:
            return [a for a in self.alerts if a["id"] > after_id]

    def wait(self, after_id: int, timeout: float) -> list:
        with self.cond:
            if not any(a["id"] > after_id for a in self.alerts):
                self.cond.wait(timeout)
            return [a for a in self.alerts if a["id"] > after_id]

    def _write(self, alert: dict) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size > LOG_LIMIT:
                self.path.replace(self.path.with_suffix(".jsonl.1"))
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
        except OSError:
            pass  # a full disk must not stop the watch


# ---------------------------------------------------------------------------
# Tripwires
# ---------------------------------------------------------------------------

class Tripwire:
    """Listens on decoy ports and reports every connection to `on_hit`."""

    def __init__(self, ports, on_hit, host: str = "0.0.0.0", max_clients: int = 64):
        self.ports = list(ports)
        self.on_hit = on_hit
        self.host = host
        self._slots = threading.BoundedSemaphore(max_clients)
        self._stop = threading.Event()
        self._socks = []

    def start(self):
        """Bind the decoys. Returns (listening ports, {port: reason} for those that failed)."""
        listening, failed = [], {}
        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if sys.platform == "win32":  # never share a port with a real service
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(16)
                sock.settimeout(0.4)
            except OSError as exc:
                sock.close()
                failed[port] = exc.strerror or str(exc)
                continue
            actual = sock.getsockname()[1]
            self._socks.append(sock)
            listening.append(actual)
            threading.Thread(target=self._accept, args=(sock, actual), daemon=True).start()
        return listening, failed

    def stop(self) -> None:
        self._stop.set()
        for sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass
        self._socks = []

    def _accept(self, sock, port: int) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._slots.acquire(blocking=False):  # a flood must not exhaust us
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, addr, port), daemon=True).start()

    def _serve(self, conn, addr, port: int) -> None:
        data = b""
        try:
            conn.settimeout(1.5)
            banner = _BANNERS.get(port)
            if banner:
                conn.sendall(banner)
            try:
                data = conn.recv(128)
            except OSError:
                pass
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._slots.release()
        try:
            self.on_hit(addr[0], addr[1], port, data)
        except Exception:  # noqa: BLE001 - a bad handler must not kill the decoy
            pass


# ---------------------------------------------------------------------------
# Looking at the local network: ARP table, gateway, own addresses
# ---------------------------------------------------------------------------

_MAC = r"[0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5}"


def normalize_mac(mac: str):
    """'a4-2B-b0-1c-9e-10' -> 'a4:2b:b0:1c:9e:10'; None for empty or multicast MACs."""
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if not any(octets) or octets[0] & 1:  # all zero (incomplete) or broadcast/multicast
        return None
    return ":".join(f"{o:02x}" for o in octets)


def mac_is_local(mac: str) -> bool:
    """True if the 'locally administered' bit is set in the first octet.

    Such an address was not necessarily assigned to a hardware maker: virtual
    machines, containers, and phones using a private Wi-Fi address per network
    all use them. It is a fact about the bits, not proof of anything.
    """
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    return len(digits) >= 2 and bool(int(digits[:2], 16) & 0x02)


def parse_arp_table(text: str) -> dict:
    """{ip: mac} from /proc/net/arp, `ip neigh`, or `arp -a` (Windows, macOS, BSD)."""
    table = {}
    for line in text.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:dev\s+\S+\s+lladdr\s+|at\s+|\S+\s+\S+\s+)?(" + _MAC + ")", line)
        if not m:
            continue
        ip, mac = m.group(1), normalize_mac(m.group(2))
        try:
            usable = mac and not ipaddress.ip_address(ip).is_multicast
        except ValueError:
            usable = False
        if usable:
            table[ip] = mac
    return table


def read_arp_table() -> dict:
    """The operating system's ARP cache: which hardware address answers for each IP."""
    try:
        if sys.platform.startswith("linux"):
            try:
                return parse_arp_table(Path("/proc/net/arp").read_text())
            except OSError:
                pass
            out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5).stdout
        else:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
        return parse_arp_table(out)
    except (OSError, subprocess.SubprocessError):
        return {}


def nudge_arp(network: str, limit: int = 1024) -> None:
    """Send one empty UDP datagram to every address so the OS resolves it with ARP.

    Nothing is expected back; live hosts simply appear in the ARP table.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for i, host in enumerate(ipaddress.ip_network(network, strict=False).hosts()):
            if i >= limit:
                break
            try:
                sock.sendto(b"", (str(host), 9))
            except OSError:
                pass
    finally:
        sock.close()


def arp_sweep(network: str, settle: float = 1.5) -> dict:
    """{ip: mac} for the live devices of `network`, found through ARP alone."""
    nudge_arp(network)
    time.sleep(settle)
    net = ipaddress.ip_network(network, strict=False)
    return {ip: mac for ip, mac in read_arp_table().items() if ipaddress.ip_address(ip) in net}


def default_gateway():
    """The IPv4 address of the default gateway, or None if it cannot be found."""
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        elif sys.platform == "win32":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,
                                 text=True, timeout=5).stdout
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
            return m.group(1) if m else None
        else:
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True,
                                 text=True, timeout=5).stdout
            m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def own_addresses() -> set:
    """The IPv4 addresses of this computer."""
    found = {"127.0.0.1"}
    try:
        found.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        found.add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    return found


# ---------------------------------------------------------------------------
# Judging a sweep
# ---------------------------------------------------------------------------

def new_state() -> dict:
    return {"learning": True, "devices": {}, "unknown": {}, "bindings": {}}


def load_state(path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        state = new_state()
        state.update({k: data[k] for k in state if k in data})
        return state
    except (OSError, ValueError, TypeError):
        return new_state()


def save_state(path, state: dict) -> None:
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
        tmp.replace(target)
    except OSError:
        pass


def evaluate_sweep(table: dict, state: dict, gateway=None, now=None) -> list:
    """Compare a fresh {ip: mac} sweep with what we know. Updates `state` and returns
    the alerts to raise. The very first sweep only learns (everything is trusted)."""
    now = now or time.time()
    alerts = []
    learning = state["learning"]
    for ip, mac in sorted(table.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        previous = state["bindings"].get(ip)
        if previous and previous != mac and not learning:
            alerts.append({
                "kind": "arp_change", "severity": "high" if ip == gateway else "medium",
                "src_ip": ip, "mac": mac,
                "detail": {"old_mac": previous, "new_mac": mac, "gateway": ip == gateway}})
        state["bindings"][ip] = mac
        if mac in state["devices"]:
            state["devices"][mac]["ip"] = ip
        elif learning:
            state["devices"][mac] = {"ip": ip, "first_seen": now}
        elif mac not in state["unknown"]:
            state["unknown"][mac] = {"ip": ip, "first_seen": now}
            alerts.append({"kind": "new_device", "severity": "medium", "src_ip": ip, "mac": mac,
                           "detail": {"local": mac_is_local(mac)}})
    by_mac = {}
    for ip, mac in table.items():
        by_mac.setdefault(mac, []).append(ip)
    for mac, ips in by_mac.items():
        if gateway in ips and len(ips) > 1 and not learning:
            key = "dup:" + mac
            if key not in state["unknown"]:
                state["unknown"][key] = {"ip": gateway, "first_seen": now}
                alerts.append({"kind": "arp_dup", "severity": "high", "src_ip": gateway, "mac": mac,
                               "detail": {"ips": sorted(ips)}})
    if learning and table:
        state["learning"] = False
        alerts.append({"kind": "baseline", "severity": "info", "src_ip": None, "mac": None,
                       "detail": {"devices": len(state["devices"])}})
    return alerts


# ---------------------------------------------------------------------------
# Responding: commands for you to run, never run for you
# ---------------------------------------------------------------------------

class ProtectedAddress(ValueError):
    """Blocking this address would cut the computer off from the network."""


def block_commands(ip: str, gateway=None, own=(), platform=None) -> dict:
    """The firewall commands that would block `ip` from reaching THIS computer."""
    addr = ipaddress.ip_address(ip)  # ValueError for anything that is not an address
    if addr.version != 4:
        raise ValueError("only IPv4 addresses are supported")
    if (addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local
            or str(addr) in set(own) or str(addr) == gateway):
        raise ProtectedAddress(str(addr))
    plat = platform or sys.platform
    if plat.startswith("linux"):
        return {"platform": "linux", "ip": str(addr), "options": [
            {"name": "iptables", "commands": [f"sudo iptables -I INPUT -s {addr} -j DROP"],
             "undo": [f"sudo iptables -D INPUT -s {addr} -j DROP"]},
            {"name": "ufw", "commands": [f"sudo ufw insert 1 deny from {addr}"],
             "undo": [f"sudo ufw delete deny from {addr}"]}]}
    if plat == "win32":
        rule = f"Nemla block {addr}"
        return {"platform": "windows", "ip": str(addr), "options": [
            {"name": "netsh", "commands": [
                f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={addr}'],
             "undo": [f'netsh advfirewall firewall delete rule name="{rule}"']}]}
    raise ValueError("no firewall commands for this system yet")


# ---------------------------------------------------------------------------
# The guard itself
# ---------------------------------------------------------------------------

class Guard:
    """Runs the tripwires and the periodic sweep, and raises alerts on `log`."""

    def __init__(self, log: AlertLog, ports=DEFAULT_DECOYS, host: str = "0.0.0.0",
                 network=None, interval: float = 60.0, state_path=None, sweep=None,
                 trusted_ips=(), ignore_local: bool = True, gateway=None, vendor_lookup=None):
        self.log = log
        self.vendor_lookup = vendor_lookup  # optional: mac -> vendor name, or None
        self.ports = tuple(ports)
        self.host = host
        self.network = network
        self.interval = interval
        self.state_path = state_path
        self._sweep_fn = sweep or (lambda: arp_sweep(network) if network else {})
        self.trusted_ips = set(trusted_ips)
        self.ignore_local = ignore_local
        self.gateway = gateway if gateway is not None else default_gateway()
        self.own = own_addresses()
        self.state = load_state(state_path) if state_path else new_state()
        self.running = False
        self.listening, self.failed = [], {}
        self._hits = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._tripwire = None
        self._thread = None

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> dict:
        if self.running:
            return self.status()
        self._stop.clear()
        self._tripwire = Tripwire(self.ports, self._hit, self.host)
        self.listening, self.failed = self._tripwire.start()
        self.running = True
        if self.network and self.interval:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> None:
        self._stop.set()
        self.running = False
        if self._tripwire:
            self._tripwire.stop()
            self._tripwire = None
        self.listening = []

    def status(self) -> dict:
        return {
            "running": self.running, "decoys": self.listening, "failed": self.failed,
            "network": self.network, "interval": self.interval, "gateway": self.gateway,
            "learning": self.state["learning"], "trusted": len(self.state["devices"]),
            "unknown": len(self.state["unknown"]), "alerts": len(self.log.alerts),
        }

    # -- signals -------------------------------------------------------------

    def _hit(self, src: str, sport: int, dport: int, data: bytes) -> None:
        if src in self.trusted_ips or (self.ignore_local and src in self.own):
            return
        now = time.time()
        with self._lock:
            rec = self._hits.get(src)
            if rec is None or now - rec["last"] > 600:
                rec = self._hits[src] = {"count": 0, "ports": set(), "last": now}
            rec["count"] += 1
            rec["last"] = now
            rec["ports"].add(dport)
            count, ports = rec["count"], sorted(rec["ports"])
        if count in (1, 10) or count % 100 == 0:  # first contact, then escalations
            self.log.add({"kind": "tripwire", "severity": "high", "src_ip": src, "mac": None,
                          "port": dport, "detail": {"count": count, "ports": ports,
                                                    "sample": _printable(data)}})

    def sweep_once(self) -> list:
        table = self._sweep_fn()
        with self._lock:
            alerts = evaluate_sweep(table, self.state, self.gateway)
            if self.state_path:
                save_state(self.state_path, self.state)
        if self.vendor_lookup:
            for alert in alerts:
                if alert["kind"] == "new_device" and alert.get("mac"):
                    vendor = self.vendor_lookup(alert["mac"])
                    if vendor:
                        alert["detail"]["vendor"] = vendor
        return [self.log.add(a) for a in alerts]

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sweep_once()
            except Exception:  # noqa: BLE001 - keep watching whatever happens
                pass
            self._stop.wait(self.interval)

    # -- the owner's decisions -----------------------------------------------

    def trust(self, mac: str) -> bool:
        mac = normalize_mac(mac or "")
        if not mac:
            return False
        with self._lock:
            entry = self.state["unknown"].pop(mac, None) or {"ip": None, "first_seen": time.time()}
            self.state["devices"].setdefault(mac, entry)
            if self.state_path:
                save_state(self.state_path, self.state)
        return True

    def block(self, ip: str) -> dict:
        return block_commands(ip, gateway=self.gateway, own=self.own)
