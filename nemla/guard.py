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

from . import privileges
from .discovery.arp import neighbor_sweep, neighbor_table_status, nudge_arp, parse_arp_table, read_arp_table
from .discovery.mac import mac_is_local, normalize_mac
from .log import logger
from .net import ip_sort_key, parse_ip

_REEXPORTED = (nudge_arp, parse_arp_table, read_arp_table)  # kept importable from here for older code

DEFAULT_DECOYS = (2222, 2323, 5901, 8888, 3307)
MAX_ALERTS = 500
EMPTY_SWEEPS_BEFORE_NOTICE = 3      # sweeps that see nobody at all before the owner is told
MAX_NOTICES = 20                    # distinct notices per run: a broken system must not flood the alert list
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
        self.alerts: list = []
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

    def __init__(self, ports, on_hit, host: str = "0.0.0.0", max_clients: int = 64):  # noqa: S104 - a decoy must listen on the LAN
        self.ports = list(ports)
        self.on_hit = on_hit
        self.host = host
        self._slots = threading.BoundedSemaphore(max_clients)
        self._stop = threading.Event()
        self._socks: list = []

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
        except Exception:
            logger.warning("tripwire handler failed for %s", addr[0], exc_info=True)


# ---------------------------------------------------------------------------
# Looking at the local network: ARP table, gateway, own addresses
# ---------------------------------------------------------------------------

def arp_sweep(network: str, settle: float = 2.5, cancel=None) -> dict:
    """{ip: mac} for the live devices of `network`, found through ARP alone.

    The neighbour cache is polled until it stops growing instead of sleeping a fixed time.
    """
    return neighbor_sweep(network, settle, cancel)


def default_gateway():
    """The IPv4 address of the default gateway, or None if it cannot be found."""
    try:
        if sys.platform.startswith("linux"):
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        elif sys.platform == "win32":
            # the system routing tool with fixed arguments, no shell ("0.0.0.0" is the default-route destination)
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,  # noqa: S607, S104
                                 text=True, timeout=5, check=False).stdout
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
            return m.group(1) if m else None
        else:
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True,  # noqa: S607
                                 text=True, timeout=5, check=False).stdout
            m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def local_network_hint():
    """(my_ip, 'a.b.c.0/24') for the interface that reaches the outside world.

    A UDP connect() sends nothing; it only asks the OS which address it would use.
    """
    ip = "127.0.0.1"
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        ip = probe.getsockname()[0]
    except OSError:
        pass
    finally:
        probe.close()
    if ip.startswith("127."):
        return ip, "127.0.0.1"
    return ip, ip.rsplit(".", 1)[0] + ".0/24"


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
    return {"learning": True, "devices": {}, "unknown": {}, "bindings": {}, "flaps": {}}


def load_state(path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        state = new_state()
        state.update({k: data[k] for k in state if k in data})
        return state
    except (OSError, ValueError, TypeError):
        return new_state()


def save_state(path, state: dict) -> None:
    target = Path(path)
    tmp = target.with_suffix(".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        tmp.replace(target)
    except OSError as exc:
        logger.warning("could not save the guard state to %s: %s", target, exc)


def arp_change_assessment(ip, old, new, table, state, is_gateway, vendor_lookup=None) -> tuple:
    """(confidence, evidence) that an address changing hardware address is ARP spoofing.

    A changed binding is NOT proof: replaced network cards, DHCP re-leases and virtual
    machines look the same. So the confidence starts modest, moves with what surrounds
    the change, and never reaches certainty.
    """
    evidence = [f"{ip} was bound to {old} and is now bound to {new}"]
    confidence = 0.55 if is_gateway else 0.30
    if is_gateway:
        evidence.append("the address is the default gateway (a spoofed gateway lets an attacker sit in the middle)")
    flaps = state.get("flaps", {}).get(ip, 0)
    if flaps >= 3:
        confidence += 0.20
        evidence.append(f"the binding has changed {flaps} times (poisoning typically flips back and forth)")
    known_elsewhere = state["devices"].get(new, {}).get("ip")
    if known_elsewhere and known_elsewhere != ip:
        confidence -= 0.15
        evidence.append(f"{new} is a trusted device last seen at {known_elsewhere}: it may just have been given a new address")
    if old not in table.values():
        confidence -= 0.05
        evidence.append(f"{old} no longer answers anywhere: the device may have been replaced or switched off")
    else:
        evidence.append(f"{old} still answers for another address")
    if mac_is_local(new):
        evidence.append(f"{new} is a locally administered address (virtual machine, container or random Wi-Fi address)")
    if vendor_lookup:
        before, after = vendor_lookup(old), vendor_lookup(new)
        if before and after and before != after:
            evidence.append(f"vendor changed from {before} to {after}")
    return round(min(0.85, max(0.10, confidence)), 2), evidence


def sanitize_table(table) -> tuple:
    """(clean, dropped): only well-formed {IP: MAC} pairs. Anything else (a garbled line, a broadcast or all-zero
    hardware address, a multicast IP, the wrong type) is counted and skipped: it must never stop a sweep."""
    clean: dict = {}
    dropped = 0
    for ip, mac in (table.items() if isinstance(table, dict) else ()):
        addr = parse_ip(ip) if isinstance(ip, str) else None
        normal = normalize_mac(mac) if isinstance(mac, str) else None
        if addr is None or normal is None or addr.is_multicast or addr.is_unspecified:
            dropped += 1
            continue
        clean[str(addr)] = normal
    return clean, dropped


def evaluate_sweep(table: dict, state: dict, gateway=None, now=None, vendor_lookup=None) -> list:
    """Compare a fresh {ip: mac} sweep with what we know. Updates `state` and returns
    the alerts to raise. The very first sweep only learns (everything is trusted).

    Alerts carry `confidence` and `evidence`: they say what was observed and how much it
    proves, never that an attack is certain."""
    now = now or time.time()
    state.setdefault("flaps", {})
    table, _ = sanitize_table(table)
    alerts = []
    learning = state["learning"]
    for ip, mac in sorted(table.items(), key=lambda kv: ip_sort_key(kv[0])):
        previous = state["bindings"].get(ip)
        if previous and previous != mac:
            state["flaps"][ip] = state["flaps"].get(ip, 0) + 1
            if not learning:
                confidence, evidence = arp_change_assessment(ip, previous, mac, table, state, ip == gateway,
                                                             vendor_lookup)
                alerts.append({
                    "kind": "arp_change", "severity": "high" if ip == gateway else "medium",
                    "src_ip": ip, "mac": mac, "confidence": confidence, "evidence": evidence,
                    "detail": {"old_mac": previous, "new_mac": mac, "gateway": ip == gateway}})
        state["bindings"][ip] = mac
        if mac in state["devices"]:
            state["devices"][mac]["ip"] = ip
        elif learning:
            state["devices"][mac] = {"ip": ip, "first_seen": now}
        elif mac not in state["unknown"]:
            state["unknown"][mac] = {"ip": ip, "first_seen": now}
            evidence = [f"{mac} was not in the trusted baseline of {len(state['devices'])} device(s)"]
            if mac_is_local(mac):
                evidence.append("locally administered address (virtual machine, container or random Wi-Fi address)")
            alerts.append({"kind": "new_device", "severity": "medium", "src_ip": ip, "mac": mac,
                           "confidence": 0.9, "evidence": evidence, "detail": {"local": mac_is_local(mac)}})
    by_mac: dict = {}
    for ip, mac in table.items():
        by_mac.setdefault(mac, []).append(ip)
    for mac, ips in by_mac.items():
        if gateway in ips and len(ips) > 1 and not learning:
            key = "dup:" + mac
            if key not in state["unknown"]:
                state["unknown"][key] = {"ip": gateway, "first_seen": now}
                alerts.append({"kind": "arp_dup", "severity": "high", "src_ip": gateway, "mac": mac,
                               "confidence": 0.40,
                               "evidence": [f"{mac} answers for {len(ips)} addresses including the gateway",
                                            "routers doing proxy ARP behave the same way"],
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

    def __init__(self, log: AlertLog, ports=DEFAULT_DECOYS, host: str = "0.0.0.0",  # noqa: S104 - decoys listen on the LAN
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
        self.errors = 0
        self.listening: list = []
        self.failed: dict = {}
        self._hits: dict = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._tripwire: Tripwire | None = None
        self._thread: threading.Thread | None = None
        self._custom_sweep = sweep is not None
        self._notices: set = set()
        self._empty_sweeps = 0
        self.last_error = ""

    # -- limits of the watch, said out loud ----------------------------------

    def notice(self, code: str, key: str = "", evidence=(), **detail) -> None:
        """Tell the owner about something that limits what the Guard can see: one `guard_notice` alert per
        distinct problem (in the alert stream, the JSON-lines file, the CLI and the page) and a log line."""
        with self._lock:
            token = (code, key)
            if token in self._notices or len(self._notices) >= MAX_NOTICES:
                return
            self._notices.add(token)
        logger.warning("guard: %s %s %s", code, detail or "", "; ".join(evidence))
        self.log.add({"kind": "guard_notice", "severity": "info", "src_ip": None, "mac": None,
                      "detail": {"code": code, **detail}, "evidence": list(evidence)})

    def _check_environment(self) -> None:
        if self.interval and not self._custom_sweep:
            if not self.network:
                self.notice("no_network", evidence=["no interface with a private LAN address was found"])
            else:
                usable, missing = neighbor_table_status()
                if not usable:
                    self.notice("neighbor_table_unreadable", evidence=[f"missing: {missing}"])

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> dict:
        if self.running:
            return self.status()
        self._stop.clear()
        self._tripwire = Tripwire(self.ports, self._hit, self.host)
        self.listening, self.failed = self._tripwire.start()
        self.running = True
        self._check_environment()
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
        usable, missing = neighbor_table_status()
        return {
            "running": self.running, "decoys": self.listening, "failed": self.failed,
            "network": self.network, "interval": self.interval, "gateway": self.gateway,
            "learning": self.state["learning"], "trusted": len(self.state["devices"]),
            "unknown": len(self.state["unknown"]), "alerts": len(self.log.alerts),
            "errors": self.errors, "last_error": self.last_error,
            "notices": sorted({code for code, _ in self._notices}),
            # what the watch relies on: the OS neighbour table and ordinary sockets, never packet capture,
            # so it needs neither Scapy nor administrator rights
            "capabilities": {"neighbor_table": usable, "neighbor_table_missing": missing,
                             "elevated": privileges.is_elevated(), "needs_elevation": False},
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
                          "port": dport, "confidence": 0.8,
                          "evidence": [f"{src} connected to decoy port {dport}, which no legitimate service uses",
                                       f"{count} connection(s) to {len(ports)} decoy port(s) so far",
                                       "a misconfigured device or an administrator's own scanner looks the same"],
                          "detail": {"count": count, "ports": ports, "sample": _printable(data)}})

    def sweep_once(self) -> list:
        table, dropped = sanitize_table(self._sweep_fn())
        if dropped:
            self.notice("bad_entries", count=dropped, evidence=[f"{dropped} entr{'y' if dropped == 1 else 'ies'} skipped"])
        if table or not (self.network or self._custom_sweep):
            self._empty_sweeps = 0
        else:
            self._empty_sweeps += 1
            if self._empty_sweeps == EMPTY_SWEEPS_BEFORE_NOTICE:
                self.notice("sweep_empty", count=self._empty_sweeps,
                            evidence=[f"network {self.network}: {self._empty_sweeps} sweeps in a row saw no device"])
        with self._lock:
            alerts = evaluate_sweep(table, self.state, self.gateway, vendor_lookup=self.vendor_lookup)
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
            except Exception as exc:
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"[:200]
                logger.warning("guard sweep failed", exc_info=True)
                self.notice("sweep_failed", key=self.last_error, evidence=[self.last_error])
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
