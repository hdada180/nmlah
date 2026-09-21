"""The integration lab: where the real servers are, and a proxy that damages what they say.

The servers are ordinary Samba and xrdp containers started from tests/integration/docker-compose.yml (see the README
next to this file). They hold no accounts, passwords or secrets: Samba serves a read-only guest share, xrdp is only ever
asked to negotiate a connection, and nobody logs in. Each endpoint can be redirected with an environment variable, so the
same tests can point at a Windows machine or a VM you own:

    NEMLA_LAB_SMB=host:port  NEMLA_LAB_SMB_SIGNING=host:port  NEMLA_LAB_SMB1=host:port
    NEMLA_LAB_RDP=host:port  NEMLA_LAB_RDP_TLS=host:port      NEMLA_LAB_RDP_LEGACY=host:port
"""
import os
import socket
import threading
import time

DEFAULTS = {
    "SMB": "127.0.0.1:14445", "SMB_SIGNING": "127.0.0.1:14446", "SMB1": "127.0.0.1:14447",
    "RDP": "127.0.0.1:13389", "RDP_LEGACY": "127.0.0.1:13390", "RDP_TLS": "127.0.0.1:13391",
}


def endpoint(name: str) -> tuple:
    """(host, port) of a lab server, from NEMLA_LAB_<name> or the docker-compose default."""
    text = os.environ.get(f"NEMLA_LAB_{name}", DEFAULTS[name])
    host, _, port = text.rpartition(":")
    return host, int(port)


def identification_budget(timeout: float, intensity: int = 5) -> float:
    """The longest identifying one port may take, in seconds.

    A banner wait, one question per candidate detector, and a TLS attempt each wait out `timeout` when the server stays
    silent, and Samba and xrdp do exactly that to a question that is not theirs; then a little slack for a slow machine.
    Going over it means some wait is not bounded by its timeout. (Derived from the detector list: an earlier fixed 10 s
    was tuned to a shortcut that skipped detectors, and it made RDP and SMB undetectable on non-standard ports.)"""
    from nemla import fingerprint
    candidates = len(fingerprint._candidates(54321, intensity, False))         # a port no detector claims, no TLS
    return (candidates + 3) * timeout + 2.0


def wait_open(host: str, port: int, seconds: float = 30.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            socket.create_connection((host, port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


class ChaosProxy:
    """A TCP proxy in front of a real server that damages the server's answers.

    modes
        pass       forward everything untouched (proves the proxy itself is transparent)
        truncate   send the first `cut` bytes of the first answer, then close
        flip       XOR the byte at offset `at` of the first answer with 0xFF
        garbage    replace everything from offset `at` on with random-looking bytes
        delay      hold the first answer back for `seconds` (a stalled server)
        blackhole  accept the connection and never forward anything (a firewall that drops)
    """

    def __init__(self, target: tuple, mode: str = "pass", cut: int = 0, at: int = 0, seconds: float = 30.0):
        self.target, self.mode, self.cut, self.at, self.seconds = target, mode, cut, at, seconds
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self.port = self._listener.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        if self.mode == "blackhole":
            self._stop.wait(self.seconds)
            client.close()
            return
        try:
            upstream = socket.create_connection(self.target, timeout=10)
        except OSError:
            client.close()
            return

        def to_server():
            try:
                while True:
                    data = client.recv(4096)
                    if not data:
                        break
                    upstream.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    upstream.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threading.Thread(target=to_server, daemon=True).start()
        first = True
        try:
            while True:
                data = upstream.recv(4096)
                if not data:
                    break
                if first:
                    first = False
                    data = self._damage(data)
                    if data is None:
                        break
                    client.sendall(data)
                    if self.mode == "truncate":            # what follows the cut never arrives
                        break
                    continue
                client.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                try:
                    sock.close()
                except OSError:
                    pass

    def _damage(self, data: bytes):
        if self.mode == "truncate":
            return data[: self.cut] if self.cut else None            # cut=0: close without a single byte
        if self.mode == "flip" and self.at < len(data):
            return data[: self.at] + bytes([data[self.at] ^ 0xFF]) + data[self.at + 1:]
        if self.mode == "garbage":
            noise = bytes((i * 131 + 7) % 256 for i in range(len(data) - self.at))
            return data[: self.at] + noise
        if self.mode == "delay":
            self._stop.wait(self.seconds)
        return data
