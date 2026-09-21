"""Shared fixtures: throw-away servers on loopback (no real machines are ever touched)."""
import socket
import threading
import time

import pytest


def start_tcp_server(handler, host="127.0.0.1", family=socket.AF_INET):
    """Listen on a free port; run handler(conn) for every connection. Returns the listening socket."""
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.bind((host, 0))
    srv.listen(16)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


@pytest.fixture()
def tcp_server():
    """make(handler, host="127.0.0.1") -> port. Everything is closed when the test ends."""
    made = []

    def make(handler, host="127.0.0.1", family=socket.AF_INET):
        srv = start_tcp_server(handler, host, family)
        made.append(srv)
        return srv.getsockname()[1]

    yield make
    for srv in made:
        srv.close()


@pytest.fixture()
def udp_server():
    """make(handler, host="127.0.0.1") -> port. handler(data, addr, sock) is called per datagram
    (return bytes to answer, None to stay silent)."""
    made = []

    def make(handler, host="127.0.0.1", family=socket.AF_INET):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.bind((host, 0))
        made.append(sock)

        def loop():
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                except OSError:
                    return
                reply = handler(data, addr, sock)
                if reply:
                    try:
                        sock.sendto(reply, addr)
                    except OSError:
                        return

        threading.Thread(target=loop, daemon=True).start()
        return sock.getsockname()[1]

    yield make
    for sock in made:
        sock.close()


@pytest.fixture()
def closed_port():
    """A TCP port nothing listens on."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def have_ipv6() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


needs_ipv6 = pytest.mark.skipif(not have_ipv6(), reason="no IPv6 loopback on this machine")


def wait_until(predicate, timeout=3.0, step=0.01):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(step)
    return predicate()
