"""Low-level network helpers shared by every part of Nemla.

Everything here is built for hostile networks: every wait is a series of short
slices that look at the cancel event (so Stop and Ctrl+C take effect within a
tenth of a second), every clock is `time.monotonic()`, every read is capped in
size and in time, and everything that came from the wire is cleaned before it
is shown anywhere.
"""
from __future__ import annotations

import errno
import ipaddress
import select
import socket
import ssl
import time
import warnings

from .config import MAX_RESPONSE, MAX_TEXT

SLICE = 0.1  # how long a wait may block before it looks at the cancel event again

_WOULD_BLOCK = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, errno.EALREADY,
                errno.EINTR, 10035}                      # 10035 = WSAEWOULDBLOCK
REFUSED = {errno.ECONNREFUSED, 10061}                    # 10061 = WSAECONNREFUSED
RESET = {errno.ECONNRESET, 10054}                        # 10054 = WSAECONNRESET


class Cancelled(OSError):
    """The scan was stopped while a probe was in flight."""


class ScanTimeout(OSError):
    """A probe ran out of time."""


# ---------------------------------------------------------------------------
# Text that came from the network
# ---------------------------------------------------------------------------

def clean_text(value, limit: int = MAX_TEXT) -> str:
    """Printable, single-line, length-limited text.

    Banners, page titles and certificate names are written by whoever runs the
    remote machine. Control characters (terminal escapes), bidi overrides and
    line breaks are replaced by spaces and the result is cut to `limit`.
    """
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return " ".join(text.split())[:limit]


# ---------------------------------------------------------------------------
# Addresses (IPv4 and IPv6, with optional zone such as fe80::1%eth0)
# ---------------------------------------------------------------------------

def split_zone(text) -> tuple:
    addr, _, zone = str(text).partition("%")
    return addr, (zone or None)


def parse_ip(text):
    """An ipaddress object for `text` (zone id ignored), or None if it is not an address."""
    addr, zone = split_zone(text)
    try:
        obj = ipaddress.ip_address(addr)
    except ValueError:
        return None
    return None if zone and obj.version == 4 else obj


def ip_version(text) -> int:
    obj = parse_ip(text)
    return obj.version if obj else 0


def af_of(ip) -> int:
    return socket.AF_INET6 if ":" in str(ip) else socket.AF_INET


def sockaddr(ip, port: int) -> tuple:
    """The address tuple `connect()` wants for an IPv4 or IPv6 address string."""
    addr, zone = split_zone(ip)
    if ":" not in addr:
        return (addr, port)
    scope = 0
    if zone:
        try:
            scope = int(zone)
        except ValueError:
            try:
                scope = socket.if_nametoindex(zone)
            except (OSError, AttributeError):
                raise ValueError(f"unknown network interface '{zone}'") from None
    return (addr, port, 0, scope)


def ip_sort_key(ip) -> tuple:
    obj = parse_ip(ip)
    return (obj.version, int(obj), split_zone(ip)[1] or "") if obj else (9, 0, str(ip))


def is_external(ip) -> bool:
    """True for addresses on the public internet, where exposure is worse.

    Uses `is_global`, so shared address space (100.64.0.0/10), documentation
    ranges, multicast, link-local and unique-local addresses are all *not*
    external. IPv4-mapped IPv6 addresses are judged by the IPv4 address inside.
    """
    obj = parse_ip(ip)
    if obj is None:
        return False
    mapped = getattr(obj, "ipv4_mapped", None)
    if mapped is not None:
        obj = mapped
    return bool(obj.is_global and not (obj.is_multicast or obj.is_loopback or obj.is_link_local
                                       or obj.is_unspecified or obj.is_reserved or obj.is_private))


# ---------------------------------------------------------------------------
# Waiting
# ---------------------------------------------------------------------------

def wait_io(sock, read: bool, write: bool, end: float, cancel=None) -> None:
    """Block until `sock` is ready, `end` (a monotonic time) passes, or `cancel` is set."""
    while True:
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        left = end - time.monotonic()
        if left <= 0:
            raise ScanTimeout()
        try:
            r, w, x = select.select([sock] if read else [], [sock] if write else [],
                                    [sock] if write else [], min(SLICE, left))
        except (OSError, ValueError):  # the socket was closed under us
            if cancel is not None and cancel.is_set():
                raise Cancelled() from None
            raise OSError(errno.EBADF, "socket closed") from None
        if r or w or x:
            return


def sleep_cancellable(seconds: float, cancel=None) -> bool:
    """Sleep for `seconds`; returns False if the cancel event ended the wait early."""
    end = time.monotonic() + seconds
    while True:
        if cancel is not None and cancel.is_set():
            return False
        left = end - time.monotonic()
        if left <= 0:
            return True
        time.sleep(min(SLICE, left))


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

def tcp_connect(ip: str, port: int, timeout: float, cancel=None) -> socket.socket:
    """A connected, non-blocking TCP socket. Raises ConnectionRefusedError on RST,
    ScanTimeout when nothing answers in time, Cancelled when the scan is stopped."""
    sock = socket.socket(af_of(ip), socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        err = sock.connect_ex(sockaddr(ip, port))
        if err == 0:
            return sock
        if err not in _WOULD_BLOCK:
            raise ConnectionRefusedError(err, "refused") if err in REFUSED else OSError(err, "connect failed")
        wait_io(sock, False, True, time.monotonic() + timeout, cancel)
        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err:
            raise ConnectionRefusedError(err, "refused") if err in REFUSED else OSError(err, "connect failed")
        return sock
    except BaseException:
        sock.close()
        raise


def tcp_state(ip: str, port: int, timeout: float, cancel=None) -> str:
    """'open' (accepted), 'closed' (RST, so a host is there) or 'filtered' (silence or error)."""
    try:
        tcp_connect(ip, port, timeout, cancel).close()
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except Cancelled:
        raise
    except OSError:
        return "filtered"


def tls_context(minimum=None, maximum=None) -> ssl.SSLContext:
    """A client context that accepts anything: we inspect servers, we do not trust them."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:  # let old servers show themselves so they can be reported
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)   # asking for TLS 1.0/1.1 is the point here
            ctx.minimum_version = minimum if minimum is not None else ssl.TLSVersion.MINIMUM_SUPPORTED
            if maximum is not None:
                ctx.maximum_version = maximum
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (AttributeError, ValueError, ssl.SSLError):
        pass
    return ctx


class Conn:
    """A connected socket, plain or TLS, with hard limits on time and size."""

    def __init__(self, sock, cancel=None, max_bytes: int = MAX_RESPONSE):
        self.sock = sock
        self.cancel = cancel
        self.max_bytes = max_bytes
        self.received = 0
        self.truncated = False

    @property
    def is_tls(self) -> bool:
        return isinstance(self.sock, ssl.SSLSocket)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def send(self, data: bytes, timeout: float = 2.0) -> None:
        end = time.monotonic() + timeout
        view = memoryview(data)
        while view:
            try:
                sent = self.sock.send(view)
            except (BlockingIOError, ssl.SSLWantWriteError):
                wait_io(self.sock, False, True, end, self.cancel)
                continue
            except ssl.SSLWantReadError:
                wait_io(self.sock, True, False, end, self.cancel)
                continue
            view = view[sent:]

    def recv(self, limit: int = 4096, timeout: float = 1.0) -> bytes:
        """Up to `limit` bytes. b'' means the peer closed; ScanTimeout means silence."""
        end = time.monotonic() + timeout
        room = self.max_bytes - self.received
        if room <= 0:
            self.truncated = True
            return b""
        limit = min(limit, room)
        while True:
            try:
                data = self.sock.recv(limit)
            except (BlockingIOError, ssl.SSLWantReadError):
                wait_io(self.sock, True, False, end, self.cancel)
                continue
            except ssl.SSLWantWriteError:
                wait_io(self.sock, False, True, end, self.cancel)
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""
            self.received += len(data)
            return data

    def read(self, limit: int = MAX_RESPONSE, timeout: float = 1.5, until=None) -> bytes:
        """Collect data until the peer closes, `limit` bytes arrived, `timeout` passed or
        `until(data)` returns True. Silence and resets just end the read: what arrived is returned."""
        end = time.monotonic() + timeout
        buf = bytearray()
        while len(buf) < limit:
            try:
                chunk = self.recv(min(4096, limit - len(buf)), max(0.0, end - time.monotonic()))
            except Cancelled:
                raise
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if until is not None and until(bytes(buf)):
                break
        return bytes(buf)

    def read_exact(self, size: int, timeout: float = 1.5) -> bytes:
        """Exactly `size` bytes, or whatever arrived before the timeout."""
        return self.read(limit=size, timeout=timeout, until=lambda data: len(data) >= size)

    def start_tls(self, timeout: float = 2.0, server_hostname=None, ctx=None) -> None:
        ctx = ctx or tls_context()
        ssock = ctx.wrap_socket(self.sock, server_hostname=server_hostname,
                                do_handshake_on_connect=False)
        end = time.monotonic() + timeout
        try:
            while True:
                try:
                    ssock.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    wait_io(ssock, True, False, end, self.cancel)
                except ssl.SSLWantWriteError:
                    wait_io(ssock, False, True, end, self.cancel)
        except BaseException:
            ssock.close()
            raise
        self.sock = ssock


def open_conn(ip: str, port: int, timeout: float = 1.0, cancel=None, tls: bool = False,
              server_hostname=None, ctx=None) -> Conn:
    conn = Conn(tcp_connect(ip, port, timeout, cancel), cancel)
    if tls:
        try:
            conn.start_tls(timeout, server_hostname, ctx)
        except BaseException:
            conn.close()
            raise
    return conn


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

def udp_exchange(ip: str, port: int, payload: bytes, timeout: float, cancel=None,
                 retries: int = 1) -> tuple:
    """Send one datagram and wait for the answer. Returns (state, reply):

    open           an answer came back
    closed         the host said "port unreachable" (ICMP)
    open|filtered  silence: the port may be open and quiet, or a firewall drops the packet
    unknown        a local error stopped the probe (no route, no permission...)
    """
    try:
        sock = socket.socket(af_of(ip), socket.SOCK_DGRAM)
    except OSError:
        return "unknown", b""
    try:
        sock.setblocking(False)
        sock.connect(sockaddr(ip, port))
        for _ in range(retries + 1):
            try:
                sock.send(payload)
                wait_io(sock, True, False, time.monotonic() + timeout, cancel)
                reply = sock.recv(4096)
            except ScanTimeout:
                continue
            except OSError as exc:
                if isinstance(exc, Cancelled):
                    raise
                if exc.errno in REFUSED or exc.errno in RESET or isinstance(exc, ConnectionError):
                    return "closed", b""
                return "unknown", b""
            return "open", reply
        return "open|filtered", b""
    finally:
        sock.close()
