"""Controlled scan targets for the benchmarks and the large-network tests: loopback only, never a real machine.

One selector thread serves every listening socket, so a hundred "hosts" (127.0.x.y addresses, all of 127/8 is local
on Linux and Windows) cost one thread, not a hundred. Each listener has a behaviour:

    banner   sends an SSH banner, then waits for the client to hang up
    http     answers one HTTP request with a Server header, then closes
    silent   accepts and says nothing until the client leaves (a stalled service: banner grabs must time out)
    reset    accepts and drops the connection with a TCP reset (a broken service)
    close    accepts and closes at once
"""
import selectors
import socket
import struct
import threading

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
HTTP_REPLY = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nContent-Length: 30\r\n"
              b"Connection: close\r\n\r\n<html><title>Bench</title></html>")


class LocalTarget:
    def __init__(self):
        self._selector = selectors.DefaultSelector()
        self._lock = threading.Lock()
        self._thread = None
        self._stopping = False
        self.active = 0             # connections accepted and not yet closed
        self.peak = 0               # the most there ever were at once
        self.accepted = 0
        self.sockets = []

    def listen(self, host="127.0.0.1", port=0, behaviour="close") -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, port))
        sock.listen(512)
        sock.setblocking(False)
        self.sockets.append(sock)
        self._selector.register(sock, selectors.EVENT_READ, ("listener", behaviour))
        return sock.getsockname()[1]

    def start(self) -> "LocalTarget":
        self._thread = threading.Thread(target=self._serve, daemon=True, name="bench-target")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stopping = True
        if self._thread is not None:
            self._thread.join(timeout=5)
        for key in list(self._selector.get_map().values()):
            try:
                key.fileobj.close()
            except OSError:
                pass
        self._selector.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------ serving

    def _close(self, conn, reset=False):
        try:
            self._selector.unregister(conn)
        except (KeyError, ValueError):
            pass
        try:
            if reset:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
        except OSError:
            pass
        with self._lock:
            self.active -= 1

    def _serve(self):
        while not self._stopping:
            if not self._selector.get_map():         # select() with nothing to watch is an error on Windows
                threading.Event().wait(0.02)
                continue
            try:
                events = self._selector.select(0.05)
            except (OSError, ValueError):
                threading.Event().wait(0.02)         # a socket was closed or added under our feet: look again
                continue
            for key, _ in events:
                kind, behaviour = key.data
                if kind == "listener":
                    self._accept(key.fileobj, behaviour)
                else:
                    self._read(key.fileobj, behaviour)

    def _accept(self, listener, behaviour):
        for _ in range(64):                          # drain the backlog in one go
            try:
                conn, _ = listener.accept()
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            conn.setblocking(False)
            with self._lock:
                self.active += 1
                self.accepted += 1
                self.peak = max(self.peak, self.active)
            if behaviour == "close":
                self._close(conn)
            elif behaviour == "reset":
                self._close(conn, reset=True)
            else:
                if behaviour == "banner":
                    try:
                        conn.send(SSH_BANNER)
                    except OSError:
                        self._close(conn)
                        continue
                self._selector.register(conn, selectors.EVENT_READ, ("client", behaviour))

    def _read(self, conn, behaviour):
        try:
            data = conn.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._close(conn)
            return
        if not data:                                 # the client hung up
            self._close(conn)
        elif behaviour == "http" and b"\r\n\r\n" in data:
            try:
                conn.send(HTTP_REPLY)
            except OSError:
                pass
            self._close(conn)
        # "banner" and "silent": ignore what the client says and keep the connection until it leaves
