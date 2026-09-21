"""A very small Chrome DevTools Protocol client, standard library only.

Enough to open a real Chrome/Chromium/Edge in headless mode, set a viewport size, load a page and run
JavaScript in it: that is what the layout tests need, and it keeps the project free of dependencies.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlparse


def find_browser():
    """Path of a Chromium-based browser, or None. NEMLA_CHROME overrides the search."""
    wanted = os.environ.get("NEMLA_CHROME")
    if wanted:
        return wanted if os.path.exists(wanted) else shutil.which(wanted)
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    for path in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                 r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                 r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                 r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                 "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                 "/Applications/Chromium.app/Contents/MacOS/Chromium"):
        if os.path.exists(path):
            return path
    return None


class WebSocket:
    """Client side of RFC 6455: text frames only, which is all the DevTools protocol uses."""

    def __init__(self, url, timeout=30):
        parts = urlparse(url)
        self.sock = socket.create_connection((parts.hostname, parts.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {parts.hostname}:{parts.port}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("the browser closed the connection during the handshake")
            head += chunk
        header, _, self.buffer = head.partition(b"\r\n\r\n")
        if b" 101 " not in header.split(b"\r\n")[0]:
            raise ConnectionError(f"websocket handshake refused: {header[:80]!r}")

    def _read(self, count):
        while len(self.buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("the browser closed the connection")
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def _send(self, opcode, payload):
        size = len(payload)
        head = bytearray([0x80 | opcode])
        if size < 126:
            head.append(0x80 | size)
        elif size < 65536:
            head += bytes([0x80 | 126]) + size.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + size.to_bytes(8, "big")
        mask = os.urandom(4)
        head += mask
        self.sock.sendall(bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def send(self, text):
        self._send(0x1, text.encode())

    def recv(self):
        message = b""
        while True:
            first, second = self._read(2)
            opcode, size = first & 0x0F, second & 0x7F
            if size == 126:
                size = int.from_bytes(self._read(2), "big")
            elif size == 127:
                size = int.from_bytes(self._read(8), "big")
            data = self._read(size)
            if opcode == 0x8:
                raise ConnectionError("the browser closed the page")
            if opcode == 0x9:
                self._send(0xA, data)
                continue
            if opcode in (0x0, 0x1, 0x2):
                message += data
                if first & 0x80:
                    return message.decode()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Browser:
    """A headless browser with one page. Use as a context manager."""

    def __init__(self, executable=None):
        self.executable = executable or find_browser()
        self.process = None
        self.profile = None
        self.ws = None
        self._id = 0

    def __enter__(self):
        self.profile = tempfile.mkdtemp(prefix="nemla-browser-")
        self.process = subprocess.Popen(
            [self.executable, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
             "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--mute-audio",
             "--remote-debugging-port=0", f"--user-data-dir={self.profile}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 30
        port = None
        while port is None:                       # Chrome writes the port it picked into the profile folder
            try:
                with open(os.path.join(self.profile, "DevToolsActivePort"), encoding="utf-8") as handle:
                    port = int(handle.readline().strip())
            except (OSError, ValueError):
                if self.process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("the browser did not start") from None
                time.sleep(0.1)
        deadline = time.monotonic() + 30
        target = None
        while target is None:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10) as answer:
                pages = [t for t in json.load(answer) if t.get("type") == "page"]
            target = pages[0] if pages else None
            if target is None:
                if time.monotonic() > deadline:
                    raise RuntimeError("the browser opened no page")
                time.sleep(0.1)
        self.ws = WebSocket(target["webSocketDebuggerUrl"])
        self.call("Page.enable")
        return self

    def __exit__(self, *exc):
        if self.ws:
            self.ws.close()
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.profile:
            shutil.rmtree(self.profile, ignore_errors=True)
        return False

    def call(self, method, **params):
        self._id += 1
        self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("id") == self._id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    def viewport(self, width, height):
        self.call("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=False)

    def open(self, url):
        self.call("Page.navigate", url=url)

    def run(self, expression):
        """Evaluate JavaScript (a promise is awaited) and return its JSON-able value."""
        result = self.call("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise RuntimeError(f"script failed: {result['exceptionDetails'].get('text')}: "
                               f"{result['exceptionDetails'].get('exception', {}).get('description', '')[:300]}")
        return result["result"].get("value")
