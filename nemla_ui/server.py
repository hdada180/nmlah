"""Local web server behind Nemla's 3D interface (standard library only).

The server listens on 127.0.0.1 only. Every /api/ call needs a random
per-launch token (handed to the page in the URL fragment) and a matching
Host header, so other websites and other machines cannot drive scans.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import guard as guard_mod

WEB_DIR = Path(__file__).resolve().parent / "web"
MAX_BODY = 64 * 1024
MAX_HOSTS = 1024
IDLE_GRACE = 6          # seconds after the window says goodbye before we exit
IDLE_LIMIT = 150        # seconds without any sign of life before we exit

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
}

CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
       "script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

CHROMIUM_LIKE = (
    "google-chrome-stable", "google-chrome", "chromium", "chromium-browser",
    "brave-browser", "brave", "microsoft-edge-stable", "microsoft-edge", "vivaldi",
)

STRINGS = {
    "en": {"consent": "Please confirm you own this network or have permission to scan it.",
           "busy": "A scan is already running.",
           "bad_number": "Threads and timeout must be numbers."},
    "ar": {"consent": "أكّد أنك تملك هذه الشبكة أو عندك تصريح بفحصها.",
           "busy": "في فحص شغّال حالياً.",
           "bad_number": "عدد الخيوط والمهلة لازم يكونوا أرقام."},
    "he": {"consent": "אשרו שהרשת בבעלותכם או שיש לכם אישור לסרוק אותה.",
           "busy": "סריקה כבר רצה כרגע.",
           "bad_number": "מספר התהליכונים והזמן הקצוב חייבים להיות מספרים."},
}


class Job:
    """One scan: an append-only event list that the page replays over SSE."""

    def __init__(self, job_id: str, target: str, lang: str):
        self.id = job_id
        self.target = target
        self.lang = lang
        self.events = []
        self.cond = threading.Condition()
        self.cancel = threading.Event()
        self.closed = False
        self.hosts = None
        self.meta = None

    def emit(self, event: dict) -> None:
        with self.cond:
            self.events.append(event)
            self.cond.notify_all()

    def close(self) -> None:
        with self.cond:
            self.closed = True
            self.cond.notify_all()


class ScanRequestError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


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


def is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:  # Windows
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


class App:
    """State shared by all request threads."""

    def __init__(self, engine, lang=None, data_dir=None):
        self.engine = engine
        self.lang = lang
        self.token = secrets.token_urlsafe(18)
        self.allowed_hosts = set()
        self.auto_exit = False
        self.job = None
        self.data_dir = Path(data_dir) if data_dir else guard_mod.data_dir()
        self.alerts = guard_mod.AlertLog(self.data_dir / "guard-alerts.jsonl")
        self.guard = None
        self.guard_host = "0.0.0.0"
        self.lock = threading.Lock()
        self.last_seen = time.time()
        self.bye_at = None
        self.sse_clients = 0
        self.finished = threading.Event()

    def touch(self) -> None:
        self.last_seen = time.time()
        self.bye_at = None

    def running(self) -> bool:
        job = self.job
        return bool(job and not job.closed)

    # -- scans --------------------------------------------------------------

    def start_scan(self, body: dict) -> Job:
        engine = self.engine
        lang = body.get("lang") if body.get("lang") in engine.STRINGS else "en"
        ui = STRINGS.get(lang, STRINGS["en"])
        with self.lock:
            if self.running():
                raise ScanRequestError(ui["busy"], 409)
            engine._LANG = lang
            if body.get("authorized") is not True:
                raise ScanRequestError(ui["consent"], 403)

            target = str(body.get("target", "")).strip()
            try:
                if not target or len(target) > 200:
                    raise ValueError(target or "?")
                ips = engine.parse_targets(target, MAX_HOSTS)
            except ValueError as err:
                raise ScanRequestError(engine.t("invalid_target", err=err)) from None

            profile = body.get("profile", "quick")
            try:
                if profile == "standard":
                    ports = list(range(1, 1025))
                elif profile == "deep":
                    ports = list(range(1, 10001))
                elif profile == "custom":
                    ports = engine.parse_ports(str(body.get("ports", "")))
                else:
                    ports = sorted(engine.TOP_PORTS)
            except ValueError as err:
                raise ScanRequestError(engine.t("invalid_ports", err=err)) from None

            try:
                threads = min(500, max(1, int(body.get("threads", 150))))
                timeout = min(10.0, max(0.1, float(body.get("timeout", 0.7))))
            except (TypeError, ValueError):
                raise ScanRequestError(ui["bad_number"]) from None

            job = Job(secrets.token_hex(6), target, lang)
            self.job = job
            options = {
                "no_ping": bool(body.get("no_ping")), "no_os": bool(body.get("no_os")),
                "no_banner": bool(body.get("no_banner")),
                "threads": threads, "timeout": timeout,
            }
            threading.Thread(target=self._run_job, args=(job, ips, ports, options),
                             daemon=True).start()
            return job

    def _run_job(self, job: Job, ips: list, ports: list, options: dict) -> None:
        engine = self.engine
        engine._LOG_SINK = lambda msg: job.emit({"type": "log", "msg": msg})
        try:
            job.emit({"type": "start", "job": job.id, "target": job.target,
                      "addresses": len(ips), "ports": len(ports),
                      "started": time.time(), "options": options})
            hosts, meta = engine.run_scan(job.target, ips, ports, emit=job.emit,
                                          cancel=job.cancel, **options)
            job.hosts, job.meta = hosts, meta
            job.emit({"type": "done", "meta": meta, "hosts": hosts})
        except Exception as exc:  # noqa: BLE001 - report anything to the page
            job.emit({"type": "error", "msg": f"{type(exc).__name__}: {exc}"})
        finally:
            engine._LOG_SINK = None
            job.close()

    # -- guard mode ---------------------------------------------------------

    def start_guard(self, body: dict) -> dict:
        with self.lock:
            if self.guard and self.guard.running:
                return self.guard.status()
            raw = body.get("ports")
            try:
                if isinstance(raw, str):
                    raw = [p for p in re.split(r"[,\s]+", raw) if p]
                ports = [int(p) for p in raw] if raw else list(guard_mod.DEFAULT_DECOYS)
                if not ports or len(ports) > 16 or any(p < 0 or p > 65535 for p in ports):
                    raise ValueError
                interval = float(body.get("interval", 60))
            except (TypeError, ValueError):
                raise ScanRequestError("Decoy ports must be numbers between 1 and 65535 (at most 16).") from None
            interval = 0.0 if interval <= 0 else min(3600.0, max(10.0, interval))
            ip, network = local_network_hint()
            self.guard = guard_mod.Guard(
                self.alerts, ports=ports, host=self.guard_host,
                network=None if network.startswith("127.") else network, interval=interval,
                state_path=self.data_dir / "guard.json",
                vendor_lookup=getattr(self.engine, "mac_vendor", None))
            return self.guard.start()

    def stop_guard(self) -> dict:
        with self.lock:
            if self.guard:
                self.guard.stop()
                return self.guard.status()
        return {"running": False}

    def report(self, job: Job, fmt: str, lang: str):
        """(bytes, content_type, extension) for a finished job."""
        engine = self.engine
        with self.lock:
            previous = engine._LANG
            engine._LANG = lang if lang in engine.STRINGS else job.lang
            try:
                if fmt == "json":
                    return (engine.json_text(job.meta, job.hosts).encode("utf-8"),
                            "application/json; charset=utf-8", "json")
                if fmt == "csv":
                    return (engine.csv_text(job.hosts).encode("utf-8-sig"),
                            "text/csv; charset=utf-8", "csv")
                return (engine.render_html(job.meta, job.hosts).encode("utf-8"),
                        "text/html; charset=utf-8", "html")
            finally:
                engine._LANG = previous

    def info(self) -> dict:
        engine = self.engine
        ip, network = local_network_hint()
        job = self.job
        return {
            "version": engine.__version__, "platform": sys.platform,
            "hostname": socket.gethostname(), "local_ip": ip, "suggested_target": network,
            "root": is_root(), "scapy": bool(engine.HAVE_SCAPY),
            "top_ports": len(engine.TOP_PORTS), "max_hosts": MAX_HOSTS, "lang": self.lang,
            "job": {"id": job.id, "target": job.target, "finished": job.closed} if job else None,
            "guard": self.guard.status() if self.guard else None,
            "guard_ports": list(guard_mod.DEFAULT_DECOYS),
        }


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NemlaUI"
        sys_version = ""

        def log_message(self, *args):  # keep the terminal quiet
            pass

        # -- plumbing -------------------------------------------------------

        def _send(self, status, body=b"", ctype="application/json; charset=utf-8",
                  headers=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status, obj):
            self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

        def _read_json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                return {}
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return {}
            return data if isinstance(data, dict) else {}

        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "").lower() in app.allowed_hosts

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True
            return origin.lower() in {f"http://{h}" for h in app.allowed_hosts}

        def _authorized(self, query) -> bool:
            token = self.headers.get("X-Nemla-Token") or (query.get("k") or [""])[0]
            return hmac.compare_digest(token.encode("utf-8"), app.token.encode("utf-8"))

        # -- routing --------------------------------------------------------

        def do_GET(self):
            self._route()

        def do_HEAD(self):
            self._route()

        def do_POST(self):
            self._route()

        def _route(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            if not url.path.startswith("/api/"):
                if self.command in ("GET", "HEAD"):
                    return self._static(url.path)
                return self._json(405, {"error": "method not allowed"})
            if not self._authorized(query):
                return self._json(401, {"error": "unauthorized"})
            if self.command == "POST" and not self._origin_ok():
                return self._json(403, {"error": "bad origin"})
            app.touch()
            name = url.path[len("/api/"):]
            routes = {
                ("GET", "info"): lambda: self._json(200, app.info()),
                ("POST", "scan"): self._api_scan,
                ("POST", "stop"): self._api_stop,
                ("GET", "events"): lambda: self._api_events(query),
                ("GET", "report"): lambda: self._api_report(query),
                ("POST", "hb"): lambda: self._json(200, {"ok": True}),
                ("POST", "bye"): self._api_bye,
                ("POST", "guard/start"): self._api_guard_start,
                ("POST", "guard/stop"): lambda: self._json(200, app.stop_guard()),
                ("GET", "guard/status"): lambda: self._json(
                    200, app.guard.status() if app.guard else {"running": False}),
                ("GET", "guard/events"): lambda: self._api_guard_events(query),
                ("POST", "guard/trust"): self._api_guard_trust,
                ("GET", "guard/block"): lambda: self._api_guard_block(query),
            }
            handler = routes.get((self.command, name))
            if handler is None:
                return self._json(404, {"error": "not found"})
            handler()

        # -- static files ---------------------------------------------------

        def _static(self, path: str):
            rel = "index.html" if path in ("", "/") else unquote(path).lstrip("/")
            try:
                target = (WEB_DIR / rel).resolve()
            except (OSError, ValueError):
                return self._json(404, {"error": "not found"})
            if WEB_DIR not in target.parents or not target.is_file():
                return self._json(404, {"error": "not found"})
            ctype = MIME.get(target.suffix.lower(), "application/octet-stream")
            headers = {"Cache-Control": "no-cache"}
            if target.suffix.lower() == ".html":
                headers["Content-Security-Policy"] = CSP
                headers["X-Frame-Options"] = "DENY"
            self._send(200, target.read_bytes(), ctype, headers)

        # -- API ------------------------------------------------------------

        def _api_scan(self):
            body = self._read_json()
            try:
                job = app.start_scan(body)
            except ScanRequestError as err:
                return self._json(err.status, {"error": str(err)})
            self._json(200, {"job": job.id})

        def _api_stop(self):
            job = app.job
            if job and not job.closed:
                job.cancel.set()
            self._json(200, {"ok": True})

        def _api_bye(self):
            app.bye_at = time.time()
            self._json(200, {"ok": True})

        def _api_guard_start(self):
            try:
                self._json(200, app.start_guard(self._read_json()))
            except ScanRequestError as err:
                self._json(err.status, {"error": str(err)})

        def _api_guard_trust(self):
            guard = app.guard
            ok = bool(guard and guard.trust(str(self._read_json().get("mac", ""))))
            self._json(200 if ok else 400, {"ok": ok})

        def _api_guard_block(self, query):
            guard = app.guard
            ip = (query.get("ip") or [""])[0]
            try:
                own = guard.own if guard else guard_mod.own_addresses()
                gateway = guard.gateway if guard else guard_mod.default_gateway()
                self._json(200, guard_mod.block_commands(ip, gateway=gateway, own=own))
            except guard_mod.ProtectedAddress:
                self._json(409, {"error": "protected"})
            except ValueError as err:
                self._json(400, {"error": str(err)})

        def _api_guard_events(self, query):
            try:  # a reconnecting EventSource resumes after the last alert it saw
                after = int(self.headers.get("Last-Event-ID") or (query.get("from") or ["0"])[0])
            except ValueError:
                after = 0
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            app.sse_clients += 1
            try:
                while not app.finished.is_set():
                    batch = app.alerts.wait(after, 5)
                    if batch:
                        chunk = "".join(f"id: {a['id']}\ndata: {json.dumps(a, ensure_ascii=False)}\n\n"
                                        for a in batch)
                        after = batch[-1]["id"]
                        self.wfile.write(chunk.encode("utf-8"))
                    else:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    app.last_seen = time.time()
            except (BrokenPipeError, ConnectionError, OSError):
                return
            finally:
                app.sse_clients -= 1

        def _job_for(self, query):
            job = app.job
            if job is None or job.id != (query.get("job") or [""])[0]:
                return None
            return job

        def _api_events(self, query):
            job = self._job_for(query)
            if job is None:
                return self._json(404, {"error": "no such scan"})
            try:  # a reconnecting EventSource resumes from Last-Event-ID
                index = int(self.headers.get("Last-Event-ID") or (query.get("from") or ["0"])[0])
            except ValueError:
                index = 0
            index = max(0, index)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            app.sse_clients += 1
            try:
                while True:
                    with job.cond:
                        if index >= len(job.events) and not job.closed:
                            job.cond.wait(timeout=10)
                        batch = job.events[index:]
                        closed = job.closed
                    if batch:
                        chunk = "".join(
                            f"id: {index + i + 1}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
                            for i, ev in enumerate(batch))
                        index += len(batch)
                        self.wfile.write(chunk.encode("utf-8"))
                    elif closed:
                        return
                    else:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    app.last_seen = time.time()
            except (BrokenPipeError, ConnectionError, OSError):
                return
            finally:
                app.sse_clients -= 1

        def _api_report(self, query):
            job = self._job_for(query)
            if job is None or job.hosts is None or job.meta is None:
                return self._json(404, {"error": "no finished scan"})
            fmt = (query.get("fmt") or ["html"])[0]
            lang = (query.get("lang") or [job.lang])[0]
            body, ctype, ext = app.report(job, fmt, lang)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", job.target)[:60] or "scan"
            self._send(200, body, ctype, {
                "Content-Disposition": f'attachment; filename="nemla-{safe}-{stamp}.{ext}"'})

    return Handler


# ---------------------------------------------------------------------------
# Opening a window
# ---------------------------------------------------------------------------

def has_display() -> bool:
    if sys.platform.startswith("linux"):
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


def app_window_command(url: str, which=shutil.which):
    """Command line for a chromeless 'app' window, or None if no Chromium-family browser."""
    for name in CHROMIUM_LIKE:
        path = which(name)
        if path:
            return [path, f"--app={url}", "--window-size=1440,900", "--class=Nemla",
                    "--no-first-run", "--no-default-browser-check"]
    return None


def open_ui_window(url: str) -> bool:
    """Open Nemla in its own app-style window if possible, else the default browser."""
    if not has_display():
        return False
    command = app_window_command(url) if sys.platform.startswith("linux") else None
    if command:
        try:
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return True
        except OSError:
            pass
    try:
        return bool(webbrowser.open(url))
    except webbrowser.Error:
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _watch(app: App, httpd) -> None:
    """Quit once the window is gone (only when Nemla opened that window itself)."""
    while not app.finished.wait(1.0):
        now = time.time()
        if app.sse_clients > 0:
            continue
        gone = (app.bye_at is not None and now - app.bye_at > IDLE_GRACE) \
            or now - app.last_seen > IDLE_LIMIT
        if gone:
            if app.job is not None:
                app.job.cancel.set()
            httpd.shutdown()
            return


def serve(engine, port: int = 0, open_window: bool = True, keep_alive: bool = False,
          lang=None) -> int:
    """Run the interface until its window closes (or Ctrl+C). Returns an exit code."""
    app = App(engine, lang)
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    except OSError as exc:
        engine.log(f"Cannot start the interface server on port {port}: {exc}")
        return 1
    port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    url = f"http://127.0.0.1:{port}/#k={app.token}"

    engine.log(f"Nemla 3D interface: {url}")
    if open_window and sys.platform.startswith("linux") and is_root():
        engine.log("Running as root: browsers refuse to start as root, so open the address above yourself.")
        open_window = False
    opened = open_ui_window(url) if open_window else False
    app.auto_exit = opened and not keep_alive
    if app.auto_exit:
        engine.log("Close the Nemla window to quit (or press Ctrl+C).")
        threading.Thread(target=_watch, args=(app, httpd), daemon=True).start()
    else:
        engine.log("Open the address above in a browser. Press Ctrl+C to quit."
                   + ("" if has_display() else " Over SSH: ssh -L "
                      f"{port}:127.0.0.1:{port} <host>, then open it locally."))
    try:
        httpd.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        app.finished.set()
        if app.job is not None:
            app.job.cancel.set()
        if app.guard is not None:
            app.guard.stop()
        httpd.server_close()
    return 0
