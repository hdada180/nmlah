"""Local web server behind Nemla's 3D interface (standard library only).

Security model
--------------
* The server listens on 127.0.0.1 only.
* Every /api/ call needs a random per-launch token (handed to the page in the
  URL fragment, which browsers never send to servers). POST calls must carry
  it in the X-Nemla-Token header, so a form on another website cannot drive
  scans; GET calls (event streams, downloads) may also pass it as ?k=.
* The Host header must match (defeats DNS rebinding), a cross-site Origin or
  Sec-Fetch-Site is refused, request bodies are capped, idle connections time
  out, and the number of simultaneous connections and event streams is bounded.
* The page is served with a strict Content-Security-Policy; everything that
  came from the network is rendered with textContent, never as HTML.
* Scan input is validated and clamped (targets, ports, threads, timeouts) and
  ids of saved scans are checked before they touch the file system.
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

from nemla import guard as guard_mod
from nemla import history as history_mod
from nemla import reports as reports_mod
from nemla.config import UDP_PORTS
from nemla.log import logger

WEB_DIR = Path(__file__).resolve().parent / "web"
MAX_BODY = 64 * 1024
MAX_HOSTS = 1024
MAX_EVENTS = 60000       # events kept per scan; progress and log lines are dropped beyond this
MAX_STREAMS = 16         # simultaneous event streams
MAX_CONNECTIONS = 64     # simultaneous connections
REQUEST_TIMEOUT = 30     # seconds a connection may stall
IDLE_GRACE = 6           # seconds after the window says goodbye before we exit
IDLE_LIMIT = 150         # seconds without any sign of life before we exit
ESSENTIAL_EVENTS = {"start", "phase", "host", "host_start", "host_done", "port", "done", "error"}

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
        self.events: list = []
        self.cond = threading.Condition()
        self.cancel = threading.Event()
        self.closed = False
        self.hosts: list | None = None
        self.meta: dict | None = None

    def emit(self, event: dict) -> None:
        with self.cond:
            if len(self.events) >= MAX_EVENTS and event.get("type") not in ESSENTIAL_EVENTS:
                return  # a very long scan keeps its results but stops recording chatter
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
    """(my_ip, 'a.b.c.0/24') for the interface that reaches the outside world."""
    return guard_mod.local_network_hint()


def is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return False


def _number(body: dict, key: str, default, low, high, kind=float):
    """A number from the request, clamped to [low, high]. Anything that is not a number is an error."""
    value = body.get(key, default)
    if isinstance(value, bool):
        raise ValueError(key)
    number = kind(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise ValueError(key)
    return min(high, max(low, number))


def _flag(body: dict, key: str) -> bool:
    return body.get(key) is True


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
        self.guard_host = "0.0.0.0"  # noqa: S104 - decoy ports listen on the LAN on purpose (the web UI itself binds loopback)
        self.lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self.last_seen = time.monotonic()
        self.bye_at = None
        self.sse_clients = 0
        self.finished = threading.Event()

    def touch(self) -> None:
        self.last_seen = time.monotonic()
        self.bye_at = None

    def running(self) -> bool:
        job = self.job
        return bool(job and not job.closed)

    def stream_opened(self) -> bool:
        """Count a new event stream; False when there are too many."""
        with self._counter_lock:
            if self.sse_clients >= MAX_STREAMS:
                return False
            self.sse_clients += 1
            return True

    def stream_closed(self) -> None:
        with self._counter_lock:
            self.sse_clients = max(0, self.sse_clients - 1)

    # -- scans --------------------------------------------------------------

    def parse_scan(self, body: dict) -> tuple:
        """Validate a scan request. Returns (target, lang, ips, ports, options)."""
        engine = self.engine
        wanted = body.get("lang")
        lang = wanted if isinstance(wanted, str) and wanted in engine.STRINGS else "en"
        ui = STRINGS.get(lang, STRINGS["en"])
        if body.get("authorized") is not True:
            raise ScanRequestError(ui["consent"], 403)

        target = str(body.get("target", "")).strip()
        family = body.get("family") if body.get("family") in (4, 6) else None
        try:
            if not target or len(target) > 200:
                raise ValueError(target[:40] or "?")
            ips = engine.iter_targets(target, MAX_HOSTS, family)
        except ValueError as err:
            raise ScanRequestError(engine.t("invalid_target", lang=lang, err=err)) from None

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
            udp_ports = []
            if body.get("udp_ports"):
                udp_ports = engine.parse_ports(str(body["udp_ports"]))[:1024]
            elif _flag(body, "udp"):
                udp_ports = list(UDP_PORTS)
        except ValueError as err:
            raise ScanRequestError(engine.t("invalid_ports", lang=lang, err=err)) from None

        try:
            threads = int(_number(body, "threads", 150, 1, 500, int))
            options = {
                "no_ping": _flag(body, "no_ping"), "no_os": _flag(body, "no_os"),
                "no_banner": _flag(body, "no_banner"),
                "threads": threads,
                "timeout": _number(body, "timeout", 0.7, 0.1, 10.0),
                "per_host": int(_number(body, "per_host", 100, 1, threads, int)),
                "rate": _number(body, "rate", 0, 0, 5000.0),
                "max_probes": int(_number(body, "max_probes", 0, 0, 10_000_000, int)),
                "intensity": int(_number(body, "intensity", 5, 0, 9, int)),
                "udp_ports": tuple(udp_ports),
                "udp_timeout": _number(body, "udp_timeout", 1.0, 0.2, 5.0),
                "udp_rate": _number(body, "udp_rate", 200, 1, 1000.0),
            }
        except (TypeError, ValueError, OverflowError):
            raise ScanRequestError(ui["bad_number"]) from None
        return target, lang, ips, ports, options

    def start_scan(self, body: dict) -> Job:
        wanted = body.get("lang")
        lang = wanted if isinstance(wanted, str) and wanted in self.engine.STRINGS else "en"
        ui = STRINGS.get(lang, STRINGS["en"])
        if self.running():
            raise ScanRequestError(ui["busy"], 409)
        target, lang, ips, ports, options = self.parse_scan(body)   # may resolve names: no lock held
        with self.lock:
            if self.running():
                raise ScanRequestError(ui["busy"], 409)
            job = Job(secrets.token_hex(6), target, lang)
            self.job = job
            threading.Thread(target=self._run_job, args=(job, ips, ports, options), daemon=True).start()
            return job

    def _run_job(self, job: Job, ips, ports: list, options: dict) -> None:
        engine = self.engine
        engine._LOG_SINK = lambda msg: job.emit({"type": "log", "msg": msg})
        try:
            shown = dict(options, udp_ports=list(options["udp_ports"]))
            job.emit({"type": "start", "job": job.id, "target": job.target,
                      "addresses": len(ips), "ports": len(ports),
                      "started": time.time(), "options": shown})
            hosts, meta = engine.run_scan(job.target, ips, ports, emit=job.emit, cancel=job.cancel,
                                          lang=job.lang, **options)
            job.hosts, job.meta = hosts, meta
            done = {"type": "done", "meta": meta, "hosts": hosts}
            if not meta["cancelled"] and meta["discovered"]:
                self._remember(job, done)
            job.emit(done)
        except Exception as exc:
            logger.debug("scan failed", exc_info=True)
            job.emit({"type": "error", "msg": f"{type(exc).__name__}: {exc}"})
        finally:
            engine._LOG_SINK = None
            job.close()

    def _remember(self, job: Job, done: dict) -> None:
        """Save a finished scan and, if this target was scanned before, say what changed."""
        if job.meta is None or job.hosts is None:
            return
        try:
            done["scan_id"] = history_mod.save(self.data_dir, self.engine, job.meta, job.hosts)
            before = history_mod.previous_for(self.data_dir, job.target, done["scan_id"])
            old = history_mod.load(self.data_dir, before) if before else None
            if old:
                diff = self.engine.diff_scans(old["hosts"], job.hosts)
                diff["against"] = {"id": before, "scan_time": old.get("scan_time", "")}
                done["diff"] = diff
        except (OSError, KeyError, TypeError, ValueError) as exc:
            # history is a bonus: a full disk must never lose the scan itself, but say so
            logger.warning("could not save the scan to the history: %s", exc)
            done["history_error"] = str(exc)[:200]

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
                if interval != interval:
                    raise ValueError
            except (TypeError, ValueError):
                raise ScanRequestError("Decoy ports must be numbers between 1 and 65535 (at most 16).") from None
            interval = 0.0 if interval <= 0 else min(3600.0, max(10.0, interval))
            _, network = local_network_hint()
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
        """(bytes, content_type, extension) for a finished job, in any report format."""
        if job.meta is None or job.hosts is None:
            raise ScanRequestError("the scan has not finished", 409)
        lang = lang if lang in self.engine.STRINGS else job.lang
        return reports_mod.report_bytes(fmt, job.meta, job.hosts, lang)

    def ui_strings(self) -> dict:
        """The texts of the findings (title, why it matters, how to fix it) for the page, in every language,
        so the page can show any finding in the language the user switches to."""
        prefixes = (("f_", "find."), ("fd_", "finddesc."), ("fr_", "findfix."))
        out = {}
        for lang, table in self.engine.STRINGS.items():
            out[lang] = {target + key[len(prefix):]: text
                         for key, text in table.items() for prefix, target in prefixes if key.startswith(prefix)}
        return out

    def info(self) -> dict:
        engine = self.engine
        ip, network = local_network_hint()
        job = self.job
        return {
            "version": engine.__version__, "platform": sys.platform,
            "hostname": socket.gethostname(), "local_ip": ip, "suggested_target": network,
            "root": is_root(), "scapy": bool(engine.HAVE_SCAPY),
            "top_ports": len(engine.TOP_PORTS), "max_hosts": MAX_HOSTS, "lang": self.lang,
            "udp_ports": list(UDP_PORTS), "formats": list(reports_mod.FORMATS),
            "job": {"id": job.id, "target": job.target, "finished": job.closed} if job else None,
            "guard": self.guard.status() if self.guard else None,
            "guard_ports": list(guard_mod.DEFAULT_DECOYS),
        }


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NemlaUI"
        sys_version = ""
        timeout = REQUEST_TIMEOUT

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
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
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
            if length > MAX_BODY:
                raise ScanRequestError("request too large", 413)
            if length <= 0:
                return {}
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                return {}
            return data if isinstance(data, dict) else {}

        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "").lower() in app.allowed_hosts

        def _origin_ok(self) -> bool:
            if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
                return False
            origin = self.headers.get("Origin")
            if not origin:
                return True
            return origin.lower() in {f"http://{h}" for h in app.allowed_hosts}

        def _authorized(self, query) -> bool:
            token = self.headers.get("X-Nemla-Token")
            if token is None and self.command != "POST":   # only reads may pass the token in the address
                token = (query.get("k") or [""])[0]
            return hmac.compare_digest((token or "").encode("utf-8"), app.token.encode("utf-8"))

        # -- routing --------------------------------------------------------

        def do_GET(self):
            self._route()

        def do_HEAD(self):
            self._route()

        def do_POST(self):
            self._route()

        def _route(self):
            try:
                self._dispatch()
            except (BrokenPipeError, ConnectionError, socket.timeout):
                return  # the browser went away
            except ScanRequestError as err:
                self._json(err.status, {"error": str(err)})
            except Exception:
                logger.debug("request failed", exc_info=True)
                try:
                    self._json(500, {"error": "internal error"})
                except OSError:
                    pass

        def _dispatch(self):
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
            if not self._origin_ok():
                return self._json(403, {"error": "bad origin"})
            app.touch()
            name = url.path[len("/api/"):]
            routes = {
                ("GET", "info"): lambda: self._json(200, app.info()),
                ("GET", "strings"): lambda: self._json(200, app.ui_strings()),
                ("POST", "scan"): self._api_scan,
                ("POST", "stop"): self._api_stop,
                ("GET", "events"): lambda: self._api_events(query),
                ("GET", "report"): lambda: self._api_report(query),
                ("POST", "hb"): lambda: self._json(200, {"ok": True}),
                ("POST", "bye"): self._api_bye,
                ("GET", "history"): lambda: self._json(
                    200, {"scans": history_mod.list_scans(app.data_dir)}),
                ("GET", "history/scan"): lambda: self._api_history_scan(query),
                ("GET", "history/report"): lambda: self._api_history_report(query),
                ("GET", "history/diff"): lambda: self._api_history_diff(query),
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
                headers["Cross-Origin-Opener-Policy"] = "same-origin"
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
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
            app.bye_at = time.monotonic()
            self._json(200, {"ok": True})

        def _history_pair(self, query):
            a, b = (query.get("a") or [""])[0], (query.get("b") or [""])[0]
            return a, history_mod.load(app.data_dir, a), history_mod.load(app.data_dir, b)

        def _api_history_diff(self, query):
            a, old, new = self._history_pair(query)
            if old is None or new is None:
                return self._json(404, {"error": "no such scan"})
            diff = app.engine.diff_scans(old["hosts"], new["hosts"])
            diff["against"] = {"id": a, "scan_time": old.get("scan_time", "")}
            self._json(200, diff)

        def _api_history_scan(self, query):
            data = history_mod.load(app.data_dir, (query.get("id") or [""])[0])
            if data is None:
                return self._json(404, {"error": "no such scan"})
            self._json(200, data)

        def _api_history_report(self, query):
            data = history_mod.load(app.data_dir, (query.get("id") or [""])[0])
            if data is None:
                return self._json(404, {"error": "no such scan"})
            fmt = (query.get("fmt") or ["html"])[0]
            lang = (query.get("lang") or ["en"])[0]
            lang = lang if lang in app.engine.STRINGS else "en"
            body, ctype, ext = reports_mod.report_bytes(fmt, history_mod.meta_of(data), data["hosts"], lang)
            self._send(200, body, ctype, {
                "Content-Disposition": f'attachment; filename="nemla-{(query.get("id") or ["scan"])[0][:40]}.{ext}"'})

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

        def _stream_headers(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

        def _api_guard_events(self, query):
            try:  # a reconnecting EventSource resumes after the last alert it saw
                after = int(self.headers.get("Last-Event-ID") or (query.get("from") or ["0"])[0])
            except ValueError:
                after = 0
            if not app.stream_opened():
                return self._json(429, {"error": "too many streams"})
            try:
                self._stream_headers()
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
                    app.last_seen = time.monotonic()
            except (BrokenPipeError, ConnectionError, OSError):
                return
            finally:
                app.stream_closed()

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
            if not app.stream_opened():
                return self._json(429, {"error": "too many streams"})
            try:
                self._stream_headers()
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
                    app.last_seen = time.monotonic()
            except (BrokenPipeError, ConnectionError, OSError):
                return
            finally:
                app.stream_closed()

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


class BoundedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a ceiling on simultaneous connections."""

    daemon_threads = True
    request_queue_size = 32
    # Windows: SO_REUSEADDR lets a second process bind the very same port and receive the connections meant
    # for this one (and the token they carry). There the port is taken exclusively instead; on POSIX
    # SO_REUSEADDR only skips TIME_WAIT, which is what we want after a restart.
    allow_reuse_address = not sys.platform.startswith("win")

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def server_bind(self):
        if sys.platform.startswith("win") and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)   # too many at once: drop the newcomer
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


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
            # `command` is a browser executable plus our own loopback URL, from app_window_command(); no shell
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,  # noqa: S603
                             start_new_session=True)
            return True
        except OSError as exc:
            logger.debug("could not start the app window: %s", exc)
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
        now = time.monotonic()
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
        httpd = BoundedServer(("127.0.0.1", port), make_handler(app))
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
