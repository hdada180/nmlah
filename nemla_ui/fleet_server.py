"""HTTP for the Fleet controller: an agent listener and an operator listener, both thin shells around `Controller`.

- The agent listener answers four POST routes (enroll, poll, ack, result) and nothing else. Off loopback it requires
  TLS, and the handshake is done in the connection's own thread so a client that stalls in it cannot hold up accepts.
  Every agent request is authenticated before its body is read, bodies are size-capped, and a refusal is followed by a
  bounded discard of what the client is still sending, so the answer is not lost to a reset.
- The operator listener is loopback only and needs the operator token, the Host and Origin checks and the body cap the
  local interface uses. It serves the Fleet page and the JSON API the `nemla controller` commands talk to.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from nemla.fleet import protocol
from nemla.fleet.controller import POLL_SECONDS, Controller, FleetError
from nemla.log import logger
from nemla.reports import write_atomic
from nemla_ui.server import CSP, DISCARD_LIMIT, DISCARD_TIMEOUT, MAX_BODY, MIME, REQUEST_TIMEOUT, WEB_DIR, BoundedServer

MAX_UPLOADS = 4                    # results being received at once (each may be up to 32 MiB in memory)
PAGES = {"/": "fleet.html", "/fleet.js": "fleet.js", "/fleet.css": "fleet.css"}


class _TooLarge(Exception):
    pass


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class _JsonHandler(BaseHTTPRequestHandler):
    server_version = "NemlaFleet"
    sys_version = ""
    timeout = REQUEST_TIMEOUT

    def log_message(self, *args):
        pass

    def setup(self):
        request = self.request
        if isinstance(request, ssl.SSLSocket):
            request.settimeout(10)
            request.do_handshake()
        super().setup()

    def _send(self, status, body=b"", ctype="application/json; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj, headers=None):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), headers=headers)

    def _drain(self):
        """Read and throw away what the client is still sending (capped, time-limited) before the socket closes:
        closing with unread data makes the OS reset the connection, and a reset can destroy the answer."""
        try:
            self.connection.settimeout(DISCARD_TIMEOUT)
            left = min(int(self.headers.get("Content-Length") or 0), DISCARD_LIMIT)
            while left > 0:
                chunk = self.rfile.read(min(left, 65536))
                if not chunk:
                    break
                left -= len(chunk)
        except (OSError, ValueError):
            pass

    def _refuse(self, status, message, headers=None):
        try:
            self._json(status, {"error": message}, headers)
            self._drain()
        except OSError:
            pass

    def _body(self, limit: int) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise FleetError("chunked bodies are not accepted", 411)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise FleetError("a Content-Length is required", 411) from None
        if length < 0:
            raise FleetError("a Content-Length is required", 411)
        if length > limit:
            raise _TooLarge()
        return self.rfile.read(length)

    def _guarded(self, work):
        """Run `work`, turning every way it can fail into a clean answer that never carries a traceback."""
        try:
            work()
        except (BrokenPipeError, ConnectionError, socket.timeout, ssl.SSLError):
            return
        except _TooLarge:
            self._refuse(413, "request too large")
        except FleetError as err:
            self._refuse(err.status, str(err))
        except protocol.ProtocolError as err:
            self._refuse(400, str(err))
        except Exception:
            logger.debug("fleet request failed", exc_info=True)
            self._refuse(500, "internal error")

    def _not_found(self):
        self._refuse(404, "not found")

    do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_found


# -- the agent listener ------------------------------------------------------------------------------------------

def make_agent_handler(controller: Controller):
    uploads = threading.BoundedSemaphore(MAX_UPLOADS)

    class AgentHandler(_JsonHandler):
        def _agent(self) -> dict:
            scheme, _, credential = (self.headers.get("Authorization") or "").partition(" ")
            agent_id, _, secret = credential.partition(".")
            agent = controller.authenticate(agent_id, secret, self.client_address[0]) if scheme.lower() == "bearer" else None
            if agent is None:
                if scheme.lower() != "bearer":
                    controller.authenticate("", "", self.client_address[0])
                raise FleetError("unauthorized", 401)
            return agent

        def _object(self, limit: int) -> dict:
            data = protocol.loads_strict(self._body(limit), limit)
            if not isinstance(data, dict):
                raise protocol.ProtocolError("a message is a JSON object")
            return data

        def do_POST(self):
            self._guarded(self._route)

        def _route(self):
            path = urlparse(self.path).path
            if path == "/agent/v1/enroll":
                body = self._object(protocol.MAX_ENROLL_BYTES)
                fields = [body.get(k, "") for k in ("token", "scope", "version", "hostname")]
                if not all(isinstance(f, str) for f in fields):
                    raise protocol.ProtocolError("enrollment fields are text")
                return self._json(200, controller.enroll(fields[0], fields[1], fields[2], fields[3],
                                                          remote=self.client_address[0]))
            if path not in ("/agent/v1/poll", "/agent/v1/ack", "/agent/v1/result"):
                raise FleetError("not found", 404)
            agent = self._agent()                                     # before the body is read
            if path == "/agent/v1/result":
                if not uploads.acquire(blocking=False):
                    raise FleetError("the controller is receiving other results; try again in a few seconds", 503)
                try:
                    return self._json(200, controller.receive_result(agent, self._object(protocol.MAX_RESULT_BYTES)))
                finally:
                    uploads.release()
            body = self._object(protocol.MAX_ENROLL_BYTES)
            if path == "/agent/v1/ack":
                return self._json(200, controller.ack(agent, body.get("job")))
            wait = body.get("wait")
            wait = float(wait) if isinstance(wait, (int, float)) and not isinstance(wait, bool) and wait == wait else None
            return self._json(200, controller.poll(agent, busy=body.get("busy") is True, wait=wait))

    return AgentHandler


class AgentServer(BoundedServer):
    """The agent listener: TLS when given a context, with the handshake left to the connection's own thread."""

    def __init__(self, address, handler, tls_context=None):
        self.tls_context = tls_context
        super().__init__(address, handler)
        self._slots = threading.BoundedSemaphore(protocol.MAX_AGENTS + 10)   # every polling agent holds one

    def get_request(self):
        sock, address = super().get_request()
        if self.tls_context is not None:
            sock = self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, address

    def handle_error(self, request, client_address):
        logger.debug("fleet connection from %s ended badly", client_address, exc_info=True)


# -- the operator listener ---------------------------------------------------------------------------------------

def _operator_label(value) -> str:
    return re.sub(r"[^A-Za-z0-9._@ -]", "", value or "")[:40].strip() or "operator"


def make_operator_handler(controller: Controller, token: str, allowed_hosts: set, info: dict):
    class OperatorHandler(_JsonHandler):
        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "").lower() in allowed_hosts

        def _origin_ok(self) -> bool:
            if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
                return False
            origin = self.headers.get("Origin")
            return not origin or origin.lower() in {f"http://{h}" for h in allowed_hosts}

        def _authorized(self) -> bool:
            given = self.headers.get("X-Nemla-Token") or ""
            return hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8"))

        def do_GET(self):
            self._guarded(self._dispatch)

        def do_POST(self):
            self._guarded(self._dispatch)

        def do_HEAD(self):
            self._guarded(self._dispatch)

        def _page(self, path: str):
            target = WEB_DIR / PAGES[path]
            if not target.is_file():
                raise FleetError("not found", 404)
            headers = {"Cache-Control": "no-cache"}
            if target.suffix == ".html":
                headers.update({"Content-Security-Policy": CSP, "X-Frame-Options": "DENY",
                                "Cross-Origin-Opener-Policy": "same-origin"})
            self._send(200, target.read_bytes(), MIME.get(target.suffix, "application/octet-stream"), headers)

        def _dispatch(self):
            if not self._host_ok():
                raise FleetError("bad host", 403)
            url = urlparse(self.path)
            if not url.path.startswith("/api/fleet/"):
                if self.command in ("GET", "HEAD") and url.path in PAGES:
                    return self._page(url.path)
                raise FleetError("not found", 404)
            if not self._authorized():
                raise FleetError("unauthorized", 401)
            if not self._origin_ok():
                raise FleetError("bad origin", 403)
            self._api(url.path[len("/api/fleet/"):], parse_qs(url.query))

        def _post_body(self) -> dict:
            if self.command != "POST":
                return {}
            try:
                data = protocol.loads_strict(self._body(MAX_BODY), MAX_BODY)
            except protocol.ProtocolError as err:
                raise FleetError(str(err), 400) from None
            if not isinstance(data, dict):
                raise FleetError("a request is a JSON object", 400)
            return data

        def _api(self, name: str, query: dict):
            who = _operator_label(self.headers.get("X-Nemla-Operator"))
            first = lambda key, default="": (query.get(key) or [default])[0]        # noqa: E731
            limit = lambda default: int(first("limit", str(default))) if first("limit", str(default)).isdigit() else default  # noqa: E731
            body: dict = {}                                            # filled in once the route is known
            routes = {
                ("GET", "info"): lambda: info,
                ("GET", "agents"): lambda: {"agents": controller.agents()},
                ("POST", "enroll-token"): lambda: controller.issue_token(str(body.get("name", "")), who),
                ("POST", "revoke"): lambda: controller.revoke(str(body.get("agent", "")), who),
                ("POST", "dispatch"): lambda: controller.dispatch(str(body.get("agent", "")), body.get("job"), who),
                ("POST", "cancel"): lambda: controller.cancel(str(body.get("job", "")), who),
                ("GET", "jobs"): lambda: {"jobs": controller.job_list(limit(100))},
                ("GET", "job"): lambda: controller.job(first("id")),
                ("GET", "results"): lambda: {"results": controller.results(first("agent"), limit(30))},
                ("GET", "result"): lambda: controller.result(first("agent"), first("id")),
                ("GET", "audit"): lambda: {"events": controller.audit.tail(min(limit(100), 500))},
            }
            action = routes.get((self.command if self.command != "HEAD" else "GET", name))
            if action is None:
                raise FleetError("not found", 404)
            body.update(self._post_body())
            self._json(200, action())

    return OperatorHandler


# -- running it --------------------------------------------------------------------------------------------------

def build_tls_context(cert, key) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context


def _operator_token(folder: Path) -> str:
    """The operator token: created on first use, kept in an owner-only file so `nemla controller` commands can read it."""
    path = folder / "operator.token"
    try:
        token = path.read_text(encoding="utf-8").strip()
        if len(token) >= 32:
            return token
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    write_atomic(str(path), token.encode("utf-8"))
    return token


class RunningController:
    def __init__(self, controller, agent_httpd, operator_httpd, token, pin, folder):
        self.controller, self.token, self.pin, self.folder = controller, token, pin, folder
        self._servers = (agent_httpd, operator_httpd)
        self.agent_port = agent_httpd.server_address[1]
        self.operator_port = operator_httpd.server_address[1]
        self._threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
                         for s in self._servers]
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self.controller.close()
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(5)
        try:
            (self.folder / "controller.json").unlink()
        except OSError:
            pass


def start_controller(folder, agent_host: str = "127.0.0.1", agent_port: int = 8443, operator_port: int = 0,
                     cert=None, key=None) -> RunningController:
    """Start both listeners in background threads. Off loopback the agent listener refuses to run without TLS."""
    folder = Path(folder)
    if (cert is None) != (key is None):
        raise ValueError("give both a certificate and its key")
    if cert is None and not is_loopback(agent_host):
        raise ValueError(f"the agent listener would be reachable from the network ({agent_host}): "
                         "TLS is required, give --tls-cert and --tls-key")
    context = build_tls_context(cert, key) if cert else None
    pin = protocol.pin_from_pem(Path(cert).read_text(encoding="utf-8", errors="replace")) if cert else None
    controller = Controller(folder)
    token = _operator_token(folder)
    agent_httpd = AgentServer((agent_host, agent_port), make_agent_handler(controller), context)
    try:
        operator_httpd = BoundedServer(("127.0.0.1", operator_port), _JsonHandler)   # bound once; the real handler
    except OSError:                                                                  # needs the port it was given
        agent_httpd.server_close()
        raise
    port = operator_httpd.server_address[1]
    allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
    info = {"protocol": protocol.PROTOCOL, "poll_seconds": POLL_SECONDS, "tls": context is not None, "pin": pin,
            "agent_listen": f"{agent_host}:{agent_httpd.server_address[1]}", "max_agents": protocol.MAX_AGENTS}
    operator_httpd.RequestHandlerClass = make_operator_handler(controller, token, allowed, info)
    running = RunningController(controller, agent_httpd, operator_httpd, token, pin, folder)
    endpoint = {"operator_port": running.operator_port, "agent_host": agent_host, "agent_port": running.agent_port,
                "tls": context is not None, "pin": pin, "pid": os.getpid(), "started": time.time()}
    write_atomic(str(folder / "controller.json"), json.dumps(endpoint, indent=1).encode("utf-8"))
    return running


def read_local_endpoint(folder) -> tuple:
    """(operator base URL, operator token) of the controller running on this machine, for the CLI."""
    folder = Path(folder)
    try:
        endpoint = json.loads((folder / "controller.json").read_text(encoding="utf-8"))
        token = (folder / "operator.token").read_text(encoding="utf-8").strip()
        return f"http://127.0.0.1:{int(endpoint['operator_port'])}", token
    except (OSError, ValueError, KeyError, TypeError):
        raise FleetError("no controller is running here (start one with: nemla controller serve)", 503) from None
