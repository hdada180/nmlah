"""The local web server: authentication, origin checks, limits, path safety, new API routes."""
import http.client
import json
import socket
import threading
import time
import types
import uuid
from http.server import ThreadingHTTPServer
from urllib.parse import quote

import pytest

import nemla
from nemla import history
from nemla_ui import server
from conftest import wait_until


@pytest.fixture()
def ui(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(app))
    port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, port
    app.finished.set()
    httpd.shutdown()
    httpd.server_close()
    nemla._LANG = "en"
    nemla._LOG_SINK = None


def call(port, path, method="GET", token=None, body=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    hdrs = dict(headers or {})
    if token:
        hdrs.setdefault("X-Nemla-Token", token)
    payload = raw
    if body is not None:
        payload = json.dumps(body)
        hdrs["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=hdrs)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res.status, res, data


GOOD = {"target": "127.0.0.1", "profile": "custom", "ports": "80", "authorized": True, "no_ping": True, "no_os": True}


# --------------------------------------------------------------------------
# authentication and origin
# --------------------------------------------------------------------------

def test_api_needs_the_token(ui):
    app, port = ui
    assert call(port, "/api/info")[0] == 401
    assert call(port, "/api/info", token="wrong")[0] == 401
    assert call(port, "/api/info", token="")[0] == 401
    assert call(port, "/api/info", token=app.token[:-1])[0] == 401
    assert call(port, "/api/info", token=app.token)[0] == 200


def test_reads_may_use_the_query_but_posts_must_use_the_header(ui):
    app, port = ui
    assert call(port, f"/api/info?k={app.token}")[0] == 200
    assert call(port, f"/api/scan?k={app.token}", "POST", body=GOOD)[0] == 401          # a form on another site could do this
    assert call(port, "/api/scan", "POST", token=app.token, body={**GOOD, "authorized": False})[0] == 403


def test_the_host_header_must_match(ui):
    app, port = ui
    for host in ("evil.example", f"127.0.0.1:{port + 1}", "", "localhost", f"evil.example:{port}"):
        status, _, _ = call(port, "/api/info", token=app.token, headers={"Host": host})
        assert status == 403, host
    assert call(port, "/", headers={"Host": "evil.example"})[0] == 403                # rebinding cannot even load the page


@pytest.mark.parametrize("headers", [{"Origin": "https://evil.example"}, {"Origin": "http://127.0.0.1:1"},
                                     {"Sec-Fetch-Site": "cross-site"}, {"Origin": "null"}])
def test_cross_site_requests_are_refused_for_reads_and_writes(ui, headers):
    app, port = ui
    assert call(port, "/api/info", token=app.token, headers=headers)[0] == 403
    assert call(port, "/api/scan", "POST", token=app.token, body=GOOD, headers=headers)[0] == 403
    assert app.job is None


def test_same_origin_requests_work(ui):
    app, port = ui
    ok = {"Origin": f"http://127.0.0.1:{port}", "Sec-Fetch-Site": "same-origin"}
    assert call(port, "/api/info", token=app.token, headers=ok)[0] == 200


def test_security_headers_on_the_page_and_the_api(ui):
    app, port = ui
    _, res, _ = call(port, "/")
    assert "script-src 'self'" in res.getheader("Content-Security-Policy") and res.getheader("X-Frame-Options") == "DENY"
    assert res.getheader("X-Content-Type-Options") == "nosniff" and res.getheader("Cross-Origin-Opener-Policy") == "same-origin"
    _, res, _ = call(port, "/api/info", token=app.token)
    assert res.getheader("Cache-Control") == "no-store" and res.getheader("Referrer-Policy") == "no-referrer"
    assert res.getheader("Cross-Origin-Resource-Policy") == "same-origin"


# --------------------------------------------------------------------------
# input limits
# --------------------------------------------------------------------------

def test_oversized_bodies_are_refused_before_they_are_read(ui):
    app, port = ui
    assert call(port, "/api/scan", "POST", token=app.token, raw="x" * (server.MAX_BODY + 10),
                headers={"Content-Type": "application/json"})[0] == 413
    assert app.job is None


def test_the_413_for_an_oversized_body_always_reaches_the_client(ui):
    """The body is refused without being kept, but the client is still sending it when the answer goes out. Closing
    the socket with that data unread makes the OS reset the connection, and a reset can destroy the 413 before
    the client reads it - it was lost about one time in eight on Windows (found by a flaky run of the test above,
    measured at 4/30 failures). Repeating the request makes the old behaviour fail with near certainty."""
    app, port = ui
    for _ in range(40):
        status, res, _ = call(port, "/api/scan", "POST", token=app.token, raw="x" * (server.MAX_BODY + 10),
                              headers={"Content-Type": "application/json"})
        assert status == 413 and res.getheader("Connection") == "close"
    assert app.job is None


def test_an_oversized_body_that_never_arrives_does_not_hold_the_connection_for_long(ui):
    """Only the headers are sent, claiming a body of a gigabyte: the 413 comes back at once, and the connection is
    closed within a couple of seconds instead of waiting for data that is never coming."""
    app, port = ui
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(b"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Nemla-Token: %s\r\n"
                     b"Content-Type: application/json\r\nContent-Length: 1000000000\r\n\r\n"
                     % (port, app.token.encode()))
        started = time.monotonic()
        first = sock.recv(4096)
        assert first.startswith((b"HTTP/1.0 413", b"HTTP/1.1 413"))
        while sock.recv(4096):
            pass
        assert time.monotonic() - started < 6


@pytest.mark.parametrize("raw", ["", "not json", "[1,2,3]", '"string"', "null", "{\"target\": ", "\x00\x01"])
def test_garbage_bodies_are_a_clean_error(ui, raw):
    app, port = ui
    status, _, data = call(port, "/api/scan", "POST", token=app.token, raw=raw, headers={"Content-Type": "application/json"})
    assert status in (400, 403) and b"Traceback" not in data


@pytest.mark.parametrize("patch", [
    {"target": "10.0.0.0/8"}, {"target": "x" * 300}, {"target": "1.2.3.4; reboot"}, {"target": ["127.0.0.1"]},
    {"ports": "1-99999999999"}, {"ports": "0"}, {"ports": ""}, {"threads": "many"}, {"threads": None},
    {"timeout": "fast"}, {"timeout": [1]}, {"timeout": float("nan")}, {"intensity": "x"}, {"udp_ports": "0"},
])
def test_hostile_scan_parameters_are_refused_with_400(ui, patch):
    app, port = ui
    status, _, _ = call(port, "/api/scan", "POST", token=app.token, body={**GOOD, **patch})
    assert status == 400 and app.job is None


def test_numbers_are_clamped_not_trusted(ui):
    app, _port = ui
    parsed = app.parse_scan({**GOOD, "threads": 10 ** 9, "timeout": -5, "per_host": 10 ** 6, "rate": 10 ** 12,
                             "max_probes": -3, "intensity": 99, "udp_timeout": 999, "udp_rate": 0})
    options = parsed[4]
    assert options["threads"] == 500 and options["timeout"] == 0.1 and options["per_host"] == 500
    assert options["rate"] == 5000 and options["max_probes"] == 0 and options["intensity"] == 9
    assert options["udp_timeout"] == 5.0 and options["udp_rate"] == 1


def test_boolean_flags_must_be_real_booleans(ui):
    app, _ = ui
    options = app.parse_scan({**GOOD, "no_ping": "false", "no_os": 1, "no_banner": "yes"})[4]
    assert options["no_ping"] is False and options["no_os"] is False and options["no_banner"] is False


def test_only_one_scan_at_a_time(ui, tcp_server):
    app, port = ui
    busy = tcp_server(lambda c: time.sleep(3))
    body = {**GOOD, "ports": str(busy), "timeout": 2}
    assert call(port, "/api/scan", "POST", token=app.token, body=body)[0] == 200
    assert call(port, "/api/scan", "POST", token=app.token, body=body)[0] == 409
    call(port, "/api/stop", "POST", token=app.token)
    deadline = time.monotonic() + 5
    while app.running() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not app.running()


def test_udp_can_be_requested_through_the_api(ui, udp_server):
    app, _ = ui
    options = app.parse_scan({**GOOD, "udp": True})[4]
    assert tuple(options["udp_ports"]) == nemla.UDP_PORTS
    assert app.parse_scan({**GOOD, "udp_ports": "53,123"})[4]["udp_ports"] == (53, 123)
    assert app.parse_scan(GOOD)[4]["udp_ports"] == ()


def test_ipv6_targets_are_accepted_by_the_api(ui):
    app, _ = ui
    _target, _lang, ips, _ports, _options = app.parse_scan({**GOOD, "target": "::1"})
    assert list(ips) == ["::1"]


# --------------------------------------------------------------------------
# path safety
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/../nemla.py", "/..%2f..%2fnemla.py", "/%2e%2e/%2e%2e/nemla.py", "/..\\..\\nemla.py",
                                  "/web/../../nemla.py", "/%00", "//etc/passwd", "/index.html%00.txt", "/../../../../etc/hosts",
                                  "/app.js/../../server.py"])
def test_static_files_cannot_leave_the_web_folder(ui, path):
    _app, port = ui
    status, _, data = call(port, path)
    assert status == 404 and b"import" not in data and b"root:" not in data


def test_static_serving_still_works(ui):
    _app, port = ui
    for path, ctype in (("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css"),
                        ("/brand/nemla-mark.svg", "image/svg+xml")):
        status, res, data = call(port, path)
        assert status == 200 and res.getheader("Content-Type").startswith(ctype) and data


@pytest.mark.parametrize("bad", ["../../secret", "..", "%2e%2e%2fsecret", "", "x" * 300, "a b", "C:\\x", "20250101-101010-../x"])
def test_history_routes_refuse_ids_that_are_not_ids(ui, bad):
    app, port = ui
    for route in ("history/scan?id=", "history/report?id=", "history/diff?a=", "history/diff?b="):
        status, _, _ = call(port, f"/api/{route}{quote(bad, safe='')}", token=app.token)
        assert status == 404


def test_history_routes_return_saved_scans_in_every_report_format(ui):
    app, port = ui
    hosts = [{"ip": "10.0.0.5", "mac": None, "os_guess": "Linux", "ttl": 64, "open_ports": [], "findings": []}]
    meta = {"target": "10.0.0.0/24", "scan_time": "now", "duration": 1.0, "ports_scanned": 1, "findings": {}}
    a = history.save(app.data_dir, nemla, meta, hosts)
    b = history.save(app.data_dir, nemla, meta, [*hosts, {**hosts[0], "ip": "10.0.0.6"}])
    assert [s["id"] for s in json.loads(call(port, "/api/history", token=app.token)[2])["scans"]] == [b, a]
    assert json.loads(call(port, f"/api/history/scan?id={a}", token=app.token)[2])["hosts"][0]["ip"] == "10.0.0.5"
    diff = json.loads(call(port, f"/api/history/diff?a={a}&b={b}", token=app.token)[2])
    assert diff["new_hosts"] == ["10.0.0.6"] and diff["against"]["id"] == a
    for fmt, needle in (("html", b"<!DOCTYPE"), ("json", b"schema_version"), ("csv", b"ip,mac"), ("md", b"# "), ("sarif", b"sarif")):
        status, res, data = call(port, f"/api/history/report?id={a}&fmt={fmt}&lang=ar", token=app.token)
        assert status == 200 and needle in data and "attachment" in res.getheader("Content-Disposition")
    assert call(port, f"/api/history/scan?id={uuid.uuid4()}", token=app.token)[0] == 404


def test_report_download_names_are_safe(ui, tcp_server):
    app, port = ui
    served = tcp_server(lambda c: c.close())
    status, _, data = call(port, "/api/scan", "POST", token=app.token, body={**GOOD, "ports": str(served), "timeout": 1})
    job = json.loads(data)["job"]
    deadline = time.monotonic() + 8
    while app.running() and time.monotonic() < deadline:
        time.sleep(0.05)
    for fmt in ("html", "json", "csv", "md", "sarif", "../../x", ""):
        status, res, body = call(port, f"/api/report?job={job}&fmt={fmt}", token=app.token)
        assert status == 200 and body
        disposition = res.getheader("Content-Disposition")
        assert "/" not in disposition.split("filename=")[1] and ".." not in disposition and "\\" not in disposition
    assert call(port, f"/api/report?job={job}x", token=app.token)[0] == 404


# --------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------

def test_internal_errors_never_leak_a_traceback(ui, monkeypatch):
    app, port = ui
    monkeypatch.setattr(app, "info", lambda: 1 / 0)
    status, _, data = call(port, "/api/info", token=app.token)
    assert status == 500 and json.loads(data) == {"error": "internal error"}


def test_unknown_routes_and_methods(ui):
    app, port = ui
    assert call(port, "/api/nothing", token=app.token)[0] == 404
    assert call(port, "/api/info", "POST", token=app.token)[0] == 404
    assert call(port, "/", "POST")[0] == 405
    assert call(port, "/api/scan", "PUT", token=app.token)[0] in (404, 501)


def test_event_streams_are_limited(ui, monkeypatch):
    app, port = ui
    monkeypatch.setattr(server, "MAX_STREAMS", 2)
    socks = []
    try:
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(f"GET /api/guard/events?k={app.token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            socks.append(s)
        deadline = time.monotonic() + 3
        while app.sse_clients < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert app.sse_clients == 2
        assert call(port, "/api/guard/events", token=app.token)[0] == 429
    finally:
        for s in socks:
            s.close()


def test_job_event_log_is_capped_but_keeps_the_essentials(monkeypatch):
    monkeypatch.setattr(server, "MAX_EVENTS", 50)
    job = server.Job("j", "t", "en")
    for i in range(500):
        job.emit({"type": "log", "msg": str(i)})
        job.emit({"type": "progress", "done": i})
    job.emit({"type": "port", "port": 1})
    job.emit({"type": "done"})
    assert len(job.events) <= 53 and job.events[-1]["type"] == "done" and job.events[-2]["type"] == "port"


def test_the_stream_counter_is_thread_safe():
    app = server.App(nemla)
    barrier = threading.Barrier(8)
    opened = []

    def grab():
        barrier.wait()
        for _ in range(50):
            if app.stream_opened():
                opened.append(1)
                app.stream_closed()

    threads = [threading.Thread(target=grab) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert app.sse_clients == 0 and len(opened) == 400


def test_bounded_server_drops_connections_beyond_the_ceiling(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "MAX_CONNECTIONS", 2)
    app = server.App(nemla, data_dir=tmp_path)
    httpd = server.BoundedServer(("127.0.0.1", 0), server.make_handler(app))
    port = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{port}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    idle = []
    try:
        for _ in range(2):                                    # two silent connections hold both slots
            idle.append(socket.create_connection(("127.0.0.1", port), timeout=5))
        time.sleep(0.3)
        third = socket.create_connection(("127.0.0.1", port), timeout=5)
        third.sendall(b"GET / HTTP/1.0\r\n\r\n")
        third.settimeout(3)
        try:
            answer = third.recv(100)
        except OSError:                                       # Windows reports the close as an abort
            answer = b""
        assert answer == b""                                  # dropped without an answer
        third.close()
    finally:
        for s in idle:
            s.close()
        httpd.shutdown()
        httpd.server_close()


def test_no_second_server_can_share_the_ui_port(tmp_path):
    """On Windows SO_REUSEADDR would let another process bind the same port and receive our connections."""
    app = server.App(nemla, data_dir=tmp_path)
    first = server.BoundedServer(("127.0.0.1", 0), server.make_handler(app))
    port = first.server_address[1]
    try:
        with pytest.raises(OSError):
            server.BoundedServer(("127.0.0.1", port), server.make_handler(app)).server_close()
    finally:
        first.server_close()
    # once the first one is gone the port can be used again (a restart must not wait for TIME_WAIT)
    again = server.BoundedServer(("127.0.0.1", port), server.make_handler(app))
    again.server_close()


def test_window_and_ui_settings(ui):
    app, port = ui
    info = json.loads(call(port, "/api/info", token=app.token)[2])
    assert info["version"] == nemla.__version__ and "sarif" in info["formats"] and info["udp_ports"]


# --------------------------------------------------------------------------
# hostile input the routes above did not already cover
# --------------------------------------------------------------------------

def test_a_content_length_that_is_not_a_number_is_treated_as_no_body(ui):
    app, port = ui
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("POST", "/api/scan")
    conn.putheader("X-Nemla-Token", app.token)
    conn.putheader("Content-Length", "not-a-number")
    conn.endheaders()
    res = conn.getresponse()
    body = json.loads(res.read())
    conn.close()
    # a bad Content-Length is read as no body at all: an empty {} reaches parse_scan and fails on
    # missing consent, the ordinary validation error - not a 500 and not a hang on the malformed header
    assert res.status == 403 and "confirm" in body["error"]


def test_events_for_a_job_that_is_not_the_current_one_is_no_such_scan(ui):
    app, port = ui
    assert call(port, "/api/events?job=not-the-real-job-id", token=app.token)[0] == 404


def test_a_non_numeric_last_event_id_on_guard_events_is_treated_as_the_start(ui):
    app, port = ui
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.putrequest("GET", f"/api/guard/events?k={app.token}")
    conn.putheader("Last-Event-ID", "not-a-number")
    conn.endheaders()
    res = conn.getresponse()
    assert res.status == 200          # accepted as a stream, not a 500 on the malformed header
    conn.close()


def test_a_non_numeric_last_event_id_on_the_job_stream_is_treated_as_the_start(ui, tcp_server):
    app, port = ui
    greeter = tcp_server(lambda conn: (conn.sendall(b"SSH-2.0-NemlaLab\r\n"), conn.close()))
    body = {"target": "127.0.0.1", "profile": "custom", "ports": str(greeter), "no_ping": True,
            "no_os": True, "authorized": True}
    status, _, data = call(port, "/api/scan", "POST", app.token, body)
    assert status == 200
    job = json.loads(data)["job"]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("GET", f"/api/events?job={job}&k={app.token}")
    conn.putheader("Last-Event-ID", "not-a-number")
    conn.endheaders()
    res = conn.getresponse()
    raw = res.read()          # replays from the start rather than crashing; the scan is short-lived, so this returns
    conn.close()
    assert res.status == 200 and b"data: " in raw


# --------------------------------------------------------------------------
# BoundedServer: the connection slot is released even when a request crashes
# --------------------------------------------------------------------------

def test_a_crashing_request_still_releases_its_connection_slot(tmp_path, monkeypatch):
    """socketserver swallows an exception from process_request itself (its own handle_error, printed to stderr) -
    a live socket cannot observe that from the client side. Call it directly instead."""
    app = server.App(nemla, data_dir=tmp_path)
    httpd = server.BoundedServer(("127.0.0.1", 0), server.make_handler(app))
    try:
        def boom(self, request, client_address):
            raise RuntimeError("simulated failure inside the real handler")
        monkeypatch.setattr(server.ThreadingHTTPServer, "process_request", boom)
        with pytest.raises(RuntimeError):
            httpd.process_request(object(), ("127.0.0.1", 1))
        # the slot the failed attempt held was released, not leaked
        assert httpd._slots.acquire(blocking=False) is True
        httpd._slots.release()
    finally:
        httpd.server_close()


# --------------------------------------------------------------------------
# opening a window: platform branches, no real browser or display needed
# --------------------------------------------------------------------------

def test_has_display_follows_the_environment_on_linux(monkeypatch):
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert server.has_display() is False
    monkeypatch.setenv("DISPLAY", ":0")
    assert server.has_display() is True


def test_has_display_is_always_true_off_linux(monkeypatch):
    monkeypatch.setattr(server.sys, "platform", "win32")
    monkeypatch.delenv("DISPLAY", raising=False)
    assert server.has_display() is True


def test_open_ui_window_does_nothing_without_a_display(monkeypatch):
    monkeypatch.setattr(server, "has_display", lambda: False)
    assert server.open_ui_window("http://127.0.0.1:1/") is False


def test_open_ui_window_prefers_a_chromium_app_window_on_linux(monkeypatch):
    monkeypatch.setattr(server, "has_display", lambda: True)
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.setattr(server, "app_window_command", lambda url: ["chromium", f"--app={url}"])
    started = []
    monkeypatch.setattr(server.subprocess, "Popen", lambda cmd, **kw: started.append(cmd))
    assert server.open_ui_window("http://127.0.0.1:1/") is True
    assert started == [["chromium", "--app=http://127.0.0.1:1/"]]


def test_open_ui_window_falls_back_to_the_default_browser_when_the_app_window_fails(monkeypatch):
    monkeypatch.setattr(server, "has_display", lambda: True)
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.setattr(server, "app_window_command", lambda url: ["chromium", f"--app={url}"])

    def refuses(cmd, **kw):
        raise OSError("no such file")
    monkeypatch.setattr(server.subprocess, "Popen", refuses)
    monkeypatch.setattr(server.webbrowser, "open", lambda url: True)
    assert server.open_ui_window("http://127.0.0.1:1/") is True


def test_open_ui_window_uses_the_default_browser_off_linux(monkeypatch):
    monkeypatch.setattr(server, "has_display", lambda: True)
    monkeypatch.setattr(server.sys, "platform", "win32")
    opened = []
    monkeypatch.setattr(server.webbrowser, "open", lambda url: opened.append(url) or True)
    assert server.open_ui_window("http://127.0.0.1:1/") is True and opened == ["http://127.0.0.1:1/"]


def test_open_ui_window_is_false_when_no_browser_can_be_reached(monkeypatch):
    monkeypatch.setattr(server, "has_display", lambda: True)
    monkeypatch.setattr(server.sys, "platform", "win32")

    def no_browser(url):
        raise server.webbrowser.Error("no browser")
    monkeypatch.setattr(server.webbrowser, "open", no_browser)
    assert server.open_ui_window("http://127.0.0.1:1/") is False


# --------------------------------------------------------------------------
# serve(): the real entry point (every other test here bypasses it)
# --------------------------------------------------------------------------

def test_serve_refuses_a_port_already_in_use(tmp_path):
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    port = taken.getsockname()[1]
    try:
        assert server.serve(nemla, port=port, open_window=False) == 1
    finally:
        taken.close()


def test_serve_runs_until_ctrl_c_and_cleans_up(monkeypatch, tmp_path):
    """open_window=False so this never touches a real browser; Ctrl+C is simulated so the test does not block."""
    monkeypatch.setattr(server.BoundedServer, "serve_forever", lambda self, poll_interval=0.25: (_ for _ in ()).throw(KeyboardInterrupt))
    logged = []
    monkeypatch.setattr(nemla, "log", logged.append)
    code = server.serve(nemla, port=0, open_window=False, keep_alive=True)
    assert code == 0
    assert any("Nemla 3D interface: http://127.0.0.1:" in line for line in logged)

# --------------------------------------------------------------------------
# request handling edges
# --------------------------------------------------------------------------

def test_head_requests_get_the_headers_of_a_page(ui):
    _app, port = ui
    status, res, data = call(port, "/", "HEAD")
    assert status == 200 and data == b"" and res.getheader("Content-Security-Policy")


def test_a_path_with_a_null_byte_is_a_clean_404(ui):
    _app, port = ui
    assert call(port, "/%00")[0] == 404


def test_a_path_the_file_system_cannot_resolve_is_a_clean_404(ui, monkeypatch):
    class Unresolvable:
        def __truediv__(self, other):
            return self

        def resolve(self):
            raise OSError("cannot resolve this path")

    monkeypatch.setattr(server, "WEB_DIR", Unresolvable())
    _app, port = ui
    assert call(port, "/anything.html")[0] == 404


def test_the_window_saying_goodbye_is_remembered(ui):
    app, port = ui
    assert call(port, "/api/bye", "POST", token=app.token, body={})[0] == 200 and app.bye_at is not None


def test_a_client_that_vanishes_mid_request_gets_no_answer_and_costs_nothing(ui, monkeypatch):
    app, port = ui

    def gone():
        raise ConnectionResetError("the browser went away")
    monkeypatch.setattr(app, "info", gone)
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
        call(port, "/api/info", token=app.token)


def test_a_request_error_with_its_own_status_is_answered_with_that_status(ui, monkeypatch):
    app, port = ui

    def refuses():
        raise server.ScanRequestError("no coffee here", 418)
    monkeypatch.setattr(app, "info", refuses)
    status, _, data = call(port, "/api/info", token=app.token)
    assert status == 418 and json.loads(data) == {"error": "no coffee here"}


def test_a_crash_that_cannot_even_be_reported_is_swallowed(ui, monkeypatch):
    """The handler fails, then the 500 it tries to send fails too (the client is gone): nothing may escape."""
    app, port = ui

    def crashes():
        raise RuntimeError("boom")
    monkeypatch.setattr(app, "info", crashes)
    real_dumps = json.dumps

    def dumps(obj, *args, **kwargs):
        if obj == {"error": "internal error"}:
            raise OSError("the client vanished")
        return real_dumps(obj, *args, **kwargs)
    monkeypatch.setattr(server.json, "dumps", dumps)
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
        call(port, "/api/info", token=app.token)


def test_too_many_open_streams_are_refused_with_429(ui):
    app, port = ui
    app.job = server.Job("j1", "10.0.0.5", "en")
    app.sse_clients = server.MAX_STREAMS
    assert call(port, "/api/events?job=j1", token=app.token)[0] == 429


class _QuickCondition:
    """A Job.cond whose wait returns at once, so the keep-alive branch of the event stream is reached without
    the real ten second wait."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def wait(self, timeout=None):
        time.sleep(0.02)

    def notify_all(self):
        pass


def test_a_quiet_event_stream_sends_keep_alive_pings_and_frees_its_slot_when_the_client_leaves(ui):
    app, port = ui
    job = server.Job("j2", "10.0.0.5", "en")
    job.cond = _QuickCondition()
    app.job = job
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        client.sendall(f"GET /api/events?job=j2 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                       f"X-Nemla-Token: {app.token}\r\n\r\n".encode())
        data = b""
        while b": ping" not in data:
            chunk = client.recv(4096)
            assert chunk
            data += chunk
    assert wait_until(lambda: app.sse_clients == 0, timeout=8)     # the write to the vanished client failed, quietly


def test_a_body_the_client_stops_sending_is_not_waited_for(ui):
    """The 413 is answered first; if the client then closes its side without sending the rest, the discard ends."""
    app, port = ui
    with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
        client.sendall(f"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Nemla-Token: {app.token}\r\n"
                       f"Content-Type: application/json\r\nContent-Length: 500000\r\n\r\n".encode() + b"x" * 1000)
        assert client.recv(4096).startswith((b"HTTP/1.0 413", b"HTTP/1.1 413"))
        client.shutdown(socket.SHUT_WR)
        started = time.monotonic()
        while client.recv(4096):
            pass
        assert time.monotonic() - started < 1.5                     # closed on the end of the stream, not the 2 s limit


# --------------------------------------------------------------------------
# the application object: scan lifecycle and guard control
# --------------------------------------------------------------------------

def test_a_boolean_is_not_a_number():
    with pytest.raises(ValueError):
        server._number({"threads": True}, "threads", 150, 1, 500, int)


@pytest.mark.parametrize("profile, count", [("standard", 1024), ("deep", 10000), ("quick", len(nemla.TOP_PORTS)),
                                            ("something-else", len(nemla.TOP_PORTS))])
def test_every_scan_profile_picks_its_ports(tmp_path, profile, count):
    app = server.App(nemla, data_dir=tmp_path)
    ports = app.parse_scan({"target": "127.0.0.1", "profile": profile, "authorized": True})[3]
    assert len(ports) == count


def test_two_scans_started_at_the_same_moment_cannot_both_run(tmp_path, monkeypatch):
    app = server.App(nemla, data_dir=tmp_path)
    answers = iter([False, True])                       # nothing running at the first look, a scan by the second
    monkeypatch.setattr(app, "running", lambda: next(answers))
    with pytest.raises(server.ScanRequestError) as caught:
        app.start_scan(GOOD)
    assert caught.value.status == 409 and app.job is None


def test_a_scan_that_crashes_reports_an_error_event_and_ends(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(nemla, "run_scan", boom)
    app = server.App(nemla, data_dir=tmp_path)
    job = app.start_scan(GOOD)
    assert wait_until(lambda: job.closed, timeout=10)
    assert job.events[-1] == {"type": "error", "msg": "RuntimeError: boom"}


def test_remembering_a_scan_that_never_produced_results_does_nothing(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    done = {}
    app._remember(server.Job("x", "10.0.0.5", "en"), done)
    assert done == {}


def test_a_history_that_cannot_be_saved_is_reported_but_never_loses_the_scan(tmp_path, monkeypatch):
    def full_disk(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(server.history_mod, "save", full_disk)
    app = server.App(nemla, data_dir=tmp_path)
    job = server.Job("x", "10.0.0.5", "en")
    job.meta, job.hosts = {"cancelled": False, "discovered": 1}, []
    done = {"type": "done"}
    app._remember(job, done)
    assert done["history_error"] == "disk full" and "scan_id" not in done


def test_starting_the_guard_while_it_runs_returns_the_running_one(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    app.guard = types.SimpleNamespace(running=True, status=lambda: {"running": True, "decoys": [2222]})
    assert app.start_guard({}) == {"running": True, "decoys": [2222]}


def test_a_guard_interval_that_is_not_a_number_is_refused(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    with pytest.raises(server.ScanRequestError):
        app.start_guard({"interval": "nan"})


def test_stopping_a_guard_that_was_never_started_says_it_is_not_running(tmp_path):
    assert server.App(nemla, data_dir=tmp_path).stop_guard() == {"running": False}


def test_a_report_of_an_unfinished_scan_is_a_conflict(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    with pytest.raises(server.ScanRequestError) as caught:
        app.report(server.Job("x", "10.0.0.5", "en"), "html", "en")
    assert caught.value.status == 409


# --------------------------------------------------------------------------
# watching the window, and serve() around it
# --------------------------------------------------------------------------

class _Ticks:
    """app.finished stand-in: wait() says "not finished" a fixed number of times, then "finished"."""

    def __init__(self, ticks):
        self.ticks = ticks

    def wait(self, seconds):
        self.ticks -= 1
        return self.ticks < 0


def test_the_watcher_quits_and_stops_the_scan_when_the_window_shows_no_sign_of_life(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    app.finished = _Ticks(5)
    app.last_seen = time.monotonic() - server.IDLE_LIMIT - 1
    app.job = types.SimpleNamespace(cancel=threading.Event())
    stopped = []
    server._watch(app, types.SimpleNamespace(shutdown=lambda: stopped.append(True)))
    assert stopped == [True] and app.job.cancel.is_set()


def test_the_watcher_quits_once_the_window_said_goodbye_and_the_grace_period_passed(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    app.finished = _Ticks(5)
    app.bye_at = time.monotonic() - server.IDLE_GRACE - 1
    stopped = []
    server._watch(app, types.SimpleNamespace(shutdown=lambda: stopped.append(True)))
    assert stopped == [True]


def test_the_watcher_never_quits_while_an_event_stream_is_open(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    app.finished = _Ticks(3)
    app.sse_clients = 1
    app.last_seen = time.monotonic() - server.IDLE_LIMIT - 1
    stopped = []
    server._watch(app, types.SimpleNamespace(shutdown=lambda: stopped.append(True)))
    assert stopped == []


def test_serve_as_root_on_linux_asks_the_user_to_open_the_address_themselves(monkeypatch):
    monkeypatch.setattr(server.BoundedServer, "serve_forever", lambda self, poll_interval=0.25: (_ for _ in ()).throw(KeyboardInterrupt))
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.setattr(server, "is_root", lambda: True)
    opened, logged = [], []
    monkeypatch.setattr(server, "open_ui_window", lambda url: opened.append(url) or True)
    monkeypatch.setattr(nemla, "log", logged.append)
    assert server.serve(nemla, port=0, open_window=True) == 0
    assert opened == [] and any("Running as root" in line for line in logged)


def test_serve_watches_the_window_it_opened_and_cleans_up_a_running_scan_and_guard(monkeypatch, tmp_path):
    job = types.SimpleNamespace(cancel=threading.Event())
    stops = []
    guard = types.SimpleNamespace(stop=lambda: stops.append(True))

    class Preloaded(server.App):
        def __init__(self, engine, lang=None):
            super().__init__(engine, lang, data_dir=tmp_path)
            self.job, self.guard = job, guard

    watched = []
    monkeypatch.setattr(server, "App", Preloaded)
    monkeypatch.setattr(server, "open_ui_window", lambda url: True)
    monkeypatch.setattr(server, "_watch", lambda app, httpd: watched.append(app.auto_exit))
    monkeypatch.setattr(server.BoundedServer, "serve_forever", lambda self, poll_interval=0.25: (_ for _ in ()).throw(KeyboardInterrupt))
    logged = []
    monkeypatch.setattr(nemla, "log", logged.append)
    assert server.serve(nemla, port=0, open_window=True, keep_alive=False) == 0
    assert wait_until(lambda: watched == [True]) and any("Close the Nemla window" in line for line in logged)
    assert job.cancel.is_set() and stops == [True]
