"""The local web server: authentication, origin checks, limits, path safety, new API routes."""
import http.client
import json
import socket
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from urllib.parse import quote

import pytest

import nemla
from nemla import history
from nemla_ui import server


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
    app, port = ui
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
    target, lang, ips, ports, options = app.parse_scan({**GOOD, "target": "::1"})
    assert list(ips) == ["::1"]


# --------------------------------------------------------------------------
# path safety
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/../nemla.py", "/..%2f..%2fnemla.py", "/%2e%2e/%2e%2e/nemla.py", "/..\\..\\nemla.py",
                                  "/web/../../nemla.py", "/%00", "//etc/passwd", "/index.html%00.txt", "/../../../../etc/hosts",
                                  "/app.js/../../server.py"])
def test_static_files_cannot_leave_the_web_folder(ui, path):
    app, port = ui
    status, _, data = call(port, path)
    assert status == 404 and b"import" not in data and b"root:" not in data


def test_static_serving_still_works(ui):
    app, port = ui
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
    b = history.save(app.data_dir, nemla, meta, hosts + [{**hosts[0], "ip": "10.0.0.6"}])
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


def test_window_and_ui_settings(ui):
    app, port = ui
    info = json.loads(call(port, "/api/info", token=app.token)[2])
    assert info["version"] == nemla.__version__ and "sarif" in info["formats"] and info["udp_ports"]
