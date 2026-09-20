import http.client
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import nemla
from nemla_ui import launcher, server


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@pytest.fixture()
def lab_port():
    """A service that greets first, like SSH."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-NemlaLab\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


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


def call(port, path, method="GET", token=None, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    hdrs = dict(headers or {})
    if token:
        hdrs["X-Nemla-Token"] = token
    if host:
        hdrs["Host"] = host
    payload = None
    if body is not None:
        payload = json.dumps(body)
        hdrs["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=hdrs)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res.status, res, data


def run_job(app, port, body):
    status, _, data = call(port, "/api/scan", "POST", app.token, body)
    assert status == 200, data
    job = json.loads(data)["job"]
    # the stream ends by itself once the scan is over
    status, _, raw = call(port, f"/api/events?job={job}&k={app.token}")
    assert status == 200
    events = [json.loads(line[6:]) for line in raw.decode().splitlines() if line.startswith("data: ")]
    return job, events


# --------------------------------------------------------------------------
# the scan pipeline
# --------------------------------------------------------------------------

def test_run_scan_emits_events_and_results(lab_port):
    events = []
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [lab_port], no_ping=True,
                                 no_os=True, emit=events.append)
    kinds = [e["type"] for e in events]
    assert kinds[0] == "phase" and "host" in kinds and "host_start" in kinds
    assert "port" in kinds and kinds[-1] == "host_done"
    assert hosts[0]["open_ports"][0]["port"] == lab_port
    assert "NemlaLab" in hosts[0]["open_ports"][0]["banner"]
    assert meta["discovered"] == 1 and meta["cancelled"] is False


def test_run_scan_cancel_before_start(lab_port):
    cancel = threading.Event()
    cancel.set()
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [lab_port], no_ping=True,
                                 no_os=True, cancel=cancel)
    assert hosts == [] and meta["cancelled"] is True


def test_run_scan_cancel_between_hosts(lab_port):
    cancel = threading.Event()

    def emit(event):
        if event["type"] == "host_done":
            cancel.set()

    hosts, meta = nemla.run_scan("127.0.0.1-2", ["127.0.0.1", "127.0.0.2"], [lab_port],
                                 no_ping=True, no_os=True, emit=emit, cancel=cancel)
    assert [h["ip"] for h in hosts] == ["127.0.0.1"]
    assert meta["cancelled"] is True


def test_pool_map_stops_when_cancelled():
    cancel = threading.Event()
    threading.Timer(0.15, cancel.set).start()
    started = time.time()
    results = list(nemla._pool_map(lambda n: time.sleep(0.3) or n, range(40), 2, cancel))
    assert len(results) < 40
    assert time.time() - started < 3


def test_html_report_is_single_pass():
    meta = {"target": "@@FOOTER@@", "scan_time": "now", "duration": 1.0, "ports_scanned": 1}
    page = nemla.render_html(meta, [])
    assert "@@FOOTER@@" in page  # the scanned text stays literal
    assert page.count("responsible use only") == 1
    assert "<svg" in page


# --------------------------------------------------------------------------
# the interface server
# --------------------------------------------------------------------------

def test_index_is_served_with_security_headers(ui):
    app, port = ui
    status, res, body = call(port, "/")
    assert status == 200 and b"<canvas" in body
    assert "script-src 'self'" in res.getheader("Content-Security-Policy")
    assert res.getheader("X-Frame-Options") == "DENY"
    for asset in ("/style.css", "/app.js", "/scene.js", "/i18n.js", "/demo.js",
                  "/brand/nemla-mark.svg", "/brand/nemla-logo.svg", "/brand/nemla-icon.svg"):
        assert call(port, asset)[0] == 200, asset


@pytest.mark.parametrize("path", ["/../nemla.py", "/%2e%2e/nemla.py", "/..%2fnemla.py",
                                  "/brand/../../nemla.py", "/nope.txt"])
def test_static_path_traversal_is_blocked(ui, path):
    _, port = ui
    assert call(port, path)[0] == 404


def test_api_needs_the_token(ui):
    app, port = ui
    assert call(port, "/api/info")[0] == 401
    assert call(port, "/api/info", token="wrong")[0] == 401
    assert call(port, f"/api/info?k={app.token}")[0] == 200
    status, _, data = call(port, "/api/info", token=app.token)
    info = json.loads(data)
    assert status == 200 and info["version"] == nemla.__version__
    assert info["top_ports"] == len(nemla.TOP_PORTS)


def test_foreign_host_and_origin_are_rejected(ui):
    app, port = ui
    assert call(port, "/", host="evil.example:80")[0] == 403
    assert call(port, "/api/info", token=app.token, host="evil.example")[0] == 403
    status, _, _ = call(port, "/api/hb", "POST", app.token, headers={"Origin": "http://evil.example"})
    assert status == 403
    status, _, _ = call(port, "/api/hb", "POST", app.token,
                        headers={"Origin": f"http://127.0.0.1:{port}"})
    assert status == 200


def test_scan_validation(ui):
    app, port = ui
    good = {"target": "127.0.0.1", "profile": "custom", "ports": "80", "authorized": True}
    assert call(port, "/api/scan", "POST", app.token, {**good, "authorized": False})[0] == 403
    assert call(port, "/api/scan", "POST", app.token, {**good, "target": ""})[0] == 400
    assert call(port, "/api/scan", "POST", app.token, {**good, "target": "::1"})[0] == 400
    assert call(port, "/api/scan", "POST", app.token, {**good, "target": "10.0.0.0/8"})[0] == 400
    assert call(port, "/api/scan", "POST", app.token, {**good, "ports": "abc"})[0] == 400
    assert call(port, "/api/scan", "POST", app.token, {**good, "threads": "many"})[0] == 400
    status, _, data = call(port, "/api/scan", "POST", app.token, {**good, "lang": "ar", "target": "10.0.0.0/8"})
    assert "max-hosts" in json.loads(data)["error"]


def test_full_scan_over_the_api_and_reports(ui, lab_port):
    app, port = ui
    body = {"target": "127.0.0.1", "profile": "custom", "ports": str(lab_port), "no_ping": True,
            "no_os": True, "authorized": True, "lang": "en"}
    job, events = run_job(app, port, body)
    kinds = [e["type"] for e in events]
    assert kinds[0] == "start" and kinds[-1] == "done"
    assert {"phase", "host", "host_start", "port", "host_done", "log"} <= set(kinds)
    done = events[-1]
    assert done["hosts"][0]["open_ports"][0]["port"] == lab_port
    assert done["meta"]["cancelled"] is False

    status, res, data = call(port, f"/api/report?job={job}&fmt=html&lang=ar&k={app.token}")
    assert status == 200 and b'dir="rtl"' in data and str(lab_port).encode() in data
    assert "attachment" in res.getheader("Content-Disposition")
    status, _, data = call(port, f"/api/report?job={job}&fmt=json&k={app.token}")
    assert json.loads(data)["hosts"][0]["open_ports"][0]["port"] == lab_port
    status, _, data = call(port, f"/api/report?job={job}&fmt=csv&k={app.token}")
    assert str(lab_port) in data.decode("utf-8-sig")
    assert call(port, f"/api/report?job=nope&fmt=html&k={app.token}")[0] == 404
    assert call(port, "/api/info", token=app.token)[0] == 200
    assert json.loads(call(port, "/api/info", token=app.token)[2])["job"]["finished"] is True


def test_event_stream_can_be_resumed(ui, lab_port):
    app, port = ui
    body = {"target": "127.0.0.1", "profile": "custom", "ports": str(lab_port), "no_ping": True,
            "no_os": True, "authorized": True}
    job, events = run_job(app, port, body)
    status, _, raw = call(port, f"/api/events?job={job}&k={app.token}", headers={"Last-Event-ID": "3"})
    resumed = [line for line in raw.decode().splitlines() if line.startswith("data: ")]
    assert len(resumed) == len(events) - 3


def test_second_scan_is_refused_while_one_runs(ui):
    app, port = ui
    job = server.Job("busy", "x", "en")
    app.job = job  # a job that never closes
    body = {"target": "127.0.0.1", "profile": "quick", "authorized": True}
    assert call(port, "/api/scan", "POST", app.token, body)[0] == 409
    assert call(port, "/api/stop", "POST", app.token)[0] == 200
    assert job.cancel.is_set()
    job.close()


def test_local_network_hint_shape():
    ip, target = server.local_network_hint()
    assert ip.count(".") == 3
    assert target == "127.0.0.1" or target.endswith(".0/24")


def test_app_window_prefers_chromium_family():
    fake = {"chromium": "/usr/bin/chromium"}.get
    cmd = server.app_window_command("http://127.0.0.1:1/#k=x", which=fake)
    assert cmd[0] == "/usr/bin/chromium" and "--app=http://127.0.0.1:1/#k=x" in cmd
    assert server.app_window_command("http://x", which=lambda name: None) is None


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

def test_no_arguments_opens_the_ui(monkeypatch):
    import nemla_ui
    seen = {}
    monkeypatch.setattr(nemla_ui, "serve", lambda engine, **kw: seen.update(kw) or 0)
    assert nemla.main([]) == 0
    assert seen["open_window"] is True and seen["keep_alive"] is False
    seen.clear()
    assert nemla.main(["--ui", "--no-browser", "--ui-port", "4242", "--keep-alive"]) == 0
    assert seen == {"port": 4242, "open_window": False, "keep_alive": True, "lang": None}


def test_target_is_still_required_for_cli_scans(capsys):
    with pytest.raises(SystemExit) as exc:
        nemla.main(["-o", "x.html"])
    assert exc.value.code == 2


def test_banner_has_the_logo_and_respects_color():
    plain = nemla.banner_text(color=False)
    assert all(row in plain for row in nemla.LOGO_LINES)
    assert "\x1b[" not in plain and nemla.__version__ in plain
    colored = nemla.banner_text(color=True)
    assert "\x1b[38;2;255;196;107m" in colored
    assert colored.count("\x1b[0m") >= len(nemla.LOGO_LINES)


def test_fancy_banner_only_on_utf8_terminals(monkeypatch):
    class Stream:
        encoding = "utf-8"
        tty = True

        def isatty(self):
            return self.tty

    stream = Stream()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert nemla.fancy_output_ok() is True
    stream.encoding = "cp1252"
    assert nemla.fancy_output_ok() is False
    stream.encoding, stream.tty = "utf-8", False
    assert nemla.fancy_output_ok() is False


# --------------------------------------------------------------------------
# Linux launcher
# --------------------------------------------------------------------------

def test_desktop_entry_quotes_paths_with_spaces():
    entry = launcher.desktop_entry(["/usr/bin/python3", "/home/me/my tools/nemla.py", "--ui"])
    assert 'Exec=/usr/bin/python3 "/home/me/my tools/nemla.py" --ui' in entry
    assert "Icon=nemla" in entry and "Terminal=false" in entry
    assert "Name[ar]=نملة" in entry and "Name[he]=נמלה" in entry
    assert "Categories=Network;Security;" in entry
    assert launcher._quote('a"b$c%') == '"a\\"b\\$c%%"'


def test_install_and_uninstall_launcher(tmp_path):
    data, bin_dir = tmp_path / "share", tmp_path / "bin"
    script = launcher.SCRIPT
    assert launcher.install(data, bin_dir, python="/usr/bin/python3", script=script) == 0

    entry = (data / "applications" / "nemla.desktop").read_text(encoding="utf-8")
    assert "--ui" in entry and launcher._quote(str(script)) in entry
    assert (data / "icons" / "hicolor" / "scalable" / "apps" / "nemla.svg").read_text().startswith("<svg")
    wrapper = bin_dir / "nemla"
    assert wrapper.read_text().startswith("#!/bin/sh") and "exec" in wrapper.read_text()

    assert launcher.uninstall(data, bin_dir) == 0
    assert not (data / "applications" / "nemla.desktop").exists()
    assert not wrapper.exists()


def test_install_keeps_a_foreign_nemla_command(tmp_path):
    data, bin_dir = tmp_path / "share", tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "nemla").write_text("#!/bin/sh\necho pip-installed\n")
    assert launcher.install(data, bin_dir, python="python3", script=launcher.SCRIPT) == 0
    assert "pip-installed" in (bin_dir / "nemla").read_text()
    launcher.uninstall(data, bin_dir)
    assert (bin_dir / "nemla").exists()
