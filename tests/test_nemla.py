import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import nemla


# --------------------------------------------------------------------------
# helpers: tiny local servers so tests never touch a real network
# --------------------------------------------------------------------------

class _Quiet(BaseHTTPRequestHandler):
    server_version = "NemlaTest/1.0"

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def http_port():
    srv = HTTPServer(("127.0.0.1", 0), _Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def banner_port():
    """A server that greets first, like SSH/FTP/SMTP, with a hostile banner."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-<script>alert(1)</script>\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def test_parse_ports():
    assert nemla.parse_ports("22") == [22]
    assert nemla.parse_ports("80, 22,443") == [22, 80, 443]
    assert nemla.parse_ports("1-3,10") == [1, 2, 3, 10]


@pytest.mark.parametrize("bad", ["", "abc", "0", "70000", "10-5", "1-99999"])
def test_parse_ports_invalid(bad):
    with pytest.raises(ValueError):
        nemla.parse_ports(bad)


def test_parse_targets_forms():
    assert nemla.parse_targets("10.0.0.5") == ["10.0.0.5"]
    assert nemla.parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert nemla.parse_targets("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert nemla.parse_targets("10.0.0.254-10.0.1.1") == [
        "10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]
    assert nemla.parse_targets("10.0.0.7/32") == ["10.0.0.7"]


def test_parse_targets_limits_and_errors():
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.0/16", max_hosts=1024)
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.9-10.0.0.1")
    assert nemla.parse_targets("::1") == ["::1"]          # IPv6 is supported now
    with pytest.raises(ValueError):
        nemla.parse_targets("10.0.0.1; rm -rf /")


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------

def test_scan_open_http_port_gets_banner(http_port):
    res = nemla.scan_port("127.0.0.1", http_port)
    assert res is not None
    assert res["port"] == http_port
    assert res["banner"].startswith("HTTP/")
    assert "NemlaTest" in res["banner"]


def test_scan_closed_port_returns_none():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert nemla.scan_port("127.0.0.1", port, timeout=0.3) is None


def test_tcp_ping_treats_refused_as_alive():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens -> RST -> host is up
    # Windows answers a refused connection only after its SYN retries (about 2 s)
    wait = 3.0 if sys.platform == "win32" else 0.6
    assert nemla.tcp_ping("127.0.0.1", ports=(port,), timeout=wait) is True


# --------------------------------------------------------------------------
# report safety
# --------------------------------------------------------------------------

def test_html_report_escapes_hostile_banner(banner_port):
    res = nemla.scan_port("127.0.0.1", banner_port)
    assert "<script>" in res["banner"]  # the raw banner really is hostile
    host = {"ip": "127.0.0.1", "mac": None, "os_guess": "<b>x</b>",
            "ttl": 64, "open_ports": [res]}
    meta = {"target": "<img src=x>", "scan_time": "now", "duration": 1.0,
            "ports_scanned": 1}
    page = nemla.render_html(meta, [host])
    assert "<script>alert" not in page
    assert "<img src=x>" not in page
    assert "<b>x</b>" not in page
    assert "&lt;script&gt;" in page


def test_report_languages():
    meta = {"target": "t", "scan_time": "now", "duration": 0.1, "ports_scanned": 1}
    nemla._LANG = "ar"
    try:
        page = nemla.render_html(meta, [])
    finally:
        nemla._LANG = "en"
    assert 'dir="rtl"' in page and "تقرير نملة" in page
    assert 'dir="ltr"' in nemla.render_html(meta, [])


# --------------------------------------------------------------------------
# end to end
# --------------------------------------------------------------------------

def test_end_to_end_outputs(http_port, tmp_path, capsys):
    html_p, json_p, csv_p = (tmp_path / n for n in ("r.html", "r.json", "r.csv"))
    code = nemla.main([
        "-t", "127.0.0.1", "-p", str(http_port), "--no-ping", "--no-os",
        "-o", str(html_p), "--json", str(json_p), "--csv", str(csv_p),
    ])
    assert code == 0
    data = json.loads(json_p.read_text(encoding="utf-8"))
    assert data["hosts"][0]["open_ports"][0]["port"] == http_port
    assert html_p.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert str(http_port) in csv_p.read_text(encoding="utf-8")


def test_bad_target_returns_error(capsys):
    assert nemla.main(["-t", "10.0.0.0/8"]) == 1
    assert nemla.main(["-t", "10.0.0.1", "-p", "abc"]) == 1
