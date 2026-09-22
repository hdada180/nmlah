import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import nemla

# A throw-away self-signed EC certificate (valid until 2126) used only by these tests.
TEST_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILL+YxfAXLg507/VZpaqlGQQFV724JvrNHNrO1HhGuFToAoGCCqGSM49
AwEHoUQDQgAEIWh6WpWT8p+DDghqsxqdCsyAbctGRco+zwFrjC9SraOdejJB+W7l
5m5iu+HJHjU9okaayJTpimBAB3n1Vk0QuA==
-----END EC PRIVATE KEY-----
"""
TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIBgjCCASegAwIBAgIUJHuyOKYaH6lqsSellxYtRhZB8/EwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKbmVtbGEudGVzdDAgFw0yNjA5MjAxNjQ1MzJaGA8yMTI2MDgy
NzE2NDUzMlowFTETMBEGA1UEAwwKbmVtbGEudGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABCFoelqVk/Kfgw4IarManQrMgG3LRkXKPs8Ba4wvUq2jnXoyQflu
5eZuYrvhyR41PaJGmsiU6YpgQAd59VZNELijUzBRMB0GA1UdDgQWBBR13YOz85rD
4fFg2vauiJJd/s1FAjAfBgNVHSMEGDAWgBR13YOz85rD4fFg2vauiJJd/s1FAjAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQC8sm8648hVAyA0NaWZ
o9HeEAQIm+ViGEGaoo/s4rjKYAIhALDejVGrtjWM5ukYi5g92oMnwLY4uE92zs9b
jydYgoGp
-----END CERTIFICATE-----
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def start_server(handler):
    """Listen on a free loopback port; run handler(conn) for every connection."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


@pytest.fixture()
def servers():
    made = []

    def make(handler):
        srv = start_server(handler)
        made.append(srv)
        return srv.getsockname()[1]

    yield make
    for srv in made:
        srv.close()


def host_with(ip, *ports):
    return {"ip": ip, "open_ports": [
        {"port": p, "service": nemla.service_name(p), "banner": "", **extra} for p, extra in ports]}


def ids(findings):
    return {(f["id"], f["severity"]) for f in findings}


# --------------------------------------------------------------------------
# banners
# --------------------------------------------------------------------------

@pytest.mark.parametrize("banner, expected", [
    ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", ("OpenSSH", "9.6p1")),
    ("SSH-2.0-dropbear_2022.83", ("Dropbear", "2022.83")),
    ("HTTP/1.1 200 OK | Server: nginx/1.24.0", ("nginx", "1.24.0")),
    ("HTTP/1.1 200 OK | Server: Apache/2.4.58 (Debian)", ("Apache httpd", "2.4.58")),
    ("HTTP/1.1 200 OK | Server: Microsoft-IIS/10.0", ("Microsoft IIS", "10.0")),
    ("220 (vsFTPd 3.0.5)", ("vsftpd", "3.0.5")),
    ("220 mail.lab.local ESMTP Postfix (Ubuntu)", ("Postfix", None)),
    ("RFB 003.008", ("VNC (RFB)", "003.008")),
    ("nothing we know", (None, None)),
])
def test_parse_banner(banner, expected):
    assert nemla.parse_banner(banner) == expected


def test_os_hint_from_banner():
    assert nemla.banner_os_hint("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13") == "Ubuntu Linux"
    assert nemla.banner_os_hint("Server: Microsoft-IIS/10.0") == "Windows"
    assert nemla.banner_os_hint("SSH-2.0-mystery") is None


def test_mysql_and_mariadb_handshakes():
    assert nemla._mysql_product(b"J\x00\x00\x00\n8.0.35-0ubuntu0.22.04.1\x00xx") == ("MySQL", "8.0.35")
    assert nemla._mysql_product(b"J\x00\x00\x00\n5.5.5-10.6.12-MariaDB-1\x00") == ("MariaDB", "10.6.12")
    assert nemla._mysql_product(b"not a handshake") == (None, None)


def test_detection_never_raises_on_garbage():
    assert isinstance(nemla.detect_service("127.0.0.1", 1, b"\xff\xfe\x00", "\x00", 0.2), dict)


# --------------------------------------------------------------------------
# live probes against local throw-away servers
# --------------------------------------------------------------------------

def test_scan_port_identifies_ssh_and_distro(servers):
    def ssh(conn):
        conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        conn.close()

    port = servers(ssh)
    res = nemla.scan_port("127.0.0.1", port)
    assert (res["product"], res["version"], res["os_hint"]) == ("OpenSSH", "9.6p1", "Ubuntu Linux")


def test_scan_port_reads_web_title_and_server(servers):
    class Web(BaseHTTPRequestHandler):
        server_version = "nginx/1.24.0"
        sys_version = ""

        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            body = b"<html><head><title>Nemla  Lab\n Router</title></head></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Web)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = nemla.scan_port("127.0.0.1", srv.server_address[1])
    finally:
        srv.shutdown()
        srv.server_close()
    assert (res["product"], res["version"]) == ("nginx", "1.24.0")
    assert res["title"] == "Nemla Lab Router" and res["status"] == 200


def test_tls_probe_reads_the_certificate(servers, tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text(TEST_CERT)
    key.write_text(TEST_KEY)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))

    def tls(conn):
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.settimeout(2)
                try:
                    s.recv(1024)
                except OSError:
                    pass
                body = b"<title>Secure Lab</title>"
                s.sendall(b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: %d\r\n\r\n%s"
                          % (len(body), body))
        except (OSError, ssl.SSLError):
            pass

    port = servers(tls)
    info, extra = nemla.tls_probe("127.0.0.1", port, http=True)
    assert info["version"].startswith("TLSv1")
    assert info["subject"] == "nemla.test" and info["self_signed"] is True
    assert info["days_left"] > 36000 and info["not_after"] == "2126-08-27"
    assert extra["http"]["title"] == "Secure Lab"

    res = nemla.detect_service("127.0.0.1", port, b"", "", 1.5)  # silent plain banner -> TLS fallback
    assert res["tls"]["subject"] == "nemla.test" and res["product"] == "nginx"


def test_tls_probe_on_a_plain_port_returns_nothing(servers):
    port = servers(lambda conn: (conn.sendall(b"hello\r\n"), conn.close()))
    assert nemla.tls_probe("127.0.0.1", port, timeout=0.5) == (None, {})


def test_tls_probe_reads_the_greeting_on_implicit_tls_mail_ports(monkeypatch, servers, tmp_path):
    """Port 465/993/995 (SMTPS/IMAPS/POP3S) speak in TLS from the first byte, and the mail server greets
    first - unlike the http=True path, this only fires when the *port number itself* says "mail"."""
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text(TEST_CERT)
    key.write_text(TEST_KEY)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))

    def tls_greeting(conn):
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.sendall(b"220 mail.example.com ESMTP ready\r\n")
        except (OSError, ssl.SSLError):
            pass

    real_port = servers(tls_greeting)
    real_probe = nemla.Probe
    # tls_probe() must dial the literal port it was asked about (993) to decide whether to read a
    # greeting, so the real test server has to sit behind a Probe whose connection target is faked
    # to the free port it's actually listening on.
    monkeypatch.setattr(nemla, "Probe", lambda ip, port, timeout: real_probe(ip, real_port, timeout))

    info, extra = nemla.tls_probe("127.0.0.1", 993, timeout=1.0)
    assert info is not None
    assert extra["greeting"] == "220 mail.example.com ESMTP ready"


def test_tls_probe_ignores_a_greeting_connection_that_fails(monkeypatch, servers, tmp_path):
    """tls_probe() makes two connections: inspect_tls's own handshake (must succeed, or there is no info
    to return at all) and a second one just for the greeting. If that second one fails outright - the port
    refused the TLS handshake this time, a transient blip - the greeting is silently left out."""
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text(TEST_CERT)
    key.write_text(TEST_KEY)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    seen = {"n": 0}

    def handler(conn):
        seen["n"] += 1
        if seen["n"] == 1:
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass                     # a normal handshake for inspect_tls's own connection
            except (OSError, ssl.SSLError):
                pass
        else:
            conn.close()                     # refuses the handshake outright for the greeting connection

    real_port = servers(handler)
    real_probe = nemla.Probe
    monkeypatch.setattr(nemla, "Probe", lambda ip, port, timeout: real_probe(ip, real_port, timeout))

    info, extra = nemla.tls_probe("127.0.0.1", 995, timeout=1.0)
    assert info is not None and "greeting" not in extra


def test_redis_probe_reports_auth_state(servers):
    def redis_open(conn):
        data = conn.recv(1024)
        if data.startswith(b"PING"):
            conn.sendall(b"+PONG\r\n")
        elif data.startswith(b"INFO"):
            conn.sendall(b"$40\r\n# Server\r\nredis_version:7.0.11\r\n\r\n")
        conn.close()

    def redis_locked(conn):
        conn.recv(1024)
        conn.sendall(b"-NOAUTH Authentication required.\r\n")
        conn.close()

    res = nemla.detect_service("127.0.0.1", servers(redis_open), b"", "", 1.0)
    assert (res["product"], res["version"], res["auth"]) == ("Redis", "7.0.11", "none")
    assert res["detected"] == "redis" and res["heuristic"] is False and res["confidence"] >= 0.9

    res = nemla.detect_service("127.0.0.1", servers(redis_locked), b"", "", 1.0)
    assert (res["product"], res["auth"]) == ("Redis", "required")


def test_memcached_probe(servers):
    def memcached(conn):
        if conn.recv(64).startswith(b"version"):
            conn.sendall(b"VERSION 1.6.21\r\n")
        conn.close()

    res = nemla.detect_service("127.0.0.1", servers(memcached), b"", "", 1.0)
    assert (res["product"], res["version"], res["auth"]) == ("Memcached", "1.6.21", "none")


def test_postgres_probe(servers):
    def postgres(conn):
        conn.recv(8)
        conn.sendall(b"N")
        conn.close()

    assert nemla.detect_service("127.0.0.1", servers(postgres), b"", "", 1.0)["product"] == "PostgreSQL"


def test_no_banner_skips_all_probes(servers):
    seen = []

    def spy(conn):
        seen.append(1)
        conn.close()

    port = servers(spy)
    res = nemla.scan_port("127.0.0.1", port, grab=False)
    assert {"port", "service", "banner"} <= set(res)
    assert "product" not in res and "tls" not in res
    assert res["heuristic"] is True and res["method"] == "port"   # the service name is only a guess
    assert len(seen) <= 1  # only the connect itself


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------

def test_internal_host_findings():
    host = host_with("192.168.1.10", (23, {}), (21, {}), (3389, {}), (3306, {}), (445, {}), (22, {}))
    assert ids(nemla.assess_host(host)) == {
        ("telnet", "high"), ("ftp", "medium"), ("remote", "medium"), ("db", "medium"), ("files", "low")}


def test_exposure_is_worse_on_the_public_internet():
    host = host_with("8.8.8.8", (21, {}), (3389, {}), (3306, {}), (445, {}))
    assert ids(nemla.assess_host(host)) == {
        ("ftp", "high"), ("remote", "high"), ("db", "high"), ("files", "high")}
    assert nemla._is_external("8.8.8.8") and not nemla._is_external("10.1.2.3")
    assert not nemla._is_external("127.0.0.1") and not nemla._is_external("169.254.1.1")


def test_unauthenticated_services_are_high_everywhere():
    host = host_with("10.0.0.5", (6379, {"auth": "none"}), (11211, {"auth": "none"}),
                     (9200, {"auth": "none", "status": 200}))
    assert ids(nemla.assess_host(host)) == {
        ("redis_open", "high"), ("memcached", "high"), ("es_open", "high")}
    locked = host_with("10.0.0.5", (6379, {"auth": "required"}))
    assert ids(nemla.assess_host(locked)) == {("db", "medium")}


def test_tls_findings():
    def tls(**kw):
        return {"tls": {"version": "TLSv1.3", "days_left": 400, "self_signed": False, **kw}}

    assert ids(nemla.assess_host(host_with("10.0.0.5", (443, tls(days_left=-3))))) == {("tls_expired", "high")}
    assert ids(nemla.assess_host(host_with("10.0.0.5", (443, tls(days_left=12))))) == {("tls_expiring", "medium")}
    assert ids(nemla.assess_host(host_with("10.0.0.5", (443, tls(version="TLSv1"))))) == {("tls_old", "medium")}
    assert ids(nemla.assess_host(host_with("10.0.0.5", (443, tls(self_signed=True))))) == {("tls_selfsigned", "low")}
    assert nemla.assess_host(host_with("10.0.0.5", (443, tls()))) == []


def test_plain_http_only_when_there_is_no_tls():
    web = {"status": 200}
    looked = {"tcp": "80,443"}
    plain = host_with("10.0.0.5", (80, web))
    plain["scanned"] = looked
    assert ids(nemla.assess_host(plain)) == {("http_plain", "low")}
    both = host_with("10.0.0.5", (80, web), (443, {"status": 200, "tls": {"version": "TLSv1.3", "days_left": 90}}))
    both["scanned"] = looked
    assert nemla.assess_host(both) == []


def test_plain_http_is_not_reported_when_https_was_never_looked_for():
    """The old check said 'no HTTPS' after scanning port 80 alone: a false positive."""
    only80 = host_with("10.0.0.5", (80, {"status": 200}))
    only80["scanned"] = {"tcp": "80"}
    assert nemla.assess_host(only80) == []
    unknown = host_with("10.0.0.5", (80, {"status": 200}))        # a scan saved by an older version
    assert nemla.assess_host(unknown) == []
    redirecting = host_with("10.0.0.5", (80, {"status": 301, "location": "https://example.test/"}))
    redirecting["scanned"] = {"tcp": "80,443"}
    assert nemla.assess_host(redirecting) == []                     # it hands visitors over to HTTPS


def test_findings_are_sorted_worst_first_and_version_is_info():
    host = host_with("10.0.0.5", (22, {"product": "OpenSSH", "version": "9.6"}), (445, {}), (23, {}))
    order = [f["severity"] for f in nemla.assess_host(host)]
    assert order == sorted(order, key=nemla.SEV_RANK.get, reverse=True)
    assert order[0] == "high" and order[-1] == "info"


@pytest.mark.parametrize("lang, marker", [("en", "clear text"), ("ar", "نص واضح"), ("he", "טקסט גלוי")])
def test_finding_text_in_every_language(lang, marker):
    nemla._LANG = lang
    try:
        finding = nemla.assess_host(host_with("10.0.0.5", (23, {})))[0]
        text = nemla.finding_text(finding)
    finally:
        nemla._LANG = "en"
    assert "23" in text and marker in text


def test_every_finding_id_has_text_in_every_language():
    ids_used = ["telnet", "ftp", "remote", "db", "files", "redis_open", "memcached", "es_open",
                "http_plain", "tls_expired", "tls_expiring", "tls_old", "tls_selfsigned", "version"]
    params = {"port": 1, "service": "x", "days": 2, "version": "v", "product": "p"}
    for lang in nemla.STRINGS:
        nemla._LANG = lang
        try:
            for fid in ids_used:
                assert nemla.finding_text({"id": fid, "port": 1, "params": params})
        finally:
            nemla._LANG = "en"


# --------------------------------------------------------------------------
# reports, command line, Hebrew
# --------------------------------------------------------------------------

def sample_host():
    return {"ip": "10.0.0.5", "mac": None, "os_guess": "Linux", "ttl": 64, "open_ports": [
        {"port": 23, "service": "Telnet", "banner": "login:", "product": "<b>evil</b>", "version": "1",
         "title": "<script>alert(1)</script>"},
        {"port": 443, "service": "HTTPS", "banner": "", "tls": {
            "version": "TLSv1.3", "subject": "nemla.test", "not_after": "2126-08-27", "days_left": 9000}}],
        "findings": [{"id": "telnet", "severity": "high", "port": 23, "params": {}}]}


def test_report_shows_findings_products_and_escapes_them():
    meta = {"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 2}
    page = nemla.render_html(meta, [sample_host()])
    assert "sev-high" in page and "Telnet is open on port 23" in page
    assert "&lt;b&gt;evil&lt;/b&gt;" in page and "&lt;script&gt;alert(1)" in page
    assert "<b>evil</b>" not in page and "<script>alert(1)" not in page
    assert "TLSv1.3" in page and "2126-08-27" in page


def test_report_in_hebrew_is_rtl():
    meta = {"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 2}
    nemla._LANG = "he"
    try:
        page = nemla.render_html(meta, [sample_host()])
    finally:
        nemla._LANG = "en"
    assert 'lang="he"' in page and 'dir="rtl"' in page
    assert "דוח סריקה של נמלה" in page and "ממצאים" in page and "טקסט גלוי" in page


def test_json_and_csv_carry_the_new_fields():
    meta = {"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 2,
            "findings": {"info": 0, "low": 0, "medium": 0, "high": 1}}
    data = json.loads(nemla.json_text(meta, [sample_host()]))
    assert data["findings_summary"]["high"] == 1
    assert data["hosts"][0]["findings"][0]["id"] == "telnet"
    header, first = nemla.csv_text([sample_host()]).splitlines()[:2]
    assert header.startswith("ip,mac,vendor,os_guess,ttl,port,service,banner,product,version")  # Nemla 1 columns first
    assert "<b>evil</b>,1," in first


def fake_scan(monkeypatch, severity):
    host = {"ip": "10.0.0.5", "mac": None, "os_guess": "Linux", "ttl": 64, "open_ports": [],
            "findings": [{"id": "ftp", "severity": severity, "port": 21, "params": {}}]}
    meta = {"target": "10.0.0.5", "scan_time": "now", "duration": 0.1, "ports_scanned": 1,
            "discovered": 1, "cancelled": False, "findings": nemla.summarize_findings([host])}
    monkeypatch.setattr(nemla.cli, "run_scan", lambda *a, **k: ([host], meta))


@pytest.mark.parametrize("severity, level, code", [
    ("medium", "high", 0), ("medium", "medium", 3), ("high", "medium", 3),
    ("low", "medium", 0), ("low", "low", 3), ("info", "low", 0)])
def test_fail_on_sets_the_exit_code(monkeypatch, tmp_path, capsys, severity, level, code):
    fake_scan(monkeypatch, severity)
    argv = ["-t", "10.0.0.5", "-o", str(tmp_path / "r.html"), "--fail-on", level]
    assert nemla.main(argv) == code
    out = capsys.readouterr().out
    assert "Findings:" in out


def test_without_fail_on_findings_never_change_the_exit_code(monkeypatch, tmp_path):
    fake_scan(monkeypatch, "high")
    assert nemla.main(["-t", "10.0.0.5", "-o", str(tmp_path / "r.html")]) == 0


def test_cli_scan_in_hebrew(servers, tmp_path, capsys):
    port = servers(lambda conn: (conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"), conn.close()))
    out = tmp_path / "r.html"
    code = nemla.main(["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os",
                       "--lang", "he", "-o", str(out)])
    nemla._LANG = "en"
    assert code == 0
    page = out.read_text(encoding="utf-8")
    assert 'lang="he"' in page and "OpenSSH" in page
    assert "סורק" in capsys.readouterr().out


@pytest.mark.parametrize("mac, expected", [
    ("00:0C:29:AB:CD:EF", "VMware"), ("00-50-56-01-02-03", "VMware"),
    ("08:00:27:11:22:33", "Oracle VirtualBox"), ("52:54:00:12:34:56", "QEMU/KVM (libvirt)"),
    ("b8:27:eb:11:22:33", "Raspberry Pi Foundation"), ("DC:A6:32:aa:bb:cc", "Raspberry Pi Trading"),
    ("02:42:ac:11:00:02", "Docker (bridge network)"),
    ("aa:bb:cc:dd:ee:ff", None), ("", None), (None, None), ("00:0C", None), ("not a mac", None)])
def test_mac_vendor(mac, expected):
    assert nemla.mac_vendor(mac) == expected


# A sample of the vendor table added from the IEEE public OUI registry (nemla/discovery/mac.py): real assignments,
# picked to cover the categories the table groups them into (networking gear, phones/laptops, smart-home, printers...).
@pytest.mark.parametrize("mac, expected", [
    ("F0:EE:7A:11:22:33", "Apple"), ("64:1B:2F:11:22:33", "Samsung"), ("E8:0A:B9:11:22:33", "Cisco"),
    ("9C:E3:30:11:22:33", "Cisco Meraki"), ("F0:9F:C2:11:22:33", "Ubiquiti"), ("34:F7:16:11:22:33", "TP-Link"),
    ("D4:8A:FC:11:22:33", "Espressif (ESP32/ESP8266)"), ("84:28:59:11:22:33", "Amazon (Echo/Kindle/Fire)"),
    ("60:70:6C:11:22:33", "Google"), ("64:16:66:11:22:33", "Nest (Google)"), ("D0:43:1E:11:22:33", "Dell"),
    ("00:E0:4C:11:22:33", "Realtek"), ("0C:75:D2:11:22:33", "Hikvision")])
def test_mac_vendor_from_the_ieee_registry_sample(mac, expected):
    assert nemla.mac_vendor(mac) == expected


def test_mac_vendor_prefers_the_longest_matching_prefix(monkeypatch):
    """When one table entry is a prefix of another, the more specific one wins whatever order they are listed in. The
    shipped table has no such pair today (see the next test); this pins the lookup rule so adding one later, say a
    short platform prefix next to a longer vendor block, cannot silently return the less specific name."""
    from nemla.discovery import mac
    table = (("AABB", "short platform prefix"), ("AABBCC", "specific vendor block"))       # short one listed first
    monkeypatch.setattr(mac, "_BY_LENGTH", tuple(sorted(table, key=lambda item: -len(item[0]))))
    assert nemla.mac_vendor("aa:bb:cc:00:00:01") == "specific vendor block"
    assert nemla.mac_vendor("aa:bb:dd:00:00:01") == "short platform prefix"


def test_the_shipped_vendor_table_has_no_ambiguous_entry():
    from nemla.discovery.mac import _MAC_PREFIXES
    prefixes = [p for p, _ in _MAC_PREFIXES]
    assert len(prefixes) == len(set(prefixes)), "two entries share the exact same prefix: the lookup would be ambiguous"
    assert all(len(p) % 2 == 0 and p == p.upper() and int(p, 16) >= 0 for p in prefixes), "prefixes are whole octets of hex"
    for i, shorter in enumerate(prefixes):
        for longer in prefixes[i + 1:]:
            a, b = (shorter, longer) if len(shorter) <= len(longer) else (longer, shorter)
            assert not b.startswith(a), f"{a!r} shadows {b!r}: two different vendors would collide on this address"


def test_scan_results_carry_the_vendor(servers, monkeypatch):
    port = servers(lambda conn: conn.close())
    for mac, expected in (("b8:27:eb:11:22:33", "Raspberry Pi Foundation"), ("aa:bb:cc:dd:ee:ff", None)):
        monkeypatch.setattr(nemla.engine, "discover_hosts",
                            lambda ips, mac=mac, **kw: {"127.0.0.1": {"mac": mac, "method": "ARP"}})
        hosts, _ = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_os=True)
        assert hosts[0]["mac"] == mac and hosts[0]["vendor"] == expected


def test_vendor_is_shown_in_every_report_format():
    host = sample_host()
    host["mac"], host["vendor"] = "52:54:00:12:34:56", "QEMU/KVM (libvirt)"
    meta = {"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 2}
    assert "MAC: 52:54:00:12:34:56 (QEMU/KVM (libvirt))" in nemla.render_html(meta, [host])
    assert json.loads(nemla.json_text(meta, [host]))["hosts"][0]["vendor"] == "QEMU/KVM (libvirt)"
    header, first = nemla.csv_text([host]).splitlines()[:2]
    assert header.split(",")[:3] == ["ip", "mac", "vendor"]
    assert first.split(",")[1:3] == ["52:54:00:12:34:56", "QEMU/KVM (libvirt)"]
    host["vendor"] = "<script>alert(1)</script>"  # never trusted blindly in the page
    assert "<script>alert(1)" not in nemla.render_html(meta, [host])


def test_hebrew_is_an_offered_language():
    assert "he" in nemla.STRINGS and "he" in nemla.RTL_LANGS
    parser = nemla.build_parser()
    assert parser.parse_args(["--lang", "he"]).lang == "he"
    english = set(nemla.STRINGS["en"])
    assert set(nemla.STRINGS["he"]) == english == set(nemla.STRINGS["ar"])
