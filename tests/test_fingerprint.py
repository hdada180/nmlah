"""Service fingerprinting: one fake server per protocol, plus malformed and malicious input."""
import re
import socket
import ssl
import struct
import time

import pytest

import nemla
from nemla.fingerprint import databases, dns, rdp, smb, smtp, ssh, tls
from nemla.fingerprint.base import BudgetExhausted, Detection, Probe
from nemla.net import Cancelled

from test_detect import TEST_CERT, TEST_KEY


def detect(port, **kw):
    return nemla.detect_service("127.0.0.1", port, b"", "", kw.pop("timeout", 1.5), **kw)


def scan(port, **kw):
    return nemla.scan_port("127.0.0.1", port, kw.pop("timeout", 1.0), **kw)


def read_line(conn, limit=2000):
    data = b""
    while not data.endswith(b"\n") and len(data) < limit:
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------

def ssh_packet(payload):
    pad = 8 - (5 + len(payload)) % 8
    pad = pad + 8 if pad < 4 else pad
    return struct.pack("!IB", 1 + len(payload) + pad, pad) + payload + b"\x00" * pad


def name_list(names):
    raw = ",".join(names).encode()
    return struct.pack("!I", len(raw)) + raw


def kexinit(kex, host_keys, ciphers, macs):
    payload = bytes([20]) + b"\x11" * 16
    for names in (kex, host_keys, ciphers, ciphers, macs, macs, ["none"], ["none"], [], []):
        payload += name_list(names)
    return ssh_packet(payload + b"\x00" + b"\x00" * 4)


def ssh_server(banner, packet=None):
    def handler(conn):
        try:
            conn.sendall(banner + b"\r\n")
            if packet:
                read_line(conn)
                conn.sendall(packet)
                time.sleep(0.2)
        except OSError:
            pass
        conn.close()
    return handler


def test_ssh_banner_product_version_and_distribution(tcp_server):
    res = scan(tcp_server(ssh_server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")))
    assert (res["service"], res["product"], res["version"], res["os_hint"]) == ("SSH", "OpenSSH", "9.6p1", "Ubuntu Linux")
    assert res["confidence"] >= 0.9 and res["heuristic"] is False and res["method"] == "banner"
    assert res["details"]["protocol"] == "2.0"


def test_ssh_weak_algorithms_are_read_from_the_key_exchange(tcp_server):
    packet = kexinit(["curve25519-sha256", "diffie-hellman-group1-sha1"], ["ssh-rsa", "ssh-dss"],
                     ["aes128-ctr", "3des-cbc", "arcfour"], ["hmac-sha2-256", "hmac-md5"])
    res = scan(tcp_server(ssh_server(b"SSH-2.0-OpenSSH_5.3", packet)))
    weak = res["details"]["weak_algorithms"]
    assert {"kex:diffie-hellman-group1-sha1", "cipher:3des-cbc", "cipher:arcfour", "mac:hmac-md5",
            "hostkey:ssh-dss"} <= set(weak)
    ids = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]})}
    assert ids["ssh_weak_crypto"]["severity"] == "medium" and "arcfour" in ids["ssh_weak_crypto"]["evidence"]


def test_modern_ssh_has_no_weak_algorithms(tcp_server):
    packet = kexinit(["curve25519-sha256"], ["ssh-ed25519"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    res = scan(tcp_server(ssh_server(b"SSH-2.0-OpenSSH_9.6", packet)))
    assert "weak_algorithms" not in res.get("details", {})
    assert not [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]}) if f["severity"] != "info"]


def test_ssh_protocol_1_is_a_high_finding(tcp_server):
    res = scan(tcp_server(ssh_server(b"SSH-1.5-OldServer_1.2")))
    assert res["details"]["protocol"] == "1.5"
    found = [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]}) if f["id"] == "ssh_protocol1"]
    assert found and found[0]["severity"] == "high" and "1.5" in found[0]["evidence"]
    compat = scan(tcp_server(ssh_server(b"SSH-1.99-OpenSSH_3.9")))
    found = [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [compat]}) if f["id"] == "ssh_protocol1"]
    assert found[0]["severity"] == "medium"


@pytest.mark.parametrize("payload", [b"", b"\x00" * 30, bytes([20]) + b"\x00" * 16 + struct.pack("!I", 10 ** 9),
                                     bytes([21]) + b"\x00" * 50])
def test_ssh_kexinit_parser_rejects_garbage(payload):
    with pytest.raises(ValueError):
        ssh.parse_kexinit(payload)


def test_ssh_survives_a_truncated_or_hostile_kexinit(tcp_server):
    for packet in (b"\xff" * 64, struct.pack("!IB", 5, 200) + b"x" * 4, kexinit(["a"], ["b"], ["c"], ["d"])[:20]):
        res = scan(tcp_server(ssh_server(b"SSH-2.0-OpenSSH_9.6", packet)))
        assert res["product"] == "OpenSSH" and "weak_algorithms" not in res.get("details", {})


# --------------------------------------------------------------------------
# FTP, SMTP, POP3, IMAP, Telnet, VNC
# --------------------------------------------------------------------------

def line_server(banner, replies):
    """A text protocol: send `banner`, then answer each command line by its first word."""
    def handler(conn):
        try:
            conn.sendall(banner)
            while True:
                line = read_line(conn)
                if not line:
                    break
                word = line.split()[0].upper().decode("latin-1") if line.split() else ""
                answer = replies.get(word)
                if answer:
                    conn.sendall(answer)
                if word in ("QUIT", "LOGOUT", "A2"):
                    break
        except OSError:
            pass
        conn.close()
    return handler


def test_ftp_banner_features_and_system(tcp_server):
    port = tcp_server(line_server(b"220 (vsFTPd 3.0.5)\r\n", {
        "FEAT": b"211-Features:\r\n AUTH TLS\r\n PBSZ\r\n211 End\r\n", "SYST": b"215 UNIX Type: L8\r\n",
        "QUIT": b"221 Bye\r\n"}))
    res = scan(port)
    assert (res["service"], res["product"], res["version"]) == ("FTP", "vsftpd", "3.0.5")
    assert res["details"]["starttls"] is True and res["details"]["system"].startswith("UNIX")
    finding = next(f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]}) if f["id"] == "ftp")
    assert finding["severity"] == "low"                       # encryption offered: one step down from medium


def test_ftp_without_tls_support_is_medium_internally_and_high_publicly(tcp_server):
    port = tcp_server(line_server(b"220 Microsoft FTP Service\r\n", {"FEAT": b"211-Features:\r\n SIZE\r\n211 End\r\n"}))
    res = scan(port)
    assert res["details"]["starttls"] is False
    assert nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]})[0]["severity"] == "medium"
    assert nemla.assess_host({"ip": "8.8.8.8", "open_ports": [res]})[0]["severity"] == "high"


def test_smtp_extensions(tcp_server):
    port = tcp_server(line_server(b"220 mail.lab.local ESMTP Postfix (Ubuntu)\r\n", {
        "EHLO": b"250-mail.lab.local\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
        "QUIT": b"221 Bye\r\n"}))
    res = scan(port)
    assert (res["service"], res["product"]) == ("SMTP", "Postfix")
    assert res["details"]["starttls"] is True and res["details"]["auth_mechanisms"] == ["PLAIN", "LOGIN"]
    assert not [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]}) if f["severity"] != "info"]


def test_smtp_ehlo_host_is_recorded_when_the_banner_named_no_product(tcp_server):
    """A generic banner (no recognizable product) still lets refine() learn something: the name the server
    gives itself in the EHLO reply."""
    port = tcp_server(line_server(b"220 ESMTP ready\r\n", {
        "EHLO": b"250-mail.example.com\r\n250 SIZE 100\r\n", "QUIT": b"221 bye\r\n"}))
    res = scan(port)
    # refine() matches against the reply uppercased (same as its STARTTLS/AUTH checks), so the captured
    # hostname comes back upper too - this pins that actual behavior rather than the nicer-looking one
    assert not res.get("product") and res["details"]["ehlo_host"] == "MAIL.EXAMPLE.COM"


def test_smtp_refine_keeps_the_passive_detection_when_the_second_connection_fails(closed_port):
    detection = Detection("smtp", "SMTP", "Exim", "4.96", 0.7, "banner", "220 mx ESMTP Exim 4.96", "", "", False, {})
    result = smtp.Smtp().refine(Probe("127.0.0.1", closed_port, timeout=0.3), detection)
    assert result is detection and result.extra == {}


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_smtp_refine_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    def raise_it(**kw):
        raise exc
    probe = Probe("127.0.0.1", 25, timeout=0.3)
    monkeypatch.setattr(probe, "connect", raise_it)
    with pytest.raises(type(exc)):
        smtp.Smtp().refine(probe, Detection("smtp", "SMTP", "", "", 0.5, "banner", "", "", "", False, {}))


def test_smtp_plain_auth_without_starttls_is_a_finding(tcp_server):
    port = tcp_server(line_server(b"220 mx ESMTP Exim 4.96\r\n", {
        "EHLO": b"250-mx\r\n250-AUTH LOGIN\r\n250 SIZE 100\r\n", "QUIT": b"221 bye\r\n"}))
    res = scan(port)
    assert (res["product"], res["version"]) == ("Exim", "4.96")
    found = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]})}
    assert found["smtp_plain_auth"]["severity"] == "medium" and "LOGIN" in found["smtp_plain_auth"]["evidence"]


def test_pop3_passive_needs_a_recognizable_word_on_a_non_standard_port():
    from nemla.fingerprint.mail import Imap, Pop3
    probe = Probe("127.0.0.1", 12345, banner=b"+OK server up\r\n")           # no POP3/Dovecot/Courier/Cyrus/mail/ready
    assert Pop3().passive(probe) is None
    # on one of POP3's own ports the same banner is still accepted (the port itself is the evidence)
    assert Pop3().passive(Probe("127.0.0.1", 110, banner=b"+OK server up\r\n")) is not None
    assert Imap().passive(probe) is None                                     # unrelated: no "* OK" greeting at all


@pytest.mark.parametrize("cls,detected", [(0, "pop3"), (1, "imap")])
def test_pop3_and_imap_refine_keep_the_passive_detection_when_the_second_connection_fails(closed_port, cls, detected):
    from nemla.fingerprint.mail import Imap, Pop3
    detector = (Pop3(), Imap())[cls]
    detection = Detection(detected, detected.upper(), "Dovecot", "", 0.7, "banner", "", "", "", False, {})
    result = detector.refine(Probe("127.0.0.1", closed_port, timeout=0.3), detection)
    assert result is detection and result.extra == {}


@pytest.mark.parametrize("cls", [0, 1])
@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_pop3_and_imap_refine_let_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc, cls):
    from nemla.fingerprint.mail import Imap, Pop3
    detector = (Pop3(), Imap())[cls]

    def raise_it(**kw):
        raise exc
    probe = Probe("127.0.0.1", 110, timeout=0.3)
    monkeypatch.setattr(probe, "connect", raise_it)
    with pytest.raises(type(exc)):
        detector.refine(probe, Detection("x", "X", "", "", 0.5, "banner", "", "", "", False, {}))


def test_pop3_and_imap(tcp_server):
    pop = scan(tcp_server(line_server(b"+OK Dovecot ready.\r\n", {"CAPA": b"+OK\r\nUSER\r\nSTLS\r\n.\r\n", "QUIT": b"+OK\r\n"})))
    assert (pop["service"], pop["product"]) == ("POP3", "Dovecot") and pop["details"]["starttls"] is True
    imap = scan(tcp_server(line_server(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", {
        "A1": b"* CAPABILITY IMAP4rev1 LOGINDISABLED\r\na1 OK done\r\n", "A2": b"* BYE\r\na2 OK\r\n"})))
    assert (imap["service"], imap["product"]) == ("IMAP", "Dovecot")
    assert imap["details"]["starttls"] is False and imap["details"]["login_disabled"] is True
    found = {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [imap]})}
    assert "mail_plain" in found


def test_telnet_and_vnc_banners(tcp_server):
    telnet = scan(tcp_server(lambda c: (c.sendall(b"\xff\xfb\x01\xff\xfb\x03login: "), time.sleep(0.2), c.close())))
    assert telnet["service"] == "Telnet" and telnet["details"]["cleartext"] is True and telnet["confidence"] >= 0.8
    vnc = scan(tcp_server(lambda c: (c.sendall(b"RFB 003.008\n"), time.sleep(0.2), c.close())))
    assert (vnc["service"], vnc["version"]) == ("VNC", "003.008")


def test_unrecognised_banner_falls_back_to_a_labelled_guess(tcp_server):
    res = scan(tcp_server(lambda c: (c.sendall(b"hello from my custom protocol\r\n"), time.sleep(0.3), c.close())))
    assert res["heuristic"] is True and res["method"] == "port" and res["confidence"] <= 0.3
    assert res["banner"].startswith("hello from")


# --------------------------------------------------------------------------
# Redis, Memcached, MySQL, PostgreSQL
# --------------------------------------------------------------------------

def mysql_packet(version=b"8.0.35-0ubuntu0.22.04.1", ssl_flag=True):
    body = b"\x0a" + version + b"\x00" + b"\x01\x00\x00\x00" + b"A" * 8 + b"\x00"
    body += struct.pack("<H", 0xFFFF if ssl_flag else 0xF7FF)      # 0x0800 is CLIENT_SSL + b"\x21\x02\x00" + b"\x00" * 13
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


def test_mysql_and_mariadb_greetings(tcp_server):
    res = scan(tcp_server(lambda c: (c.sendall(mysql_packet()), time.sleep(0.2), c.close())))
    assert (res["service"], res["product"], res["version"]) == ("MySQL", "MySQL", "8.0.35")
    assert res["details"]["ssl_support"] is True and res["os_hint"] == "Ubuntu Linux"
    maria = scan(tcp_server(lambda c: (c.sendall(mysql_packet(b"5.5.5-10.6.12-MariaDB-1", False)), time.sleep(0.2), c.close())))
    assert (maria["product"], maria["version"]) == ("MariaDB", "10.6.12") and maria["details"]["ssl_support"] is False


def test_mysql_host_blocked_error_packet_is_still_mysql(tcp_server):
    err = b"\xff\x6a\x04Host '10.0.0.9' is not allowed to connect to this MySQL server"
    packet = struct.pack("<I", len(err))[:3] + b"\x00" + err
    res = scan(tcp_server(lambda c: (c.sendall(packet), time.sleep(0.2), c.close())))
    assert res["service"] == "MySQL" and res["details"]["blocked"] is True


def test_greeting_parser_rejects_garbage():
    assert databases.mysql_greeting(b"") is None
    assert databases.mysql_greeting(b"\x00" * 30) is None
    assert databases.mysql_greeting(b"\x10\x00\x00\x00\x0a" + b"x" * 200) is None       # no terminator, absurd version


def test_postgres_answers_the_ssl_request(tcp_server):
    for answer, ssl_support in ((b"S", True), (b"N", False)):
        def handler(conn, answer=answer):
            conn.recv(8)
            conn.sendall(answer)
            conn.close()
        res = detect(tcp_server(handler))
        assert res["product"] == "PostgreSQL" and res["details"]["ssl_support"] is ssl_support


def test_redis_and_memcached_findings_from_real_probes(tcp_server):
    def redis(conn):
        data = conn.recv(1024)
        conn.sendall(b"+PONG\r\n" if data.startswith(b"PING") else b"$50\r\n# Server\r\nredis_version:6.2.6\r\nos:Linux 5.15.0 x86_64\r\n\r\n")
        conn.close()
    res = scan(tcp_server(redis))
    assert res["auth"] == "none" and res["version"] == "6.2.6" and res["details"]["os"].startswith("Linux")
    found = [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]}) if f["id"] == "redis_open"]
    assert found and found[0]["severity"] == "high" and found[0]["confidence"] >= 0.9

    def memcached(conn):
        if conn.recv(64).startswith(b"version"):
            conn.sendall(b"VERSION 1.6.9\r\n")
        conn.close()
    res = scan(tcp_server(memcached))
    assert {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]})} >= {"memcached"}


def test_a_web_server_is_not_mistaken_for_redis(tcp_server):
    body = b"<html><title>Not Redis</title></html>"
    res = detect(tcp_server(lambda c: (c.recv(2048), c.sendall(b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n" + body), c.close())))
    assert res["detected"] == "http" and res["title"] == "Not Redis"


# --------------------------------------------------------------------------
# DNS over TCP
# --------------------------------------------------------------------------

def dns_reply(query, recursion=True, version=b"9.16.1-Ubuntu"):
    ident = query[:2]
    flags = 0x8180 if recursion else 0x8100
    question = query[12:]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 3, 0, len(version) + 1) + bytes([len(version)]) + version
    return ident + struct.pack("!HHHHH", flags, 1, 1, 0, 0) + question + answer


def test_dns_over_tcp_reports_recursion_and_version(tcp_server):
    def server(conn):
        size = struct.unpack("!H", conn.recv(2))[0]
        reply = dns_reply(conn.recv(size))
        conn.sendall(struct.pack("!H", len(reply)) + reply)
        conn.close()
    res = detect(tcp_server(server))
    assert (res["detected"], res["product"], res["version"]) == ("dns", "BIND", "9.16.1-Ubuntu")
    assert res["details"]["recursion_available"] is True
    findings = {f["id"]: f for f in nemla.assess_host({"ip": "8.8.8.8", "open_ports": [{"port": 53, "proto": "tcp", **res}]})}
    assert findings["dns_recursion"]["severity"] == "medium" and findings["dns_recursion"]["confidence"] <= 0.7
    assert "RA" in findings["dns_recursion"]["evidence"]


def test_dns_response_with_the_wrong_id_is_ignored():
    query = dns.build_query(ident=1234)
    assert dns.parse_response(dns_reply(query), 1234)["recursion_available"] is True
    assert dns.parse_response(dns_reply(query), 9999) == {}
    assert dns.parse_response(b"\x00" * 5) == {} and dns.parse_response(b"") == {}
    truncated = dns_reply(query)[:20]
    assert isinstance(dns.parse_response(truncated, 1234), dict)          # never raises


# --------------------------------------------------------------------------
# RDP
# --------------------------------------------------------------------------

def rdp_response(kind, value=0):
    neg = struct.pack("<BBHI", 0x02 if kind == "ok" else 0x03, 0, 8, value)
    return struct.pack("!BBH", 3, 0, 19) + bytes([14, 0xD0, 0, 0, 0, 0, 0]) + neg


def rdp_server(policy):
    def handler(conn):
        try:
            data = conn.recv(64)
            requested = struct.unpack_from("<I", data, 15)[0]
            conn.sendall(policy(requested))
        except (OSError, struct.error):
            pass
        conn.close()
    return handler


def test_rdp_without_nla(tcp_server):
    def tls_only(requested):        # legacy refused, TLS accepted, no NLA required
        return rdp_response("fail", 1) if requested == 0 else rdp_response("ok", 1)
    res = detect(tcp_server(rdp_server(tls_only)))
    assert res["detected"] == "rdp" and res["details"]["nla"] == "not required"
    finding = [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 3389, **res}]}) if f["id"] == "rdp_no_nla"]
    assert finding and finding[0]["severity"] == "medium"


def test_rdp_with_nla_required_has_no_rdp_finding(tcp_server):
    res = detect(tcp_server(rdp_server(lambda requested: rdp_response("fail", 5))))
    assert res["details"]["nla"] == "required"
    ids = {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 3389, **res}]})}
    assert "rdp_no_nla" not in ids and "rdp_weak_security" not in ids and "remote" in ids


def test_rdp_legacy_security_is_high(tcp_server):
    res = detect(tcp_server(rdp_server(lambda requested: rdp_response("ok", 0))))
    assert res["details"]["weak_security"] is True
    found = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 3389, **res}]})}
    assert found["rdp_weak_security"]["severity"] == "high"


def test_rdp_parser_and_request_shape():
    request = rdp.connection_request(0)
    assert request[0] == 3 and struct.unpack("!H", request[2:4])[0] == len(request) == 19
    assert rdp.parse_confirm(b"") is None and rdp.parse_confirm(b"GET / HTTP/1.0") is None
    assert rdp.parse_confirm(rdp_response("ok", 2)) == ("ok", 2)
    assert rdp.parse_confirm(rdp_response("fail", 5)) == ("fail", 5)


def test_rdp_parser_recognises_a_pre_negotiation_server():
    """A server old enough to have no RFC 5073 negotiation at all: a bare X.224 connect confirm, nothing after it."""
    bare = bytes([3, 0, 0, 11, 6, 0xD0, 0, 0, 0, 0, 0])
    assert len(bare) == 11 and rdp.parse_confirm(bare) == ("legacy", 0)


def test_ask_returns_none_on_a_refused_connection(closed_port):
    probe = Probe("127.0.0.1", closed_port, timeout=0.3)
    assert rdp.Rdp()._ask(probe, 0) is None


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_ask_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    def raise_it(*a, **k):
        raise exc
    probe = Probe("127.0.0.1", 3389, timeout=0.3)
    monkeypatch.setattr(probe, "connect", raise_it)
    with pytest.raises(type(exc)):
        rdp.Rdp()._ask(probe, 0)


def test_rdp_nla_requirement_revealed_only_by_the_second_probe(tcp_server):
    """The legacy request is refused for an ordinary reason (not code 5), so a second, TLS-only request is sent;
    that one is what actually demands NLA."""
    def policy(requested):
        return rdp_response("fail", 2) if requested == 0 else rdp_response("fail", 5)
    res = detect(tcp_server(rdp_server(policy)))
    assert res["details"]["nla"] == "required"


def test_rdp_reports_unknown_when_neither_probe_settles_it(tcp_server):
    def policy(requested):
        return rdp_response("fail", 2)          # refused both times, never for the NLA-specific reason
    res = detect(tcp_server(rdp_server(policy)))
    assert res["details"]["nla"] == "unknown"


# --------------------------------------------------------------------------
# SMB
# --------------------------------------------------------------------------

def smb2_reply(dialect=0x0302, mode=0x01):
    return b"\x00\x00\x00\x46" + b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 58 + struct.pack("<HHH", 65, mode, dialect)


def smb1_reply(mode=0x03):
    header = b"\xffSMB" + bytes([0x72]) + struct.pack("<I", 0) + b"\x00" * 23
    return b"\x00\x00\x00\x28" + header + b"\x11" + struct.pack("<H", 0) + bytes([mode])


def smb_server(smb1=True, smb2=True, dialect=0x0302, mode=0x01):
    def handler(conn):
        try:
            data = conn.recv(1024)
            if data[4:8] == b"\xfeSMB" and smb2:
                conn.sendall(smb2_reply(dialect, mode))
            elif data[4:8] == b"\xffSMB" and smb1:
                conn.sendall(smb1_reply())
        except OSError:
            pass
        conn.close()
    return handler


def test_smb_v1_enabled_and_signing_not_required(tcp_server):
    res = detect(tcp_server(smb_server()))
    assert res["detected"] == "smb" and res["details"]["smb1"] is True
    assert res["details"]["dialect"] == "3.0.2" and res["details"]["signing"] == "enabled"
    found = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 445, **res}]})}
    assert found["smb1"]["severity"] == "high" and found["smb_signing"]["severity"] == "medium"
    assert found["files"]["severity"] == "low"


def test_smb_v2_only_with_required_signing_is_clean(tcp_server):
    res = detect(tcp_server(smb_server(smb1=False, mode=0x03)))
    assert res["details"]["smb1"] is False and res["details"]["signing"] == "required"
    ids = {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 445, **res}]})
           if f["severity"] != "info"}
    assert ids == {"files"}


@pytest.mark.parametrize("data", [b"", b"\x00" * 10, b"\x00\x00\x00\x10\xfeSMB" + b"\xff" * 20, b"\xffSMB" * 30])
def test_smb_parsers_reject_garbage(data):
    assert smb.parse_smb1(data) is None and smb.parse_smb2(data) is None


def test_smb1_parser_rejects_a_nonzero_status():
    header = b"\xffSMB" + bytes([0x72]) + struct.pack("<I", 1) + b"\x00" * 23   # status=1, not STATUS_SUCCESS
    data = b"\x00\x00\x00\x28" + header + b"\x11" + struct.pack("<H", 0) + bytes([0x03])
    assert smb.parse_smb1(data) is None


def test_smb2_parser_rejects_an_unrecognized_dialect():
    assert smb.parse_smb2(smb2_reply(dialect=0x9999)) is None


def test_smb_ask_returns_empty_when_the_connection_fails(closed_port):
    result = smb.Smb()._ask(Probe("127.0.0.1", closed_port, timeout=0.3), smb.smb2_negotiate())
    assert result == b""


def test_smb_probe_returns_none_when_neither_negotiate_gets_an_answer(tcp_server):
    port = tcp_server(lambda conn: conn.close())    # accepts, then hangs up: not an SMB service
    assert smb.Smb().probe(Probe("127.0.0.1", port, timeout=0.3)) is None


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_smb_ask_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    def raise_it(**kw):
        raise exc
    probe = Probe("127.0.0.1", 445, timeout=0.3)
    monkeypatch.setattr(probe, "connect", raise_it)
    with pytest.raises(type(exc)):
        smb.Smb()._ask(probe, smb.smb2_negotiate())


# --------------------------------------------------------------------------
# HTTP and TLS
# --------------------------------------------------------------------------

def http_server(status_line, headers, body=b""):
    def handler(conn):
        try:
            conn.recv(4096)
            head = status_line + b"\r\n" + b"".join(h + b"\r\n" for h in headers)
            conn.sendall(head + b"Content-Length: %d\r\n\r\n" % len(body) + body)
        except OSError:
            pass
        conn.close()
    return handler


def test_http_admin_console_and_basic_auth_over_plain_http(tcp_server):
    port = tcp_server(http_server(b"HTTP/1.0 401 Unauthorized", [b"Server: Jetty(9.4.2)", b'WWW-Authenticate: Basic realm="x"',
                                                                  b"X-Jenkins: 2.401"], b"<title>Jenkins</title>"))
    res = scan(port)
    assert res["status"] == 401 and res["details"]["admin"] == "Jenkins" and res["product"] == "Jetty"
    found = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [res]})}
    assert found["basic_auth_plain"]["severity"] == "medium" and found["admin_panel"]["severity"] == "low"
    public = {f["id"]: f for f in nemla.assess_host({"ip": "8.8.8.8", "open_ports": [res]})}
    assert public["basic_auth_plain"]["severity"] == "high" and public["admin_panel"]["severity"] == "medium"


def test_http_redirect_to_https_is_recorded(tcp_server):
    res = scan(tcp_server(http_server(b"HTTP/1.1 301 Moved", [b"Location: https://example.test/"])))
    assert res["details"]["redirects_to_https"] is True


def test_elasticsearch_without_login(tcp_server):
    body = b'{"name":"n","cluster_name":"c","version":{"number":"7.17.9"}}'
    res = scan(tcp_server(http_server(b"HTTP/1.0 200 OK", [b"Content-Type: application/json"], body)))
    assert (res["product"], res["version"], res["auth"]) == ("Elasticsearch", "7.17.9", "none")
    assert "es_open" in {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{**res, "port": 9200}]})}


def tls_server(tcp_server, tmp_path, maximum=None, minimum=None, body=b"<title>Secure</title>"):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text(TEST_CERT)
    key.write_text(TEST_KEY)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    if maximum is not None:
        ctx.maximum_version = maximum
    if minimum is not None:
        ctx.minimum_version = minimum
        if minimum < ssl.TLSVersion.TLSv1_2:
            ctx.set_ciphers("ALL:@SECLEVEL=0")

    def handler(conn):
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.settimeout(2)
                try:
                    s.recv(2048)
                except OSError:
                    pass
                s.sendall(b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        except (OSError, ssl.SSLError):
            pass
    return tcp_server(handler)


def test_tls_certificate_is_read_without_touching_the_disk(tcp_server, tmp_path, monkeypatch):
    import tempfile
    calls = []
    monkeypatch.setattr(tempfile, "mkstemp", lambda *a, **k: calls.append(1) or (_ for _ in ()).throw(AssertionError))
    port = tls_server(tcp_server, tmp_path)
    res = scan(port)
    assert res["service"] == "HTTPS" and res["product"] == "nginx" and res["title"] == "Secure"
    tls = res["tls"]
    assert tls["subject"] == "nemla.test" and tls["self_signed"] is True and tls["expired"] is False
    assert tls["key_type"].startswith("EC") and tls["key_bits"] == 256 and tls["sig_alg"] == "ecdsa-with-SHA256"
    assert tls["weak_sig"] is False and tls["not_before"] == "2026-09-20" and tls["not_after"] == "2126-08-27"
    assert calls == []


def test_tls_12_only_server_is_not_reported_as_obsolete(tcp_server, tmp_path):
    # a TLS 1.2-only server: without the minimum, older OpenSSL builds (Python 3.8 on Windows) also accept TLS 1.0/1.1,
    # and reporting that legacy support is then the correct answer
    port = tls_server(tcp_server, tmp_path, maximum=ssl.TLSVersion.TLSv1_2, minimum=ssl.TLSVersion.TLSv1_2)
    tls = scan(port)["tls"]
    assert tls["version"] == "TLSv1.2" and "legacy" not in tls
    ids = {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 443, "service": "HTTPS", "banner": "", "tls": tls}]})}
    assert "tls_old" not in ids and "tls_selfsigned" in ids


def test_server_accepting_tls10_is_detected_when_this_openssl_can_speak_it(tcp_server, tmp_path):
    try:
        with warnings_ignored():
            port = tls_server(tcp_server, tmp_path, maximum=ssl.TLSVersion.TLSv1, minimum=ssl.TLSVersion.TLSv1)
    except (ValueError, ssl.SSLError):
        pytest.skip("this OpenSSL cannot even offer TLS 1.0")
    tls = scan(port, intensity=6)
    tls = tls.get("tls")
    if not tls or "TLSv1" not in tls.get("legacy", []):
        pytest.skip("this OpenSSL refuses TLS 1.0 handshakes")
    found = [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 443, "service": "HTTPS", "banner": "", "tls": tls}]})
             if f["id"] == "tls_old"]
    assert found and "TLSv1" in found[0]["evidence"]


# A throw-away self-signed EC certificate with a SAN extension (nemla.test, www.nemla.test, 127.0.0.1),
# generated once with openssl and never used for anything but parsing in this test.
SAN_CERT = """-----BEGIN CERTIFICATE-----
MIIBrzCCAVWgAwIBAgIUZNWOSvQtZG3dKV/w0492sHlzjqAwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKbmVtbGEudGVzdDAgFw0yNjA5MjIxNDUwNThaGA8yMTI2MDgy
OTE0NTA1OFowFTETMBEGA1UEAwwKbmVtbGEudGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLMvCpJsQCiuGYgtMTbpWenuihMZpoImbwsmNZzRWAyXU0Maz2i7
G9nEXgldgB+ooW8b1DezSaRseaLO2TPcDjGjgYAwfjAdBgNVHQ4EFgQU02PPFv5h
nM4SD+3r2AQTEsxlCgQwHwYDVR0jBBgwFoAU02PPFv5hnM4SD+3r2AQTEsxlCgQw
DwYDVR0TAQH/BAUwAwEB/zArBgNVHREEJDAiggpuZW1sYS50ZXN0gg53d3cubmVt
bGEudGVzdIcEfwAAATAKBggqhkjOPQQDAgNIADBFAiB0BcNrgwxjUr/oigL0JUXp
Swza2uBGjcy9x6DkG3mnCQIhAN+sB3rvcYeDjLtzRLCs8kmCVcOWvR6eccBYTVaN
+JSe
-----END CERTIFICATE-----
"""


def test_certificate_facts_include_the_san_list():
    der = ssl.PEM_cert_to_DER_cert(SAN_CERT)
    facts = tls.certificate_facts(der)
    assert facts["san"] == ["nemla.test", "www.nemla.test", "127.0.0.1"]


class FakeTlsContext:
    def __init__(self, minimum_version, maximum_version):
        self.minimum_version, self.maximum_version = minimum_version, maximum_version


def test_accepts_refuses_a_version_this_openssl_build_cannot_even_attempt(monkeypatch):
    # tls_context is asked for (5, 5) but hands back a context that settled on something else
    monkeypatch.setattr(tls, "tls_context", lambda low, high: FakeTlsContext(3, 3))
    assert tls._accepts(Probe("127.0.0.1", 443, timeout=0.3), 5, 5) is False


def test_accepts_true_on_a_successful_handshake(monkeypatch):
    monkeypatch.setattr(tls, "tls_context", FakeTlsContext)
    closed = []

    class FakeConn:
        def close(self):
            closed.append(1)
    monkeypatch.setattr(tls, "open_conn", lambda *a, **k: FakeConn())
    assert tls._accepts(Probe("127.0.0.1", 443, timeout=0.3), 5, 5) is True and closed == [1]


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_accepts_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    monkeypatch.setattr(tls, "tls_context", FakeTlsContext)

    def raise_it(*a, **k):
        raise exc
    monkeypatch.setattr(tls, "open_conn", raise_it)
    with pytest.raises(type(exc)):
        tls._accepts(Probe("127.0.0.1", 443, timeout=0.3), 5, 5)


def test_legacy_protocols_collects_every_version_this_openssl_will_still_complete(monkeypatch):
    monkeypatch.setattr(tls, "_accepts", lambda probe, low, high: True)
    assert tls.legacy_protocols(Probe("127.0.0.1", 443, timeout=0.3)) == ["TLSv1", "TLSv1.1"]


def test_legacy_protocols_skips_a_version_this_python_build_does_not_even_define(monkeypatch):
    asked = []
    monkeypatch.setattr(tls, "_accepts", lambda probe, low, high: asked.append(low) or True)

    class PartialTLSVersion:
        TLSv1_1 = ssl.TLSVersion.TLSv1_1                        # only the second _LEGACY entry is defined here
    monkeypatch.setattr(ssl, "TLSVersion", PartialTLSVersion)
    assert tls.legacy_protocols(Probe("127.0.0.1", 443, timeout=0.3)) == ["TLSv1.1"]
    assert asked == [ssl.TLSVersion.TLSv1_1]                     # TLSv1 was skipped, never asked about


def test_legacy_protocols_stops_asking_once_the_probe_budget_is_gone(monkeypatch):
    from nemla.scanning.scheduler import ProbeBudget
    monkeypatch.setattr(tls, "_accepts", lambda probe, low, high: pytest.fail("must not probe once the budget is gone"))
    budget = ProbeBudget(1)
    assert budget.take()                              # use up the one unit this probe is allowed
    assert tls.legacy_protocols(Probe("127.0.0.1", 443, timeout=0.3, budget=budget)) == []


class FakeSslSocket:
    def __init__(self, version="TLSv1.3", cert_error=None):
        self._version, self._cert_error = version, cert_error

    def version(self):
        return self._version

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self, binary_form=False):
        if self._cert_error:
            raise self._cert_error
        return b""


class FakeTlsConn:
    def __init__(self, sock):
        self.sock = sock

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_inspect_tls_returns_none_when_the_handshake_fails(monkeypatch):
    def raise_it(**kw):
        raise OSError("connection reset")
    probe = Probe("127.0.0.1", 443, timeout=0.3)
    monkeypatch.setattr(probe, "connect", raise_it)
    assert tls.inspect_tls(probe) is None


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_inspect_tls_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    def raise_it(**kw):
        raise exc
    probe = Probe("127.0.0.1", 443, timeout=0.3)
    monkeypatch.setattr(probe, "connect", raise_it)
    with pytest.raises(type(exc)):
        tls.inspect_tls(probe)


def test_inspect_tls_survives_a_certificate_it_cannot_read(monkeypatch):
    sock = FakeSslSocket(cert_error=ssl.SSLError("no certificate available"))
    probe = Probe("127.0.0.1", 443, timeout=0.3)
    monkeypatch.setattr(probe, "connect", lambda **kw: FakeTlsConn(sock))
    assert tls.inspect_tls(probe) == {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}


def test_inspect_tls_records_legacy_protocols_still_accepted(monkeypatch):
    sock = FakeSslSocket(version="TLSv1.3")
    probe = Probe("127.0.0.1", 443, timeout=0.3)
    monkeypatch.setattr(probe, "connect", lambda **kw: FakeTlsConn(sock))
    monkeypatch.setattr(tls, "legacy_protocols", lambda p: ["TLSv1", "TLSv1.1"])
    assert tls.inspect_tls(probe, legacy=True)["legacy"] == ["TLSv1", "TLSv1.1"]


# --------------------------------------------------------------------------
# the core identification pipeline: _passive / _inside_tls / identify / detect_service
# --------------------------------------------------------------------------

def test_passive_survives_a_detector_that_crashes_on_the_banner(monkeypatch):
    from nemla.fingerprint import REGISTRY, _passive
    diagnostics = nemla.Diagnostics()

    class Boom:
        name = "boom"

        def passive(self, probe):
            raise RuntimeError("hostile banner crashed this detector")
    monkeypatch.setattr("nemla.fingerprint.REGISTRY", [Boom(), *REGISTRY])
    assert _passive(Probe("127.0.0.1", 1, banner=b"not empty"), 5, diagnostics) is None
    assert diagnostics.as_list()[0]["code"] == "detector_error" and "boom" in diagnostics.as_list()[0]["message"]


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_passive_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    from nemla.fingerprint import REGISTRY, _passive

    class Boom:
        name = "boom"

        def passive(self, probe):
            raise exc
    monkeypatch.setattr("nemla.fingerprint.REGISTRY", [Boom(), *REGISTRY])
    with pytest.raises(type(exc)):
        _passive(Probe("127.0.0.1", 1, banner=b"not empty"), 5, nemla.Diagnostics())


def test_inside_tls_synthesizes_a_generic_detection_when_nothing_inside_is_recognised(monkeypatch):
    from nemla.fingerprint import _inside_tls
    monkeypatch.setattr("nemla.fingerprint._passive", lambda *a, **k: None)
    monkeypatch.setattr("nemla.fingerprint._active", lambda *a, **k: None)
    probe = Probe("127.0.0.1", 8443, timeout=0.3)          # in HTTP_TLS_PORTS: never greets first, no connect made
    found = _inside_tls(probe, {"version": "TLSv1.3"}, 5, None)
    assert found.service == "tls" and found.label == "TLS" and "TLSv1.3" in found.evidence
    assert found.tls is True and found.extra["tls"] == {"version": "TLSv1.3"}


def test_inside_tls_relabels_a_service_whose_own_detector_did_not_already_mark_it_tls(monkeypatch):
    """HTTP/SMTP/IMAP/POP3/FTP's own detectors already self-label under TLS (Detection(..., 'HTTPS' if probe.tls
    else 'HTTP', ...)), so this fixup normally never fires for them - it exists for whatever does not."""
    from nemla.fingerprint import _inside_tls
    plain = Detection("http", "HTTP", "", "", 0.7, "protocol", "", "", "", False, {})
    monkeypatch.setattr("nemla.fingerprint._passive", lambda *a, **k: plain)
    found = _inside_tls(Probe("127.0.0.1", 8443, timeout=0.3), {"version": "TLSv1.3"}, 5, None)
    assert found.label == "HTTPS"


def test_inside_tls_appends_a_tls_note_to_a_label_the_relabel_table_does_not_know(monkeypatch):
    from nemla.fingerprint import _inside_tls
    other = Detection("redis", "Redis", "", "", 0.7, "protocol", "", "", "", False, {})
    monkeypatch.setattr("nemla.fingerprint._passive", lambda *a, **k: other)
    found = _inside_tls(Probe("127.0.0.1", 8443, timeout=0.3), {"version": "TLSv1.3"}, 5, None)
    assert found.label == "Redis (TLS)"


def test_inside_tls_treats_a_silent_or_refused_inner_banner_as_empty(closed_port):
    from nemla.fingerprint import _inside_tls
    found = _inside_tls(Probe("127.0.0.1", closed_port, timeout=0.3), {"version": "TLSv1.3"}, 5, None)
    assert found.service == "tls"                          # nothing answered inside the tunnel either


@pytest.mark.parametrize("exc", [Cancelled(), BudgetExhausted("probe budget exhausted")])
def test_inside_tls_lets_cancellation_and_budget_exhaustion_propagate(monkeypatch, exc):
    from nemla.fingerprint import _inside_tls

    def raise_it(**kw):
        raise exc
    probe = Probe("127.0.0.1", 25, timeout=0.3)             # not in HTTP_TLS_PORTS: the inner banner read runs
    monkeypatch.setattr(probe, "derive", lambda **kw: probe)
    monkeypatch.setattr(probe, "connect", raise_it)
    with pytest.raises(type(exc)):
        _inside_tls(probe, {"version": "TLSv1.3"}, 5, None)


def test_identify_does_nothing_at_intensity_zero():
    assert nemla.identify(Probe("127.0.0.1", 1, banner=b"SSH-2.0-OpenSSH\r\n"), 0, None) is None


def test_detect_service_reports_an_exhausted_budget_instead_of_crashing(monkeypatch):
    diagnostics = nemla.Diagnostics()

    def raise_it(*a, **k):
        raise BudgetExhausted("probe budget exhausted")
    monkeypatch.setattr("nemla.fingerprint.identify", raise_it)
    assert nemla.detect_service("127.0.0.1", 1, b"", "", 0.3, None, None, 5, diagnostics) == {}
    assert diagnostics.as_list()[0]["code"] == "budget"


class warnings_ignored:
    def __enter__(self):
        import warnings
        self._ctx = warnings.catch_warnings()
        self._ctx.__enter__()
        warnings.simplefilter("ignore")

    def __exit__(self, *exc):
        return self._ctx.__exit__(*exc)


def test_a_plain_port_is_not_reported_as_tls(tcp_server):
    assert nemla.tls_probe("127.0.0.1", tcp_server(lambda c: (c.sendall(b"hello\r\n"), c.close())), timeout=0.5) == (None, {})


# --------------------------------------------------------------------------
# intensity, confidence semantics
# --------------------------------------------------------------------------

def test_intensity_zero_sends_no_probes(tcp_server):
    seen = []
    port = tcp_server(lambda c: (seen.append(1), c.close()))
    res = scan(port, intensity=0)
    assert res["heuristic"] is True and "product" not in res
    assert len(seen) <= 1


def test_low_intensity_skips_rare_protocols(tcp_server):
    def redis(conn):
        data = conn.recv(1024)
        if data.startswith(b"PING"):
            conn.sendall(b"+PONG\r\n")
        conn.close()
    port = tcp_server(redis)
    assert detect(port, intensity=1).get("product") != "Redis"          # rarity 3 is not tried at intensity 1
    assert detect(port, intensity=5)["product"] == "Redis"


def test_confidence_is_never_certain_and_port_guesses_are_labelled(tcp_server, closed_port):
    port = tcp_server(ssh_server(b"SSH-2.0-OpenSSH_9.6p1"))
    exact = scan(port)
    assert 0.9 <= exact["confidence"] < 1.0
    guess = scan(port, grab=False)
    assert guess["heuristic"] is True and guess["confidence"] < 0.5 and "product" not in guess
    assert scan(closed_port) is None


def test_every_detector_is_registered_and_has_the_plugin_interface():
    names = {d.name for d in nemla.fingerprint.REGISTRY} if hasattr(nemla, "fingerprint") else None
    from nemla.fingerprint import REGISTRY
    names = {d.name for d in REGISTRY}
    assert {"http", "ssh", "ftp", "smtp", "dns", "redis", "memcached", "mysql", "postgresql", "rdp", "smb",
            "pop3", "imap", "telnet", "vnc"} <= names
    for detector in REGISTRY:
        assert isinstance(detector.rarity, int) and 1 <= detector.rarity <= 9
        assert hasattr(detector, "passive") and hasattr(detector, "probe") and hasattr(detector, "refine")


def test_probe_helper_counts_against_the_budget(tcp_server):
    from nemla.fingerprint.base import BudgetExhausted
    from nemla.scanning.scheduler import ProbeBudget
    port = tcp_server(lambda c: c.close())
    probe = Probe("127.0.0.1", port, 0.5, budget=ProbeBudget(1))
    probe.connect().close()
    with pytest.raises(BudgetExhausted):
        probe.connect()
    assert re and socket


def test_the_example_in_docs_architecture_md_really_works(tcp_server):
    """A new protocol is one small class: this is the plugin from docs/architecture.md."""
    from nemla.fingerprint import REGISTRY, identify
    from nemla.fingerprint.base import CONFIDENCE, Detection, Detector, register
    from nemla.net import clean_text

    @register
    class MyProto(Detector):
        name, label, ports, rarity = "myproto", "MyProto", (), 4

        def probe(self, probe):
            reply = probe.ask(b"HELLO\r\n")
            if not reply.startswith(b"MYPROTO "):
                return None
            version = clean_text(reply[8:20], 20)
            return Detection("myproto", "MyProto", "MyProto", version, CONFIDENCE["exact"], "protocol",
                             "answered HELLO", "MYPROTO " + version, "", False, {"some_fact": True})

    try:
        port = tcp_server(lambda c: (c.sendall(b"MYPROTO 1.2\r\n") if c.recv(16).startswith(b"HELLO") else None, c.close()))
        found = identify(Probe("127.0.0.1", port, 1.0), 5)
        assert (found.service, found.version, found.method) == ("myproto", "1.2", "protocol")
        assert nemla.detect_service("127.0.0.1", port, b"", "", 1.0)["detected"] == "myproto"
    finally:
        REGISTRY[:] = [d for d in REGISTRY if d.name != "myproto"]
