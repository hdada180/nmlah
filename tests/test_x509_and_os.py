"""Certificate parsing (including malformed and hostile DER) and OS fingerprinting."""
import calendar
import os
import random
import time

import pytest

import nemla
from nemla import os_detection as osd
from nemla.fingerprint import tls as tlsmod
from nemla.fingerprint.x509 import X509Error, parse_certificate

# --------------------------------------------------------------------------
# a tiny DER builder: enough to make certificates with any dates, algorithms and key sizes
# --------------------------------------------------------------------------

SHA1_RSA, SHA256_RSA, MD5_RSA = "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.4"
RSA_KEY, EC_KEY, P256 = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1", "1.2.840.10045.3.1.7"


def der(tag, content):
    n = len(content)
    size = bytes([n]) if n < 0x80 else (b"\x81" + bytes([n]) if n < 0x100 else b"\x82" + n.to_bytes(2, "big"))
    return bytes([tag]) + size + content


def oid(text):
    parts = [int(p) for p in text.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        value = part
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, out)


def utc(ts):
    return der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(ts)).encode())


def general(ts):
    return der(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(ts)).encode())


def name(cn):
    return der(0x30, der(0x31, der(0x30, oid("2.5.4.3") + der(0x0C, cn.encode()))))


def build_cert(cn="host.test", issuer=None, not_before=None, not_after=None, sig=SHA256_RSA, key=RSA_KEY,
               bits=2048, san=(), general_time=False):
    now = time.time()
    nb = now - 86400 * 30 if not_before is None else not_before
    na = now + 86400 * 90 if not_after is None else not_after
    stamp = general if general_time else utc
    if key == RSA_KEY:
        modulus = b"\x00" + bytes([0x80 | random.randrange(128)]) + os.urandom(bits // 8 - 1)  # noqa: S311 - test data
        public = der(0x30, der(0x02, modulus) + der(0x02, b"\x01\x00\x01"))
        spki = der(0x30, der(0x30, oid(RSA_KEY) + der(0x05, b"")) + der(0x03, b"\x00" + public))
    else:
        spki = der(0x30, der(0x30, oid(EC_KEY) + oid(P256)) + der(0x03, b"\x00\x04" + os.urandom(64)))
    extensions = b""
    if san:
        general_names = b"".join(der(0x82, s.encode()) if not s.startswith("ip:") else der(0x87, bytes(map(int, s[3:].split("."))))
                                 for s in san)
        extensions = der(0xA3, der(0x30, der(0x30, oid("2.5.29.17") + der(0x04, der(0x30, general_names)))))
    tbs = der(0x30, b"\xa0\x03\x02\x01\x02" + der(0x02, b"\x01") + der(0x30, oid(sig) + der(0x05, b""))
              + name(issuer or cn) + der(0x30, stamp(nb) + stamp(na)) + name(cn) + spki + extensions)
    return der(0x30, tbs + der(0x30, oid(sig) + der(0x05, b"")) + der(0x03, b"\x00" + os.urandom(32)))


def test_certificate_fields():
    cert = parse_certificate(build_cert("shop.example.test", san=["shop.example.test", "www.example.test", "ip:10.1.2.3"]))
    assert cert["subject"]["commonName"] == "shop.example.test" and cert["self_signed"] is True
    assert cert["sig_alg"] == "sha256WithRSAEncryption" and cert["weak_sig"] is False
    assert (cert["key_type"], cert["key_bits"]) == ("RSA", 2048)
    assert cert["san"] == ["shop.example.test", "www.example.test", "10.1.2.3"]


def test_issuer_differs_and_generalized_time_dates():
    cert = parse_certificate(build_cert("a.test", issuer="Some CA", not_before=calendar.timegm((2049, 1, 1, 0, 0, 0)),
                                        not_after=calendar.timegm((2060, 1, 1, 0, 0, 0)), general_time=True))
    assert cert["self_signed"] is False and cert["issuer"]["commonName"] == "Some CA"
    assert cert["not_before"] == calendar.timegm((2049, 1, 1, 0, 0, 0)) and cert["not_after"] > cert["not_before"]


def test_ec_key_details():
    cert = parse_certificate(build_cert(key=EC_KEY))
    assert cert["key_type"] == "EC P-256" and cert["key_bits"] == 256


def test_expired_certificate_facts():
    facts = tlsmod.certificate_facts(build_cert(not_before=time.time() - 86400 * 400, not_after=time.time() - 86400 * 5))
    assert facts["expired"] is True and facts["days_left"] <= -5 and facts["not_yet_valid"] is False
    tls = {"version": "TLSv1.3", **facts}
    found = [f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 443, "service": "HTTPS", "banner": "", "tls": tls}]})
             if f["id"] == "tls_expired"]
    assert found and found[0]["severity"] == "high" and found[0]["params"]["days"] >= 5


def test_expiring_soon_and_not_yet_valid():
    soon = tlsmod.certificate_facts(build_cert(not_after=time.time() + 86400 * 10 + 60))
    assert soon["expired"] is False and 9 <= soon["days_left"] <= 10
    future = tlsmod.certificate_facts(build_cert(not_before=time.time() + 86400 * 3, not_after=time.time() + 86400 * 90))
    assert future["not_yet_valid"] is True

    def ids(tls):
        return {f["id"] for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 443, "service": "HTTPS", "banner": "", "tls": {"version": "TLSv1.3", **tls}}]})}
    assert "tls_expiring" in ids(soon) and "tls_not_yet_valid" in ids(future)


def test_weak_signature_and_short_key_are_findings():
    weak = tlsmod.certificate_facts(build_cert(sig=SHA1_RSA, bits=1024))
    assert weak["weak_sig"] is True and weak["key_bits"] == 1024
    ids = {f["id"]: f for f in nemla.assess_host({"ip": "10.0.0.5", "open_ports": [{"port": 443, "service": "HTTPS", "banner": "", "tls": {"version": "TLSv1.2", **weak}}]})}
    assert ids["tls_weak_sig"]["severity"] == "medium" and "sha1" in ids["tls_weak_sig"]["evidence"]
    assert ids["tls_weak_key"]["severity"] == "medium" and "1024" in ids["tls_weak_key"]["evidence"]
    assert tlsmod.certificate_facts(build_cert(sig=MD5_RSA))["weak_sig"] is True
    good = tlsmod.certificate_facts(build_cert())
    assert good["weak_sig"] is False and good["key_bits"] == 2048


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x30\x03\x01\x02", b"A" * 100,
                                  b"\x30\x82" + b"\xff" * 10, os.urandom(300)])
def test_malformed_certificates_raise_only_x509_error(data):
    with pytest.raises(X509Error):
        parse_certificate(data)


def test_truncation_and_bit_flips_never_crash_the_parser():
    good = build_cert("fuzz.test", san=["fuzz.test"])
    rng = random.Random(1234)  # noqa: S311 - a seeded fuzzer, not a secret
    for cut in range(0, len(good), 3):
        try:
            parse_certificate(good[:cut])
        except X509Error:
            pass
    for _ in range(400):
        mutated = bytearray(good)
        for _ in range(rng.randint(1, 4)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        try:
            parse_certificate(bytes(mutated))
        except X509Error:
            pass                                                # any other exception type would fail the test


def test_oversized_certificate_is_refused():
    with pytest.raises(X509Error):
        parse_certificate(b"\x30\x83\x10\x00\x00" + b"\x00" * 300000)
    assert tlsmod.certificate_facts(b"\x00" * 10) == {"cert_error": "unreadable certificate"}


def test_hostile_names_are_cleaned_in_the_facts():
    facts = tlsmod.certificate_facts(build_cert("evil\x1b[31m.test\u202e"))
    assert "\x1b" not in facts["subject"] and "\u202e" not in facts["subject"]


# --------------------------------------------------------------------------
# OS fingerprinting: evidence, confidence, honesty
# --------------------------------------------------------------------------

def open_port(port, service="X", **extra):
    return {"port": port, "proto": "tcp", "state": "open", "service": service, "banner": "", **extra}


def test_ttl_alone_is_a_weak_labelled_guess():
    guess = osd.guess_os_detailed(64, [])
    assert guess.family == "unix" and guess.heuristic is True and 0 < guess.confidence <= 0.35 and guess.label == "low"
    assert any("TTL 64" in line for line in guess.evidence)
    windows = osd.guess_os_detailed(127, [])
    assert windows.family == "windows" and windows.heuristic is True and windows.confidence <= 0.5
    assert osd.guess_os_detailed(None, []).family == "unknown"
    assert osd.guess_os_detailed(None, []).confidence == 0.0


@pytest.mark.parametrize("observed, initial", [(1, 32), (32, 32), (33, 64), (64, 64), (65, 128), (117, 128), (128, 128),
                                               (129, 255), (250, 255)])
def test_initial_ttl_estimate(observed, initial):
    assert osd.initial_ttl(observed) == initial


def test_a_banner_naming_the_os_is_stronger_but_never_certain():
    ports = [open_port(22, "SSH", os_hint="Ubuntu Linux", product="OpenSSH", version="9.6"),
             open_port(80, "HTTP", os_hint="Ubuntu Linux")]
    guess = osd.guess_os_detailed(64, ports)
    assert guess.family == "linux" and guess.name == "Ubuntu Linux" and guess.heuristic is False
    assert 0.6 <= guess.confidence <= 0.92 and guess.confidence < 1.0
    assert sum("Ubuntu" in e for e in guess.evidence) == 2


def test_conflicting_evidence_lowers_confidence_and_is_shown():
    agree = osd.guess_os_detailed(128, [open_port(3389, "RDP"), open_port(445, "SMB"), open_port(135, "MS-RPC")])
    clash = osd.guess_os_detailed(128, [open_port(22, "SSH", os_hint="Ubuntu Linux")])
    assert agree.family == "windows" and agree.confidence > clash.confidence
    assert any("Windows" in e for e in clash.evidence) and any("Ubuntu" in e for e in clash.evidence)


def test_open_ports_are_only_heuristics():
    guess = osd.guess_os_detailed(None, [open_port(3389, "RDP")])
    assert guess.family == "windows" and guess.heuristic is True and guess.confidence <= osd.CAP_HEURISTIC
    assert osd.guess_os_detailed(None, [open_port(22, "SSH")]).family == "unix"


def test_iis_version_names_the_windows_release():
    guess = osd.guess_os_detailed(None, [open_port(80, "HTTP", product="Microsoft IIS", version="10.0", os_hint="Windows")])
    assert guess.family == "windows" and any("Windows 10 / Server 2016" in e for e in guess.evidence)


def test_mac_vendor_can_hint_at_linux_boards():
    guess = osd.guess_os_detailed(64, [open_port(22, "SSH")], vendor="Raspberry Pi Foundation")
    assert guess.family == "linux" and "Raspberry" in guess.name


@pytest.mark.parametrize("window, options, family", [
    (64240, ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"], "linux"),
    (65535, ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"], "windows"),
    (65535, ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK", "EOL"], "apple"),
    (65535, ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"], "bsd"),
    (4128, ["MSS"], "network"),
])
def test_syn_ack_shapes(window, options, family):
    votes = osd.classify_syn_ack(window, options, True)
    assert votes and votes[0][0] == family and votes[0][1] <= 0.55 and "window=" in votes[0][2]


def test_syn_ack_with_df_clear_hints_at_embedded_stacks_and_unknown_shapes_vote_nothing():
    assert any(f == "network" for f, _, _ in osd.classify_syn_ack(8192, ["MSS", "NOP"], False))
    assert osd.classify_syn_ack(1234, ["Weird", "Option"], True) == []


def test_syn_evidence_feeds_the_guess_but_stays_heuristic():
    tcp = {"window": 64240, "options": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"], "df": True, "ttl": 64}
    guess = osd.guess_os_detailed(64, [], tcp)
    assert guess.family == "linux" and guess.heuristic is True and guess.confidence <= osd.CAP_HEURISTIC
    assert any("SYN-ACK" in e for e in guess.evidence)


def test_syn_fingerprint_without_scapy_is_a_clean_none():
    if osd.HAVE_SCAPY:
        pytest.skip("scapy is installed here")
    assert osd.syn_fingerprint("127.0.0.1", 80) is None and osd.syn_fingerprint("::1", 80) is None


def test_os_result_shape_and_legacy_text():
    guess = osd.guess_os_detailed(64, [open_port(22, "SSH", os_hint="Debian Linux")])
    data = guess.as_dict()
    assert set(data) == {"family", "name", "confidence", "label", "heuristic", "evidence"}
    assert osd.os_display(guess, 64) == "Debian Linux (TTL=64)"
    assert nemla.guess_os(64, [open_port(22, "SSH")]).startswith("Linux")


def test_scan_records_carry_os_confidence_and_evidence(tcp_server):
    import time as _t
    port = tcp_server(lambda c: (c.sendall(b"SSH-2.0-OpenSSH_9.6p1 Debian-5\r\n"), _t.sleep(0.2), c.close()))
    hosts, _ = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_ping=True, timeout=1.0)
    host = hosts[0]
    assert host["os"]["family"] == "linux" and host["os"]["evidence"] and 0 < host["os"]["confidence"] < 1
    assert "Debian" in host["os_guess"]


def test_no_os_skips_the_guess(tcp_server):
    port = tcp_server(lambda c: c.close())
    hosts, _ = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_ping=True, no_os=True, timeout=1.0)
    assert hosts[0]["ttl"] is None and hosts[0]["os_guess"] == "Skipped" and hosts[0]["os"]["family"] == "unknown"
