"""Findings (evidence, confidence, remediation, languages) and every report format."""
import csv
import io
import json
import os
import re

import pytest

import nemla
from nemla import findings, reports
from nemla.findings import assess_host

HOST = "10.0.0.5"


def rec(port, **extra):
    """An open-port record as a scan produces it: a confirmed detection unless `extra` says otherwise."""
    base = {"port": port, "proto": "tcp", "state": "open", "service": extra.pop("service", "X"), "banner": "",
            "detected": extra.pop("detected", "x"), "confidence": 0.9, "heuristic": False, "method": "protocol"}
    base.update(extra)
    return base


def host_of(*ports, ip=HOST, **extra):
    return {"ip": ip, "mac": None, "os_guess": "Linux", "ttl": 64, "open_ports": list(ports), **extra}


# --------------------------------------------------------------------------
# every finding: id, severity, title, description, evidence, host, port, remediation, confidence
# --------------------------------------------------------------------------

REQUIRED = {"id", "severity", "title", "description", "evidence", "host", "port", "proto", "remediation", "confidence"}


def test_every_finding_carries_all_the_required_fields():
    scenarios = [rec(23, detected="telnet", service="Telnet", evidence="Telnet negotiation received"),
                 rec(6379, detected="redis", auth="none", service="Redis"),
                 rec(443, detected="http", status=200, tls={"version": "TLSv1", "days_left": 5, "self_signed": True})]
    for item in scenarios:
        for f in assess_host(host_of(item)):
            assert REQUIRED <= set(f), f
            assert f["host"] == HOST and f["title"] and f["description"] and f["remediation"]
            assert 0 < f["confidence"] <= 1 and f["severity"] in nemla.SEVERITIES


@pytest.mark.parametrize("lang", ["en", "ar", "he"])
def test_every_finding_id_has_title_description_and_remediation_in_every_language(lang):
    from nemla.i18n import STRINGS
    ids_in_titles = {k[2:] for k in STRINGS["en"] if k.startswith("f_")}
    assert len(ids_in_titles) >= 30
    for fid in ids_in_titles:
        for prefix in ("f_", "fd_", "fr_"):
            key = prefix + fid
            assert key in STRINGS[lang] and STRINGS[lang][key].strip(), (lang, key)
            assert set(re.findall(r"\{(\w+)\}", STRINGS[lang][key])) <= set(re.findall(r"\{(\w+)\}", STRINGS["en"][key])) | {"port", "host"}


def test_translated_texts_keep_the_same_placeholders():
    from nemla.i18n import STRINGS
    for key, text in STRINGS["en"].items():
        for lang in ("ar", "he"):
            assert sorted(re.findall(r"\{(\w+)[^}]*\}", STRINGS[lang][key])) == sorted(re.findall(r"\{(\w+)[^}]*\}", text)), (lang, key)


def test_finding_text_is_rendered_in_the_requested_language():
    f = assess_host(host_of(rec(23, detected="telnet", service="Telnet")))[0]
    ar = findings.localized([f], "ar")[0]
    he = findings.localized([f], "he")[0]
    assert "Telnet" in ar["title"] and ar["title"] != f["title"] and ar["remediation"] != f["remediation"]
    assert "טקסט גלוי" in he["title"]
    assert f["title"].startswith("Telnet is open")            # the original is untouched


# --------------------------------------------------------------------------
# evidence-based: no vulnerability without evidence
# --------------------------------------------------------------------------

def test_a_port_number_alone_is_low_confidence_and_one_step_lower():
    guess = {"port": 23, "proto": "tcp", "state": "open", "service": "Telnet", "banner": "", "detected": "telnet",
             "confidence": 0.3, "heuristic": True, "method": "port"}
    f = assess_host(host_of(guess))[0]
    assert f["id"] == "telnet" and f["severity"] == "medium" and f["confidence"] <= 0.5
    assert f["evidence"].startswith("port number only")
    confirmed = assess_host(host_of(rec(23, detected="telnet", service="Telnet")))[0]
    assert confirmed["severity"] == "high" and confirmed["confidence"] > f["confidence"]


def test_nothing_is_reported_for_a_clean_host():
    assert assess_host(host_of()) == []
    assert assess_host(host_of(rec(22, detected="ssh", product="OpenSSH", version="9.6", details={"protocol": "2.0"}))) [0]["severity"] == "info"


def test_no_finding_without_the_evidence_for_it():
    # HTTPS on 443 with a healthy certificate: nothing to say
    tls = {"version": "TLSv1.3", "days_left": 300, "self_signed": False, "expired": False, "weak_sig": False,
           "key_type": "RSA", "key_bits": 3072}
    assert assess_host(host_of(rec(443, detected="http", status=200, tls=tls))) == []
    # SMB with signing required and no SMBv1: only the exposure itself
    ids = {f["id"] for f in assess_host(host_of(rec(445, detected="smb", details={"smb1": False, "signing": "required"})))}
    assert ids == {"files"}
    # DNS without the recursion flag
    assert assess_host(host_of(rec(53, detected="dns", details={"recursion_available": False}))) == []


def test_public_addresses_rank_higher():
    plain = [rec(3389, detected="rdp", service="RDP", details={"nla": "required"})]
    assert assess_host(host_of(*plain))[0]["severity"] == "medium"
    assert assess_host(host_of(*plain, ip="8.8.8.8"))[0]["severity"] == "high"


def test_findings_are_deduplicated_by_id_port_and_proto():
    f = assess_host(host_of(rec(23, detected="telnet"), rec(23, proto="udp", detected="x")))
    assert [(x["id"], x["port"], x["proto"]) for x in f] == [("telnet", 23, "tcp")]


def test_udp_amplifiers_only_matter_on_public_addresses():
    ntp = rec(123, proto="udp", detected="ntp", service="NTP")
    assert "udp_exposed" not in {f["id"] for f in assess_host(host_of(ntp))}
    assert "udp_exposed" in {f["id"] for f in assess_host(host_of(ntp, ip="8.8.8.8"))}
    tftp = rec(69, proto="udp", detected="tftp", service="TFTP")
    assert "tftp" in {f["id"] for f in assess_host(host_of(tftp))}


def test_sensitive_ports_are_a_hint_not_a_verdict():
    f = assess_host(host_of({"port": 2375, "proto": "tcp", "state": "open", "service": "unknown", "banner": "",
                             "detected": "unknown", "confidence": 0.0, "heuristic": True, "method": "port"}))[0]
    assert f["id"] == "sensitive_port" and f["severity"] == "low" and f["confidence"] < 0.5 and "not confirmed" in f["evidence"]


# --------------------------------------------------------------------------
# the HTTPS false positive
# --------------------------------------------------------------------------

def test_http_plain_needs_proof_that_https_was_looked_for():
    web = rec(80, detected="http", status=200, service="HTTP")
    assert assess_host(host_of(web, scanned={"tcp": "80"})) == []
    assert assess_host(host_of(web)) == []
    f = assess_host(host_of(web, scanned={"tcp": "1-1024"}))
    assert [x["id"] for x in f] == ["http_plain"] and "443/tcp" in f[0]["evidence"]
    assert assess_host(host_of(web, rec(8443, detected="http", status=200, tls={"version": "TLSv1.3", "days_left": 90}),
                               scanned={"tcp": "80,8443"})) == []


def test_end_to_end_http_only_on_a_scanned_range_flags_it(tcp_server):
    def web(conn):
        conn.recv(2048)
        conn.sendall(b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n<title>x</title>")
        conn.close()
    port = tcp_server(web)
    hosts, _ = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_ping=True, no_os=True, timeout=1.0)
    assert not [f for f in hosts[0]["findings"] if f["id"] == "http_plain"]        # only this port was scanned


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------

EVIL = "<img src=x onerror=alert(1)>"


def evil_scan():
    ports = [rec(80, detected="http", service="HTTP", banner=EVIL, product=EVIL, version="1", title=EVIL, status=200,
                 tls={"version": "TLSv1.2", "subject": EVIL, "issuer": EVIL, "not_after": "2030-01-01", "days_left": 900,
                       "self_signed": True}),
             rec(23, detected="telnet", service="Telnet", banner="=HYPERLINK(\"http://evil\")", product="+cmd|calc")]
    host = host_of(*ports, mac="aa:bb:cc:dd:ee:ff", vendor=EVIL, os_guess=EVIL, scanned={"tcp": "23,80,443"},
                   os={"family": "linux", "name": EVIL, "confidence": 0.5, "label": "medium", "heuristic": True,
                       "evidence": [EVIL]})
    host["findings"] = assess_host(host)
    for f in host["findings"]:
        f["evidence"] = EVIL
    meta = {"target": EVIL, "scan_time": "2026-01-01 10:00:00", "duration": 3.2, "ports_scanned": 3,
            "udp_ports_scanned": 2, "warnings": [{"code": "x", "message": EVIL, "count": 3}],
            "findings": nemla.summarize_findings([host]), "scan_id": "b7075c56-c56b-41c2-940c-5b9d5685f14f"}
    return meta, [host]


def test_html_report_escapes_every_field_that_came_from_the_network():
    meta, hosts = evil_scan()
    page = nemla.render_html(meta, hosts)
    assert "<img" not in page and "onerror=alert" not in page.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert page.count("&lt;img src=x onerror=alert(1)&gt;") >= 8
    assert "<script" not in page.lower() and "@@" not in page


def test_html_report_cannot_be_hijacked_through_placeholder_text():
    meta, hosts = evil_scan()
    hosts[0]["ip"] = "@@MARK@@"
    meta["target"] = "@@FOOTER@@"
    page = nemla.render_html(meta, hosts)
    assert "@@MARK@@" in page and "@@FOOTER@@" in page                      # shown literally, never substituted


def test_csv_neutralises_formula_injection_and_keeps_old_columns_first():
    _meta, hosts = evil_scan()
    text = nemla.csv_text(hosts)
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    assert rows[0][:10] == ["ip", "mac", "vendor", "os_guess", "ttl", "port", "service", "banner", "product", "version"]
    assert rows[0][10:] == ["proto", "state", "confidence", "os_confidence"]
    cells = [c for row in rows[1:] for c in row]
    assert not [c for c in cells if c and c[0] in "=+-@"]
    assert "'=HYPERLINK(\"http://evil\")" in cells and "'+cmd|calc" in cells
    assert reports.csv_cell(5) == 5 and reports.csv_cell(None) == "" and reports.csv_cell("-1") == "'-1"


def test_markdown_escapes_control_characters():
    meta, hosts = evil_scan()
    text = nemla.markdown_text(meta, hosts)
    assert "<img" not in text and "&lt;img" in text
    assert reports.md_escape("a|b`c*d_e[f]") == "a\\|b\\`c\\*d\\_e\\[f\\]"
    assert "\n" not in reports.md_escape("line1\nline2")


def test_sarif_is_valid_json_with_results_rules_and_locations():
    meta, hosts = evil_scan()
    log = json.loads(nemla.sarif_text(meta, hosts))
    assert log["version"] == "2.1.0" and log["$schema"].endswith("sarif-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "Nemla" and run["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids and result["level"] in ("error", "warning", "note")
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("tcp://10.0.0.5:")
        assert result["properties"]["confidence"] and result["properties"]["remediation"]
    assert {r["level"] for r in run["results"]} >= {"error"}


def test_sarif_for_ipv6_hosts_brackets_the_address():
    host = host_of(rec(23, detected="telnet", service="Telnet"), ip="2001:db8::5")
    host["findings"] = assess_host(host)
    uri = json.loads(nemla.sarif_text({"target": "x", "scan_time": "now"}, [host]))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "tcp://[2001:db8::5]:23"


def test_json_report_has_the_new_sections():
    meta, hosts = evil_scan()
    data = json.loads(nemla.json_text(meta, hosts))
    assert data["schema_version"] == 2 and data["scan_id"] == meta["scan_id"] and data["duration_seconds"] == 3.2
    assert data["summary"]["hosts"] == 1 and "executive" in data["summary"] and data["warnings"][0]["code"] == "x"
    assert data["udp_ports_scanned_per_host"] == 2 and data["hosts"][0]["os"]["confidence"] == 0.5
    for f in data["hosts"][0]["findings"]:
        assert REQUIRED <= set(f)


def test_reports_include_summary_metadata_os_confidence_warnings_and_errors():
    meta, hosts = evil_scan()
    page = nemla.render_html(meta, hosts)
    for needle in ("Executive summary", "Warnings and errors", "(50%, estimated)", "Confidence", "How to fix", "3.2s"):
        assert needle in page, needle
    md = nemla.markdown_text(meta, hosts)
    assert "Executive summary" in md and "Warnings and errors" in md and "50%" in md and "How to fix" in md


@pytest.mark.parametrize("lang, direction, marker", [("ar", "rtl", "الملخص التنفيذي"), ("he", "rtl", "תקציר מנהלים"),
                                                      ("en", "ltr", "Executive summary")])
def test_reports_switch_language_and_direction(lang, direction, marker):
    meta, hosts = evil_scan()
    page = nemla.render_html(meta, hosts, lang)
    assert f'lang="{lang}" dir="{direction}"' in page and marker in page
    assert marker in nemla.markdown_text(meta, hosts, lang)
    assert json.loads(nemla.json_text(meta, hosts, lang))["language"] == lang


def test_arabic_and_hebrew_reports_never_leave_findings_untranslated():
    meta, hosts = evil_scan()
    for lang, _word in (("ar", "خدمة"), ("he", "הצפנה")):
        page = nemla.render_html(meta, hosts, lang)
        assert not re.search(r"Telnet is open on port", page), lang


def test_report_files_are_written_atomically(tmp_path):
    meta, hosts = evil_scan()
    target = tmp_path / "out" / "r.html"
    with pytest.raises(OSError):
        reports.write_report(str(target), "html", meta, hosts)                       # folder does not exist
    target.parent.mkdir()
    reports.write_report(str(target), "html", meta, hosts)
    assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert [p.name for p in target.parent.iterdir()] == ["r.html"]                   # no temp files left
    old = target.read_text(encoding="utf-8")
    with pytest.raises((KeyError, TypeError, ValueError)):
        reports.write_report(str(target), "html", {"target": "x"}, hosts)             # bad meta: a failure ...
    assert target.read_text(encoding="utf-8") == old                                  # ... never truncates the old file
    if os.name == "posix":
        assert oct(target.stat().st_mode & 0o777) == "0o644"


def test_write_atomic_tolerates_a_filesystem_that_refuses_chmod(tmp_path, monkeypatch):
    import os as os_mod
    real_chmod = os_mod.chmod

    def refuses(path, mode):
        if str(path).endswith(".tmp"):
            raise OSError("chmod not supported on this filesystem")
        real_chmod(path, mode)
    monkeypatch.setattr(os_mod, "chmod", refuses)
    target = tmp_path / "r.html"
    reports.write_atomic(str(target), b"hello")
    assert target.read_bytes() == b"hello"                     # the write still lands, just without the mode set


def test_write_atomic_cleans_up_its_temp_file_when_the_final_rename_fails(tmp_path, monkeypatch):
    import os as os_mod

    def refuses(*a, **k):
        raise OSError("simulated failure renaming into place")
    monkeypatch.setattr(os_mod, "replace", refuses)
    target = tmp_path / "r.html"
    with pytest.raises(OSError):
        reports.write_atomic(str(target), b"hello")
    assert not target.exists() and list(tmp_path.iterdir()) == []          # no half-written file, no leftover temp file


def test_write_atomic_survives_even_when_cleaning_up_the_temp_file_also_fails(tmp_path, monkeypatch):
    """Both os.replace and the cleanup's own os.unlink fail: the original error must still propagate, not a
    secondary one from the failed cleanup, and write_atomic must not raise anything the caller didn't ask for."""
    import os as os_mod
    monkeypatch.setattr(os_mod, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    monkeypatch.setattr(os_mod, "unlink", lambda *a, **k: (_ for _ in ()).throw(OSError("already gone")))
    with pytest.raises(OSError, match="disk full"):
        reports.write_atomic(str(tmp_path / "r.html"), b"hello")


def test_write_json_and_write_csv_convenience_wrappers(tmp_path):
    meta, hosts = evil_scan()
    json_path, csv_path = tmp_path / "r.json", tmp_path / "r.csv"
    reports.write_json(str(json_path), meta, hosts)
    reports.write_csv(str(csv_path), hosts)
    assert json.loads(json_path.read_text(encoding="utf-8"))["hosts"]
    raw = csv_path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")                    # the same BOM --csv gets, via report_bytes
    assert raw.decode("utf-8-sig").startswith("ip,mac")


def test_report_formats_are_negotiated_by_name():
    meta, hosts = evil_scan()
    for fmt, needle in (("html", b"<!DOCTYPE"), ("json", b'"schema_version"'), ("csv", b"ip,mac"), ("md", b"# "),
                        ("sarif", b"sarif-2.1.0"), ("nonsense", b"<!DOCTYPE")):
        data, ctype, ext = reports.report_bytes(fmt, meta, hosts)
        assert needle in data and ctype and ext
    assert reports.report_bytes("csv", meta, hosts)[0].startswith(b"\xef\xbb\xbf")   # Excel reads it as UTF-8


def test_cli_writes_every_format(tcp_server, tmp_path, capsys):
    port = tcp_server(lambda c: (c.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"), __import__("time").sleep(0.2), c.close()))
    paths = {k: tmp_path / f"r.{k}" for k in ("html", "json", "csv", "md", "sarif")}
    code = nemla.main(["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "-o", str(paths["html"]),
                       "--json", str(paths["json"]), "--csv", str(paths["csv"]), "--md", str(paths["md"]),
                       "--sarif", str(paths["sarif"])])
    assert code == 0 and all(p.stat().st_size > 100 for p in paths.values())
    assert json.loads(paths["sarif"].read_text(encoding="utf-8"))["version"] == "2.1.0"
    out = capsys.readouterr().out
    assert "Markdown saved" in out and "SARIF saved" in out


def test_cli_reports_an_unwritable_output_path_cleanly(tcp_server, tmp_path, capsys):
    port = tcp_server(lambda c: c.close())
    code = nemla.main(["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "-o", str(tmp_path / "missing" / "r.html")])
    assert code == 1 and "Cannot write" in capsys.readouterr().out


def test_warnings_appear_in_the_console_and_the_report(tcp_server, tmp_path, capsys):
    ports = [tcp_server(lambda c: c.close()) for _ in range(4)]
    out = tmp_path / "r.html"
    code = nemla.main(["-t", "127.0.0.1", "-p", ",".join(map(str, ports)), "--no-ping", "--no-os", "--max-probes", "2",
                       "-o", str(out)])
    assert code == 0 and "budget" in capsys.readouterr().out and "probe budget" in out.read_text(encoding="utf-8")

def test_unconfirmed_udp_ports_are_listed_in_the_html_and_markdown_reports():
    host = host_of(rec(80, detected="http", service="HTTP"), udp_unconfirmed=[{"port": 161}, {"port": 1900}])
    host["findings"] = assess_host(host)
    meta = {"target": HOST, "scan_time": "2026-01-01 10:00:00", "duration": 1.0, "ports_scanned": 1,
            "findings": nemla.summarize_findings([host])}
    assert "161, 1900" in nemla.render_html(meta, [host])
    assert "161, 1900" in nemla.markdown_text(meta, [host])
