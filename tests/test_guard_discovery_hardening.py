"""Guard confidence and evidence, ARP discovery fallback, and the security audit of the source."""
import json
import logging
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

import nemla
from nemla import discovery, guard
from nemla.discovery import arp
from nemla_ui import launcher

ROOT = Path(nemla.__file__).resolve().parent
REPO = ROOT.parent

GW, A, B, X = "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.9"
M_GW, M_A, M_B, M_X = "a4:2b:b0:1c:9e:10", "00:1a:2b:03:04:05", "00:1a:2b:03:04:06", "02:aa:bb:cc:dd:ee"


def learned(table):
    state = guard.new_state()
    guard.evaluate_sweep(table, state, GW)
    return state


# --------------------------------------------------------------------------
# guard: an ARP change is a hint, never a verdict
# --------------------------------------------------------------------------

def test_arp_change_alert_carries_confidence_and_evidence():
    state = learned({GW: M_GW, A: M_A})
    alert = next(a for a in guard.evaluate_sweep({GW: M_GW, A: M_X}, state, GW) if a["kind"] == "arp_change")
    assert 0 < alert["confidence"] < 0.5 and alert["evidence"]
    assert any(M_A in line and M_X in line for line in alert["evidence"])
    assert any("locally administered" in line for line in alert["evidence"])


def test_a_gateway_change_is_more_suspicious_but_never_certain():
    state = learned({GW: M_GW, A: M_A})
    gateway = next(a for a in guard.evaluate_sweep({GW: M_X, A: M_A}, state, GW) if a["kind"] == "arp_change")
    state = learned({GW: M_GW, A: M_A})
    other = next(a for a in guard.evaluate_sweep({GW: M_GW, A: M_X}, state, GW) if a["kind"] == "arp_change")
    assert gateway["confidence"] > other["confidence"] and gateway["severity"] == "high" and gateway["confidence"] < 0.86
    assert any("default gateway" in line for line in gateway["evidence"])


def test_flapping_raises_confidence_but_it_is_capped():
    table = {GW: M_GW, A: M_A}
    state = learned(table)
    last = 0
    for i in range(6):
        table = {GW: M_X if i % 2 == 0 else M_GW, A: M_A}
        for alert in guard.evaluate_sweep(table, state, GW):
            if alert["kind"] == "arp_change":
                last = alert["confidence"]
    assert 0.6 <= last <= 0.85 and state["flaps"][GW] == 6


def test_a_known_device_moving_to_a_new_address_lowers_the_suspicion():
    state = learned({A: M_A, B: M_B})
    plain = guard.arp_change_assessment(A, M_A, M_X, {A: M_X, B: M_B}, state, False)
    moved = guard.arp_change_assessment(A, M_A, M_B, {A: M_B}, state, False)      # M_B is trusted, last seen at B
    assert moved[0] < plain[0] and any("new address" in line for line in moved[1])


def test_old_mac_still_answering_elsewhere_is_reported_as_evidence():
    state = learned({A: M_A})
    _confidence, evidence = guard.arp_change_assessment(A, M_A, M_X, {A: M_X, B: M_A}, state, False)
    assert any("still answers for another address" in line for line in evidence)


def test_new_device_and_duplicate_gateway_alerts_have_evidence():
    state = learned({GW: M_GW})
    alerts = {a["kind"]: a for a in guard.evaluate_sweep({GW: M_GW, X: M_X}, state, GW)}
    assert alerts["new_device"]["confidence"] == 0.9 and "baseline" in alerts["new_device"]["evidence"][0]
    alerts = {a["kind"]: a for a in guard.evaluate_sweep({GW: M_GW, A: M_GW}, state, GW)}
    assert alerts["arp_dup"]["confidence"] <= 0.5 and any("proxy ARP" in line for line in alerts["arp_dup"]["evidence"])


def test_the_first_sweep_still_only_learns():
    assert [a["kind"] for a in guard.evaluate_sweep({GW: M_GW, A: M_A}, guard.new_state(), GW)] == ["baseline"]


def test_tripwire_alerts_explain_themselves(tcp_server):
    log = guard.AlertLog()
    watcher = guard.Guard(log, ports=[0], host="127.0.0.1", network=None, interval=0, gateway="", trusted_ips=(),
                          ignore_local=False)
    status = watcher.start()
    try:
        decoy = status["decoys"][0]
        import socket
        socket.create_connection(("127.0.0.1", decoy), timeout=2).close()
        alerts = log.wait(0, 3)
    finally:
        watcher.stop()
    alert = alerts[0]
    assert alert["kind"] == "tripwire" and alert["confidence"] == 0.8
    assert any("no legitimate service" in line for line in alert["evidence"]) and any("administrator" in line for line in alert["evidence"])


@pytest.mark.parametrize("lang, hedge", [("en", "can be ARP spoofing"), ("ar", "قد يكون"), ("he", "עשוי להיות")])
def test_arp_alert_wording_admits_uncertainty_in_every_language(lang, hedge):
    alert = {"kind": "arp_change", "severity": "medium", "src_ip": A, "mac": M_X,
             "detail": {"old_mac": M_A, "new_mac": M_X, "gateway": False}}
    nemla._LANG = lang
    try:
        text = nemla.alert_text(alert)
        gateway = nemla.alert_text({**alert, "detail": {**alert["detail"], "gateway": True}})
        dup = nemla.alert_text({"kind": "arp_dup", "src_ip": GW, "mac": M_X, "detail": {"ips": [GW, A]}})
    finally:
        nemla._LANG = "en"
    assert hedge in text
    assert "classic sign" not in gateway and "علامة كلاسيكية" not in gateway and "סימן קלאסי" not in gateway
    assert "proxy" in dup or "proxy ARP" in dup


def test_confidence_words():
    assert nemla.cli.alert_confidence({"confidence": 0.9}) == "high confidence"
    assert nemla.cli.alert_confidence({"confidence": 0.5}) == "medium confidence"
    assert nemla.cli.alert_confidence({"confidence": 0.2}) == "low confidence"
    assert nemla.cli.alert_confidence({}) is None


def test_a_crashing_sweep_is_counted_and_logged_not_swallowed(caplog):
    def broken():
        raise RuntimeError("neighbour table unreadable")
    watcher = guard.Guard(guard.AlertLog(), ports=[], network="10.0.0.0/24", interval=0.05, sweep=broken)
    with caplog.at_level(logging.WARNING, logger="nemla"):
        watcher.start()
        deadline = time.monotonic() + 3
        while watcher.errors < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        watcher.stop()
    assert watcher.errors >= 2 and watcher.status()["errors"] >= 2
    assert any("guard sweep failed" in r.message for r in caplog.records)


def test_guard_state_is_saved_privately_and_atomically(tmp_path):
    path = tmp_path / "state.json"
    state = learned({GW: M_GW})
    guard.save_state(path, state)
    assert json.loads(path.read_text())["devices"] and not list(tmp_path.glob("*.tmp"))
    assert guard.load_state(path)["devices"] == state["devices"]
    path.write_text("{ broken")
    assert guard.load_state(path)["learning"] is True


def test_the_neighbour_table_is_polled_until_it_settles(monkeypatch):
    tables = iter([{}, {A: M_A}, {A: M_A, B: M_B}, {A: M_A, B: M_B}, {A: M_A, B: M_B}, {A: M_A, B: M_B}])
    last = {}

    def read():
        last.update(next(tables, last))
        return dict(last)
    monkeypatch.setattr(arp, "read_arp_table", read)
    started = time.monotonic()
    assert arp.wait_for_neighbors(settle=5.0) == {A: M_A, B: M_B}
    assert time.monotonic() - started < 2.5                 # it did not sleep the whole 5 seconds


def test_nudging_handles_both_families_and_junk():
    assert arp.nudge(["127.0.0.1", "::1", "not an ip", "127.0.0.2"], limit=10) >= 2
    assert arp.nudge([], limit=5) == 0


# --------------------------------------------------------------------------
# discovery: ARP is a first pass, never the whole answer
# --------------------------------------------------------------------------

@pytest.fixture()
def lan(monkeypatch):
    """127.0.0.x plays the part of a private LAN whose ARP table is incomplete."""
    monkeypatch.setattr(discovery, "is_local", lambda ip: ip.startswith("127.0.0."))
    monkeypatch.setattr(discovery, "icmp_ping", lambda ip, cancel=None: False)
    monkeypatch.setattr(discovery, "HAVE_SCAPY", False)


def test_incomplete_arp_is_completed_by_a_tcp_probe(lan, tcp_server, monkeypatch):
    port = tcp_server(lambda c: c.close(), host="127.0.0.2")
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda targets, cancel=None: {"127.0.0.1": M_A})
    diagnostics = nemla.Diagnostics()
    found = discovery.discover_hosts(["127.0.0.1", "127.0.0.2"], probe_ports=(port,), diagnostics=diagnostics, timeout=1.0)
    assert found["127.0.0.1"] == {"mac": M_A, "method": "ARP"}
    assert found["127.0.0.2"]["method"] == "ICMP/TCP"
    warning = diagnostics.as_list()[0]
    assert warning["code"] == "arp_incomplete" and "1 of 2" in warning["message"]


def test_the_fallback_can_be_switched_off(lan, tcp_server, monkeypatch):
    port = tcp_server(lambda c: c.close(), host="127.0.0.2")
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda targets, cancel=None: {"127.0.0.1": M_A})
    found = discovery.discover_hosts(["127.0.0.1", "127.0.0.2"], probe_ports=(port,), fallback=False, timeout=1.0)
    assert list(found) == ["127.0.0.1"]


def test_empty_arp_falls_back_to_probing_everything(lan, tcp_server, monkeypatch):
    """Every address is probed when ARP found nothing. (On Linux all of 127/8 is local, so a refused
    connection on an address with no listener also proves 'alive': both hosts here have a listener.)"""
    first = tcp_server(lambda c: c.close(), host="127.0.0.2")
    second = tcp_server(lambda c: c.close(), host="127.0.0.3")
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda targets, cancel=None: {})
    found = discovery.discover_hosts(["127.0.0.2", "127.0.0.3"], probe_ports=(first, second), timeout=1.0)
    assert sorted(found) == ["127.0.0.2", "127.0.0.3"]
    assert all(info["method"] == "ICMP/TCP" for info in found.values())


def test_macs_of_probed_hosts_are_read_from_the_neighbour_cache(lan, tcp_server, monkeypatch):
    port = tcp_server(lambda c: c.close(), host="127.0.0.2")
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda targets, cancel=None: {"127.0.0.1": M_A})
    monkeypatch.setattr(discovery, "read_arp_table", lambda: {"127.0.0.2": M_B})
    found = discovery.discover_hosts(["127.0.0.1", "127.0.0.2"], probe_ports=(port,), timeout=1.0)
    assert found["127.0.0.2"]["mac"] == M_B


def test_scapy_without_privileges_falls_back_to_the_neighbour_cache(lan, monkeypatch, capsys):
    monkeypatch.setattr(discovery, "HAVE_SCAPY", True)

    def denied(ips, cancel=None):
        raise PermissionError
    monkeypatch.setattr(discovery, "scapy_arp_scan", denied)
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda targets, cancel=None: {"127.0.0.1": M_A})
    found = discovery.discover_hosts(["127.0.0.1"], timeout=0.5)
    assert found["127.0.0.1"]["method"] == "ARP" and "elevated privileges" in capsys.readouterr().out


def test_public_and_ipv6_targets_skip_arp(tcp_server, monkeypatch):
    calls = []
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda *a, **k: calls.append(1) or {})
    monkeypatch.setattr(discovery, "icmp_ping", lambda ip, cancel=None: False)
    port = tcp_server(lambda c: c.close())
    assert "127.0.0.1" in discovery.discover_hosts(["127.0.0.1"], probe_ports=(port,), timeout=1.0)
    assert calls == []
    assert discovery.is_local("192.168.1.1") and not discovery.is_local("8.8.8.8") and not discovery.is_local("::1")
    assert not discovery.is_local("127.0.0.1")


def test_discovery_stops_when_cancelled(lan, monkeypatch):
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(discovery, "neighbor_sweep", lambda targets, cancel=None: {})
    started = time.monotonic()
    assert discovery.discover_hosts([f"127.0.0.{i}" for i in range(1, 60)], cancel=cancel, timeout=5.0) == {}
    assert time.monotonic() - started < 2.0


# --------------------------------------------------------------------------
# security audit of the source
# --------------------------------------------------------------------------

def python_files():
    return [*ROOT.rglob("*.py"), *(REPO / "nemla_ui").glob("*.py"), REPO / "nemla.py"]


def test_no_dangerous_calls_anywhere_in_the_code():
    banned = [r"shell\s*=\s*True", r"\bos\.system\(", r"\bos\.popen\(", r"(?<![\w.])eval\(", r"(?<![\w.])exec\(",
              r"\bpickle\b", r"\bmarshal\b", r"yaml\.load\(", r"tempfile\.mktemp\(", r"(?<![\w.])compile\(",
              r"__import__\(", r"subprocess\.getoutput"]
    hits = []
    for path in python_files():
        text = path.read_text(encoding="utf-8")
        for pattern in banned:
            for m in re.finditer(pattern, text):
                hits.append(f"{path.name}: {m.group()}")
    assert hits == []


def test_every_subprocess_call_takes_a_list_of_arguments():
    for path in python_files():
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"subprocess\.(run|Popen|call|check_output|check_call)\(\s*([^\n,)]*)", text):
            first = m.group(2).strip()
            assert not first.startswith(("f\"", "f'", "\"", "'")), f"{path.name}: string command {first!r}"


def test_the_web_page_never_builds_html_from_strings():
    for path in (REPO / "nemla_ui" / "web").glob("*.js"):
        text = path.read_bytes().decode("utf-8", "replace")
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert banned not in text, f"{path.name} uses {banned}"
    html = (REPO / "nemla_ui" / "web" / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), "inline scripts are blocked by the CSP anyway"
    assert not re.search(r"\son\w+\s*=", html)


def test_unsafe_temporary_files_are_not_used():
    for path in python_files():
        assert "mktemp(" not in path.read_text(encoding="utf-8").replace("mkstemp(", "")


def test_untrusted_json_is_only_ever_parsed_as_data():
    for path in python_files():
        text = path.read_text(encoding="utf-8")
        assert "object_hook" not in text and "object_pairs_hook" not in text, path.name


def test_deeply_nested_json_is_rejected_instead_of_crashing(tmp_path):
    from nemla import history
    folder = history.folder(tmp_path)
    folder.mkdir(parents=True)
    scan_id = "12345678-1234-4234-8234-123456789012"
    (folder / f"{scan_id}.json").write_text("[" * 200000 + "]" * 200000)
    assert history.load(tmp_path, scan_id) is None and history.list_scans(tmp_path) == []
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 200000)
    assert nemla.main(["--diff", str(deep), str(deep)]) == 1


def test_languages_are_isolated_between_threads():
    from nemla.i18n import t, use_lang
    seen = {}
    barrier = threading.Barrier(3)

    def worker(lang):
        with use_lang(lang):
            barrier.wait()
            for _ in range(200):
                if t("sev_high") != {"en": "High", "ar": "عالية", "he": "גבוהה"}[lang] and lang != "ar":
                    seen[lang] = False
                    return
            seen[lang] = True

    threads = [threading.Thread(target=worker, args=(lang,)) for lang in ("en", "he", "ar")]
    [t_.start() for t_ in threads]
    [t_.join() for t_ in threads]
    assert seen["en"] and seen["he"] and seen.get("ar", True)
    assert t("sev_high") == "High"                                      # the main thread was never touched


def test_reports_in_different_languages_can_be_rendered_at_the_same_time():
    meta = {"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 1}
    results, errors = {}, []

    def render(lang):
        try:
            for _ in range(30):
                page = nemla.render_html(meta, [], lang)
                assert f'lang="{lang}"' in page
            results[lang] = True
        except AssertionError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=render, args=(lang,)) for lang in ("en", "ar", "he") * 2]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and set(results) == {"en", "ar", "he"}


# --------------------------------------------------------------------------
# the desktop launcher: hostile paths must stay inert
# --------------------------------------------------------------------------

HOSTILE = ["/opt/my app/nemla.py", "/tmp/$(touch pwned).py", "/tmp/`touch pwned`.py", "/tmp/a;touch pwned;.py",
           "/tmp/it's here/n.py", "/tmp/%f%u.py", '/tmp/"quoted".py', "/tmp/new\nline.py", "/tmp/back\\slash.py"]


@pytest.mark.parametrize("script", HOSTILE)
def test_desktop_entry_exec_line_is_one_safe_command(script):
    entry = launcher.desktop_entry(["/usr/bin/python3", script, "--ui"])
    line = [ln for ln in entry.splitlines() if ln.startswith("Exec=")]
    assert len(line) == 1 and "\n" not in line[0]
    exec_line = line[0][5:]
    assert "%f" not in exec_line.replace("%%f", "") and "%u" not in exec_line.replace("%%u", "")
    assert "$(" not in exec_line.replace("\\$(", "") and "`" not in exec_line.replace("\\`", "")


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
@pytest.mark.parametrize("script", [s for s in HOSTILE if "\n" not in s])
def test_wrapper_script_does_not_run_anything_hidden_in_a_path(tmp_path, script):
    icon = tmp_path / "icon.svg"
    icon.write_text("<svg/>")
    launcher.ICON_SOURCE = icon
    real = tmp_path / "real script.py"
    real.write_text("print('ok')")
    launcher.install(data=tmp_path / "data", bin_dir=tmp_path / "bin", python="/bin/echo", script=real,
                     which=lambda name: None)
    wrapper = (tmp_path / "bin" / "nemla").read_text()
    quoted = launcher._shell_quote(script)
    probe = subprocess.run(["sh", "-c", f"cd {tmp_path}; printf '%s' {quoted}"], capture_output=True, encoding="utf-8")
    assert probe.stdout == script and not (tmp_path / "pwned").exists()
    assert wrapper.startswith("#!/bin/sh") and "exec " in wrapper
