"""History with UUID ids, path safety, and the richer scan comparison."""
import json
import os
import time
import types
import uuid
from pathlib import Path

import pytest

import nemla
from nemla import history
from nemla.findings import assess_host

META = {"target": "10.0.0.0/24", "scan_time": "2026-01-01 10:00:00", "duration": 1.0, "ports_scanned": 3, "discovered": 1,
        "cancelled": False, "findings": {"info": 0, "low": 0, "medium": 0, "high": 0}}


def port(number, proto="tcp", **extra):
    base = {"port": number, "proto": proto, "state": "open", "service": "X", "banner": ""}
    base.update(extra)
    return base


def host(ip="10.0.0.5", ports=(), os=None, **extra):
    h = {"ip": ip, "mac": None, "os_guess": (os or {}).get("name", "Linux"), "ttl": 64, "open_ports": list(ports), **extra}
    if os:
        h["os"] = os
    h["findings"] = assess_host(h)
    return h


# --------------------------------------------------------------------------
# ids and storage
# --------------------------------------------------------------------------

def test_scans_saved_within_one_clock_tick_keep_their_order(tmp_path, monkeypatch):
    """Windows with Python before 3.11 reads the clock in ~15 ms steps, so back-to-back saves shared one time and the
    'previous scan' of the second was lost (found by the Windows 3.8 CI job)."""
    monkeypatch.setattr(history, "time", types.SimpleNamespace(time=lambda: 1_700_000_000.0))
    first, second, third = (history.save(tmp_path, nemla, META, [host()]) for _ in range(3))
    assert [entry["id"] for entry in history.list_scans(tmp_path)] == [third, second, first]
    assert history.previous_for(tmp_path, META["target"], third) == second
    assert history.previous_for(tmp_path, META["target"], second) == first
    assert history.previous_for(tmp_path, META["target"], first) is None


def test_scan_ids_are_uuids_and_unique(tmp_path):
    ids = [history.save(tmp_path, nemla, META, [host()]) for _ in range(5)]
    assert len(set(ids)) == 5
    for scan_id in ids:
        assert str(uuid.UUID(scan_id)) == scan_id and uuid.UUID(scan_id).version == 4


def test_a_scans_own_id_is_reused_and_never_overwritten(tmp_path):
    own = str(uuid.uuid4())
    first = history.save(tmp_path, nemla, dict(META, scan_id=own), [host()])
    assert first == own and history.load(tmp_path, own)["scan_id"] == own
    second = history.save(tmp_path, nemla, dict(META, scan_id=own), [host("10.0.0.6")])     # same id again
    assert second != own and history.load(tmp_path, own)["hosts"][0]["ip"] == "10.0.0.5"
    forged = history.save(tmp_path, nemla, dict(META, scan_id="../../evil"), [host()])
    assert history.valid_id(forged) and forged != "../../evil"


@pytest.mark.parametrize("bad", ["../../etc/passwd", "..", ".", "", "a/b", "a\\b", "C:\\Windows\\win.ini", "x" * 500,
                                 "not-a-uuid", "12345678-1234-1234-1234-12345678901g", "../" + str(uuid.uuid4()),
                                 str(uuid.uuid4()) + "/../x", str(uuid.uuid4()) + "\x00", None, 5, ["a"]])
def test_ids_that_could_leave_the_folder_are_refused(tmp_path, bad):
    (tmp_path / "secret.json").write_text('{"hosts": []}')
    assert history.valid_id(bad) is False
    assert history.load(tmp_path, bad) is None


def test_legacy_timestamp_ids_still_load(tmp_path):
    folder = history.folder(tmp_path)
    folder.mkdir(parents=True)
    (folder / "20250101-101010-10.0.0.0_24.json").write_text(json.dumps({"target": "t", "hosts": [{"ip": "1.2.3.4"}]}))
    assert history.load(tmp_path, "20250101-101010-10.0.0.0_24")["hosts"][0]["ip"] == "1.2.3.4"
    assert [s["id"] for s in history.list_scans(tmp_path)] == ["20250101-101010-10.0.0.0_24"]


def test_oversized_and_corrupt_files_are_ignored(tmp_path, monkeypatch):
    scan_id = history.save(tmp_path, nemla, META, [host()])
    path = history.folder(tmp_path) / f"{scan_id}.json"
    monkeypatch.setattr(history, "MAX_FILE", 10)
    assert history.load(tmp_path, scan_id) is None and history.list_scans(tmp_path) == []
    monkeypatch.undo()
    path.write_text("{ not json")
    assert history.load(tmp_path, scan_id) is None
    path.write_text(json.dumps({"hosts": "not a list"}))
    assert history.load(tmp_path, scan_id) is None


def test_files_are_written_atomically_and_privately(tmp_path):
    scan_id = history.save(tmp_path, nemla, META, [host()])
    names = os.listdir(history.folder(tmp_path))
    assert names == [f"{scan_id}.json"]                                      # no temp files left behind
    if os.name == "posix":
        assert oct((history.folder(tmp_path) / names[0]).stat().st_mode & 0o777) == "0o600"
        assert oct(history.folder(tmp_path).stat().st_mode & 0o777) == "0o700"


def test_a_failed_write_leaves_no_partial_file(tmp_path, monkeypatch):
    def boom(meta, hosts, lang=None):
        raise OSError("disk full")
    monkeypatch.setattr(history, "json_text", boom)
    with pytest.raises(OSError):
        history.save(tmp_path, nemla, META, [host()])
    assert list(history.folder(tmp_path).iterdir()) == []


def test_save_tolerates_chmod_failing_on_the_folder_and_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError("chmod not supported here")))
    scan_id = history.save(tmp_path, nemla, META, [host()])
    assert history.load(tmp_path, scan_id)["hosts"][0]["ip"] == "10.0.0.5"


def test_save_propagates_the_original_error_when_its_own_cleanup_also_fails(tmp_path, monkeypatch):
    """Both os.replace and the cleanup's own os.unlink fail: the original error must still propagate, not a
    secondary one from the failed cleanup."""
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    monkeypatch.setattr(os, "unlink", lambda *a, **k: (_ for _ in ()).throw(OSError("already gone")))
    with pytest.raises(OSError, match="disk full"):
        history.save(tmp_path, nemla, META, [host()])


def test_saved_at_falls_back_to_zero_when_the_file_is_gone():
    assert history._saved_at(Path("/nonexistent") / "gone.json", {}) == 0.0


def test_prune_skips_files_it_cannot_stat_and_tolerates_unlink_failures(tmp_path, monkeypatch):
    folder = tmp_path / "history"
    folder.mkdir()
    names = [f"20260101-00000{i}-t.json" for i in range(4)]
    for name in names:
        (folder / name).write_text("{}", encoding="utf-8")

    real_stat, real_unlink = Path.stat, Path.unlink

    def hostile_stat(self, *a, **k):
        if self.name == names[0]:
            raise OSError("vanished mid-scan")
        return real_stat(self, *a, **k)

    def hostile_unlink(self, *a, **k):
        if self.name == names[1]:
            raise OSError("permission denied")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "stat", hostile_stat)
    monkeypatch.setattr(Path, "unlink", hostile_unlink)
    history.prune(folder, keep=1)
    remaining = {p.name for p in folder.glob("*.json")}
    # names[0]: stat failed, never a delete candidate. names[1]: selected for deletion, but unlink failed.
    # names[3]: newest, kept. names[2]: the only one actually removed.
    assert remaining == {names[0], names[1], names[3]}


@pytest.mark.skipif(os.name != "posix", reason="unprivileged symlinks need Windows developer mode")
def test_load_refuses_a_saved_scan_file_that_is_a_symlink_leaving_the_folder(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"target": "t", "hosts": []}), encoding="utf-8")
    folder = history.folder(tmp_path)
    folder.mkdir(parents=True)
    scan_id = str(uuid.uuid4())
    os.symlink(outside, folder / f"{scan_id}.json")
    assert history.load(tmp_path, scan_id) is None


def test_entries_ignores_files_whose_name_is_not_a_valid_scan_id(tmp_path):
    folder = history.folder(tmp_path)
    folder.mkdir(parents=True)
    (folder / "not-a-valid-scan-id.json").write_text(json.dumps({"target": "t", "hosts": []}), encoding="utf-8")
    real_id = history.save(tmp_path, nemla, META, [host()])
    assert [s["id"] for s in history.list_scans(tmp_path)] == [real_id]


def test_only_the_newest_scans_are_kept(tmp_path):
    ids = [history.save(tmp_path, nemla, META, [host()]) for _ in range(4)]
    history.prune(history.folder(tmp_path), keep=2)
    assert sorted(p.stem for p in history.folder(tmp_path).glob("*.json")) == sorted(ids[-2:]) or len(list(history.folder(tmp_path).glob("*.json"))) == 2


def test_previous_for_finds_the_scan_before_by_time_not_by_name(tmp_path):
    a = history.save(tmp_path, nemla, META, [host()])
    time.sleep(0.02)
    other = history.save(tmp_path, nemla, dict(META, target="somewhere else"), [host()])
    time.sleep(0.02)
    b = history.save(tmp_path, nemla, META, [host()])
    time.sleep(0.02)
    c = history.save(tmp_path, nemla, META, [host()])
    assert history.previous_for(tmp_path, META["target"], c) == b
    assert history.previous_for(tmp_path, META["target"], b) == a
    assert history.previous_for(tmp_path, META["target"], a) is None
    assert history.previous_for(tmp_path, META["target"], "99999999-999999-~") == c       # the old "newest" placeholder
    assert history.previous_for(tmp_path, "somewhere else", other) is None


def test_saved_scan_round_trips_and_re_renders_in_other_languages(tmp_path):
    h = host(ports=[port(23, detected="telnet", service="Telnet", confidence=0.9, heuristic=False)])
    scan_id = history.save(tmp_path, nemla, dict(META, findings=nemla.summarize_findings([h])), [h])
    data = history.load(tmp_path, scan_id)
    assert data["hosts"][0]["findings"][0]["id"] == "telnet" and data["saved_at"] > 0
    body, _ctype, _ext = nemla.reports.report_bytes("html", history.meta_of(data), data["hosts"], "he")
    assert 'dir="rtl"' in body.decode("utf-8") and "טקסט גלוי" in body.decode("utf-8")


# --------------------------------------------------------------------------
# comparison
# --------------------------------------------------------------------------

def test_new_and_removed_hosts_and_opened_closed_ports():
    old = [host("10.0.0.5", [port(22), port(80)]), host("10.0.0.6")]
    new = [host("10.0.0.5", [port(22), port(443), port(53, "udp")]), host("10.0.0.7")]
    diff = nemla.diff_scans(old, new)
    assert diff["new_hosts"] == ["10.0.0.7"] and diff["gone_hosts"] == ["10.0.0.6"]
    entry = diff["hosts"]["10.0.0.5"]
    assert entry["opened"] == [443, "53/udp"] and entry["closed"] == [80]
    assert diff["summary"]["opened_ports"] == 2 and diff["summary"]["worse"] is True


def test_tcp_and_udp_ports_with_the_same_number_are_different_ports():
    old = [host(ports=[port(53, "tcp")])]
    new = [host(ports=[port(53, "udp")])]
    entry = nemla.diff_scans(old, new)["hosts"]["10.0.0.5"]
    assert entry["opened"] == ["53/udp"] and entry["closed"] == [53]


def test_service_product_and_version_changes():
    old = [host(ports=[port(80, product="nginx", version="1.22.1", detected="http", heuristic=False),
                       port(22, product="OpenSSH", version="8.9", detected="ssh", heuristic=False),
                       port(8080, service="HTTP", detected="http", heuristic=False)])]
    new = [host(ports=[port(80, product="Apache httpd", version="2.4.58", detected="http", heuristic=False),
                       port(22, product="OpenSSH", version="9.6", detected="ssh", heuristic=False),
                       port(8080, service="Redis", detected="redis", heuristic=False)])]
    changed = {c["port"]: c for c in nemla.diff_scans(old, new)["hosts"]["10.0.0.5"]["changed"]}
    assert changed[80]["kind"] == "product" and changed[22]["kind"] == "version" and changed[22]["to"] == "OpenSSH 9.6"
    assert changed[8080]["kind"] == "service" and changed[8080]["from"] == "HTTP" and changed[8080]["to"] == "Redis"


def test_a_guess_that_becomes_a_detection_is_not_a_change():
    old = [host(ports=[port(80, service="HTTP", detected="http", heuristic=True)])]
    new = [host(ports=[port(80, service="SSH", detected="ssh", heuristic=False)])]
    assert nemla.diff_scans(old, new)["hosts"] == {}


def test_os_changes_only_between_different_families():
    def guessed(family, name):
        return {"family": family, "name": name, "confidence": 0.6, "label": "medium", "heuristic": True, "evidence": []}
    lin, win = guessed("linux", "Linux"), guessed("windows", "Windows")
    ubuntu = guessed("linux", "Ubuntu Linux")
    assert nemla.diff_scans([host(os=lin)], [host(os=win)])["hosts"]["10.0.0.5"]["os"] == {"from": "Linux", "to": "Windows"}
    assert nemla.diff_scans([host(os=lin)], [host(os=ubuntu)])["hosts"] == {}          # only got more specific
    assert nemla.diff_scans([host(os=lin)], [host(os=lin)])["summary"]["changed"] is False
    legacy_old = [{"ip": "10.0.0.5", "os_guess": "Linux (TTL=64)", "open_ports": []}]
    legacy_new = [{"ip": "10.0.0.5", "os_guess": "Windows (TTL=128)", "open_ports": []}]
    assert nemla.diff_scans(legacy_old, legacy_new)["hosts"]["10.0.0.5"]["os"]["to"] == "Windows"
    assert nemla.diff_scans([host(os=guessed("unknown", "Unknown"))], [host(os=win)])["hosts"] == {}


def test_new_and_resolved_findings_by_id_port_and_proto():
    telnet = port(23, detected="telnet", service="Telnet", confidence=0.9, heuristic=False)
    ftp = port(21, detected="ftp", service="FTP", confidence=0.9, heuristic=False)
    diff = nemla.diff_scans([host(ports=[telnet])], [host(ports=[ftp])])
    entry = diff["hosts"]["10.0.0.5"]
    assert [f["id"] for f in entry["new_findings"]] == ["ftp"] and [f["id"] for f in entry["resolved_findings"]] == ["telnet"]
    assert diff["summary"]["new_findings"] == 1 and diff["summary"]["resolved_findings"] == 1


def test_diff_lines_in_every_language():
    old = [host(ports=[port(80)])]
    new = [host(ports=[port(80), port(53, "udp")]), host("10.0.0.9")]
    diff = nemla.diff_scans(old, new)
    for lang, marker in (("en", "opened"), ("ar", "53/udp"), ("he", "53/udp")):
        nemla._LANG = lang
        try:
            text = "\n".join(nemla.diff_lines(diff))
        finally:
            nemla._LANG = "en"
        assert marker in text and "10.0.0.9" in text


def test_ipv6_hosts_compare_and_sort():
    old = [host("2001:db8::10"), host("2001:db8::9")]
    new = [host("2001:db8::9"), host("2001:db8::10"), host("2001:db8::11")]
    diff = nemla.diff_scans(old, new)
    assert diff["new_hosts"] == ["2001:db8::11"] and diff["gone_hosts"] == []
    assert list(diff["hosts"]) == []


def test_diff_command_and_fail_on_change(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(nemla.json_text(META, [host(ports=[port(22)])]), encoding="utf-8")
    b.write_text(nemla.json_text(META, [host(ports=[port(22), port(3389, detected="rdp", service="RDP")])]), encoding="utf-8")
    assert nemla.main(["--diff", str(a), str(b)]) == 0
    assert "3389" in capsys.readouterr().out
    assert nemla.main(["--diff", str(a), str(b), "--fail-on-change"]) == 3
    assert nemla.main(["--diff", str(b), str(a), "--fail-on-change"]) == 0
    assert nemla.main(["--diff", str(a), str(tmp_path / "missing.json")]) == 1
