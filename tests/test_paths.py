"""Files and folders on Windows and Linux: spaces, Arabic/Hebrew/emoji names, relative paths, pathlib objects, unwritable
places, temporary files that must not be left behind, and no path assembled from a hard-coded separator.

Everything Nemla writes goes through three places: write_atomic (reports), the history folder and the Guard's state file.
The tests use pytest's tmp_path, so they run on whatever the platform's temporary directory looks like.
"""
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

import nemla
from nemla import guard, history, reports

ROOT = Path(__file__).resolve().parent.parent

NAMES = ["plain", "with space", "  leading and trailing  ", "تقرير الشبكة", "דוח רשת", "emoji \U0001f41c report", "dots.in.name",
         "ünïcödé", "a" * 50,       # (kept short: on Windows the whole path must stay under MAX_PATH, 260 characters)
         "semi;colon", "quote'single", "amp&ersand", "hash#tag", "percent%20"]
if sys.platform != "win32":
    NAMES += ["back\\slash", "col:on", "star*"]          # legal on POSIX, forbidden on Windows


def meta_and_hosts():
    host = {"ip": "10.0.0.5", "mac": None, "discovery": "skipped", "os_guess": "Linux", "ttl": 64, "os": {}, "vendor": None,
            "scanned": {"tcp": "80", "udp": ""}, "udp_unconfirmed": [], "findings": [],
            "open_ports": [{"port": 80, "proto": "tcp", "state": "open", "service": "HTTP", "banner": "nginx", "product": "nginx",
                            "version": "1.24", "confidence": 0.9, "heuristic": False}]}
    meta = {"target": "10.0.0.5", "scan_time": "2026-09-21 10:00:00", "duration": 1.0, "ports_scanned": 1, "discovered": 1,
            "cancelled": False, "findings": {"high": 0, "medium": 0, "low": 0, "info": 0}, "warnings": [], "capabilities": {}}
    return meta, [host]


# ----------------------------------------------------------------------------------------------- reports

@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("fmt, ext", [("html", ".html"), ("json", ".json"), ("csv", ".csv"), ("md", ".md"), ("sarif", ".sarif")])
def test_reports_can_be_written_to_awkward_names(tmp_path, name, fmt, ext):
    folder = tmp_path / f"{name} dir"
    folder.mkdir()
    target = folder / (name + ext)
    meta, hosts = meta_and_hosts()
    reports.write_report(str(target), fmt, meta, hosts)
    assert target.is_file() and target.stat().st_size > 50
    assert [p.name for p in folder.iterdir()] == [target.name]                    # and no temporary file is left next to it


def test_a_pathlib_path_a_relative_path_and_dot_dot_all_work(tmp_path, monkeypatch):
    meta, hosts = meta_and_hosts()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    reports.write_report(Path("sub") / "a.json", "json", meta, hosts)               # a Path, relative
    reports.write_report(os.path.join("sub", "..", "b.json"), "json", meta, hosts)    # with ..
    reports.write_report("c.json", "json", meta, hosts)                             # bare file name in the current directory
    assert sorted(p.name for p in tmp_path.rglob("*.json")) == ["a.json", "b.json", "c.json"]


def test_a_missing_folder_or_a_folder_in_the_way_is_an_error_and_leaves_nothing_behind(tmp_path):
    meta, hosts = meta_and_hosts()
    with pytest.raises(OSError):
        reports.write_report(str(tmp_path / "no-such-folder" / "r.html"), "html", meta, hosts)
    (tmp_path / "taken").mkdir()
    with pytest.raises(OSError):
        reports.write_report(str(tmp_path / "taken"), "html", meta, hosts)          # the target is a directory
    assert [p.name for p in tmp_path.iterdir()] == ["taken"]


def test_an_existing_report_is_replaced_whole_or_not_at_all(tmp_path):
    meta, hosts = meta_and_hosts()
    target = tmp_path / "r.html"
    target.write_text("OLD", encoding="utf-8")
    reports.write_report(str(target), "html", meta, hosts)
    assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_files_are_not_group_or_world_writable_and_the_history_is_private(tmp_path):
    meta, hosts = meta_and_hosts()
    reports.write_report(str(tmp_path / "r.json"), "json", meta, hosts)
    assert not (tmp_path / "r.json").stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    scan_id = history.save(tmp_path, nemla, dict(meta), hosts)
    assert (history.folder(tmp_path) / f"{scan_id}.json").stat().st_mode & 0o777 == 0o600
    assert history.folder(tmp_path).stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX and a non-root user")
def test_an_unwritable_folder_is_an_error_not_a_traceback_in_the_cli(tmp_path, tcp_server):
    port = tcp_server(lambda c: c.close())
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        code = nemla.main(["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "--timeout", "0.5", "-o", str(locked / "r.html")])
    finally:
        locked.chmod(0o700)
    assert code == 1


# ----------------------------------------------------------------------------------------------- the command line

def test_the_cli_writes_every_format_to_unicode_paths_with_spaces(tmp_path, tcp_server):
    port = tcp_server(lambda c: c.close())
    folder = tmp_path / "نتائج الفحص - תוצאות"
    folder.mkdir()
    args = ["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "--timeout", "0.5", "-o", str(folder / "تقرير one.html"),
            "--json", str(folder / "דוח.json"), "--csv", str(folder / "טבלה.csv"), "--md", str(folder / "r e p o r t.md"),
            "--sarif", str(folder / "x.sarif")]
    assert nemla.main(args) == 0
    assert sorted(p.name for p in folder.iterdir()) == sorted(["تقرير one.html", "דוח.json", "טבלה.csv", "r e p o r t.md", "x.sarif"])
    assert json.loads((folder / "דוח.json").read_text(encoding="utf-8"))["hosts"]


# ----------------------------------------------------------------------------------------------- history and guard state

@pytest.mark.parametrize("name", ["data dir", "بيانات", "נתונים", "emoji \U0001f41c", "a" * 60])
def test_history_lives_in_any_data_folder(tmp_path, name):
    data = tmp_path / name
    meta, hosts = meta_and_hosts()
    first = history.save(data, nemla, dict(meta), hosts)
    second = history.save(data, nemla, dict(meta), hosts)
    assert history.load(data, first)["hosts"][0]["ip"] == "10.0.0.5"
    assert [s["id"] for s in history.list_scans(data)][:2] in ([second, first], [first, second])
    assert history.previous_for(data, "10.0.0.5", second) == first
    assert not [p for p in history.folder(data).iterdir() if p.name.endswith(".tmp")]


def test_a_history_folder_that_cannot_be_read_gives_empty_answers_not_crashes(tmp_path):
    data = tmp_path / "data"
    (data / "history").mkdir(parents=True)
    (data / "history" / "not-a-scan.json").write_text("{ broken", encoding="utf-8")
    (data / "history" / ("z" * 100 + ".json")).write_text("{}", encoding="utf-8")
    assert history.list_scans(data) == [] and history.previous_for(data, "x", "y") is None


@pytest.mark.parametrize("name", ["state dir", "حالة الحراسة", "מצב"])
def test_guard_state_and_alerts_live_in_any_folder(tmp_path, name):
    folder = tmp_path / name
    state = guard.new_state()
    guard.evaluate_sweep({"192.168.1.1": "aa:bb:cc:00:00:01"}, state, "192.168.1.1")
    guard.save_state(folder / "guard.json", state)
    assert guard.load_state(folder / "guard.json")["devices"] == state["devices"]
    log = guard.AlertLog(folder / "alerts.jsonl")
    log.add({"kind": "baseline", "severity": "info", "src_ip": None, "mac": None, "detail": {"devices": 1}})
    assert "baseline" in (folder / "alerts.jsonl").read_text(encoding="utf-8")
    assert not list(folder.glob("*.tmp"))


def test_the_data_folder_follows_the_platform_convention(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert guard.data_dir() == tmp_path / "xdg" / "nemla"
    monkeypatch.delenv("XDG_DATA_HOME")
    assert guard.data_dir() == Path.home() / ".local" / "share" / "nemla"        # the same on every platform, on purpose


def test_the_ui_server_keeps_its_data_in_a_folder_with_spaces_and_unicode(tmp_path):
    from nemla_ui import server
    data = tmp_path / "مجلد البيانات dir"
    app = server.App(nemla, data_dir=data)
    meta, hosts = meta_and_hosts()
    scan_id = history.save(app.data_dir, nemla, dict(meta), hosts)
    assert history.load(app.data_dir, scan_id)["hosts"]
    assert app.data_dir == data


def test_the_launcher_installs_into_folders_with_spaces_and_unicode(tmp_path):
    from nemla_ui import launcher
    data, bin_dir = tmp_path / "share dir" / "تطبيقات", tmp_path / "bin dir" / "בין"
    script = tmp_path / "some dir" / "nemla.py"
    script.parent.mkdir()
    script.write_text("# launcher", encoding="utf-8")
    assert launcher.install(data=data, bin_dir=bin_dir, python=sys.executable, script=str(script),
                            which=lambda name: None) == 0
    desktop = next(data.rglob("nemla.desktop"))
    text = desktop.read_text(encoding="utf-8")
    assert ("Exec=" in text and str(script).replace("\\", "\\\\") in text.replace("\\\\\\\\", "\\\\")) or "some dir" in text
    assert launcher.uninstall(data=data, bin_dir=bin_dir) == 0
    assert not list(data.rglob("nemla.desktop"))


# ----------------------------------------------------------------------------------------------- source hygiene

def test_no_path_is_built_from_a_hard_coded_separator_or_a_platform_specific_location():
    """Paths are built with pathlib / os.path.join. Linux-only files (/proc/net/...) appear only where the code first checks
    the platform; nothing else may contain an absolute POSIX or drive-letter path, or join with a literal '/' or '\\\\'."""
    allowed = {"/proc/net/arp", "/proc/net/route"}
    problems = []
    for path in [*(ROOT / "nemla").rglob("*.py"), *(ROOT / "nemla_ui").glob("*.py")]:
        if path.name in {"_strings_base.py", "strings_extra.py"}:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#")[0]
            for literal in re.findall(r"""["'](/(?:tmp|home|etc|var|usr|opt|root|proc|sys|dev)/[^"']*|[A-Za-z]:\\\\[^"']*)["']""", code):
                if not any(literal.startswith(ok) for ok in allowed):
                    problems.append(f"{path.relative_to(ROOT)}:{number}: {literal}")
            if re.search(r"""(?:\+|f["'][^"']*\{[^}]*\})\s*["']/["']|["']/["']\s*\+|\.split\(["']/["']\)|os\.sep""", code) and "http" not in code:
                problems.append(f"{path.relative_to(ROOT)}:{number}: {code.strip()[:80]}")
    assert problems == []
