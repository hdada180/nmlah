import http.client
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

import nemla
from nemla_ui import history, server


def port(n, **extra):
    return {"port": n, "service": nemla.service_name(n), "banner": "", **extra}


def finding(fid, severity, n, **params):
    return {"id": fid, "severity": severity, "port": n, "params": params}


def host(ip, ports=(), os_guess="Linux / Unix / macOS (TTL=64)", findings=()):
    return {"ip": ip, "mac": None, "os_guess": os_guess, "ttl": 64,
            "open_ports": list(ports), "findings": list(findings)}


# --------------------------------------------------------------------------
# comparing two scans
# --------------------------------------------------------------------------

def test_identical_scans_have_no_changes():
    hosts = [host("10.0.0.5", [port(22)]), host("10.0.0.6")]
    diff = nemla.diff_scans(hosts, hosts)
    assert diff["summary"]["changed"] is False and diff["summary"]["worse"] is False
    assert nemla.diff_lines(diff) == ["No changes since the previous scan."]


def test_new_and_vanished_hosts_are_listed_in_address_order():
    old = [host("10.0.0.9"), host("10.0.0.10"), host("10.0.0.2")]
    new = [host("10.0.0.9"), host("10.0.0.11"), host("10.0.0.3")]
    diff = nemla.diff_scans(old, new)
    assert diff["new_hosts"] == ["10.0.0.3", "10.0.0.11"]  # numeric order, not text order
    assert diff["gone_hosts"] == ["10.0.0.2", "10.0.0.10"]
    assert diff["summary"]["worse"] is True and diff["summary"]["gone_hosts"] == 2


def test_ports_that_opened_and_closed():
    old = [host("10.0.0.5", [port(22), port(80)])]
    new = [host("10.0.0.5", [port(22), port(443), port(8080)])]
    entry = nemla.diff_scans(old, new)["hosts"]["10.0.0.5"]
    assert entry["opened"] == [443, 8080] and entry["closed"] == [80]
    summary = nemla.diff_scans(old, new)["summary"]
    assert (summary["opened_ports"], summary["closed_ports"], summary["worse"]) == (2, 1, True)


def test_only_closing_a_port_is_not_worse():
    diff = nemla.diff_scans([host("10.0.0.5", [port(22), port(23)])], [host("10.0.0.5", [port(22)])])
    assert diff["summary"]["changed"] is True and diff["summary"]["worse"] is False


def test_product_or_version_changes_are_reported_only_when_both_sides_know_them():
    old = [host("10.0.0.5", [port(80, product="nginx", version="1.22.1"), port(22), port(21, product="vsftpd")])]
    new = [host("10.0.0.5", [port(80, product="nginx", version="1.24.0"), port(22, product="OpenSSH", version="9.6"),
                             port(21, product="vsftpd")])]
    entry = nemla.diff_scans(old, new)["hosts"]["10.0.0.5"]
    assert entry["changed"] == [{"port": 80, "from": "nginx 1.22.1", "to": "nginx 1.24.0", "kind": "version"}]  # 22 gained detail, not a change
    assert entry["opened"] == [] and entry["closed"] == []


def test_the_ttl_and_unknown_guesses_are_not_a_system_change():
    same = nemla.diff_scans([host("10.0.0.5", os_guess="Linux (TTL=64)")], [host("10.0.0.5", os_guess="Linux (TTL=63)")])
    assert same["summary"]["changed"] is False
    for unknown in ("Unknown", "Skipped", "غير معروف", "דולג"):
        diff = nemla.diff_scans([host("10.0.0.5", os_guess="Windows (TTL=128)")], [host("10.0.0.5", os_guess=unknown)])
        assert diff["hosts"] == {}
    real = nemla.diff_scans([host("10.0.0.5", os_guess="Windows (TTL=128)")], [host("10.0.0.5", os_guess="Ubuntu Linux (TTL=64)")])
    assert real["hosts"]["10.0.0.5"]["os"] == {"from": "Windows", "to": "Ubuntu Linux"}


def test_findings_that_appeared_or_were_resolved():
    telnet, tls = finding("telnet", "high", 23), finding("tls_selfsigned", "low", 443)
    version = finding("version", "info", 22, product="OpenSSH", version="9.6")
    old = [host("10.0.0.5", findings=[tls, version])]
    new = [host("10.0.0.5", findings=[telnet])]
    diff = nemla.diff_scans(old, new)
    entry = diff["hosts"]["10.0.0.5"]
    assert [f["id"] for f in entry["new_findings"]] == ["telnet"]
    assert [f["id"] for f in entry["resolved_findings"]] == ["tls_selfsigned"]  # 'info' never counts
    assert diff["summary"]["new_findings"] == 1 and diff["summary"]["resolved_findings"] == 1


def test_findings_on_a_brand_new_host_count_as_new():
    diff = nemla.diff_scans([], [host("10.0.0.7", findings=[finding("telnet", "high", 23)])])
    assert diff["summary"]["new_findings"] == 1 and diff["summary"]["worse"] is True


@pytest.mark.parametrize("lang, marker", [("en", "opened"), ("ar", "فُتح"), ("he", "נפתח")])
def test_diff_sentences_in_every_language(lang, marker):
    old = [host("10.0.0.5", [port(80, product="nginx", version="1.22")], os_guess="Windows"),
           host("10.0.0.2")]
    new = [host("10.0.0.5", [port(80, product="nginx", version="1.24"), port(23)], os_guess="Linux",
                findings=[finding("telnet", "high", 23)]), host("10.0.0.8")]
    nemla._LANG = lang
    try:
        lines = nemla.diff_lines(nemla.diff_scans(old, new))
    finally:
        nemla._LANG = "en"
    text = "\n".join(lines)
    assert marker in text and "10.0.0.8" in text and "10.0.0.2" in text and "nginx 1.24" in text
    assert all("{" not in line for line in lines)
    assert len(lines) == 7  # summary, new host, gone host, port opened, service, system guess, new finding


# --------------------------------------------------------------------------
# saved scans
# --------------------------------------------------------------------------

def save(tmp_path, target="10.0.0.0/24", hosts=None):
    meta = {"target": target, "scan_time": "2026-09-20 10:00:00", "duration": 1.0, "ports_scanned": 3,
            "findings": {"info": 0, "low": 0, "medium": 0, "high": 0}}
    return history.save(tmp_path, nemla, meta, hosts if hosts is not None else [host("10.0.0.5", [port(22)])])


def test_saved_scans_come_back_newest_first_with_summaries(tmp_path):
    first = save(tmp_path)
    time.sleep(1.05)  # ids carry the second
    second = save(tmp_path, hosts=[host("10.0.0.5", [port(22), port(80)]), host("10.0.0.6")])
    scans = history.list_scans(tmp_path)
    assert [s["id"] for s in scans] == [second, first]
    assert (scans[0]["hosts"], scans[0]["open_ports"], scans[0]["target"]) == (2, 2, "10.0.0.0/24")
    assert history.load(tmp_path, first)["hosts"][0]["ip"] == "10.0.0.5"


def test_ids_in_the_same_second_do_not_collide(tmp_path):
    ids = {save(tmp_path) for _ in range(3)}
    assert len(ids) == 3


def test_previous_scan_is_of_the_same_target_and_older(tmp_path):
    a = save(tmp_path, "10.0.0.0/24")
    save(tmp_path, "192.168.1.1")
    time.sleep(1.05)
    b = save(tmp_path, "10.0.0.0/24")
    assert history.previous_for(tmp_path, "10.0.0.0/24", b) == a
    assert history.previous_for(tmp_path, "10.0.0.0/24", a) is None
    assert history.previous_for(tmp_path, "nothing.example", b) is None


def test_target_becomes_a_safe_file_name(tmp_path):
    scan_id = save(tmp_path, "../../etc/passwd; rm -rf /")
    assert history.ID_RE.match(scan_id)
    assert (tmp_path / "history" / f"{scan_id}.json").exists()
    assert history.load(tmp_path, scan_id)["target"] == "../../etc/passwd; rm -rf /"


@pytest.mark.parametrize("bad", ["", None, "../../etc/passwd", "20260920-100000-../x", "x", "20260920-100000-a b",
                                 "20260920-100000-"])
def test_load_refuses_anything_that_is_not_a_scan_id(tmp_path, bad):
    save(tmp_path)
    assert history.load(tmp_path, bad) is None


def test_old_scans_are_pruned_and_broken_files_ignored(tmp_path):
    folder = tmp_path / "history"
    folder.mkdir()
    for i in range(5):
        (folder / f"20260101-00000{i}-t.json").write_text("{}", encoding="utf-8")
    (folder / "20260101-000009-broken.json").write_text("{ nope", encoding="utf-8")
    history.prune(folder, keep=3)
    assert len(list(folder.glob("*.json"))) == 3
    assert history.list_scans(tmp_path) == []  # none of the leftovers is a real scan
    assert history.list_scans(tmp_path / "missing") == []


# --------------------------------------------------------------------------
# through the interface server
# --------------------------------------------------------------------------

@pytest.fixture()
def lab_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


@pytest.fixture()
def gui(tmp_path):
    app = server.App(nemla, data_dir=tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(app))
    p = httpd.server_address[1]
    app.allowed_hosts = {f"127.0.0.1:{p}", f"localhost:{p}"}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, p
    app.finished.set()
    httpd.shutdown()
    httpd.server_close()
    nemla._LANG = "en"
    nemla._LOG_SINK = None


def call(p, app, path, method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", p, timeout=20)
    headers = {"X-Nemla-Token": app.token}
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, "/api/" + path, body=json.dumps(body) if body is not None else None, headers=headers)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res.status, data


def scan(p, app, ports):
    body = {"target": "127.0.0.1", "profile": "custom", "ports": ports, "no_ping": True, "no_os": True,
            "authorized": True}
    status, data = call(p, app, "scan", "POST", body)
    assert status == 200, data
    job = json.loads(data)["job"]
    status, raw = call(p, app, f"events?job={job}&k={app.token}")
    events = [json.loads(line[6:]) for line in raw.decode().splitlines() if line.startswith("data: ")]
    return events[-1]


def test_a_finished_scan_is_saved_and_the_second_one_carries_a_diff(gui, lab_port):
    app, p = gui
    first = scan(p, app, str(lab_port))
    assert first["type"] == "done" and "scan_id" in first and "diff" not in first
    assert history.load(app.data_dir, first["scan_id"])["hosts"][0]["open_ports"][0]["port"] == lab_port

    time.sleep(1.05)
    second = scan(p, app, f"{lab_port},{lab_port + 1}")  # the neighbour port is closed, nothing changes
    diff = second["diff"]
    assert diff["against"]["id"] == first["scan_id"] and diff["summary"]["changed"] is False

    status, data = call(p, app, "history")
    scans = json.loads(data)["scans"]
    assert status == 200 and [s["id"] for s in scans] == [second["scan_id"], first["scan_id"]]

    status, data = call(p, app, f"history/diff?a={first['scan_id']}&b={second['scan_id']}")
    assert status == 200 and json.loads(data)["summary"]["changed"] is False


def test_history_diff_needs_real_ids_and_the_token(gui):
    app, p = gui
    assert call(p, app, "history/diff?a=x&b=y")[0] == 404
    assert call(p, app, "history/diff?a=../../etc/passwd&b=../../etc/passwd")[0] == 404
    conn = http.client.HTTPConnection("127.0.0.1", p, timeout=5)
    conn.request("GET", "/api/history")
    assert conn.getresponse().status == 401


def test_a_stopped_scan_is_not_saved(gui, lab_port):
    app, p = gui
    job = server.Job("x", "127.0.0.1", "en")
    job.meta = {"cancelled": True, "discovered": 1}
    done = {}
    if not job.meta["cancelled"]:
        app._remember(job, done)
    assert done == {} and history.list_scans(app.data_dir) == []


# --------------------------------------------------------------------------
# the command line
# --------------------------------------------------------------------------

def write_scan(path, hosts):
    path.write_text(nemla.json_text({"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 1}, hosts),
                    encoding="utf-8")


def test_diff_command_prints_changes_and_can_fail_on_them(tmp_path, capsys):
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    write_scan(old, [host("10.0.0.5", [port(22)])])
    write_scan(new, [host("10.0.0.5", [port(22), port(23)]), host("10.0.0.6")])
    assert nemla.main(["--diff", str(old), str(new)]) == 0
    out = capsys.readouterr().out
    assert "10.0.0.5: port 23 opened" in out and "New host: 10.0.0.6" in out and "Comparing" in out
    assert nemla.main(["--diff", str(old), str(new), "--fail-on-change"]) == 3
    assert nemla.main(["--diff", str(new), str(old), "--fail-on-change"]) == 0  # things only went away


def test_diff_command_in_hebrew(tmp_path, capsys):
    old = tmp_path / "old.json"
    write_scan(old, [host("10.0.0.5")])
    assert nemla.main(["--diff", str(old), str(old), "--lang", "he"]) == 0
    nemla._LANG = "en"
    assert "אין שינויים" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["", "{ nope", "[]", '{"hosts": 3}', '{"other": 1}'])
def test_diff_command_rejects_files_that_are_not_scans(tmp_path, capsys, content):
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    write_scan(good, [])
    bad.write_text(content, encoding="utf-8")
    assert nemla.main(["--diff", str(good), str(bad)]) == 1
    assert nemla.main(["--diff", str(good), str(tmp_path / "missing.json")]) == 1
    assert "Cannot read" in capsys.readouterr().out


@pytest.mark.parametrize("text, seconds", [("90", 90), ("90s", 90), ("15m", 900), ("2h", 7200),
                                           (" 1.5m ", 90), ("10s", 10)])
def test_parse_interval(text, seconds):
    assert nemla.parse_interval(text) == seconds


@pytest.mark.parametrize("text", ["", "5s", "0", "abc", "10x", "-5m", None])
def test_parse_interval_rejects_nonsense(text):
    with pytest.raises(ValueError):
        nemla.parse_interval(text)


def test_watch_rejects_a_bad_interval_and_needs_a_target(capsys):
    assert nemla.main(["-t", "127.0.0.1", "--watch", "3s"]) == 1
    assert "Bad interval" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        nemla.main(["--watch", "5m"])


def test_watch_reports_what_changed_between_rounds(lab_port, tmp_path, monkeypatch, capsys):
    from nemla_ui import guard

    monkeypatch.setattr(guard, "data_dir", lambda: tmp_path)
    rounds = [
        [host("127.0.0.1", [port(lab_port)])],
        [host("127.0.0.1", [port(lab_port), port(23)]), host("127.0.0.2")],
    ]
    meta = {"target": "127.0.0.1", "scan_time": "now", "duration": 0.1, "ports_scanned": 1, "cancelled": False,
            "findings": {"info": 0, "low": 0, "medium": 0, "high": 0}}

    def fake_scan(*args, **kwargs):
        hosts = rounds.pop(0)
        return hosts, {**meta, "discovered": len(hosts)}

    naps = []

    def fake_sleep(seconds):
        naps.append(seconds)
        if not rounds:
            raise KeyboardInterrupt

    monkeypatch.setattr(nemla.cli, "run_scan", fake_scan)
    monkeypatch.setattr(nemla.time, "sleep", fake_sleep)
    log_file = tmp_path / "changes.jsonl"
    code = nemla.main(["-t", "127.0.0.1", "-p", str(lab_port), "--watch", "10s", "--watch-log", str(log_file),
                       "-o", str(tmp_path / "r.html")])
    out = capsys.readouterr().out
    assert code == 0 and "First scan saved" in out and "Watch stopped." in out
    assert "port 23 opened" in out and "New host: 127.0.0.2" in out
    entry = json.loads(log_file.read_text(encoding="utf-8").splitlines()[0])
    assert entry["summary"]["new_hosts"] == 1 and entry["summary"]["opened_ports"] == 1
    assert len(history.list_scans(tmp_path)) == 2  # both rounds were saved for the next run
