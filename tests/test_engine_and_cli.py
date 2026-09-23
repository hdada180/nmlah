"""The scan pipeline as a whole, the command line as a program, and the compatibility surface."""
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import nemla
from nemla import engine

REPO = Path(nemla.__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# the pipeline at scale (the network is replaced by a stub, the scheduler is real)
# --------------------------------------------------------------------------

def test_65535_ports_on_several_hosts_stay_within_the_limits(monkeypatch):
    lock = threading.Lock()
    running, peak, per_host_running, per_host_peak = [0], [0], {}, {}

    def stub(ip, port, timeout, grab, cancel, budget, intensity, diagnostics):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
            per_host_running[ip] = per_host_running.get(ip, 0) + 1
            per_host_peak[ip] = max(per_host_peak.get(ip, 0), per_host_running[ip])
        # overlap the calls so the concurrency limits are really exercised, but do not sleep every time: Windows
        # (Python < 3.11) rounds every sleep up to ~15 ms, which turned 196,000 calls into minutes
        time.sleep(0.001 if port % 97 == 0 else 0)
        with lock:
            running[0] -= 1
            per_host_running[ip] -= 1
        if port == 80:
            return {"port": 80, "proto": "tcp", "state": "open", "service": "HTTP", "banner": "", "detected": "http",
                    "confidence": 0.3, "heuristic": True, "method": "port"}
        return None

    monkeypatch.setattr(engine, "scan_port", stub)
    monkeypatch.setattr(engine, "get_ttl", lambda ip, cancel=None: 64)
    events = []
    ips = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
    started = time.monotonic()
    hosts, meta = nemla.run_scan("test", ips, list(range(1, 65536)), no_ping=True, threads=32, per_host=12,
                                 emit=events.append)
    elapsed = time.monotonic() - started
    assert [h["ip"] for h in hosts] == ips and all(h["open_ports"][0]["port"] == 80 for h in hosts)
    assert peak[0] <= 32 and max(per_host_peak.values()) <= 12
    assert min(per_host_peak.values()) >= 1 and len(per_host_peak) == 3
    assert len(events) < 3000, len(events)                          # progress events are throttled, not one per port
    assert meta["ports_scanned"] == 65535 and elapsed < 60


def test_hosts_are_scanned_side_by_side_and_finish_as_soon_as_they_are_done(tcp_server):
    ports = [tcp_server(lambda c: c.close()) for _ in range(3)]
    events = []
    _hosts, _ = nemla.run_scan("test", ["127.0.0.1", "127.0.0.2"], ports, no_ping=True, no_os=True, no_banner=True,
                              emit=events.append)
    kinds = [e["type"] for e in events]
    assert kinds.count("host_start") == 2 and kinds.count("host_done") == 2
    # Per host: it starts, then reports its ports, then is done. (Across hosts the order is a race: only 127.0.0.1
    # has listeners, and on Linux the closed ports of 127.0.0.2 are refused at once, so that host can finish first.)
    for ip in ("127.0.0.1", "127.0.0.2"):
        start = next(i for i, e in enumerate(events) if e["type"] == "host_start" and e["ip"] == ip)
        done = next(i for i, e in enumerate(events) if e["type"] == "host_done" and e["host"]["ip"] == ip)
        ports_seen = [i for i, e in enumerate(events) if e["type"] == "port" and e["ip"] == ip]
        assert start < done and all(start < i < done for i in ports_seen), ip
    assert any(e["type"] == "port" and e["ip"] == "127.0.0.1" for e in events)
    done_hosts = [e["host"]["ip"] for e in events if e["type"] == "host_done"]
    assert sorted(done_hosts) == ["127.0.0.1", "127.0.0.2"]
    progress = [e for e in events if e["type"] == "progress" and e["phase"] == "ports"]
    assert progress[-1]["done"] == progress[-1]["total"] == 2 * len(ports)


def test_run_scan_keeps_its_old_calling_convention(tcp_server):
    port = tcp_server(lambda c: (c.sendall(b"SSH-2.0-OpenSSH_9.6p1\r\n"), time.sleep(0.2), c.close()))
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_ping=True, no_os=True, no_banner=False,
                                 threads=10, timeout=1.0, emit=None, cancel=None)
    assert hosts[0]["open_ports"][0]["product"] == "OpenSSH"
    for key in ("target", "scan_time", "duration", "ports_scanned", "discovered", "cancelled", "findings"):
        assert key in meta
    for key in ("ip", "mac", "discovery", "os_guess", "ttl", "open_ports", "vendor", "findings"):
        assert key in hosts[0]
    assert meta["scan_id"] and meta["warnings"] == [] and meta["options"]["threads"] == 10 and meta["capabilities"]["platform"]


def test_run_scan_works_with_a_lazy_target_set(tcp_server):
    port = tcp_server(lambda c: c.close())
    targets = nemla.iter_targets("127.0.0.1")
    hosts, meta = nemla.run_scan("127.0.0.1", targets, [port], no_ping=True, no_os=True, timeout=0.5)
    assert len(hosts) == 1 and meta["discovered"] == 1


def test_a_scan_language_never_leaks_into_other_threads(tcp_server):
    port = tcp_server(lambda c: c.close())
    lines = []
    previous = nemla._LOG_SINK
    nemla._LOG_SINK = lines.append
    try:
        nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_ping=True, no_os=True, timeout=0.5, lang="he")
        assert any("סורק" in line for line in lines)
        assert nemla.t("sev_high") == "High"                       # the process language was not touched
    finally:
        nemla._LOG_SINK = previous


# --------------------------------------------------------------------------
# the command line as a program
# --------------------------------------------------------------------------

def run(*args, **kw):
    # nemla writes UTF-8 to pipes; decode it as such (the Windows default, cp1252, cannot read Arabic or Hebrew)
    return subprocess.run([sys.executable, *args], capture_output=True, encoding="utf-8", errors="replace",
                          cwd=kw.pop("cwd", REPO), timeout=60, **kw)


@pytest.mark.parametrize("encoding", ["cp1252", "cp437", "ascii"])
def test_the_command_line_never_crashes_on_a_legacy_output_encoding(encoding, tcp_server):
    """On Windows a piped stdout is cp1252 (or an OEM page). --help and the scan output hold Arabic, Hebrew and
    symbols: this used to end in a UnicodeEncodeError before argparse printed anything."""
    import os
    env = dict(os.environ, PYTHONIOENCODING=encoding, PYTHONUTF8="0")
    port = tcp_server(lambda c: c.close())
    for args in (["--help"], ["--lang", "ar", "--help"], ["--lang", "he", "--help"],
                 ["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "--lang", "ar", "--timeout", "0.5"],
                 ["-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "--lang", "he", "--timeout", "0.5"]):
        result = run("nemla.py", *args, env=env)
        assert result.returncode == 0 and "Traceback" not in result.stderr, (args, result.stderr[-300:])
        assert result.stdout.strip(), args                                   # and it printed something
    assert "--udp" in run("nemla.py", "--help", env=env).stdout


def test_three_ways_to_start_it_report_the_same_version():
    for command in (["nemla.py", "--version"], ["-m", "nemla", "--version"],
                    ["-c", "import nemla; import sys; sys.exit(nemla.main(['--version']))"]):
        result = run(*command)
        assert result.stdout.strip() == f"nemla {nemla.__version__}" and result.returncode == 0, (command, result.stderr)


def test_nemla_py_launcher_works_from_any_directory(tmp_path):
    result = subprocess.run([sys.executable, str(REPO / "nemla.py"), "--version"], capture_output=True, encoding="utf-8",
                            cwd=tmp_path, timeout=60)
    assert result.returncode == 0 and "nemla" in result.stdout


def test_bad_arguments_exit_with_code_2_and_a_usage_message():
    result = run("nemla.py", "-t", "127.0.0.1", "--timeout", "0")
    assert result.returncode == 2 and "timeout must be greater than 0" in result.stderr
    result = run("nemla.py", "--no-such-flag")
    assert result.returncode == 2 and "usage:" in result.stderr


def test_a_target_is_required_unless_the_ui_starts():
    result = run("nemla.py", "-p", "80")
    assert result.returncode == 2 and "Give a target" in result.stderr and "nemla 192.168.1.10" in result.stderr


def test_help_documents_the_new_switches():
    out = run("nemla.py", "--help").stdout
    for flag in ("--udp", "--udp-ports", "--udp-rate", "--rate", "--max-probes", "--per-host", "--intensity", "--md",
                 "--sarif", "--verbose", "--all-addresses", "-6", "--fail-on", "--watch", "--guard", "--diff"):
        assert flag in out, flag


def test_verbose_prints_debug_details_to_stderr(tcp_server, tmp_path):
    port = tcp_server(lambda c: c.close())
    base = ["nemla.py", "-t", "127.0.0.1", "-p", str(port), "--no-ping", "--no-os", "-o", str(tmp_path / "r.html")]
    quiet = run(*base)
    loud = run(*base, "-v")
    assert quiet.returncode == loud.returncode == 0
    assert "DEBUG" not in quiet.stderr and "DEBUG" in loud.stderr


def test_exit_codes_for_findings_and_failures(tcp_server, tmp_path):
    telnet = tcp_server(lambda c: (c.sendall(b"\xff\xfb\x01login: "), time.sleep(0.3), c.close()))
    args = ["-t", "127.0.0.1", "-p", str(telnet), "--no-ping", "--no-os", "-o", str(tmp_path / "r.html")]
    assert nemla.main(args) == 0
    assert nemla.main([*args, "--fail-on", "high"]) == 3
    assert nemla.main(["-t", "10.0.0.0/8", "--max-hosts", "10", "-o", str(tmp_path / "x.html")]) == 1
    assert nemla.main(["-t", "127.0.0.1", "-p", "99999", "-o", str(tmp_path / "x.html")]) == 1


def test_installing_and_running_as_a_module_uses_the_console_entry_point():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'nemla = "nemla.main:main"' in pyproject and "nemla_ui" in pyproject and 'version = "2.0.0"' in pyproject


# --------------------------------------------------------------------------
# the compatibility surface of Nemla 1
# --------------------------------------------------------------------------

OLD_NAMES = ["STRINGS", "RTL_LANGS", "TOP_PORTS", "COMMON_SERVICE_NAMES", "t", "log", "parse_targets", "parse_ports",
             "mac_vendor", "tcp_ping", "icmp_ping", "discover_hosts", "service_name", "scan_port", "parse_banner",
             "banner_os_hint", "detect_service", "tls_probe", "scan_host_ports", "get_ttl", "guess_os", "assess_host",
             "finding_text", "summarize_findings", "diff_scans", "diff_lines", "run_scan", "render_html", "json_text",
             "csv_text", "write_json", "write_csv", "build_parser", "main", "banner_text", "print_banner",
             "fancy_output_ok", "parse_interval", "alert_text", "scan_inputs", "run_diff", "run_watch", "run_guard",
             "_is_external", "_mysql_product", "_pool_map", "_LANG", "_LOG_SINK", "__version__", "LOGO_LINES", "SEV_RANK",
             "SEVERITIES", "HAVE_SCAPY", "HTML_TEMPLATE", "BRAND_MARK", "DISCOVERY_PORTS", "HTTP_PORTS", "TLS_PORTS"]


@pytest.mark.parametrize("name", OLD_NAMES)
def test_every_public_name_of_nemla_1_still_exists(name):
    assert hasattr(nemla, name), name


def test_language_and_log_sink_can_still_be_assigned_on_the_package():
    from nemla import i18n
    nemla._LANG = "ar"
    try:
        assert i18n._LANG == "ar" and nemla.t("sev_high") == "عالية"
    finally:
        nemla._LANG = "en"
    seen = []
    nemla._LOG_SINK = seen.append
    try:
        nemla.log("hello")
        assert seen == ["hello"]
    finally:
        nemla._LOG_SINK = None


def test_guard_and_history_are_importable_from_their_old_place_and_are_the_same_module():
    from nemla import guard, history
    from nemla_ui import guard as old_guard
    from nemla_ui import history as old_history
    assert old_guard is guard and old_history is history


def test_the_package_is_split_into_the_modules_the_design_asks_for():
    root = Path(nemla.__file__).parent
    for path in ("cli.py", "config.py", "targets.py", "os_detection.py", "findings.py", "history.py", "i18n.py", "main.py",
                 "engine.py", "guard.py", "net.py", "discovery/arp.py", "discovery/ping.py", "scanning/tcp.py",
                 "scanning/udp.py", "scanning/scheduler.py", "fingerprint/http.py", "fingerprint/ssh.py",
                 "fingerprint/tls.py", "fingerprint/databases.py",
                 "fingerprint/smb.py", "fingerprint/rdp.py", "fingerprint/dns.py", "fingerprint/ftp.py",
                 "fingerprint/smtp.py", "reports/html.py", "reports/data.py", "reports/markdown.py", "reports/sarif.py"):
        assert (root / path).is_file(), path
    assert sum(1 for _ in (root / "fingerprint").glob("*.py")) >= 12
    assert len((REPO / "nemla.py").read_text(encoding="utf-8").splitlines()) < 40      # a launcher, no longer a monolith

@pytest.mark.parametrize("value, message", [(-1, "must not be negative"), (10 ** 9, "must not be more than")])
def test_a_rate_that_is_negative_or_absurd_is_refused(value, message):
    from nemla import config
    with pytest.raises(config.OptionError, match=message):
        config.non_negative_float(value, "rate")

# --------------------------------------------------------------------------
# engine and command-line edges
# --------------------------------------------------------------------------

def test_discovery_progress_reaches_the_event_stream(tcp_server):
    port = tcp_server(lambda conn: conn.close())
    events = []
    nemla.run_scan("127.0.0.1", ["127.0.0.1"], [port], no_os=True, no_banner=True, timeout=0.5, emit=events.append)
    assert {"type": "progress", "phase": "discovery", "done": 1, "total": 1} in events


def test_a_scan_that_finds_no_host_returns_an_empty_result(monkeypatch):
    from nemla import engine
    monkeypatch.setattr(engine, "discover_hosts", lambda *args, **kwargs: {})
    hosts, meta = nemla.run_scan("192.0.2.1", ["192.0.2.1"], [80], no_os=True, timeout=0.3)
    assert hosts == [] and meta["discovered"] == 0


def test_ctrl_c_during_the_port_scan_ends_it_as_cancelled(monkeypatch):
    from nemla import engine

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(engine, "_scan_hosts", interrupted)
    hosts, meta = nemla.run_scan("127.0.0.1", ["127.0.0.1"], [80], no_ping=True, no_os=True, timeout=0.3)
    assert hosts == [] and meta["cancelled"] is True


def test_fancy_output_is_off_when_the_stream_cannot_say_whether_it_is_a_terminal(monkeypatch):
    import sys

    class Closed:
        encoding = "utf-8"

        def isatty(self):
            raise ValueError("I/O operation on closed file")
    monkeypatch.setattr(sys, "stdout", Closed())
    assert nemla.fancy_output_ok() is False


@pytest.mark.parametrize("no_color, coloured", [(False, True), (True, False)])
def test_the_fancy_banner_is_coloured_unless_no_color_is_set(monkeypatch, capsys, no_color, coloured):
    monkeypatch.setattr(nemla.cli, "fancy_output_ok", lambda: True)
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        monkeypatch.delenv("NO_COLOR", raising=False)
    nemla.print_banner()
    assert ("\x1b[" in capsys.readouterr().out) is coloured


def test_an_alert_of_an_unknown_kind_is_shown_as_its_kind():
    assert nemla.alert_text({"kind": "brand-new-kind"}) == "brand-new-kind"


def test_utf8_output_setup_survives_a_stream_that_refuses_to_reconfigure(monkeypatch):
    import sys

    class Stubborn:
        def reconfigure(self, **kwargs):
            raise ValueError("I/O operation on closed file")
    monkeypatch.setattr(sys, "stdout", Stubborn())
    monkeypatch.setattr(sys, "stderr", Stubborn())
    nemla.cli.use_utf8_output()


def test_the_launcher_flags_run_the_launcher_and_the_verbose_flag_turns_on_debug_output(monkeypatch):
    from nemla_ui import launcher
    debug = []
    monkeypatch.setattr(nemla.cli, "enable_debug", lambda: debug.append(True))
    monkeypatch.setattr(launcher, "install", lambda: 7)
    monkeypatch.setattr(launcher, "uninstall", lambda: 8)
    assert nemla.main(["--install-launcher"]) == 7 and debug == []
    assert nemla.main(["--uninstall-launcher", "--verbose"]) == 8 and debug == [True]


def test_the_launcher_flags_explain_a_missing_interface_folder(monkeypatch, capsys):
    import sys
    monkeypatch.setitem(sys.modules, "nemla_ui", None)          # `from nemla_ui import launcher` now fails
    assert nemla.main(["--install-launcher"]) == 1
    assert "nemla_ui" in capsys.readouterr().out
