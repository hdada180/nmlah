"""The short ways to run Nemla: a plain target, `nemla ui|guard|watch|diff|scan`, `-p all` - and the README that shows them.

Every older spelling (`-t TARGET`, `--ui`, `--guard`, `--watch`, `--diff`) is exercised by the rest of the suite and keeps working.
"""
import pathlib
import re
import shlex

import pytest

import nemla
from nemla.cli import build_parser, expand_command_word, scan_inputs
from nemla.fleet.cli import build_parser as fleet_parser

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ------------------------------------------------------------------------------------------------ the words

@pytest.mark.parametrize("given, expected", [
    (["ui"], ["--ui"]),
    (["ui", "--no-browser", "--lang", "ar"], ["--ui", "--no-browser", "--lang", "ar"]),
    (["guard"], ["--guard"]),
    (["guard", "--guard-ports", "2222"], ["--guard", "--guard-ports", "2222"]),
    (["diff", "a.json", "b.json", "--fail-on-change"], ["--diff", "a.json", "b.json", "--fail-on-change"]),
    (["scan", "10.0.0.5", "-p", "22"], ["10.0.0.5", "-p", "22"]),
    (["watch", "10.0.0.0/24"], ["--watch", "15m", "10.0.0.0/24"]),                           # every 15 minutes unless told
    (["watch", "10.0.0.0/24", "90s", "--udp"], ["--watch", "90s", "10.0.0.0/24", "--udp"]),
    (["watch", "--udp"], ["--watch", "15m", "--udp"]),                                        # no target: the usual error follows
    ([], []),
    (["10.0.0.5"], ["10.0.0.5"]),
    (["-t", "ui"], ["-t", "ui"]),                                     # a host that is called `ui` is reached with -t
    (["--ui"], ["--ui"]),
    (["UI"], ["UI"]),                                                 # only the exact lowercase words are commands
])
def test_a_first_word_stands_for_the_flags_it_replaces(given, expected):
    assert expand_command_word(given) == expected


def test_expanding_never_changes_its_input():
    given = ["watch", "10.0.0.5", "1m"]
    expand_command_word(given)
    assert given == ["watch", "10.0.0.5", "1m"]


def test_the_expanded_watch_command_parses_to_what_the_flags_would():
    parser = build_parser()
    short = parser.parse_args(expand_command_word(["watch", "192.168.1.0/24", "5m", "--watch-log", "c.jsonl"]))
    long = parser.parse_args(["-t", "192.168.1.0/24", "--watch", "5m", "--watch-log", "c.jsonl"])
    assert (short.target_arg, short.watch, short.watch_log) == ("192.168.1.0/24", "5m", "c.jsonl")
    assert (long.target, long.watch, long.watch_log) == ("192.168.1.0/24", "5m", "c.jsonl")


# ------------------------------------------------------------------------------------------------ a plain target

def ssh_server(tcp_server):
    return tcp_server(lambda conn: (conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"), conn.close()))


@pytest.mark.parametrize("shape", ["target first", "target last", "scan word", "dash t"])
def test_a_plain_target_scans_exactly_like_dash_t(tcp_server, tmp_path, shape):
    port = ssh_server(tcp_server)
    report = tmp_path / "r.html"
    options = ["-p", str(port), "--no-ping", "--no-os", "-o", str(report)]
    argv = {"target first": ["127.0.0.1", *options], "target last": [*options, "127.0.0.1"],
            "scan word": ["scan", "127.0.0.1", *options], "dash t": ["-t", "127.0.0.1", *options]}[shape]
    assert nemla.main(argv) == 0
    assert "OpenSSH" in report.read_text(encoding="utf-8")


def test_naming_the_target_twice_is_an_error_not_a_silent_choice(capsys):
    with pytest.raises(SystemExit) as exc:
        nemla.main(["10.0.0.5", "-t", "10.0.0.6"])
    assert exc.value.code == 2 and "once" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["scan"], ["-o", "x.html"], ["--udp"], ["watch"]])
def test_no_target_says_what_to_type(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        nemla.main(argv)
    assert exc.value.code == 2
    assert "nemla 192.168.1.10" in capsys.readouterr().err


def test_scan_is_not_the_same_as_no_arguments(monkeypatch):
    """No arguments opens the interface; `scan` with nothing to scan must not."""
    import nemla_ui
    opened = []
    monkeypatch.setattr(nemla_ui, "serve", lambda engine, **kw: opened.append(kw) or 0)
    with pytest.raises(SystemExit):
        nemla.main(["scan"])
    assert opened == []


# ------------------------------------------------------------------------------------------------ the other words

def test_ui_opens_the_interface_like_the_flag(monkeypatch):
    import nemla_ui
    seen = []
    monkeypatch.setattr(nemla_ui, "serve", lambda engine, **kw: seen.append(kw) or 0)
    assert nemla.main(["ui", "--no-browser", "--ui-port", "4243", "--keep-alive"]) == 0
    assert seen == [{"port": 4243, "open_window": False, "keep_alive": True, "lang": None}]


def test_guard_word_reaches_guard_mode(capsys):
    assert nemla.main(["guard", "--guard-ports", "abc"]) == 1                     # its own validation answered


def write_scan(path, ports):
    hosts = [{"ip": "10.0.0.5", "mac": None, "os_guess": "Linux", "ttl": 64, "findings": [],
              "open_ports": [{"port": p, "proto": "tcp", "state": "open", "service": "X", "banner": ""} for p in ports]}]
    path.write_text(nemla.json_text({"target": "t", "scan_time": "now", "duration": 1.0, "ports_scanned": 1}, hosts), encoding="utf-8")


def test_diff_word_compares_two_saved_scans(tmp_path, capsys):
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    write_scan(old, [22])
    write_scan(new, [22, 23])
    assert nemla.main(["diff", str(old), str(new)]) == 0
    assert "port 23 opened" in capsys.readouterr().out
    assert nemla.main(["diff", str(old), str(new), "--fail-on-change"]) == 3
    assert nemla.main(["diff", str(new), str(old), "--fail-on-change"]) == 0


def test_diff_word_without_two_files_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        nemla.main(["diff", "only-one.json"])
    assert exc.value.code == 2


def test_watch_word_validates_the_interval_like_the_flag(capsys):
    assert nemla.main(["watch", "127.0.0.1", "3s"]) == 1
    assert "Bad interval" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------------ -p all

def test_all_means_every_tcp_port():
    assert nemla.parse_ports("all") == list(range(1, 65536))
    assert nemla.parse_ports("ALL") == nemla.parse_ports("all")
    assert nemla.parse_ports("22,all,53") == list(range(1, 65536))


@pytest.mark.parametrize("text", ["allx", "al", "all-1", "none", "1-all"])
def test_only_the_exact_word_all_is_a_port_list(text):
    with pytest.raises(ValueError):
        nemla.parse_ports(text)


def test_dash_p_all_reaches_the_scan_inputs():
    args = build_parser().parse_args(["-t", "10.0.0.5", "-p", "all"])
    ips, ports, udp = scan_inputs(args)
    assert list(ips) == ["10.0.0.5"] and ports == list(range(1, 65536)) and udp == []


# ------------------------------------------------------------------------------------------------ --help and the README

def test_help_shows_the_short_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        nemla.main(["--help"])
    text = capsys.readouterr().out
    assert exc.value.code == 0
    for line in ("nemla 192.168.1.10 ", "nemla watch 192.168.1.0/24 15m", "nemla diff old.json new.json", "nemla guard", "nemla ui",
                 "-p all"):
        assert line in text


PROGRAM = re.compile(r"^(?:sudo\s+)?(?:python3?\s+nemla\.py|python3?\s+-m\s+nemla|nemla)(?:\s+(.*))?$")


def commands_in(readme: pathlib.Path):
    """(line number, arguments) of every Nemla command inside the fenced code blocks of a README."""
    fenced = False
    for number, line in enumerate(readme.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        found = PROGRAM.match(line.strip()) if fenced else None
        if found:
            yield number, shlex.split(found.group(1) or "", comments=True)


@pytest.mark.parametrize("name", ["README.md", "README.ar.md", "README.he.md"])
def test_every_command_in_the_readme_is_one_the_tool_accepts(name):
    """The README is the manual: a command that stops parsing (a renamed flag, a typo in a translation) fails here."""
    seen = 0
    parser, fleet = build_parser(), fleet_parser()
    for number, args in commands_in(ROOT / name):
        seen += 1
        try:
            if args and args[0] in ("controller", "agent"):           # Fleet mode has its own sub-commands
                fleet.parse_args(args)
            else:
                parser.parse_args(expand_command_word(args))
        except SystemExit as exit_:
            if exit_.code not in (0, None):                       # --help and --version leave with 0: that is accepted
                pytest.fail(f"{name}:{number}: nemla {' '.join(args)} is not accepted by the command line")
    assert seen >= 12, f"{name}: only {seen} commands found - is the code-block format still what this test reads?"
