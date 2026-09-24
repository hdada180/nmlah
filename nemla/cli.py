"""The command line: argument parsing and the commands (scan, watch, diff, guard, UI)."""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import sys
import time

from . import history as history_mod
from .config import (DEFAULT_INTENSITY, DEFAULT_MAX_HOSTS, DEFAULT_PER_HOST, DEFAULT_THREADS, DEFAULT_TIMEOUT,
                     DEFAULT_UDP_RATE, DEFAULT_UDP_TIMEOUT, MAX_HOSTS_HARD, MAX_PER_HOST, MAX_THREADS, TOP_PORTS,
                     UDP_PORTS, OptionError, __version__, bounded_int, non_negative_float, positive_float)
from .diff import diff_lines, diff_scans
from .discovery import mac_vendor
from .engine import run_scan
from .findings import SEV_RANK, finding_text
from .i18n import STRINGS, t
from . import i18n
from .log import enable_debug, log
from .reports import open_private_append, write_report
from .targets import iter_targets, parse_ports

# -- the startup banner ------------------------------------------------------------

LOGO_LINES = (
    "██      ██  ██████████  ██      ██  ██            ██████  ",
    "████    ██  ██          ████  ████  ██          ██      ██",
    "██  ██  ██  ████████    ██  ██  ██  ██          ██████████",
    "██    ████  ██          ██      ██  ██          ██      ██",
    "██      ██  ██████████  ██      ██  ██████████  ██      ██",
)
# amber -> ember -> deep ember, top to bottom (the Nemla palette)
LOGO_GRADIENT = ((255, 196, 107), (255, 152, 48), (255, 122, 26), (240, 92, 18), (232, 70, 12))


def fancy_output_ok() -> bool:
    """True when stdout is a UTF-8 terminal that can show the block-letter logo."""
    stream = sys.stdout
    try:
        tty = stream.isatty()
    except (AttributeError, ValueError):
        tty = False
    encoding = (getattr(stream, "encoding", "") or "").lower()
    return tty and "utf" in encoding and os.environ.get("TERM") != "dumb"


def banner_text(color: bool = True) -> str:
    """The startup banner: block-letter NEMLA in the ember gradient."""
    lines = [""]
    for row, rgb in zip(LOGO_LINES, LOGO_GRADIENT):
        lines.append("  " + (f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{row}\x1b[0m" if color else row))
    dim, reset = ("\x1b[38;2;162;171;190m", "\x1b[0m") if color else ("", "")
    lines += [
        "",
        f"  {dim}{t('brand_local')}  ·  Discover · Scan · Fingerprint · Report  ·  v{__version__}{reset}",
        f"  {dim}{t('notice')}{reset}",
        "",
    ]
    return "\n".join(lines)


def print_banner() -> None:
    if fancy_output_ok():
        print(banner_text(color="NO_COLOR" not in os.environ))
    else:
        print(f"\n  \U0001F41C  Nemla / نملة  v{__version__}  -  Network Recon")
        print(f"  {t('notice')}\n")


# -- argument validation (argparse turns these errors into a clean usage message) ---------

def _argument(func):
    """Turn a validation error into the message argparse prints (instead of 'invalid <function> value')."""
    @functools.wraps(func)
    def convert(text):
        try:
            return func(text)
        except OptionError as err:
            raise argparse.ArgumentTypeError(str(err)) from None
    return convert


@_argument
def timeout_arg(text):
    return positive_float(text, "timeout")


@_argument
def threads_arg(text):
    return bounded_int(text, "threads", 1, MAX_THREADS)


@_argument
def per_host_arg(text):
    return bounded_int(text, "per-host", 1, MAX_PER_HOST)


@_argument
def max_hosts_arg(text):
    return bounded_int(text, "max-hosts", 1, MAX_HOSTS_HARD)


@_argument
def rate_arg(text):
    return non_negative_float(text, "rate")


@_argument
def intensity_arg(text):
    return bounded_int(text, "intensity", 0, 9)


@_argument
def probes_arg(text):
    return bounded_int(text, "max-probes", 0, 10**12)


EXAMPLES = """
examples:
  nemla                                 open the 3D interface
  nemla 192.168.1.10                    scan one host (the common ports)
  nemla 192.168.1.0/24                  scan a whole network
  nemla 192.168.1.10 -p 1-1000 --udp    more TCP ports, plus the common UDP ports
  nemla 192.168.1.10 -p all             every TCP port
  nemla 192.168.1.10 --json scan.json   also save the results as JSON (--csv, --md, --sarif too)
  nemla 10.0.0.0/24 --fail-on high      for CI: exit code 3 on a high finding
  nemla watch 192.168.1.0/24 15m        scan again every 15 minutes and say what changed
  nemla diff old.json new.json          what changed between two saved scans
  nemla guard                           watch this network for suspicious activity
  nemla ui                              open the 3D interface

Every option above works with these too, and `-t TARGET` is the same as a plain TARGET.

"""

# The first word of a command line may be one of these; each stands for the flags it replaces.
COMMAND_WORDS = ("scan", "ui", "guard", "watch", "diff")
DEFAULT_WATCH_EVERY = "15m"


def expand_command_word(argv: list) -> list:
    """The short spellings, as the flags they stand for (a name that is also a host is still reachable with `-t`).

        nemla scan TARGET ...            ->  TARGET ...
        nemla ui ...                     ->  --ui ...
        nemla guard ...                  ->  --guard ...
        nemla diff OLD NEW ...           ->  --diff OLD NEW ...
        nemla watch TARGET [EVERY] ...   ->  --watch EVERY TARGET ...       (EVERY defaults to 15m)
    """
    if not argv or argv[0] not in COMMAND_WORDS:
        return list(argv)
    word, rest = argv[0], list(argv[1:])
    if word == "scan":
        return rest
    if word == "watch":
        target = rest.pop(0) if rest and not rest[0].startswith("-") else None
        every = rest.pop(0) if target is not None and rest and not rest[0].startswith("-") else DEFAULT_WATCH_EVERY
        return ["--watch", every, *([target] if target is not None else []), *rest]
    return [f"--{word}", *rest]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nemla",
        usage="nemla [TARGET] [options]   |   nemla ui | guard | watch TARGET [EVERY] | diff OLD NEW   |   nemla --help",
        description="Nemla (نملة) - network reconnaissance, service intelligence and defensive monitoring. "
                    "Run it without arguments to open the 3D interface.",
        epilog=EXAMPLES + "Only scan systems you own or have explicit permission to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target_arg", nargs="?", metavar="TARGET",
                   help="what to scan: IP, hostname, CIDR (10.0.0.0/24), range (10.0.0.1-50), IPv6 (2001:db8::/120); "
                        "several separated by commas (same as -t)")
    p.add_argument("-t", "--target",
                   help="the same as the TARGET argument (kept so older commands keep working)")
    p.add_argument("-p", "--ports", help="TCP ports: 22 | 22,80,443 | 1-1000 | all")
    p.add_argument("--top-ports", action="store_true",
                   help="scan the common-ports list (default when -p is not given)")
    p.add_argument("-4", dest="family", action="store_const", const=4, help="resolve names to IPv4 only")
    p.add_argument("-6", dest="family", action="store_const", const=6, help="resolve names to IPv6 only")
    p.add_argument("--all-addresses", action="store_true",
                   help="scan every address a host name resolves to (default: the first one)")
    p.add_argument("-o", "--output", default="nemla_report.html", help="HTML report path")
    p.add_argument("--json", metavar="FILE", help="also write results as JSON")
    p.add_argument("--csv", metavar="FILE", help="also write results as CSV")
    p.add_argument("--md", metavar="FILE", help="also write a Markdown report")
    p.add_argument("--sarif", metavar="FILE", help="also write a SARIF 2.1.0 file (for code-scanning dashboards)")
    p.add_argument("--no-os", action="store_true", help="skip OS fingerprinting")
    p.add_argument("--no-ping", action="store_true",
                   help="skip host discovery, treat every target as up (like nmap -Pn)")
    p.add_argument("--no-banner", action="store_true",
                   help="skip banner grabbing and service detection (versions, TLS, web titles)")
    p.add_argument("--fail-on", choices=("low", "medium", "high"), metavar="LEVEL",
                   help="exit with code 3 if any finding is at this level or higher "
                        "(low, medium or high), for CI and scheduled checks")
    p.add_argument("--threads", type=threads_arg, default=DEFAULT_THREADS,
                   help=f"global limit of concurrent probes (default {DEFAULT_THREADS})")
    p.add_argument("--per-host", type=per_host_arg, default=DEFAULT_PER_HOST,
                   help=f"limit of concurrent probes on one host (default {DEFAULT_PER_HOST})")
    p.add_argument("--timeout", type=timeout_arg, default=DEFAULT_TIMEOUT,
                   help=f"TCP connect timeout in seconds, greater than 0 (default {DEFAULT_TIMEOUT})")
    p.add_argument("--rate", type=rate_arg, default=0.0, metavar="PPS",
                   help="limit TCP connection attempts per second (default: unlimited)")
    p.add_argument("--max-probes", type=probes_arg, default=0, metavar="N",
                   help="stop after N connections/datagrams in total (default: no limit)")
    p.add_argument("--intensity", type=intensity_arg, default=DEFAULT_INTENSITY, metavar="0-9",
                   help=f"service detection effort: 0 = none, 9 = try every protocol (default {DEFAULT_INTENSITY})")
    p.add_argument("--max-hosts", type=max_hosts_arg, default=DEFAULT_MAX_HOSTS,
                   help=f"refuse targets larger than this many addresses (default {DEFAULT_MAX_HOSTS})")
    p.add_argument("--lang", choices=sorted(STRINGS), help="interface and report language (default en)")
    p.add_argument("-v", "--verbose", action="store_true", help="print debug details to stderr")
    p.add_argument("--version", action="version", version=f"nemla {__version__}")

    udp = p.add_argument_group("UDP scanning")
    udp.add_argument("--udp", action="store_true",
                     help="also probe the common UDP ports (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS, TFTP...)")
    udp.add_argument("--udp-ports", metavar="LIST", help="UDP ports to probe, e.g. 53,123,161 (implies --udp)")
    udp.add_argument("--udp-timeout", type=timeout_arg, default=DEFAULT_UDP_TIMEOUT, metavar="SECONDS",
                     help=f"wait per UDP probe (default {DEFAULT_UDP_TIMEOUT})")
    udp.add_argument("--udp-rate", type=rate_arg, default=DEFAULT_UDP_RATE, metavar="PPS",
                     help=f"limit UDP packets per second (default {DEFAULT_UDP_RATE:g}; 0 = no limit)")

    watch = p.add_argument_group("watching for changes")
    watch.add_argument("--watch", metavar="INTERVAL",
                       help="repeat the scan every INTERVAL (90s, 15m, 2h) and say what changed "
                            "each time; stop with Ctrl+C")
    watch.add_argument("--watch-log", metavar="FILE",
                       help="append every change found by --watch to this JSON-lines file")
    watch.add_argument("--diff", nargs=2, metavar=("OLD.json", "NEW.json"),
                       help="compare two scans saved with --json and print what changed")
    watch.add_argument("--fail-on-change", action="store_true",
                       help="with --diff: exit with code 3 if a host, an open port or a finding appeared")

    guard = p.add_argument_group("guard mode (defensive)")
    guard.add_argument("--guard", action="store_true",
                       help="watch this network for suspicious activity (decoy ports, unknown "
                            "devices, ARP changes) and print alerts until Ctrl+C")
    guard.add_argument("--guard-ports", metavar="LIST",
                       help="decoy ports to open, e.g. 2222,2323 (default 2222,2323,5901,8888,3307)")
    guard.add_argument("--guard-interval", type=float, default=60.0, metavar="SECONDS",
                       help="seconds between device checks (default 60, 0 = decoy ports only)")
    guard.add_argument("--guard-log", metavar="FILE",
                       help="append alerts to this JSON-lines file "
                            "(default: nemla/guard-alerts.jsonl in your data folder)")

    ui = p.add_argument_group("3D interface")
    ui.add_argument("--ui", action="store_true",
                    help="open the 3D interface (this is also what happens with no arguments)")
    ui.add_argument("--ui-port", type=int, default=0, metavar="PORT",
                    help="port for the local interface server (default: any free port)")
    ui.add_argument("--no-browser", action="store_true",
                    help="start the interface server but do not open a window")
    ui.add_argument("--keep-alive", action="store_true",
                    help="keep the server running after its window is closed")
    ui.add_argument("--install-launcher", action="store_true",
                    help="Linux: add Nemla to your applications menu (installs under ~/.local)")
    ui.add_argument("--uninstall-launcher", action="store_true",
                    help="Linux: remove the applications-menu entry again")
    return p


# -- commands ------------------------------------------------------------------------------

def launch_ui(args) -> int:
    """Start the local 3D interface (needs the nemla_ui/ folder)."""
    try:
        import nemla_ui
        import nemla
    except ImportError:
        log("The 3D interface files (the nemla_ui/ folder) were not found next to the nemla package.")
        return 1
    return nemla_ui.serve(nemla, port=args.ui_port, open_window=not args.no_browser,
                          keep_alive=args.keep_alive, lang=args.lang)


def scan_inputs(args):
    """(addresses, ports, udp_ports) for a scan from the command line, or None after logging the problem."""
    try:
        ips = iter_targets(args.target, args.max_hosts, getattr(args, "family", None),
                           getattr(args, "all_addresses", False))
    except ValueError as err:
        log(t("invalid_target", err=err))
        return None
    try:
        ports = set(parse_ports(args.ports)) if args.ports else set()
        udp = []
        if getattr(args, "udp_ports", None):
            udp = parse_ports(args.udp_ports)
        elif getattr(args, "udp", False):
            udp = list(UDP_PORTS)
    except ValueError as err:
        log(t("invalid_ports", err=err))
        return None
    if args.top_ports or not ports:
        ports |= set(TOP_PORTS)
    return ips, sorted(ports), udp


def parse_interval(text: str) -> float:
    """'90s', '15m', '2h' or plain seconds -> seconds (at least 10)."""
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([smh]?)\s*", text or "")
    if not m:
        raise ValueError(text)
    seconds = float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]
    if seconds < 10:
        raise ValueError(text)
    return seconds


def _load_scan(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        hosts = json.load(fh)["hosts"]
    if not isinstance(hosts, list):
        raise TypeError("hosts is not a list")
    return hosts


def run_diff(args) -> int:
    """`nemla --diff OLD.json NEW.json`: print what changed between two saved scans."""
    old_path, new_path = args.diff
    scans = []
    for path in (old_path, new_path):
        try:
            scans.append(_load_scan(path))
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as err:
            log(t("d_bad_file", path=path, err=err))
            return 1
    diff = diff_scans(*scans)
    print(t("d_compare_head", old=old_path, new=new_path))
    for line in diff_lines(diff):
        print("  " + line)
    return 3 if args.fail_on_change and diff["summary"]["worse"] else 0


def scan_options(args, udp_ports) -> dict:
    return {"no_ping": args.no_ping, "no_os": args.no_os, "no_banner": args.no_banner, "threads": args.threads,
            "timeout": args.timeout, "per_host": args.per_host, "rate": args.rate, "max_probes": args.max_probes,
            "intensity": args.intensity, "udp_ports": udp_ports, "udp_timeout": args.udp_timeout,
            "udp_rate": args.udp_rate}


def data_dir():
    from .guard import data_dir as guard_data_dir
    return guard_data_dir()


def run_watch(args) -> int:
    """`nemla --watch 15m -t ...`: scan again and again, saying what changed each time."""
    try:
        interval = parse_interval(args.watch)
    except ValueError:
        log(t("w_bad_interval", value=args.watch))
        return 1
    print_banner()
    inputs = scan_inputs(args)
    if inputs is None:
        return 1
    ips, ports, udp = inputs
    folder = data_dir()
    last = history_mod.previous_for(folder, args.target, "99999999-999999-~")
    previous = (history_mod.load(folder, last) or {}).get("hosts") if last else None
    log(t("w_started", target=args.target, every=args.watch))
    try:
        while True:
            hosts, meta = run_scan(args.target, ips, ports, **scan_options(args, udp))
            if len(hosts) < meta["discovered"]:  # interrupted part-way: a partial scan proves nothing
                log(t("interrupted"))
                return 0
            if meta["discovered"]:
                # a full disk or a mistyped path must not end a watch that is meant to run for days: say so, keep watching
                try:
                    write_report(args.output, "html", meta, hosts)
                except OSError as err:
                    log(f"Cannot write the report to {args.output}: {err.strerror or err}; still watching.")
                try:                              # the history is what the next round is compared with
                    scan_id = history_mod.save(folder, None, meta, hosts)
                except OSError as err:
                    log(f"Cannot save this round to the history: {err.strerror or err}; still watching.")
                    scan_id = None
                if previous is None:
                    log(t("w_first"))
                else:
                    diff = diff_scans(previous, hosts)
                    for line in diff_lines(diff):
                        log(line)
                    if args.watch_log and diff["summary"]["changed"]:
                        try:
                            with open_private_append(args.watch_log) as fh:
                                fh.write(json.dumps({"time": meta["scan_time"], "target": args.target,
                                                     "scan_id": scan_id, "summary": diff["summary"],
                                                     "lines": diff_lines(diff)}, ensure_ascii=False) + "\n")
                        except OSError as err:
                            log(f"Cannot write the change log {args.watch_log}: {err.strerror or err}")
                previous = hosts
            deadline = time.monotonic() + interval
            while time.monotonic() < deadline:
                time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        log(t("w_stopped"))
    return 0


def alert_text(alert: dict) -> str:
    """One guard alert as a sentence in the active language."""
    kind, detail = alert["kind"], alert.get("detail") or {}
    if kind == "tripwire":
        return t("g_tripwire", src=alert["src_ip"], count=detail.get("count", 1),
                 ports=", ".join(str(p) for p in detail.get("ports", [])))
    if kind == "new_device":
        text = t("g_new_device", ip=alert["src_ip"], mac=alert["mac"])
        if detail.get("vendor"):  # a named maker is more useful than the generic note
            text += t("g_new_device_vendor", vendor=detail["vendor"])
        elif detail.get("local"):
            text += t("g_new_device_local")
        return text
    if kind == "arp_change":
        return t("g_arp_gateway" if detail.get("gateway") else "g_arp_change", ip=alert["src_ip"],
                 old_mac=detail.get("old_mac"), new_mac=detail.get("new_mac"))
    if kind == "arp_dup":
        return t("g_arp_dup", mac=alert["mac"], ip=alert["src_ip"], ips=", ".join(detail.get("ips", [])))
    if kind == "baseline":
        return t("g_baseline", devices=detail.get("devices", 0))
    if kind == "guard_notice":
        return t("g_notice_" + str(detail.get("code", "")), **{k: v for k, v in detail.items() if k != "code"})
    return kind


def alert_confidence(alert: dict):
    """'medium confidence' for alerts that carry a confidence, else None."""
    value = alert.get("confidence")
    if value is None:
        return None
    return t("g_conf_high" if value >= 0.75 else "g_conf_medium" if value >= 0.45 else "g_conf_low")


def run_guard(args) -> int:
    """Headless guard mode: print alerts until Ctrl+C. Watches only, never attacks."""
    from . import guard
    try:
        ports = parse_ports(args.guard_ports) if args.guard_ports else list(guard.DEFAULT_DECOYS)
    except ValueError as err:
        log(t("invalid_ports", err=err))
        return 1
    print_banner()
    alerts = guard.AlertLog(args.guard_log or guard.data_dir() / "guard-alerts.jsonl")
    _, network = guard.local_network_hint()
    network = None if network.startswith("127.") else network
    watcher = guard.Guard(alerts, ports=ports, network=network, interval=max(0.0, args.guard_interval),
                          state_path=guard.data_dir() / "guard.json", vendor_lookup=mac_vendor)
    status = watcher.start()
    for port, reason in status["failed"].items():
        log(t("g_port_failed", port=port, reason=reason))
    log(t("g_started", ports=", ".join(str(p) for p in status["decoys"]) or "-"))
    seen = 0
    try:
        while True:
            for alert in alerts.wait(seen, 1.0):
                seen = alert["id"]
                confidence = alert_confidence(alert)
                log(f"[{t('sev_' + alert['severity'])}] {alert_text(alert)}" + (f" ({confidence})" if confidence else ""))
                if alert.get("evidence"):
                    log("    " + t("g_evidence", evidence="; ".join(str(e) for e in alert["evidence"][:4])))
                if alert["kind"] != "baseline" and alert.get("src_ip"):
                    try:
                        command = watcher.block(alert["src_ip"])["options"][0]["commands"][0]
                        log("    " + t("g_block_hint", command=command))
                    except ValueError:
                        pass  # our own address or the gateway: never suggest blocking those
    except KeyboardInterrupt:
        pass
    finally:
        watcher.stop()
        log(t("g_stopped"))
    return 0


def manage_launcher(args) -> int:
    try:
        from nemla_ui import launcher
    except ImportError:
        log("The 3D interface files (the nemla_ui/ folder) were not found next to the nemla package.")
        return 1
    if args.install_launcher:
        return launcher.install()
    return launcher.uninstall()


def _save(path: str, kind: str, meta: dict, hosts: list, fmt: str) -> bool:
    try:
        write_report(path, fmt, meta, hosts)
    except OSError as err:
        log(f"Cannot write the {kind} report to {path}: {err.strerror or err}")
        return False
    log(t("saved", kind=kind, path=path))
    return True


def use_utf8_output() -> None:
    """Write UTF-8 (never crash on a character the console's code page lacks). This has to happen before argparse
    prints anything: `--help` and error messages contain Arabic, Hebrew and symbols, and on Windows a piped stdout
    is cp1252 (or a legacy OEM page), which raised UnicodeEncodeError and printed nothing."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)   # TextIOWrapper has it, a redirected stream may not
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv=None) -> int:
    use_utf8_output()
    parser = build_parser()
    given = sys.argv[1:] if argv is None else list(argv)
    if given and given[0] in ("controller", "agent"):        # Fleet mode has its own sub-commands
        from .fleet.cli import main as fleet_main
        return fleet_main(given)
    bare = not given
    args = parser.parse_args(expand_command_word(given))
    if args.target_arg:
        if args.target:
            parser.error("give the target once: either as an argument or with -t, not both")
        args.target = args.target_arg
    i18n._LANG = args.lang or "en"
    if args.verbose:
        enable_debug()

    if args.install_launcher or args.uninstall_launcher:
        return manage_launcher(args)
    if args.diff:
        return run_diff(args)
    if args.guard:
        return run_guard(args)
    if args.ui or bare:
        print_banner()
        return launch_ui(args)
    if not args.target:
        parser.error("what should I scan? Give a target, for example: nemla 192.168.1.10 "
                     "(or run nemla with no arguments to open the 3D interface)")
    if args.watch:
        return run_watch(args)
    print_banner()

    inputs = scan_inputs(args)
    if inputs is None:
        return 1
    ips, ports, udp = inputs

    hosts, meta = run_scan(args.target, ips, ports, **scan_options(args, udp))
    if not meta["discovered"]:
        return 0
    log(t("done", sec=meta["duration"]))

    counts = meta["findings"]
    log(t("findings_summary", high=counts["high"], medium=counts["medium"], low=counts["low"]))
    for host in hosts:
        for finding in host["findings"]:
            if finding["severity"] != "info":
                log(f"[{t('sev_' + finding['severity'])}] {host['ip']}: {finding_text(finding)}")
    for item in meta.get("warnings", []):
        log(f"! {item['code']}: {item['message']}")

    ok = _save(args.output, "HTML", meta, hosts, "html")
    for path, kind, fmt in ((args.json, "JSON", "json"), (args.csv, "CSV", "csv"),
                            (args.md, "Markdown", "md"), (args.sarif, "SARIF", "sarif")):
        if path:
            ok = _save(path, kind, meta, hosts, fmt) and ok
    if not ok:
        return 1
    if args.fail_on:
        hits = sum(n for name, n in counts.items() if SEV_RANK[name] >= SEV_RANK[args.fail_on])
        if hits:
            log(t("fail_on", n=hits, level=t("sev_" + args.fail_on)))
            return 3
    return 0
