"""`nemla controller ...` and `nemla agent ...`: the command line of Fleet mode.

    nemla controller serve [--tls-cert F --tls-key F]     run the controller (keep it running)
    nemla controller enroll-token NAME                    a one-time token for a new agent
    nemla controller agents | jobs | results AGENT | audit
    nemla controller dispatch AGENT TARGET -p PORTS       queue a scan for an agent (inside its scope)
    nemla controller job ID | cancel ID | revoke AGENT

    nemla agent enroll URL --token T --scope S --pin P    enroll THIS machine (scope and limits are set here)
    nemla agent run | status | leave

The controller commands talk to the controller running on this machine through its loopback operator API, so the
controller is the only process that ever writes its files.
"""
from __future__ import annotations

import argparse
import getpass
import http.client
import json
import sys
import threading
import time
from pathlib import Path

from ..guard import data_dir as default_data_dir
from ..log import log
from . import agent as agent_mod
from .controller import FleetError

_PROG = "nemla"


def _folders(args) -> tuple:
    base = Path(args.data_dir) if args.data_dir else default_data_dir()
    return base / "fleet", base / "agent"


def _api(folder, method: str, name: str, body=None, query=None):
    from nemla_ui.fleet_server import read_local_endpoint      # the UI package is only needed for the controller
    url, token = read_local_endpoint(folder)
    port = int(url.rsplit(":", 1)[1])
    path = "/api/fleet/" + name + (("?" + "&".join(f"{k}={v}" for k, v in query.items())) if query else "")
    headers = {"X-Nemla-Token": token, "X-Nemla-Operator": getpass.getuser()}
    payload = None
    if body is not None:
        payload = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read()
    except OSError as err:
        raise FleetError(f"cannot reach the controller on this machine ({err.strerror or err})", 503) from None
    finally:
        conn.close()
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        data = {}
    if response.status != 200:
        raise FleetError(str(data.get("error") or f"the controller answered {response.status}"), response.status)
    return data


def _when(epoch) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if isinstance(epoch, (int, float)) else "-"


def _table(header, rows, widths) -> list:
    def line(cells):
        return "  ".join(str(cell)[:width].ljust(width) for cell, width in zip(cells, widths)).rstrip()
    return [line(header), *[line(row) for row in rows]]


def _print(args, data, lines=None) -> None:
    if args.json or lines is None:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        for line in lines:
            print(line)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", help="where Nemla keeps its files (default: the usual data folder)")
    common.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser = argparse.ArgumentParser(prog=_PROG, description="Fleet mode: one controller, several enrolled agents.")
    top = parser.add_subparsers(dest="role", required=True)

    ctl = top.add_parser("controller", help="run and operate the controller").add_subparsers(dest="action", required=True)
    serve = ctl.add_parser("serve", parents=[common], help="run the controller until Ctrl+C")
    serve.add_argument("--host", default="127.0.0.1", help="address for agents to connect to (default: this machine only)")
    serve.add_argument("--port", type=int, default=8443, help="agent port (default 8443)")
    serve.add_argument("--operator-port", type=int, default=0, help="loopback port of the operator API and page (default: any)")
    serve.add_argument("--tls-cert", help="certificate file (PEM); required to listen on anything but this machine")
    serve.add_argument("--tls-key", help="its private key file (PEM)")
    token = ctl.add_parser("enroll-token", parents=[common], help="a one-time token for a new agent")
    token.add_argument("name", help="the agent's name (letters, digits, dots, dashes)")
    ctl.add_parser("agents", parents=[common], help="the enrolled agents and their state")
    jobs = ctl.add_parser("jobs", parents=[common], help="recent jobs")
    jobs.add_argument("-n", type=int, default=20, help="how many (default 20)")
    job = ctl.add_parser("job", parents=[common], help="one job")
    job.add_argument("id")
    dispatch = ctl.add_parser("dispatch", parents=[common], help="queue a scan for an agent")
    dispatch.add_argument("agent")
    dispatch.add_argument("target", help="addresses, CIDR blocks or ranges (never names) inside the agent's scope")
    dispatch.add_argument("-p", "--ports", default="1-1024", help="TCP ports (default 1-1024)")
    dispatch.add_argument("--udp-ports", help="UDP ports to probe as well")
    dispatch.add_argument("--no-os", action="store_true", help="skip OS fingerprinting")
    dispatch.add_argument("--no-ping", action="store_true", help="treat every address as up")
    dispatch.add_argument("--timeout", type=float, help="seconds to wait per connection")
    dispatch.add_argument("--threads", type=int, help="concurrent connections")
    cancel = ctl.add_parser("cancel", parents=[common], help="cancel a queued or running job")
    cancel.add_argument("id")
    revoke = ctl.add_parser("revoke", parents=[common], help="revoke an agent at once")
    revoke.add_argument("agent")
    results = ctl.add_parser("results", parents=[common], help="an agent's saved scans")
    results.add_argument("agent")
    audit = ctl.add_parser("audit", parents=[common], help="the newest audit entries")
    audit.add_argument("-n", type=int, default=30)

    ag = top.add_parser("agent", help="enroll and run an agent on this machine").add_subparsers(dest="action", required=True)
    enroll = ag.add_parser("enroll", parents=[common], help="enroll this machine with a controller")
    enroll.add_argument("url", help="https://HOST:PORT of the controller")
    enroll.add_argument("--token", required=True, help="the one-time token from `nemla controller enroll-token`")
    enroll.add_argument("--scope", required=True, help="the addresses this agent may ever scan, e.g. 10.20.0.0/16")
    enroll.add_argument("--pin", help="the controller certificate's SHA-256 fingerprint (printed by `controller serve`)")
    enroll.add_argument("--max-hosts", type=int, default=agent_mod.DEFAULT_MAX_HOSTS, help="most addresses in one job")
    enroll.add_argument("--max-minutes", type=int, default=agent_mod.DEFAULT_MAX_MINUTES, help="longest a job may run")
    ag.add_parser("run", parents=[common], help="run the agent until Ctrl+C")
    ag.add_parser("status", parents=[common], help="what this agent is set up to do")
    ag.add_parser("leave", parents=[common], help="delete this machine's credentials")
    return parser


def _serve(args, fleet_folder) -> int:
    try:
        from nemla_ui.fleet_server import start_controller
    except ImportError:
        log("The Fleet controller needs the nemla_ui package next to nemla.")
        return 1
    try:
        running = start_controller(fleet_folder, args.host, args.port, args.operator_port, args.tls_cert, args.tls_key)
    except (ValueError, OSError) as err:
        log(f"Cannot start the controller: {err}")
        return 1
    transport = "TLS" if running.pin else "no TLS: this machine only"
    log(f"Controller: agents connect to {args.host}:{running.agent_port} ({transport})")
    if running.pin:
        log(f"Certificate pin for `nemla agent enroll --pin`: {running.pin}")
    log(f"Operator page: http://127.0.0.1:{running.operator_port}/#k={running.token}")
    log("Operate it with `nemla controller ...` from this machine. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    running.stop()
    log("Controller stopped.")
    return 0


def _controller(args, folder) -> int:
    if args.action == "serve":
        return _serve(args, folder)
    action = args.action
    if action == "enroll-token":
        data = _api(folder, "POST", "enroll-token", {"name": args.name})
        _print(args, data, [f"Token for agent {data['name']} (one use, valid {data['expires_in'] // 60} minutes):", "",
                            f"    {data['token']}", "",
                            "On the machine to be watched:",
                            f"    nemla agent enroll https://CONTROLLER:PORT --token {data['token']} --scope NETWORK --pin PIN"])
    elif action == "agents":
        data = _api(folder, "GET", "agents")
        agent_rows = [(a["name"], a["status"], a["scope"] or "", a["queued"], _when(a["last_seen"])) for a in data["agents"]]
        _print(args, data, _table(("NAME", "STATUS", "SCOPE", "QUEUED", "LAST SEEN"), agent_rows, (18, 8, 22, 6, 19))
               if agent_rows else ["No agents yet."])
    elif action == "jobs":
        data = _api(folder, "GET", "jobs", query={"limit": args.n})
        job_rows = [(j["id"], j["agent"], j["state"], j["target"], j["ports"]) for j in data["jobs"]]
        _print(args, data, _table(("JOB", "AGENT", "STATE", "TARGET", "PORTS"), job_rows, (17, 14, 9, 24, 20)))
    elif action == "job":
        data = _api(folder, "GET", "job", query={"id": args.id})
        _print(args, data)
    elif action == "dispatch":
        wanted = (("no_os", args.no_os or None), ("no_ping", args.no_ping or None), ("timeout", args.timeout),
                  ("threads", args.threads), ("udp_ports", args.udp_ports))
        options = {key: value for key, value in wanted if value is not None}
        data = _api(folder, "POST", "dispatch", {"agent": args.agent, "job": {"target": args.target, "ports": args.ports,
                                                                                "options": options}})
        _print(args, data, [f"Queued job {data['id']} for {data['agent']}: {data['target']} ports {data['ports']}"])
    elif action == "cancel":
        data = _api(folder, "POST", "cancel", {"job": args.id})
        _print(args, data, [f"Job {data['id']} is {data['state']}."])
    elif action == "revoke":
        data = _api(folder, "POST", "revoke", {"agent": args.agent})
        _print(args, data, [f"Revoked {data['name']}; {data['jobs_dropped']} job(s) dropped. It is refused from now on."])
    elif action == "results":
        data = _api(folder, "GET", "results", query={"agent": args.agent})
        result_rows = [(r["id"], r["target"], r["hosts"], r["open_ports"]) for r in data["results"]]
        _print(args, data, _table(("SCAN", "TARGET", "HOSTS", "OPEN PORTS"), result_rows, (38, 20, 6, 10)))
    elif action == "audit":
        data = _api(folder, "GET", "audit", query={"limit": args.n})
        def detail(entry):
            return " ".join(f"{k}={v}" for k, v in entry.items() if k not in ("time", "epoch", "event"))
        _print(args, data, [f"{e['time']}  {e['event']:<22} {detail(e)}" for e in data["events"]])
    return 0


def _agent(args, folder) -> int:
    action = args.action
    if action == "enroll":
        status = agent_mod.enroll(folder, args.url, args.token, args.scope, args.pin or "", args.max_hosts, args.max_minutes)
        _print(args, status, [f"Enrolled as {status['name']} with {status['controller']}.",
                              f"Scope: {status['scope']} ({status['scope_addresses']} addresses); at most "
                              f"{status['max_hosts']} addresses and {status['max_minutes']} minutes per job - "
                              "set here, not changeable by the controller.",
                              "Start it with: nemla agent run"])
    elif action == "status":
        status = agent_mod.status_of(folder)
        _print(args, status, [f"{k}: {v}" for k, v in status.items()])
    elif action == "leave":
        gone = agent_mod.leave(folder)
        _print(args, {"left": gone}, ["Credentials deleted. Also run `nemla controller revoke NAME` on the controller."
                                       if gone else "This machine was not enrolled."])
    elif action == "run":
        stop = threading.Event()
        runner = agent_mod.Runner(folder, stop)
        try:
            reason = runner.run()
        except KeyboardInterrupt:
            stop.set()
            reason = "stopped"
        return 0 if reason == "stopped" else 3
    return 0


def main(argv) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv))
    fleet_folder, agent_folder = _folders(args)
    try:
        return _controller(args, fleet_folder) if args.role == "controller" else _agent(args, agent_folder)
    except (FleetError, agent_mod.AgentError) as err:
        print(f"{_PROG}: {err}", file=sys.stderr)
        return 1
