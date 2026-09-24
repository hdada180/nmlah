"""The Fleet agent against a real controller (plain loopback and TLS), a real scan, and a hostile fake controller."""
import http.server
import json
import os
import socket
import ssl
import threading
import time

import pytest

import nemla
from nemla.fleet import agent, protocol
from nemla_ui import fleet_server

from conftest import wait_until
from test_detect import TEST_CERT, TEST_KEY
from test_fleet_controller import op

posix_only = pytest.mark.skipif(os.name != "posix", reason="owner-only permissions are checked on POSIX")
BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
OPTIONS = {"no_os": True, "no_ping": True, "timeout": 1}


@pytest.fixture()
def rc(tmp_path):
    controller = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0)
    yield controller
    controller.stop()


@pytest.fixture()
def tls_rc(tmp_path):
    (tmp_path / "cert.pem").write_text(TEST_CERT, encoding="utf-8")
    (tmp_path / "key.pem").write_text(TEST_KEY, encoding="utf-8")
    controller = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0, tmp_path / "cert.pem", tmp_path / "key.pem")
    yield controller
    controller.stop()


@pytest.fixture()
def target_port(tcp_server):
    return tcp_server(lambda conn: (conn.sendall(BANNER), conn.close()))


def token_for(controller, name):
    return op(controller, "POST", "enroll-token", {"name": name})[1]["token"]


def enroll_agent(controller, folder, name="acme-hq", scope="127.0.0.0/24", tls=False, **kwargs):
    url = f"{'https' if tls else 'http'}://127.0.0.1:{controller.agent_port}"
    return agent.enroll(folder, url, token_for(controller, name), scope, controller.pin or "", **kwargs)


class Running:
    """A Runner on its own thread, with its log lines collected."""

    def __init__(self, folder, run=None, poll=1.0, busy=0.2):
        self.stop, self.lines, self.reason = threading.Event(), [], None
        extra = {"run": run} if run else {}
        self.runner = agent.Runner(folder, self.stop, say=self.lines.append, poll_seconds=poll, busy_wait=busy, **extra)
        self.thread = threading.Thread(target=self._go, daemon=True)
        self.thread.start()

    def _go(self):
        self.reason = self.runner.run()

    def finish(self, timeout=20):
        self.stop.set()
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "the agent did not stop"
        return self.reason


@pytest.fixture()
def running_agents():
    started = []
    yield started
    for one in started:
        one.stop.set()
    for one in started:
        one.thread.join(20)


def start(running_agents, folder, **kwargs):
    one = Running(folder, **kwargs)
    running_agents.append(one)
    return one


def dispatch(controller, name, target="127.0.0.1", ports="22", options=None):
    status, body, _ = op(controller, "POST", "dispatch", {"agent": name, "job": {"target": target, "ports": ports,
                                                                                    "options": options if options is not None else OPTIONS}})
    assert status == 200, body
    return body


def job_state(controller, job_id):
    return op(controller, "GET", f"job?id={job_id}")[1]


def wait_for_state(controller, job_id, *states, timeout=25):
    assert wait_until(lambda: job_state(controller, job_id)["state"] in states, timeout=timeout), job_state(controller, job_id)
    return job_state(controller, job_id)


def agent_events(folder, name=None):
    log = agent._audit(folder)
    return [e for e in log.tail(500) if name is None or e["event"] == name]


class FakeScan:
    """A stand-in for run_scan that records its calls and can be told to block, crash or return a result."""

    def __init__(self, mode="result", hosts=None):
        self.calls, self.mode, self.cancelled, self.started = [], mode, threading.Event(), threading.Event()
        self.hosts = hosts if hosts is not None else [{"ip": "127.0.0.1", "mac": None, "os_guess": "x", "ttl": 64, "findings": [],
                                                       "open_ports": [{"port": 22, "proto": "tcp", "state": "open", "service": "SSH",
                                                                       "banner": "", "detected": "ssh"}]}]

    def __call__(self, target, ips, ports, *, cancel=None, **kwargs):
        self.calls.append({"target": target, "ports": ports, **kwargs})
        self.started.set()
        if self.mode == "crash" and len(self.calls) == 1:
            raise RuntimeError("the scan blew up")
        if self.mode == "block":
            cancel.wait(60)
            if cancel.is_set():
                self.cancelled.set()
                return [], {"scan_time": "t", "duration": 0.1, "ports_scanned": 1, "cancelled": True, "discovered": 0}
        return self.hosts, {"scan_time": "2026-01-01 10:00:00", "duration": 0.5, "ports_scanned": len(ports), "cancelled": False,
                            "findings": {"info": 0, "low": 0, "medium": 0, "high": 0}, "discovered": len(self.hosts)}


# --------------------------------------------------------------------------
# a real scan, end to end
# --------------------------------------------------------------------------

def test_a_real_scan_runs_end_to_end_and_is_recorded_on_both_sides(rc, tmp_path, target_port, running_agents):
    folder = tmp_path / "agent"
    status = enroll_agent(rc, folder)
    assert status["name"] == "acme-hq" and status["scope"] == "127.0.0.0/24" and "secret" not in status
    one = start(running_agents, folder)
    job = dispatch(rc, "acme-hq", ports=str(target_port))
    done = wait_for_state(rc, job["id"], "done", "failed")
    assert done["state"] == "done", done
    assert done["summary"]["hosts"] == 1 and done["summary"]["open_ports"] == 1
    scan_id = op(rc, "GET", "results?agent=acme-hq")[1]["results"][0]["id"]
    stored = op(rc, "GET", f"result?agent=acme-hq&id={scan_id}")[1]
    assert stored["target"] == "127.0.0.1" and stored["hosts"][0]["open_ports"][0]["port"] == target_port
    assert "OpenSSH" in json.dumps(stored["hosts"][0]["open_ports"][0])
    assert [e["event"] for e in agent_events(folder)] == ["enrolled", "started", "job_received", "job_started", "job_finished"]
    controller_side = [e["event"] for e in op(rc, "GET", "audit")[1]["events"]]
    assert controller_side == ["enroll_token_issued", "enroll", "dispatch", "job_sent", "job_started", "job_finished"]
    assert one.runner.jobs_done == 1 and any("scanning 127.0.0.1" in line for line in one.lines)


def test_the_same_scan_over_tls_with_a_pinned_certificate(tls_rc, tmp_path, target_port, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(tls_rc, folder, tls=True)
    assert agent.load_config(folder)["pin"] == tls_rc.pin and agent.load_config(folder)["controller"].startswith("https://")
    start(running_agents, folder)
    job = dispatch(tls_rc, "acme-hq", ports=str(target_port))
    assert wait_for_state(tls_rc, job["id"], "done", "failed")["state"] == "done"


def test_a_second_scan_from_the_same_agent_is_compared_with_the_first(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    scan = FakeScan()
    start(running_agents, folder, run=scan)
    first = dispatch(rc, "acme-hq", target="127.0.0.1,127.0.0.2")
    assert wait_for_state(rc, first["id"], "done")["summary"]["changes"] is None            # nothing to compare with yet
    scan.hosts = [*scan.hosts, {**scan.hosts[0], "ip": "127.0.0.2"}]
    second = dispatch(rc, "acme-hq", target="127.0.0.1,127.0.0.2")                         # history compares scans of the same target
    done = wait_for_state(rc, second["id"], "done")
    assert done["summary"]["changes"]["new_hosts"] == 1


# --------------------------------------------------------------------------
# the agent decides what it will scan
# --------------------------------------------------------------------------

def test_the_agents_own_scope_wins_even_when_the_controller_would_send_the_job(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    record = enroll_agent(rc, folder, scope="127.0.0.0/30")
    rc.controller.registry._agents[record["agent_id"]]["scope"] = "127.0.0.0/24"          # the controller's copy is wider
    scan = FakeScan()
    start(running_agents, folder, run=scan)
    job = dispatch(rc, "acme-hq", target="127.0.0.9")                                      # the controller lets it through
    failed = wait_for_state(rc, job["id"], "failed")
    assert "refused by the agent" in failed["error"] and "outside" in failed["error"]
    assert scan.calls == []
    refused = agent_events(folder, "job_refused")
    assert len(refused) == 1 and refused[0]["job"] == job["id"] and "outside" in refused[0]["reason"]


def test_the_agents_own_host_limit_wins(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder, max_hosts=4)
    scan = FakeScan()
    start(running_agents, folder, run=scan)
    job = dispatch(rc, "acme-hq", target="127.0.0.0/29")                                   # 6 addresses
    assert "refused by the agent" in wait_for_state(rc, job["id"], "failed")["error"]
    ok = dispatch(rc, "acme-hq", target="127.0.0.0/30")                                    # 2 addresses
    wait_for_state(rc, ok["id"], "done")
    assert len(scan.calls) == 1


def test_a_scan_that_crashes_is_a_failed_job_and_the_agent_carries_on(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    scan = FakeScan("crash")
    one = start(running_agents, folder, run=scan)
    first = dispatch(rc, "acme-hq")
    assert "RuntimeError: the scan blew up" in wait_for_state(rc, first["id"], "failed")["error"]
    second = dispatch(rc, "acme-hq")
    assert wait_for_state(rc, second["id"], "done")["state"] == "done"
    assert one.thread.is_alive()


def test_a_scan_that_outlives_the_agents_time_limit_is_stopped_by_the_agent(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    scan = FakeScan("block")
    one = start(running_agents, folder, run=scan)
    one.runner.limits["seconds"] = 1
    job = dispatch(rc, "acme-hq")
    failed = wait_for_state(rc, job["id"], "failed")
    assert "time limit" in failed["error"] and scan.cancelled.is_set()


def test_a_result_too_large_for_the_controller_is_reported_as_a_failure(rc, tmp_path, running_agents, monkeypatch):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    start(running_agents, folder, run=FakeScan())
    monkeypatch.setattr(protocol, "MAX_RESULT_BYTES", 200)
    job = dispatch(rc, "acme-hq")
    assert "scan a smaller range" in wait_for_state(rc, job["id"], "failed")["error"]


def test_cancelling_a_running_job_stops_the_scan(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    scan = FakeScan("block")
    start(running_agents, folder, run=scan)
    job = dispatch(rc, "acme-hq")
    assert scan.started.wait(15)
    assert wait_until(lambda: job_state(rc, job["id"])["state"] == "running")
    op(rc, "POST", "cancel", {"job": job["id"]})
    assert scan.cancelled.wait(15)
    assert job_state(rc, job["id"])["state"] == "cancelled"


# --------------------------------------------------------------------------
# revocation, from both sides
# --------------------------------------------------------------------------

def test_revoking_an_idle_agent_stops_it_at_once(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    one = start(running_agents, folder, poll=20)             # a long poll: revocation must wake it, not wait for it
    assert wait_until(lambda: op(rc, "GET", "agents")[1]["agents"][0]["status"] == "online")
    started = time.monotonic()
    op(rc, "POST", "revoke", {"agent": "acme-hq"})
    one.thread.join(10)
    assert one.reason == "revoked" and time.monotonic() - started < 8
    assert agent_events(folder, "ended")[0]["reason"] == "revoked"


def test_revoking_an_agent_in_the_middle_of_a_scan_stops_the_scan_and_drops_the_result(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    scan = FakeScan("block")
    one = start(running_agents, folder, run=scan)
    job = dispatch(rc, "acme-hq")
    assert scan.started.wait(15)
    op(rc, "POST", "revoke", {"agent": "acme-hq"})
    one.thread.join(20)
    assert one.reason == "revoked" and scan.cancelled.is_set()
    assert op(rc, "GET", "results?agent=acme-hq")[1]["results"] == []
    assert job_state(rc, job["id"])["state"] == "cancelled"


def test_leaving_deletes_the_credentials_and_the_agent_can_no_longer_run(rc, tmp_path):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    assert agent.leave(folder) is True and agent.leave(folder) is False
    with pytest.raises(agent.AgentError, match="not enrolled"):
        agent.Runner(folder, threading.Event())
    assert [e["event"] for e in agent_events(folder)] == ["enrolled", "left"]


# --------------------------------------------------------------------------
# the pin
# --------------------------------------------------------------------------

def test_a_wrong_pin_stops_the_enrollment_before_the_token_is_sent_or_spent(tls_rc, tmp_path):
    token = token_for(tls_rc, "acme-hq")
    url = f"https://127.0.0.1:{tls_rc.agent_port}"
    with pytest.raises(agent.PinMismatch):
        agent.enroll(tmp_path / "agent", url, token, "127.0.0.0/24", "sha256:" + "0" * 64)
    assert not (tmp_path / "agent" / "agent.json").exists()
    status = agent.enroll(tmp_path / "agent", url, token, "127.0.0.0/24", tls_rc.pin)      # the very same token still works
    assert status["name"] == "acme-hq"


def test_an_agent_whose_controller_changed_certificate_stops_and_sends_nothing(tmp_path):
    (tmp_path / "cert.pem").write_text(TEST_CERT, encoding="utf-8")
    (tmp_path / "key.pem").write_text(TEST_KEY, encoding="utf-8")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(tmp_path / "cert.pem"), str(tmp_path / "key.pem"))
    seen = []
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)

    def serve():
        while True:
            try:
                raw, _ = server.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(2)
                    seen.append(tls.recv(4096))
            except (OSError, ssl.SSLError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    folder = tmp_path / "agent"
    folder.mkdir()
    (folder / "agent.json").write_text(json.dumps({
        "controller": f"https://127.0.0.1:{server.getsockname()[1]}", "pin": "sha256:" + "1" * 64, "agent_id": "abcdef0123456789",
        "secret": "the-secret-that-must-never-leave", "name": "acme-hq", "scope": "127.0.0.0/24"}), encoding="utf-8")
    try:
        stop = threading.Event()
        lines = []
        reason = agent.Runner(folder, stop, say=lines.append, poll_seconds=1).run()
        assert reason == "pin_mismatch" and any("not the one pinned" in line for line in lines)
        assert all(b"the-secret-that-must-never-leave" not in chunk and chunk == b"" for chunk in seen)     # nothing arrived
        assert agent_events(folder, "ended")[0]["reason"] == "pin_mismatch"
    finally:
        server.close()


@pytest.mark.parametrize("url, pin", [
    ("https://controller.example:8443", None), ("https://controller.example:8443", "sha256:abc"),
    ("http://10.0.0.5:8443", None), ("http://controller.example", None), ("ftp://127.0.0.1:1", None),
    ("https://user:pass@controller.example:8443", "sha256:" + "a" * 64), ("https://c.example:8443/path", "sha256:" + "a" * 64),
    ("https://c.example:8443/?x=1", "sha256:" + "a" * 64), ("https://c.example:notaport", "sha256:" + "a" * 64), ("", None),
    ("https://", "sha256:" + "a" * 64)])
def test_a_controller_address_is_https_with_a_pin_or_plain_http_to_this_machine(url, pin):
    with pytest.raises(agent.AgentError):
        agent.Transport(url, pin)


@pytest.mark.parametrize("url, pin", [("https://c.example:8443", "sha256:" + "a" * 64), ("c.example:8443", "AA" * 32),
                                      ("http://127.0.0.1:9", None), ("http://localhost:9", None), ("http://[::1]:9", None)])
def test_the_usual_spellings_of_a_good_controller_address_are_accepted(url, pin):
    transport = agent.Transport(url, pin)
    assert transport.url.count("://") == 1 and (transport.pin is None) == (not transport.tls)


# --------------------------------------------------------------------------
# local limits on enrolling, and what is kept
# --------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs, message", [({"scope_spec": "example.com"}, "scope"), ({"scope_spec": "0.0.0.0/0"}, "scope"),
                                             ({"scope_spec": ""}, "scope"), ({"max_hosts": 0}, "max-hosts"),
                                             ({"max_hosts": 10 ** 6}, "max-hosts"), ({"max_minutes": 0}, "max-minutes"),
                                             ({"max_minutes": 5000}, "max-minutes"), ({"max_hosts": "5"}, "max-hosts")])
def test_a_scope_or_limit_that_makes_no_sense_is_refused_before_any_network_use(tmp_path, kwargs, message):
    args = {"url": "http://127.0.0.1:9", "token": "t", "scope_spec": "127.0.0.0/24", "pin": ""}
    args.update(kwargs)
    with pytest.raises(agent.AgentError, match=message):
        agent.enroll(tmp_path / "agent", **args)


def test_a_controller_that_is_not_there_is_reported_plainly(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(agent.AgentError, match="cannot reach the controller"):
        agent.enroll(tmp_path / "agent", f"http://127.0.0.1:{port}", "t", "127.0.0.0/24", "")


def test_enrolling_twice_is_refused_and_a_refused_enrollment_leaves_nothing_behind(rc, tmp_path):
    folder = tmp_path / "agent"
    with pytest.raises(agent.AgentError, match="refused"):
        agent.enroll(folder, f"http://127.0.0.1:{rc.agent_port}", "wrong-token", "127.0.0.0/24", "")
    assert not (folder / "agent.json").exists()
    enroll_agent(rc, folder)
    with pytest.raises(agent.AgentError, match="already enrolled"):
        enroll_agent(rc, folder, "second")


def test_the_status_never_shows_the_secret_and_a_damaged_file_is_reported(rc, tmp_path):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    secret = agent.load_config(folder)["secret"]
    assert secret not in json.dumps(agent.status_of(folder))
    (folder / "agent.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(agent.AgentError, match="damaged"):
        agent.status_of(folder)
    (folder / "agent.json").write_text('{"controller": 5}', encoding="utf-8")
    with pytest.raises(agent.AgentError, match="damaged"):
        agent.load_config(folder)


@posix_only
def test_the_agent_files_are_owner_only(rc, tmp_path):
    folder = tmp_path / "agent"
    enroll_agent(rc, folder)
    assert oct((folder / "agent.json").stat().st_mode & 0o777) == "0o600"
    assert oct((folder / "audit.jsonl").stat().st_mode & 0o777) == "0o600"
    assert oct(folder.stat().st_mode & 0o777) == "0o700"


def test_the_agents_audit_trail_never_holds_the_secret_or_the_token(rc, tmp_path, running_agents):
    folder = tmp_path / "agent"
    token = token_for(rc, "acme-hq")
    agent.enroll(folder, f"http://127.0.0.1:{rc.agent_port}", token, "127.0.0.0/24", "")
    start(running_agents, folder, run=FakeScan())
    wait_for_state(rc, dispatch(rc, "acme-hq")["id"], "done")
    text = (folder / "audit.jsonl").read_text(encoding="utf-8")
    assert agent.load_config(folder)["secret"] not in text and token not in text


# --------------------------------------------------------------------------
# a hostile controller cannot make the agent do anything but refuse
# --------------------------------------------------------------------------

class HostileController:
    """A plain-HTTP 'controller' that answers polls with scripted jobs and records everything the agent posts."""

    def __init__(self, jobs):
        self.jobs, self.posted, self.acks = list(jobs), [], []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                if self.path == "/agent/v1/poll":
                    job = outer.jobs.pop(0) if outer.jobs and not body.get("busy") else None
                    time.sleep(0.05 if job else 0.3)
                    answer = json.dumps({"job": job, "cancel": [], "poll_seconds": 25}).encode()
                elif self.path == "/agent/v1/ack":
                    outer.acks.append(body)
                    answer = b'{"ok": true}'
                else:
                    outer.posted.append(body)
                    answer = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def hostile_agent(tmp_path, port, scope="127.0.0.0/30", **extra):
    folder = tmp_path / "agent"
    folder.mkdir()
    cfg = {"controller": f"http://127.0.0.1:{port}", "pin": None, "agent_id": "abcdef0123456789", "secret": "s", "name": "acme-hq",
           "scope": scope, "max_hosts": 4, "max_minutes": 1, **extra}
    (folder / "agent.json").write_text(json.dumps(cfg), encoding="utf-8")
    return folder


@pytest.mark.parametrize("job", [
    {"id": "0123456789abcdef", "target": "10.0.0.5", "ports": "22"},                                     # outside the scope
    {"id": "0123456789abcdef", "target": "127.0.0.0/24", "ports": "22"},                                 # more than its host limit
    {"id": "0123456789abcdef", "target": "example.com", "ports": "22"},                                  # a name
    {"id": "0123456789abcdef", "target": "127.0.0.1", "ports": "22", "options": {"shell": "id"}},        # an option that does not exist
    {"id": "0123456789abcdef", "target": "127.0.0.1", "ports": "22", "options": {"threads": 10 ** 9}},   # an absurd one
    {"id": "0123456789abcdef", "target": "127.0.0.1", "ports": "0"},
    {"id": "0123456789abcdef", "target": "$(reboot)", "ports": "22"},
    {"id": "0123456789abcdef", "target": ["127.0.0.1"], "ports": "22"},
    {"id": "0123456789abcdef", "ports": "22"},
])
def test_a_hostile_job_is_refused_reported_and_never_scanned(tmp_path, running_agents, job):
    fake = HostileController([job])
    try:
        scan = FakeScan()
        one = Running(hostile_agent(tmp_path, fake.port), run=scan, poll=1)
        running_agents.append(one)
        assert wait_until(lambda: fake.posted, timeout=15)
        assert scan.calls == [] and fake.acks == []
        assert fake.posted[0]["state"] == "failed" and fake.posted[0]["error"].startswith("refused by the agent")
        assert agent_events(tmp_path / "agent", "job_refused")
        assert one.thread.is_alive()                                        # and it keeps working
    finally:
        fake.close()


@pytest.mark.parametrize("job", [{"target": "127.0.0.1", "ports": "22"}, {"id": "../../etc/passwd", "target": "127.0.0.1", "ports": "22"},
                                 {"id": 5, "target": "127.0.0.1", "ports": "22"}, "not a job", 7, ["127.0.0.1"]])
def test_a_job_without_a_valid_id_is_ignored(tmp_path, running_agents, job):
    fake = HostileController([job])
    try:
        scan = FakeScan()
        one = Running(hostile_agent(tmp_path, fake.port), run=scan, poll=1)
        running_agents.append(one)
        time.sleep(1.5)
        assert scan.calls == [] and fake.posted == [] and fake.acks == [] and one.thread.is_alive()
    finally:
        fake.close()


def test_a_controller_that_sends_extra_fields_cannot_add_anything_to_a_valid_job(tmp_path, running_agents):
    job = {"id": "0123456789abcdef", "target": "127.0.0.1", "ports": "22,80", "options": {"timeout": 1}, "cmd": "id",
           "script": "x", "url": "http://evil", "expires": 1}
    fake = HostileController([job])
    try:
        scan = FakeScan()
        one = Running(hostile_agent(tmp_path, fake.port), run=scan, poll=1)
        running_agents.append(one)
        assert wait_until(lambda: fake.posted, timeout=15)
        assert scan.calls == [{"target": "127.0.0.1", "ports": [22, 80], "timeout": 1}]     # exactly the validated fields
        assert fake.posted[0]["state"] == "done"
    finally:
        fake.close()


def test_an_unreachable_controller_is_retried_with_a_backoff_and_the_agent_can_still_be_stopped(tmp_path, monkeypatch):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    monkeypatch.setattr(agent, "MAX_BACKOFF", 0.2)
    one = Running(hostile_agent(tmp_path, port), poll=1)
    try:
        assert wait_until(lambda: any("Cannot reach the controller" in line for line in one.lines), timeout=10)
    finally:
        assert one.finish() == "stopped"
    assert agent_events(tmp_path / "agent", "ended")[0]["reason"] == "stopped"


# --------------------------------------------------------------------------
# the command line, end to end
# --------------------------------------------------------------------------

def cli(capsys, *argv):
    code = nemla.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_command_line_runs_a_whole_fleet_session(rc, tmp_path, capsys, target_port, running_agents):
    data = ["--data-dir", str(tmp_path)]
    assert (tmp_path / "fleet").exists()
    code, out, _ = cli(capsys, "controller", "enroll-token", "acme-hq", "--json", *data)
    token = json.loads(out)["token"]
    assert code == 0 and len(token) >= 40
    code, out, _ = cli(capsys, "agent", "enroll", f"http://127.0.0.1:{rc.agent_port}", "--token", token, "--scope", "127.0.0.0/24", *data)
    assert code == 0 and "Enrolled as acme-hq" in out and "set here, not changeable by the controller" in out
    code, out, _ = cli(capsys, "agent", "status", *data)
    assert code == 0 and "scope: 127.0.0.0/24" in out and "secret" not in out
    start(running_agents, tmp_path / "agent")
    code, out, _ = cli(capsys, "controller", "dispatch", "acme-hq", "127.0.0.1", "-p", str(target_port), "--no-os", "--no-ping",
                       "--timeout", "1", *data)
    assert code == 0 and "Queued job" in out
    job_id = out.split()[2]
    assert wait_until(lambda: job_state(rc, job_id)["state"] == "done", timeout=25)
    code, out, _ = cli(capsys, "controller", "jobs", *data)
    assert code == 0 and job_id in out and "done" in out
    code, out, _ = cli(capsys, "controller", "agents", *data)
    assert code == 0 and "acme-hq" in out and "online" in out
    code, out, _ = cli(capsys, "controller", "results", "acme-hq", *data)
    assert code == 0 and "127.0.0.1" in out
    code, out, _ = cli(capsys, "controller", "audit", "-n", "50", *data)
    assert code == 0 and "dispatch" in out and "job_finished" in out and token not in out
    code, out, _ = cli(capsys, "controller", "dispatch", "acme-hq", "10.9.9.9", "--json", *data)
    assert code == 1
    code, out, err = cli(capsys, "controller", "revoke", "acme-hq", *data)
    assert code == 0 and "Revoked acme-hq" in out
    code, out, _ = cli(capsys, "agent", "leave", *data)
    assert code == 0 and "Credentials deleted" in out
    code, out, err = cli(capsys, "agent", "status", *data)
    assert code == 1 and "not enrolled" in err


def test_the_command_line_says_so_when_no_controller_is_running(tmp_path, capsys):
    code, _out, err = cli(capsys, "controller", "agents", "--data-dir", str(tmp_path))
    assert code == 1 and "no controller is running" in err
    code, _out, err = cli(capsys, "agent", "run", "--data-dir", str(tmp_path))
    assert code == 1 and "not enrolled" in err


def test_the_command_line_refuses_a_controller_that_would_be_open_to_the_network_without_tls(tmp_path, capsys):
    code, out, _ = cli(capsys, "controller", "serve", "--host", "0.0.0.0", "--data-dir", str(tmp_path))
    assert code == 1 and "TLS is required" in out


def test_fleet_subcommands_do_not_touch_the_ordinary_scanner_syntax(capsys):
    with pytest.raises(SystemExit) as version:
        nemla.main(["--version"])
    assert version.value.code == 0 and "nemla" in capsys.readouterr().out
    with pytest.raises(SystemExit) as caught:
        nemla.main(["agent"])
    assert caught.value.code == 2
    with pytest.raises(SystemExit):
        nemla.main(["controller", "no-such-command"])


def test_an_enrollment_token_can_always_be_typed_on_the_command_line(rc, tmp_path, capsys, monkeypatch):
    """One token in sixty-four used to start with '-': argparse read `--token -abc` as an option and enrolling failed."""
    real = protocol.secrets.token_urlsafe
    draws = iter(["-" + "x" * 42, "-" + "y" * 42])                 # the controller's first two draws start with a dash
    monkeypatch.setattr(protocol.secrets, "token_urlsafe", lambda nbytes: next(draws, None) or real(nbytes))
    code, out, _ = cli(capsys, "controller", "enroll-token", "dash", "--json", "--data-dir", str(tmp_path))
    token = json.loads(out)["token"]
    assert code == 0 and not token.startswith("-")
    code, out, _ = cli(capsys, "agent", "enroll", f"http://127.0.0.1:{rc.agent_port}", "--token", token, "--scope", "127.0.0.0/24",
                       "--data-dir", str(tmp_path))
    assert code == 0 and "Enrolled as dash" in out
