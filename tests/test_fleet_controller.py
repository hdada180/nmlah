"""The Fleet controller: the rules (dispatch, scope, revocation, results, audit) and the two HTTP listeners."""
import http.client
import json
import os
import socket
import ssl
import threading
import time

import pytest

from nemla.fleet import audit, controller as fleet, protocol
from nemla_ui import fleet_server

from test_detect import TEST_CERT, TEST_KEY

posix_only = pytest.mark.skipif(os.name != "posix", reason="owner-only permissions are checked on POSIX")
JOB = {"target": "127.0.0.0/30", "ports": "22,80"}
HOSTS = [{"ip": "127.0.0.1", "mac": None, "os_guess": "Linux", "ttl": 64, "findings": [],
          "open_ports": [{"port": 22, "proto": "tcp", "state": "open", "service": "SSH", "banner": "", "detected": "ssh"}]}]
META = {"scan_time": "2026-01-01 10:00:00", "duration": 1.5, "ports_scanned": 2, "findings": {"info": 0, "low": 1, "medium": 0, "high": 0}}


class Clock:
    def __init__(self, now=1_700_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


# --------------------------------------------------------------------------
# the rules, directly
# --------------------------------------------------------------------------

@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def ctl(tmp_path, clock):
    controller = fleet.Controller(tmp_path / "fleet", clock=clock)
    yield controller
    controller.close()


def enroll(ctl, name="acme-hq", scope="127.0.0.0/24"):
    token = ctl.issue_token(name, "alice")["token"]
    record = ctl.enroll(token, scope, "2.0.0", "lab", remote="10.9.9.9")
    return ctl.authenticate(record["agent_id"], record["secret"], "10.9.9.9"), record


def events(ctl, name=None):
    return [e for e in ctl.audit.tail(1000) if name is None or e["event"] == name]


def test_a_job_goes_from_dispatch_to_a_stored_result_and_the_next_scan_shows_what_changed(ctl):
    agent, _ = enroll(ctl)
    job = ctl.dispatch("acme-hq", JOB, "alice")
    assert job["state"] == "queued" and job["operator"] == "alice"
    sent = ctl.poll(agent, wait=0)["job"]
    assert sent["id"] == job["id"] and sent["target"] == "127.0.0.0/30" and ctl.job(job["id"])["state"] == "sent"
    ctl.ack(agent, job["id"])
    assert ctl.job(job["id"])["state"] == "running"
    done = ctl.receive_result(agent, {"job": job["id"], "state": "done", "meta": META, "hosts": HOSTS})
    assert done["state"] == "done" and done["scan_id"]
    view = ctl.job(job["id"])
    assert view["summary"]["hosts"] == 1 and view["summary"]["open_ports"] == 1 and view["summary"]["changes"] is None
    second = ctl.dispatch("acme-hq", JOB, "alice")
    ctl.poll(agent, wait=0)
    more = [*HOSTS, {**HOSTS[0], "ip": "127.0.0.2"}]
    ctl.receive_result(agent, {"job": second["id"], "state": "done", "meta": META, "hosts": more})
    assert ctl.job(second["id"])["summary"]["changes"]["new_hosts"] == 1
    assert [r["hosts"] for r in ctl.results("acme-hq")] == [2, 1]
    assert ctl.result("acme-hq", done["scan_id"])["hosts"][0]["ip"] == "127.0.0.1"
    assert [e["event"] for e in events(ctl)] == ["enroll_token_issued", "enroll", "dispatch", "job_sent", "job_started",
                                                 "job_finished", "dispatch", "job_sent", "job_finished"]


def test_a_job_outside_the_agents_scope_is_refused_and_recorded_and_never_queued(ctl):
    enroll(ctl, scope="127.0.0.0/24")
    for target in ("10.0.0.5", "127.0.0.0/23", "127.0.0.5,8.8.8.8"):
        with pytest.raises(fleet.FleetError) as caught:
            ctl.dispatch("acme-hq", {"target": target, "ports": "22"}, "mallory")
        assert caught.value.status == 403
    refused = events(ctl, "dispatch_refused")
    assert len(refused) == 3 and all(e["operator"] == "mallory" for e in refused)
    assert ctl.job_list() == [] and ctl.agents()[0]["queued"] == 0


@pytest.mark.parametrize("job", [{"target": "example.com", "ports": "22"}, {"target": "127.0.0.1", "ports": "22", "cmd": "id"},
                                 {"target": "127.0.0.1", "ports": "0"}, {"target": "127.0.0.1", "ports": "22", "options": {"x": 1}},
                                 "job", None])
def test_a_malformed_job_is_refused_before_the_scope_is_even_looked_at(ctl, job):
    enroll(ctl)
    with pytest.raises(fleet.FleetError) as caught:
        ctl.dispatch("acme-hq", job)
    assert caught.value.status == 400 and ctl.job_list() == []


def test_nobody_can_dispatch_to_an_unknown_or_revoked_agent(ctl):
    enroll(ctl)
    with pytest.raises(fleet.FleetError) as caught:
        ctl.dispatch("nobody", JOB)
    assert caught.value.status == 404
    ctl.revoke("acme-hq")
    with pytest.raises(fleet.FleetError) as caught:
        ctl.dispatch("acme-hq", JOB)
    assert caught.value.status == 409


def test_an_agents_queue_is_bounded(ctl):
    enroll(ctl)
    for _ in range(protocol.MAX_QUEUED_PER_AGENT):
        ctl.dispatch("acme-hq", JOB)
    with pytest.raises(fleet.FleetError) as caught:
        ctl.dispatch("acme-hq", JOB)
    assert caught.value.status == 429


def test_revoking_an_agent_drops_its_jobs_and_locks_it_out_at_once(ctl):
    agent, record = enroll(ctl)
    queued, sent = ctl.dispatch("acme-hq", JOB), ctl.dispatch("acme-hq", JOB)
    ctl.poll(agent, wait=0)                                                  # the first job is now with the agent
    result = ctl.revoke("acme-hq", "alice")
    assert result["revoked"] is True and result["jobs_dropped"] == 2
    assert {ctl.job(queued["id"])["state"], ctl.job(sent["id"])["state"]} == {"cancelled"}
    assert ctl.authenticate(record["agent_id"], record["secret"]) is None
    with pytest.raises(fleet.FleetError) as caught:
        ctl.poll(agent, wait=0)
    assert caught.value.status == 401
    assert events(ctl, "revoke")[0]["jobs_dropped"] == 2 and ctl.agents()[0]["status"] == "revoked"
    with pytest.raises(fleet.FleetError):
        ctl.revoke("acme-hq")


def test_cancelling_a_job_before_and_after_the_agent_has_it(ctl):
    agent, _ = enroll(ctl)
    first, second = ctl.dispatch("acme-hq", JOB), ctl.dispatch("acme-hq", JOB)
    assert ctl.cancel(first["id"], "alice")["state"] == "cancelled"
    assert ctl.poll(agent, wait=0)["job"]["id"] == second["id"]              # the cancelled one is skipped
    assert ctl.cancel(second["id"])["state"] == "cancelled"
    assert ctl.poll(agent, busy=True, wait=0)["cancel"] == [second["id"]]    # the agent learns of it on its next poll
    assert ctl.poll(agent, busy=True, wait=0)["cancel"] == []
    with pytest.raises(fleet.FleetError) as caught:
        ctl.cancel(second["id"])
    assert caught.value.status == 409
    with pytest.raises(fleet.FleetError) as caught:
        ctl.cancel("nosuchjob")
    assert caught.value.status == 404


def test_a_busy_agent_is_not_given_another_job(ctl):
    agent, _ = enroll(ctl)
    job = ctl.dispatch("acme-hq", JOB)
    assert ctl.poll(agent, busy=True, wait=0)["job"] is None
    assert ctl.poll(agent, wait=0)["job"]["id"] == job["id"]


def test_an_agent_can_only_report_on_its_own_jobs_and_only_while_they_are_open(ctl):
    agent_a, _ = enroll(ctl, "site-a")
    agent_b, _ = enroll(ctl, "site-b", "127.0.1.0/24")
    job = ctl.dispatch("site-a", JOB)
    ctl.poll(agent_a, wait=0)
    with pytest.raises(fleet.FleetError) as caught:
        ctl.receive_result(agent_b, {"job": job["id"], "state": "done", "meta": META, "hosts": HOSTS})
    assert caught.value.status == 404
    with pytest.raises(fleet.FleetError) as caught:
        ctl.ack(agent_b, job["id"])
    assert caught.value.status == 404
    ctl.receive_result(agent_a, {"job": job["id"], "state": "failed", "error": "outside my scope"})
    assert ctl.job(job["id"])["state"] == "failed" and ctl.job(job["id"])["error"] == "outside my scope"
    with pytest.raises(fleet.FleetError) as caught:
        ctl.receive_result(agent_a, {"job": job["id"], "state": "done", "meta": META, "hosts": HOSTS})
    assert caught.value.status == 409
    with pytest.raises(fleet.FleetError):
        ctl.receive_result(agent_a, {"job": "0123456789abcdef", "state": "done"})


@pytest.mark.parametrize("meta, hosts", [
    ({}, HOSTS),                                                             # no scan_time, no findings: filled in
    ({"scan_time": 5, "duration": "fast", "ports_scanned": None, "findings": {"high": "many", 3: 1}}, HOSTS),
    (META, [{"ip": "127.0.0.1", "open_ports": "many", "findings": "none"}]),   # hostile shapes inside a host
])
def test_a_result_is_normalised_or_refused_never_trusted_and_never_a_crash(ctl, meta, hosts):
    agent, _ = enroll(ctl)
    job = ctl.dispatch("acme-hq", JOB)
    ctl.poll(agent, wait=0)
    result = ctl.receive_result(agent, {"job": job["id"], "state": "done", "meta": {**meta, "target": "evil.example"}, "hosts": hosts})
    assert result["state"] in ("done", "failed")
    if result["state"] == "done":
        assert ctl.result("acme-hq", result["scan_id"])["target"] == "127.0.0.0/30"       # the label is ours, not the agent's
    else:
        assert ctl.job(job["id"])["error"] == "the result could not be stored (malformed)"


def test_when_the_audit_trail_cannot_be_written_nothing_happens(ctl, tmp_path):
    enroll(ctl)
    blocker = tmp_path / "blocker"
    blocker.write_text("a file", encoding="utf-8")
    ctl.audit = audit.AuditLog(blocker / "audit.jsonl")
    with pytest.raises(fleet.FleetError) as caught:
        ctl.dispatch("acme-hq", JOB)
    assert caught.value.status == 503 and ctl.job_list() == []
    with pytest.raises(fleet.FleetError) as caught:
        ctl.issue_token("other-site")
    assert caught.value.status == 503


def test_an_enrollment_that_cannot_be_recorded_is_undone(ctl, tmp_path):
    token = ctl.issue_token("acme-hq")["token"]
    blocker = tmp_path / "blocker"
    blocker.write_text("a file", encoding="utf-8")
    ctl.audit = audit.AuditLog(blocker / "audit.jsonl")
    with pytest.raises(fleet.FleetError):
        ctl.enroll(token, "127.0.0.0/24")
    assert ctl.agents()[0]["revoked"] is True


def test_a_refused_enrollment_says_nothing_about_why_but_the_audit_does(ctl):
    for token in ("wrong", "", "x" * 50):
        with pytest.raises(fleet.FleetError) as caught:
            ctl.enroll(token, "127.0.0.0/24", remote="203.0.113.7")
        assert str(caught.value) == "enrollment refused" and caught.value.status == 403
    logged = events(ctl, "enroll_refused")
    assert len(logged) == 1 and logged[0]["remote"] == "203.0.113.7"          # one line per address per half minute


def test_refused_credentials_are_audited_at_most_once_per_address_per_half_minute(ctl, clock):
    enroll(ctl)
    for _ in range(50):
        assert ctl.authenticate("acme", "wrong", "198.51.100.1") is None
    assert len(events(ctl, "auth_refused")) == 1
    clock.now += 31
    ctl.authenticate("acme", "wrong", "198.51.100.1")
    lines = events(ctl, "auth_refused")
    assert len(lines) == 2 and lines[1]["also_refused_since_last_line"] == 49
    ctl.authenticate("acme", "wrong", "198.51.100.2")
    assert len(events(ctl, "auth_refused")) == 3


def test_old_jobs_expire_instead_of_waiting_forever(ctl, clock):
    agent, _ = enroll(ctl)
    job = ctl.dispatch("acme-hq", JOB)
    clock.now += fleet.QUEUED_TTL + 1
    assert ctl.poll(agent, wait=0)["job"] is None and ctl.job(job["id"])["state"] == "expired"
    sent = ctl.dispatch("acme-hq", JOB)
    ctl.poll(agent, wait=0)
    clock.now += fleet.RUNNING_TTL + 1
    ctl.job_list()
    assert ctl.job(sent["id"])["state"] == "expired"


def test_a_waiting_poll_wakes_when_a_job_arrives_and_when_its_agent_is_revoked(ctl):
    agent, _ = enroll(ctl)
    got = {}

    def waiting():
        started = time.monotonic()
        got["job"] = ctl.poll(agent, wait=20)["job"]
        got["after"] = time.monotonic() - started
    thread = threading.Thread(target=waiting)
    thread.start()
    time.sleep(0.3)
    job = ctl.dispatch("acme-hq", JOB)
    thread.join(10)
    assert got["job"]["id"] == job["id"] and got["after"] < 5

    errors = []

    def waiting_again():
        try:
            ctl.poll(agent, wait=20)
        except fleet.FleetError as err:
            errors.append(err.status)
    thread = threading.Thread(target=waiting_again)
    thread.start()
    time.sleep(0.3)
    ctl.revoke("acme-hq")
    thread.join(10)
    assert errors == [401]


def test_agents_are_online_offline_or_revoked_and_the_operator_sees_their_queue(ctl, clock):
    agent, _ = enroll(ctl)
    ctl.dispatch("acme-hq", JOB)
    (listed,) = ctl.agents()
    assert listed["status"] == "online" and listed["queued"] == 1 and "secret_hash" not in listed and listed["running_job"] is None
    clock.now += fleet.ONLINE_WITHIN + 1
    assert ctl.agents()[0]["status"] == "offline"
    ctl.poll(agent, wait=0)
    assert ctl.agents()[0]["running_job"] is not None


def test_the_number_of_kept_jobs_is_bounded(ctl, monkeypatch):
    monkeypatch.setattr(fleet, "MAX_JOBS_KEPT", 5)
    agent, _ = enroll(ctl)
    for _ in range(12):
        job = ctl.dispatch("acme-hq", JOB)
        ctl.poll(agent, wait=0)
        ctl.receive_result(agent, {"job": job["id"], "state": "failed", "error": "x"})
    assert len(ctl.job_list(100)) <= 6


def test_the_audit_trail_never_holds_a_token_or_a_secret(ctl, tmp_path):
    token = ctl.issue_token("acme-hq", "alice")["token"]
    record = ctl.enroll(token, "127.0.0.0/24", remote="10.9.9.9")
    ctl.dispatch("acme-hq", JOB, "alice")
    ctl.revoke("acme-hq", "alice")
    text = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "fleet").glob("audit.jsonl*"))
    assert token not in text and record["secret"] not in text and record["agent_id"] in text


# --------------------------------------------------------------------------
# the listeners, over real sockets
# --------------------------------------------------------------------------

def req(port, method, path, body=None, headers=None, raw=None, tls=False, timeout=15):
    if tls:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=timeout)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
    conn.request(method, path, body=payload, headers=dict(headers or {}))
    res = conn.getresponse()
    data = res.read()
    conn.close()
    is_json = (res.getheader("Content-Type") or "").startswith("application/json")
    return res.status, (json.loads(data) if data and is_json else data), res


@pytest.fixture()
def running(tmp_path):
    rc = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0)
    yield rc
    rc.stop()


def op(rc, method, name, body=None, **kw):
    headers = {"X-Nemla-Token": rc.token, **kw.pop("headers", {})}
    return req(rc.operator_port, method, "/api/fleet/" + name, body, headers=headers, **kw)


def wire_enroll(rc, name="acme-hq", scope="127.0.0.0/24", tls=False):
    token = op(rc, "POST", "enroll-token", {"name": name})[1]["token"]
    status, body, _ = req(rc.agent_port, "POST", "/agent/v1/enroll",
                          {"token": token, "scope": scope, "version": "2.0.0", "hostname": "lab"}, tls=tls)
    assert status == 200, body
    return body


def bearer(agent):
    return {"Authorization": f"Bearer {agent['agent_id']}.{agent['secret']}"}


def agent_poll(rc, agent, busy=False, wait=0, tls=False):
    return req(rc.agent_port, "POST", "/agent/v1/poll", {"busy": busy, "wait": wait}, headers=bearer(agent), tls=tls)


def test_a_whole_job_over_the_wire_and_the_operator_sees_every_step(running):
    agent = wire_enroll(running)
    assert set(agent) == {"agent_id", "secret", "name", "poll_seconds", "protocol"} and agent["name"] == "acme-hq"
    job = op(running, "POST", "dispatch", {"agent": "acme-hq", "job": JOB}, headers={"X-Nemla-Operator": "alice"})[1]
    status, polled, _ = agent_poll(running, agent)
    assert status == 200 and polled["job"]["id"] == job["id"] and polled["job"]["ports"] == "22,80"
    assert req(running.agent_port, "POST", "/agent/v1/ack", {"job": job["id"]}, headers=bearer(agent))[0] == 200
    status, body, _ = req(running.agent_port, "POST", "/agent/v1/result",
                          {"job": job["id"], "state": "done", "meta": META, "hosts": HOSTS}, headers=bearer(agent))
    assert status == 200 and body["state"] == "done"
    finished = op(running, "GET", f"job?id={job['id']}")[1]
    assert finished["state"] == "done" and finished["operator"] == "alice" and finished["summary"]["hosts"] == 1
    assert op(running, "GET", "jobs")[1]["jobs"][0]["id"] == job["id"]
    scan_id = op(running, "GET", "results?agent=acme-hq")[1]["results"][0]["id"]
    assert op(running, "GET", f"result?agent=acme-hq&id={scan_id}")[1]["hosts"][0]["ip"] == "127.0.0.1"
    trail = [e["event"] for e in op(running, "GET", "audit")[1]["events"]]
    assert trail == ["enroll_token_issued", "enroll", "dispatch", "job_sent", "job_started", "job_finished"]
    assert op(running, "GET", "agents")[1]["agents"][0]["status"] == "online"


def test_an_enrollment_token_works_once_over_the_wire_and_the_refusal_is_generic(running):
    token = op(running, "POST", "enroll-token", {"name": "acme-hq"})[1]["token"]
    body = {"token": token, "scope": "127.0.0.0/24"}
    assert req(running.agent_port, "POST", "/agent/v1/enroll", body)[0] == 200
    status, answer, _ = req(running.agent_port, "POST", "/agent/v1/enroll", body)
    assert status == 403 and answer == {"error": "enrollment refused"}
    status, answer, _ = req(running.agent_port, "POST", "/agent/v1/enroll", {"token": "nope", "scope": "127.0.0.0/24"})
    assert status == 403 and answer == {"error": "enrollment refused"}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer"}, {"Authorization": "Bearer nodot"}, {"Authorization": "Basic YTpi"},
                                     {"Authorization": "Bearer abc.def"}, {"Authorization": "bearer a.b.c"}])
def test_every_agent_route_needs_valid_credentials(running, headers):
    for path in ("poll", "ack", "result"):
        status, body, _ = req(running.agent_port, "POST", f"/agent/v1/{path}", {"busy": False}, headers=headers)
        assert status == 401 and body == {"error": "unauthorized"}


def test_the_right_id_with_the_wrong_secret_and_a_revoked_agent_are_refused(running):
    agent = wire_enroll(running)
    wrong = {"Authorization": f"Bearer {agent['agent_id']}.{agent['secret'][::-1]}"}
    assert req(running.agent_port, "POST", "/agent/v1/poll", {"wait": 0}, headers=wrong)[0] == 401
    assert agent_poll(running, agent)[0] == 200
    op(running, "POST", "revoke", {"agent": "acme-hq"})
    assert agent_poll(running, agent)[0] == 401


def test_a_refusal_reaches_a_client_that_is_still_sending_a_large_body(running):
    """Answering before reading and then closing makes the OS reset the connection, which can destroy the answer
    (found on the local interface: one in eight on Windows). The refusal is followed by a bounded discard."""
    big = "x" * (512 * 1024)
    for _ in range(25):
        status, _, _ = req(running.agent_port, "POST", "/agent/v1/result", raw=big,
                              headers={"Authorization": "Bearer a.b", "Content-Type": "application/json"})
        assert status == 401


def test_bodies_are_bounded_and_strict(running, monkeypatch):
    agent = wire_enroll(running)
    headers = bearer(agent)
    assert req(running.agent_port, "POST", "/agent/v1/poll", raw="x" * (protocol.MAX_ENROLL_BYTES + 1), headers=headers)[0] == 413
    for raw, want in (("{not json", 400), ("[1, 2]", 400), ('{"busy": NaN}', 400), ('"text"', 400), ("", 400)):
        assert req(running.agent_port, "POST", "/agent/v1/poll", raw=raw, headers=headers)[0] == want, raw
    with socket.create_connection(("127.0.0.1", running.agent_port), timeout=5) as sock:     # no Content-Length
        sock.sendall(b"POST /agent/v1/poll HTTP/1.1\r\nHost: x\r\n" + f"Authorization: Bearer {agent['agent_id']}.{agent['secret']}".encode() + b"\r\n\r\n")
        assert sock.recv(64).startswith(b"HTTP/1.0 411")
    with socket.create_connection(("127.0.0.1", running.agent_port), timeout=5) as sock:     # chunked
        sock.sendall(b"POST /agent/v1/poll HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                     + f"Authorization: Bearer {agent['agent_id']}.{agent['secret']}".encode() + b"\r\n\r\n0\r\n\r\n")
        assert sock.recv(64).startswith(b"HTTP/1.0 411")
    monkeypatch.setattr(protocol, "MAX_RESULT_BYTES", 300)
    big = {"job": "0123456789abcdef", "state": "done", "meta": {}, "hosts": [{"ip": "127.0.0.1", "pad": "x" * 500}]}
    assert req(running.agent_port, "POST", "/agent/v1/result", big, headers=headers)[0] == 413


def test_the_agent_listener_answers_only_its_four_post_routes(running):
    agent = wire_enroll(running)
    for method in ("GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
        assert req(running.agent_port, method, "/agent/v1/poll", headers=bearer(agent))[0] == 404
    for path in ("/", "/agent/v1/other", "/agent/v1/", "/api/fleet/agents", "/agent/v2/poll"):
        assert req(running.agent_port, "POST", path, {"x": 1}, headers=bearer(agent))[0] == 404


def test_the_operator_api_needs_the_token_the_host_and_a_same_site_origin(running):
    port = running.operator_port
    assert req(port, "GET", "/api/fleet/agents")[0] == 401
    assert req(port, "GET", "/api/fleet/agents", headers={"X-Nemla-Token": "wrong"})[0] == 401
    assert req(port, "GET", f"/api/fleet/agents?k={running.token}")[0] == 401                # never accepted in the address
    assert req(port, "GET", "/api/fleet/agents", headers={"X-Nemla-Token": running.token, "Host": "evil.example"})[0] == 403
    assert op(running, "GET", "agents", headers={"Origin": "http://evil.example"})[0] == 403
    assert op(running, "GET", "agents", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert op(running, "GET", "agents", headers={"Origin": f"http://127.0.0.1:{port}"})[0] == 200
    assert op(running, "GET", "nothing")[0] == 404 and op(running, "POST", "agents")[0] == 404
    assert req(port, "PUT", "/api/fleet/agents", headers={"X-Nemla-Token": running.token})[0] == 404


def test_the_operator_body_is_bounded_and_strict(running):
    assert op(running, "POST", "dispatch", raw="x" * (65 * 1024))[0] == 413
    for raw in ("{bad", "[1]", '{"a": Infinity}'):
        assert op(running, "POST", "dispatch", raw=raw)[0] == 400
    assert op(running, "POST", "dispatch", {"agent": "nobody", "job": JOB})[0] == 404
    assert op(running, "POST", "enroll-token", {"name": "../evil"})[0] == 400


def test_operator_actions_are_attributed_to_a_sanitised_label(running):
    wire_enroll(running)
    op(running, "POST", "dispatch", {"agent": "acme-hq", "job": JOB}, headers={"X-Nemla-Operator": 'alice<script>"x'})
    assert op(running, "GET", "audit")[1]["events"][-1]["operator"] == "alicescriptx"
    op(running, "POST", "dispatch", {"agent": "acme-hq", "job": JOB})
    assert op(running, "GET", "audit")[1]["events"][-1]["operator"] == "operator"


def test_the_operator_api_never_returns_a_token_or_a_secret(running):
    token = op(running, "POST", "enroll-token", {"name": "acme-hq"})[1]["token"]
    agent = req(running.agent_port, "POST", "/agent/v1/enroll", {"token": token, "scope": "127.0.0.0/24"})[1]
    shown = "".join(json.dumps(op(running, "GET", name)[1]) for name in ("agents", "audit", "jobs", "info"))
    assert token not in shown and agent["secret"] not in shown and "secret_hash" not in shown


def test_agents_never_see_each_others_jobs_over_the_wire(running):
    agents = [wire_enroll(running, f"site-{i}", f"127.0.{i}.0/24") for i in range(4)]
    jobs = [op(running, "POST", "dispatch", {"agent": f"site-{i}", "job": {"target": f"127.0.{i}.5", "ports": "22"}})[1]
            for i in range(4)]
    seen = {}

    def poll(i):
        seen[i] = agent_poll(running, agents[i])[1]["job"]["id"]
    threads = [threading.Thread(target=poll, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert seen == {i: jobs[i]["id"] for i in range(4)}
    status = req(running.agent_port, "POST", "/agent/v1/result", {"job": jobs[0]["id"], "state": "failed", "error": "x"},
                 headers=bearer(agents[1]))[0]
    assert status == 404


def test_the_controller_refuses_to_listen_off_loopback_without_tls(tmp_path):
    for host in ("0.0.0.0", "192.0.2.1", "controller.example"):
        with pytest.raises(ValueError, match="TLS is required"):
            fleet_server.start_controller(tmp_path / "fleet", host, 0, 0)
    with pytest.raises(ValueError, match="both"):
        fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0, cert=tmp_path / "c.pem")
    assert not any((tmp_path / "fleet").glob("controller.json"))


def test_the_local_endpoint_is_published_while_running_and_removed_after(tmp_path):
    rc = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0)
    try:
        url, token = fleet_server.read_local_endpoint(tmp_path / "fleet")
        assert url == f"http://127.0.0.1:{rc.operator_port}" and token == rc.token
    finally:
        rc.stop()
    with pytest.raises(fleet.FleetError, match="no controller is running"):
        fleet_server.read_local_endpoint(tmp_path / "fleet")
    again = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0)
    try:
        assert again.token == token                                        # the token survives a restart
    finally:
        again.stop()


@posix_only
def test_the_endpoint_and_token_files_are_owner_only(running):
    for name in ("controller.json", "operator.token"):
        assert oct((running.folder / name).stat().st_mode & 0o777) == "0o600"


@pytest.fixture()
def tls_running(tmp_path):
    (tmp_path / "cert.pem").write_text(TEST_CERT, encoding="utf-8")
    (tmp_path / "key.pem").write_text(TEST_KEY, encoding="utf-8")
    rc = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0, tmp_path / "cert.pem", tmp_path / "key.pem")
    yield rc
    rc.stop()


def test_over_tls_the_pin_printed_for_operators_is_the_certificate_an_agent_sees(tls_running):
    assert tls_running.pin == protocol.pin_from_pem(TEST_CERT)
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", tls_running.agent_port), timeout=5) as raw:
        with context.wrap_socket(raw) as tls:
            assert protocol.pin_of(tls.getpeercert(binary_form=True)) == tls_running.pin
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
    assert op(tls_running, "GET", "info")[1]["pin"] == tls_running.pin


def test_a_whole_enrollment_and_poll_work_over_tls_and_plain_http_does_not(tls_running):
    agent = wire_enroll(tls_running, tls=True)
    op(tls_running, "POST", "dispatch", {"agent": "acme-hq", "job": JOB})
    assert agent_poll(tls_running, agent, tls=True)[1]["job"]["target"] == "127.0.0.0/30"
    with pytest.raises((http.client.HTTPException, OSError)):
        req(tls_running.agent_port, "POST", "/agent/v1/poll", {"wait": 0}, headers=bearer(agent))


def test_a_client_that_stalls_in_the_tls_handshake_does_not_hold_up_the_others(tls_running):
    stalled = [socket.create_connection(("127.0.0.1", tls_running.agent_port), timeout=5) for _ in range(5)]
    try:
        started = time.monotonic()
        agent = wire_enroll(tls_running, tls=True)
        assert agent_poll(tls_running, agent, tls=True)[0] == 200
        assert time.monotonic() - started < 5
    finally:
        for sock in stalled:
            sock.close()

# --------------------------------------------------------------------------
# what is left: audit failures, bounds, the pages, and the odd request
# --------------------------------------------------------------------------

def broken_audit(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file", encoding="utf-8")
    return audit.AuditLog(blocker / "audit.jsonl")


def test_a_revocation_still_happens_when_it_cannot_be_recorded_and_the_operator_is_told(ctl, tmp_path):
    enroll(ctl)
    ctl.audit = broken_audit(tmp_path)
    with pytest.raises(fleet.FleetError, match="is revoked, but the audit trail could not be written") as caught:
        ctl.revoke("acme-hq")
    assert caught.value.status == 503 and ctl.agents()[0]["status"] == "revoked"


def test_refusing_credentials_never_fails_because_the_audit_trail_does(ctl, tmp_path):
    ctl.audit = broken_audit(tmp_path)
    assert ctl.authenticate("acme", "wrong", "198.51.100.9") is None


def test_the_memory_of_refusing_addresses_is_bounded(ctl, clock):
    for i in range(600):
        ctl.authenticate("x", "y", f"192.0.2.{i % 250}.{i}")
    clock.now += 31
    for i in range(500):
        ctl.authenticate("x", "y", f"198.51.{i % 250}.{i}")
    assert len(ctl._refusals) <= 1000


def test_jobs_that_are_still_open_are_never_trimmed_away(ctl, monkeypatch):
    monkeypatch.setattr(fleet, "MAX_JOBS_KEPT", 2)
    enroll(ctl)
    for _ in range(4):
        ctl.dispatch("acme-hq", JOB)
    ctl.job_list(100)
    assert len(ctl.jobs) == 4                                                  # more than the limit, all still open


def test_an_agent_cannot_acknowledge_a_job_it_has_not_been_given_or_report_a_malformed_result(ctl):
    agent, _ = enroll(ctl)
    job = ctl.dispatch("acme-hq", JOB)
    with pytest.raises(fleet.FleetError) as caught:
        ctl.ack(agent, job["id"])                                            # still queued: nothing was sent
    assert caught.value.status == 409
    with pytest.raises(fleet.FleetError) as caught:
        ctl.receive_result(agent, {"job": "zz"})
    assert caught.value.status == 400


def test_an_unknown_job_or_result_is_a_404(ctl):
    enroll(ctl)
    with pytest.raises(fleet.FleetError) as caught:
        ctl.job("nosuchjob")
    assert caught.value.status == 404
    with pytest.raises(fleet.FleetError) as caught:
        ctl.result("acme-hq", "00000000-0000-4000-8000-000000000000")
    assert caught.value.status == 404
    with pytest.raises(fleet.FleetError) as caught:
        ctl.results("nobody")
    assert caught.value.status == 404


@pytest.mark.parametrize("host, expected", [("localhost", True), ("127.0.0.1", True), ("127.5.5.5", True), ("::1", True),
                                            ("[::1]", True), ("0.0.0.0", False), ("10.0.0.1", False),
                                            ("controller.example", False), ("", False)])
def test_only_loopback_addresses_may_skip_tls(host, expected):
    assert fleet_server.is_loopback(host) is expected


def test_enrollment_fields_must_be_text(running):
    for body in ({"token": 5, "scope": "127.0.0.0/24"}, {"token": "t", "scope": ["127.0.0.0/24"]},
                 {"token": "t", "scope": "127.0.0.0/24", "version": {"a": 1}}):
        status, answer, _ = req(running.agent_port, "POST", "/agent/v1/enroll", body)
        assert status == 400 and "text" in answer["error"]


def test_a_crash_inside_a_request_is_a_plain_500_with_no_details(running, monkeypatch):
    agent = wire_enroll(running)

    def explode(*args, **kwargs):
        raise RuntimeError("secret internal detail /home/user/x.py line 42")
    monkeypatch.setattr(running.controller, "poll", explode)
    status, body, _ = agent_poll(running, agent)
    assert status == 500 and body == {"error": "internal error"}


def test_a_negative_content_length_is_refused(running):
    agent = wire_enroll(running)
    with socket.create_connection(("127.0.0.1", running.agent_port), timeout=5) as sock:
        sock.sendall(b"POST /agent/v1/poll HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n"
                     + f"Authorization: Bearer {agent['agent_id']}.{agent['secret']}".encode() + b"\r\n\r\n")
        assert sock.recv(64).startswith(b"HTTP/1.0 411")


def test_results_are_received_a_few_at_a_time(tmp_path, monkeypatch):
    monkeypatch.setattr(fleet_server, "MAX_UPLOADS", 0)
    rc = fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, 0)
    try:
        agent = wire_enroll(rc)
        status, body, _ = req(rc.agent_port, "POST", "/agent/v1/result", {"job": "0123456789abcdef", "state": "failed"},
                              headers=bearer(agent))
        assert status == 503 and "try again" in body["error"]
    finally:
        rc.stop()


def test_the_fleet_page_is_served_from_a_fixed_list_with_the_security_headers(running, tmp_path, monkeypatch):
    web = tmp_path / "web"
    web.mkdir()
    (web / "fleet.html").write_text("<!doctype html><title>Fleet</title>", encoding="utf-8")
    (web / "fleet.js").write_text("// fleet", encoding="utf-8")
    (web / "secret.txt").write_text("not a page", encoding="utf-8")
    monkeypatch.setattr(fleet_server, "WEB_DIR", web)
    port = running.operator_port
    status, body, res = req(port, "GET", "/")
    assert status == 200 and b"Fleet" in body and "default-src 'self'" in res.getheader("Content-Security-Policy")
    assert res.getheader("X-Frame-Options") == "DENY"
    assert req(port, "GET", "/fleet.js")[2].getheader("Content-Type").startswith("text/javascript")
    assert req(port, "HEAD", "/")[0] == 200
    assert req(port, "GET", "/fleet.css")[0] == 404                        # listed, but not there
    for path in ("/secret.txt", "/../pyproject.toml", "/fleet.js/../secret.txt", "/%2e%2e/x", "/index.html", "/api/fleet"):
        assert req(port, "GET", path)[0] == 404, path
    assert req(port, "POST", "/")[0] == 404
    assert req(port, "GET", "/", headers={"Host": "evil.example"})[0] == 403


def test_a_stale_or_missing_operator_token_is_replaced(tmp_path):
    folder = tmp_path / "fleet"
    folder.mkdir()
    (folder / "operator.token").write_text("short", encoding="utf-8")
    token = fleet_server._operator_token(folder)
    assert len(token) >= 32 and fleet_server._operator_token(folder) == token


def test_a_controller_that_cannot_bind_its_operator_port_starts_nothing(tmp_path):
    taken = socket.socket()
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    try:
        with pytest.raises(OSError):
            fleet_server.start_controller(tmp_path / "fleet", "127.0.0.1", 0, taken.getsockname()[1])
    finally:
        taken.close()
