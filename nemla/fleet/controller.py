"""The controller's brain: it queues jobs for agents, hands them out, takes the results and audits everything.

No HTTP in here (see nemla_ui/fleet_server.py), so every rule can be tested directly. The controller never scans and
never runs anything an agent sends it: a result is data that is checked, normalised and stored through the same history
files a local scan uses, so a scan of one target can be compared with the last one from the same agent.

Every action that changes anything is written to the audit trail *first*; if the trail cannot be written the action is
refused (FleetError 503), so nothing happens unrecorded.
"""
from __future__ import annotations

import collections
import threading
import time
from pathlib import Path

from .. import history
from ..diff import diff_scans
from ..targets import iter_targets
from . import protocol
from .audit import AuditError, AuditLog
from .registry import Registry, RegistryError
from .scope import ScopeError, check_scope, parse_scope

POLL_SECONDS = 25                       # how long an agent's poll may wait for work
ONLINE_WITHIN = 3 * POLL_SECONDS        # an agent that polled this recently is "online"
QUEUED_TTL = 3600                       # a job nobody collected in an hour expires
RUNNING_TTL = 6 * 3600                  # a collected job with no result after six hours expires
MAX_JOBS_KEPT = 500
_REFUSAL_LOG_EVERY = 30                 # seconds between audit lines about refused credentials from one address


class FleetError(Exception):
    """A refused request, with the HTTP status the server answers it with."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _count(value) -> int:
    return len(value) if isinstance(value, list) else 0


def _number(value, default=0.0):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value == value else default


class Controller:
    def __init__(self, folder, clock=time.time):
        self.folder = Path(folder)
        self._clock = clock
        self.registry = Registry(self.folder, clock=clock)
        self.audit = AuditLog(self.folder / "audit.jsonl", clock=clock)
        self._cond = threading.Condition(threading.RLock())
        self.jobs: collections.OrderedDict = collections.OrderedDict()
        self._queues: dict = {}
        self._cancel_requests: dict = {}
        self._refusals: dict = {}
        self._closed = False

    # -- plumbing -----------------------------------------------------------------------------------------------

    def _note(self, event: str, **fields) -> None:
        try:
            self.audit.record(event, **fields)
        except AuditError as err:
            raise FleetError(f"the audit trail cannot be written, so nothing was done: {err}", 503) from None

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def _agent_folder(self, agent_id: str) -> Path:
        return self.folder / "agents" / agent_id

    def _expire(self) -> None:
        now = self._clock()
        for job in self.jobs.values():
            age = now - job["created"]
            if (job["state"] == "queued" and age > QUEUED_TTL) or (job["state"] in ("sent", "running") and age > RUNNING_TTL):
                job["state"], job["finished_at"], job["error"] = "expired", now, "expired"
        while len(self.jobs) > MAX_JOBS_KEPT:
            oldest = next(iter(self.jobs))
            if self.jobs[oldest]["state"] in ("queued", "sent", "running"):
                break
            del self.jobs[oldest]

    @staticmethod
    def _view(job: dict) -> dict:
        return {k: job.get(k) for k in ("id", "agent", "agent_id", "target", "ports", "options", "operator", "state",
                                        "created", "sent_at", "started_at", "finished_at", "error", "summary", "scan_id")}

    def _agent_ref(self, ref):
        record = self.registry.get(ref) if isinstance(ref, str) else None
        if record is None:
            raise FleetError("no such agent", 404)
        return record

    # -- enrollment and authentication ---------------------------------------------------------------------------

    def issue_token(self, name: str, operator: str = "") -> dict:
        try:
            token = self.registry.issue_token(name, operator)
        except RegistryError as err:
            raise FleetError(str(err), 400) from None
        self._note("enroll_token_issued", agent=name, operator=operator)         # the token itself is never recorded
        return {"name": name, "token": token, "expires_in": 900}

    def enroll(self, token, scope_spec, agent_version="", hostname="", remote="") -> dict:
        try:
            record, secret = self.registry.enroll(token, scope_spec, agent_version, hostname)
        except RegistryError as err:
            self._refused("enroll_refused", remote, reason=str(err))
            raise FleetError("enrollment refused", 403) from None
        try:
            self._note("enroll", agent=record["name"], agent_id=record["id"], scope=record["scope"], remote=remote)
        except FleetError:
            self.registry.revoke(record["id"])                                   # not recorded, so not enrolled
            raise
        return {"agent_id": record["id"], "secret": secret, "name": record["name"], "poll_seconds": POLL_SECONDS,
                "protocol": protocol.PROTOCOL}

    def _refused(self, event: str, remote: str, **fields) -> None:
        """Audit refused credentials, but at most one line per address per half minute (256-bit secrets cannot be
        guessed; what is worth limiting is the noise)."""
        now = self._clock()
        with self._cond:
            last, hidden = self._refusals.get(remote, (0.0, 0))
            if now - last < _REFUSAL_LOG_EVERY:
                self._refusals[remote] = (last, hidden + 1)
                return
            self._refusals[remote] = (now, 0)
            if len(self._refusals) > 1000:
                self._refusals = {k: v for k, v in self._refusals.items() if now - v[0] < _REFUSAL_LOG_EVERY}
        try:
            self.audit.record(event, remote=remote, also_refused_since_last_line=hidden, **fields)
        except AuditError:
            pass                                                                 # the refusal stands either way

    def authenticate(self, agent_id, secret, remote: str = ""):
        record = self.registry.authenticate(agent_id, secret)
        if record is None:
            self._refused("auth_refused", remote, claimed_agent=str(agent_id)[:24])
            return None
        self.registry.touch(record["id"])
        return record

    # -- operators: dispatching, cancelling, revoking ------------------------------------------------------------

    def dispatch(self, agent_ref, raw_job, operator: str = "") -> dict:
        record = self._agent_ref(agent_ref)
        if record["revoked"]:
            raise FleetError("that agent is revoked", 409)
        try:
            job = protocol.validate_job(raw_job)
        except protocol.ProtocolError as err:
            self._note("dispatch_refused", agent=record["name"], operator=operator, reason=str(err))
            raise FleetError(str(err), 400) from None
        try:
            check_scope(iter_targets(job["target"], protocol.MAX_JOB_HOSTS), parse_scope(record["scope"]))
        except ScopeError as err:
            self._note("dispatch_refused", agent=record["name"], operator=operator, target=job["target"], reason=str(err))
            raise FleetError("the target is outside the agent's scope", 403) from None
        with self._cond:
            self._expire()
            queue = self._queues.setdefault(record["id"], collections.deque())
            if sum(1 for j in queue if self.jobs.get(j, {}).get("state") == "queued") >= protocol.MAX_QUEUED_PER_AGENT:
                raise FleetError("that agent already has a full queue", 429)
            job_id = protocol.new_id()
            self._note("dispatch", job=job_id, agent=record["name"], agent_id=record["id"], operator=operator,
                       target=job["target"], ports=job["ports"], options=job["options"])
            self.jobs[job_id] = {"id": job_id, "agent": record["name"], "agent_id": record["id"], **job,
                                 "operator": operator, "state": "queued", "created": self._clock(), "sent_at": None,
                                 "started_at": None, "finished_at": None, "error": "", "summary": None, "scan_id": None}
            queue.append(job_id)
            self._cond.notify_all()
            return self._view(self.jobs[job_id])

    def cancel(self, job_id, operator: str = "") -> dict:
        with self._cond:
            job = self.jobs.get(job_id)
            if job is None:
                raise FleetError("no such job", 404)
            if not protocol.can_move(job["state"], "cancelled"):
                raise FleetError(f"the job is already {job['state']}", 409)
            self._note("job_cancelled", job=job_id, agent=job["agent"], operator=operator, was=job["state"])
            if job["state"] in ("sent", "running"):
                self._cancel_requests.setdefault(job["agent_id"], set()).add(job_id)
            job["state"], job["finished_at"], job["error"] = "cancelled", self._clock(), "cancelled by an operator"
            self._cond.notify_all()
            return self._view(job)

    def revoke(self, ref, operator: str = "") -> dict:
        record = self.registry.revoke(ref) if isinstance(ref, str) else None
        if record is None:
            raise FleetError("no such active agent", 404)
        with self._cond:
            dropped = 0
            for job in self.jobs.values():
                if job["agent_id"] == record["id"] and job["state"] in ("queued", "sent", "running"):
                    job["state"], job["finished_at"], job["error"] = "cancelled", self._clock(), "agent revoked"
                    dropped += 1
            self._queues.pop(record["id"], None)
            self._cancel_requests.pop(record["id"], None)
            self._cond.notify_all()                                              # wake its long poll: it will get a 401
        try:
            self.audit.record("revoke", agent=record["name"], agent_id=record["id"], operator=operator,
                              jobs_dropped=dropped)
        except AuditError as err:
            raise FleetError(f"{record['name']} is revoked, but the audit trail could not be written: {err}", 503) from None
        return {**record, "jobs_dropped": dropped}

    # -- agents: polling, acknowledging, reporting ---------------------------------------------------------------

    def poll(self, agent: dict, busy: bool = False, wait=None) -> dict:
        """The next job for `agent` (unless it is busy) and any jobs to cancel. Waits for one up to `wait` seconds:
        never more than POLL_SECONDS, and a busy agent asks for a short wait to keep reporting in."""
        wanted = POLL_SECONDS if wait is None else min(float(wait), POLL_SECONDS)
        deadline = time.monotonic() + max(0.0, wanted)
        with self._cond:
            while True:
                record = self.registry.get(agent["id"])
                if record is None or record["revoked"]:
                    raise FleetError("unauthorized", 401)
                cancels = sorted(self._cancel_requests.pop(agent["id"], ()))
                job = None if busy else self._next_job(agent["id"])
                remaining = deadline - time.monotonic()
                if job is not None or cancels or remaining <= 0 or self._closed:
                    return {"job": job, "cancel": cancels, "poll_seconds": POLL_SECONDS}
                self._cond.wait(min(remaining, 1.0))

    def _next_job(self, agent_id: str):
        self._expire()
        queue = self._queues.get(agent_id)
        while queue:
            job = self.jobs.get(queue.popleft())
            if job is None or job["state"] != "queued":
                continue
            self._note("job_sent", job=job["id"], agent=job["agent"])
            job["state"], job["sent_at"] = "sent", self._clock()
            return {"id": job["id"], "target": job["target"], "ports": job["ports"], "options": job["options"],
                    "expires": job["created"] + RUNNING_TTL}
        return None

    def _own_job(self, agent: dict, job_id):
        job = self.jobs.get(job_id) if isinstance(job_id, str) else None
        if job is None or job["agent_id"] != agent["id"]:
            raise FleetError("no such job", 404)
        return job

    def ack(self, agent: dict, job_id) -> dict:
        with self._cond:
            job = self._own_job(agent, job_id)
            if not protocol.can_move(job["state"], "running"):
                raise FleetError(f"the job is {job['state']}", 409)
            self._note("job_started", job=job["id"], agent=job["agent"])
            job["state"], job["started_at"] = "running", self._clock()
            return {"ok": True}

    def receive_result(self, agent: dict, raw) -> dict:
        try:
            result = protocol.validate_result(raw)
        except protocol.ProtocolError as err:
            raise FleetError(str(err), 400) from None
        with self._cond:
            job = self._own_job(agent, result["job"])
            if job["state"] not in ("sent", "running"):
                raise FleetError(f"the job is {job['state']}", 409)
            state, error, scan_id, summary = result["state"], result["error"], None, None
            if state == "done":
                try:
                    scan_id, summary = self._store(agent["id"], job, result)
                except Exception:      # the result is attacker-shaped: whatever is wrong with it, refuse it
                    state, error = "failed", "the result could not be stored (malformed)"
            self._note("job_finished", job=job["id"], agent=job["agent"], state=state, scan_id=scan_id,
                       summary=summary, error=error)
            job.update(state=state, finished_at=self._clock(), error=error, scan_id=scan_id, summary=summary)
            self._cond.notify_all()
            return {"ok": True, "state": state, "scan_id": scan_id}

    def _store(self, agent_id: str, job: dict, result: dict) -> tuple:
        """Normalise an agent's meta (the target is ours, never the agent's) and keep the scan in that agent's history."""
        hosts, meta = result["hosts"], result["meta"]
        findings = meta.get("findings") if isinstance(meta.get("findings"), dict) else {}
        clean = {"target": job["target"], "scan_time": str(meta.get("scan_time") or "")[:40] or "unknown",
                 "duration": _number(meta.get("duration")), "ports_scanned": int(_number(meta.get("ports_scanned"))),
                 "udp_ports_scanned": int(_number(meta.get("udp_ports_scanned"))), "options": job["options"],
                 "findings": {k: int(_number(v)) for k, v in findings.items() if isinstance(k, str)},
                 "warnings": [], "capabilities": {}, "cancelled": False, "discovered": len(hosts)}
        folder = self._agent_folder(agent_id)
        scan_id = history.save(folder, None, clean, hosts)
        before = history.previous_for(folder, job["target"], scan_id)
        old = history.load(folder, before) if before else None
        changes = diff_scans(old["hosts"], hosts)["summary"] if old else None
        summary = {"hosts": len(hosts), "open_ports": sum(_count(h.get("open_ports")) for h in hosts),
                   "findings": clean["findings"], "changes": changes}
        return scan_id, summary

    # -- what the operator sees ---------------------------------------------------------------------------------

    def agents(self) -> list:
        now = self._clock()
        with self._cond:
            out = []
            for record in self.registry.agents():
                busy = [j for j in self.jobs.values() if j["agent_id"] == record["id"] and j["state"] in ("sent", "running")]
                seen = record["last_seen"]
                status = "revoked" if record["revoked"] else "online" if seen and now - seen <= ONLINE_WITHIN else "offline"
                queued = sum(1 for j in self.jobs.values() if j["agent_id"] == record["id"] and j["state"] == "queued")
                out.append({**record, "status": status, "queued": queued, "running_job": busy[0]["id"] if busy else None})
            return out

    def job_list(self, limit: int = 100) -> list:
        with self._cond:
            self._expire()
            return [self._view(j) for j in list(self.jobs.values())[-max(1, min(limit, MAX_JOBS_KEPT)):]][::-1]

    def job(self, job_id) -> dict:
        with self._cond:
            job = self.jobs.get(job_id) if isinstance(job_id, str) else None
            if job is None:
                raise FleetError("no such job", 404)
            return self._view(job)

    def results(self, agent_ref, limit: int = 30) -> list:
        return history.list_scans(self._agent_folder(self._agent_ref(agent_ref)["id"]), max(1, min(limit, 100)))

    def result(self, agent_ref, scan_id):
        data = history.load(self._agent_folder(self._agent_ref(agent_ref)["id"]), scan_id)
        if data is None:
            raise FleetError("no such result", 404)
        return data
