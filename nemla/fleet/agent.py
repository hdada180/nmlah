"""The Fleet agent: enrolled once, on the machine it watches, then it asks its controller for jobs.

What an agent guarantees, whatever the controller sends:

- It connects OUT to one controller and nothing connects in. Over TLS it checks the controller certificate's SHA-256
  fingerprint against the pin recorded at enrollment *before* sending any credential (no pin, no enrollment).
- Its scope is a local setting the controller cannot change. Every job is validated as data and checked against that
  scope on the resolved addresses, and against a local host limit; a job that fails either is refused, reported as
  failed and written to the agent's own audit trail. The controller's opinion about the scope never matters.
- It runs one job at a time, only through `engine.run_scan`, with a local time limit, and it stops the scan at once
  when the controller cancels it, when it is revoked, or when the operator stops the agent.
- `nemla agent leave` deletes its credentials on this machine, whatever the controller says.
"""
from __future__ import annotations

import http.client
import json
import random
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from ..config import MAX_HOSTS_HARD, __version__
from ..engine import run_scan
from ..log import log
from ..reports import PRIVATE_DIR, write_atomic
from ..reports.common import hosts_for_report
from ..targets import iter_targets, parse_ports
from . import protocol
from .audit import AuditError, AuditLog
from .scope import ScopeError, check_scope, parse_scope

CONFIG_FILE = "agent.json"
POLL_SECONDS = 25
DEFAULT_MAX_HOSTS = 1024
DEFAULT_MAX_MINUTES = 60
MAX_RESPONSE = 256 * 1024
MAX_BACKOFF = 60
_RESULT_TRIES = 6


class AgentError(Exception):
    """Something the agent cannot or will not do."""


class PinMismatch(AgentError):
    """The controller's certificate is not the one pinned at enrollment."""


class Revoked(AgentError):
    """The controller no longer accepts this agent."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


# -- talking to the controller -----------------------------------------------------------------------------------

class Transport:
    """POST JSON to the controller. Over TLS the certificate is pinned, not verified against a name."""

    def __init__(self, url: str, pin=None):
        parsed = urlparse(url if "://" in url else "https://" + url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise AgentError("the controller address is https://HOST:PORT "
                             "(or http://127.0.0.1:PORT for one on this machine)")
        self.tls = parsed.scheme == "https"
        self.pin: str | None
        self.host = parsed.hostname
        try:
            self.port = parsed.port or (443 if self.tls else 80)
        except ValueError:
            raise AgentError("the controller address has an invalid port") from None
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise AgentError("the controller address is just https://HOST:PORT, without a path")
        if self.tls:
            try:
                self.pin = protocol.normalize_pin(pin or "")
            except protocol.ProtocolError as err:
                raise AgentError(f"a pin is required for https: {err}") from None
        else:
            if not is_loopback(self.host):
                raise AgentError("plain http is only allowed to a controller on this machine; use https with a pin")
            self.pin = None
        self.url = f"{parsed.scheme}://{self.host}:{self.port}"

    def _connect(self, timeout: float):
        if not self.tls:
            return http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE                   # the pin below replaces name and chain validation
        conn = http.client.HTTPSConnection(self.host, self.port, context=context, timeout=timeout)
        conn.connect()
        try:
            der = conn.sock.getpeercert(binary_form=True) if conn.sock else None
            if not der or not protocol.pins_equal(protocol.pin_of(der), self.pin or ""):
                raise PinMismatch("the controller's certificate is not the one pinned at enrollment; nothing was sent")
        except BaseException:
            conn.close()
            raise
        return conn

    def post(self, path: str, body: dict, auth=None, timeout: float = 30.0):
        """(status, answer) - the answer is a dict. Raises PinMismatch, or OSError when the controller is unreachable."""
        conn = self._connect(timeout)                         # the pin is checked here, before anything is sent
        try:
            payload = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
            if auth:
                headers["Authorization"] = f"Bearer {auth[0]}.{auth[1]}"
            conn.request("POST", path, body=payload, headers=headers)
            response = conn.getresponse()
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise AgentError("the controller's answer is too large")
            try:
                answer = protocol.loads_strict(data, MAX_RESPONSE) if data else {}
            except protocol.ProtocolError:
                answer = {}
            return response.status, answer if isinstance(answer, dict) else {}
        finally:
            conn.close()


# -- the agent's local state -------------------------------------------------------------------------------------

def load_config(folder) -> dict:
    path = Path(folder) / CONFIG_FILE
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AgentError("this machine is not enrolled (run: nemla agent enroll ...)") from None
    except (OSError, ValueError):
        raise AgentError(f"{path} is damaged; run `nemla agent leave` and enroll again") from None
    required = ("controller", "agent_id", "secret", "scope", "name")
    if not isinstance(cfg, dict) or not all(isinstance(cfg.get(k), str) for k in required):
        raise AgentError(f"{path} is damaged; run `nemla agent leave` and enroll again")
    return cfg


def _audit(folder) -> AuditLog:
    return AuditLog(Path(folder) / "audit.jsonl")


def _note(folder, event: str, **fields) -> None:
    try:
        _audit(folder).record(event, **fields)
    except AuditError as err:
        log(f"warning: {err}")


def enroll(folder, url: str, token: str, scope_spec: str, pin: str, max_hosts: int = DEFAULT_MAX_HOSTS,
           max_minutes: int = DEFAULT_MAX_MINUTES, hostname: str = "") -> dict:
    """Enroll this machine with the controller at `url`. The scope, the host limit and the time limit are set here,
    on this machine, and stay here."""
    folder = Path(folder)
    try:
        scope = parse_scope(scope_spec)
    except ScopeError as err:
        raise AgentError(f"the scope is not usable: {err}") from None
    if not isinstance(max_hosts, int) or not 1 <= max_hosts <= protocol.MAX_JOB_HOSTS:
        raise AgentError(f"--max-hosts is between 1 and {protocol.MAX_JOB_HOSTS}")
    if not isinstance(max_minutes, int) or not 1 <= max_minutes <= 24 * 60:
        raise AgentError("--max-minutes is between 1 and 1440")
    if (folder / CONFIG_FILE).exists():
        raise AgentError("this machine is already enrolled; run `nemla agent leave` first")
    transport = Transport(url, pin)
    try:
        who = hostname or socket.gethostname()
        status, answer = transport.post("/agent/v1/enroll", {"token": token, "scope": scope_spec.strip(),
                                                              "version": __version__, "hostname": who})
    except PinMismatch:
        raise
    except OSError as err:
        raise AgentError(f"cannot reach the controller at {transport.url}: {err.strerror or err}") from None
    if status != 200 or not all(isinstance(answer.get(k), str) for k in ("agent_id", "secret", "name")):
        raise AgentError("the controller refused the enrollment (a token works once and expires after 15 minutes)")
    cfg = {"controller": transport.url, "pin": transport.pin, "agent_id": answer["agent_id"], "secret": answer["secret"],
           "name": answer["name"], "scope": scope_spec.strip(), "scope_addresses": scope.count(), "max_hosts": max_hosts,
           "max_minutes": max_minutes, "enrolled": time.time()}
    folder.mkdir(mode=PRIVATE_DIR, parents=True, exist_ok=True)
    write_atomic(str(folder / CONFIG_FILE), json.dumps(cfg, indent=1).encode("utf-8"))
    _note(folder, "enrolled", controller=transport.url, agent=cfg["name"], agent_id=cfg["agent_id"], scope=cfg["scope"],
          max_hosts=max_hosts, max_minutes=max_minutes)
    return status_of(folder)


def status_of(folder) -> dict:
    """What this agent is set up to do (never its secret)."""
    cfg = load_config(folder)
    return {k: cfg.get(k) for k in ("name", "agent_id", "controller", "pin", "scope", "scope_addresses", "max_hosts",
                                    "max_minutes", "enrolled")}


def leave(folder) -> bool:
    """Delete this machine's credentials. True if there were any. The controller should be told to revoke the agent
    too (`nemla controller revoke NAME`); until then it merely has an agent that never comes back."""
    folder = Path(folder)
    try:
        cfg = load_config(folder)
        _note(folder, "left", agent=cfg["name"], agent_id=cfg["agent_id"], controller=cfg["controller"])
    except AgentError:
        pass
    try:
        (folder / CONFIG_FILE).unlink()
        return True
    except FileNotFoundError:
        return False


def scan_kwargs(options: dict) -> dict:
    """A validated job's options as run_scan keyword arguments."""
    kwargs = {k: v for k, v in options.items() if k != "udp_ports"}
    if options.get("udp_ports"):
        kwargs["udp_ports"] = tuple(parse_ports(options["udp_ports"]))
    return kwargs


# -- running ----------------------------------------------------------------------------------------------------

class Runner:
    def __init__(self, folder, stop: threading.Event, say=log, run=run_scan, poll_seconds: float = POLL_SECONDS,
                 busy_wait: float = 3.0):
        self.folder = Path(folder)
        self.poll_seconds = poll_seconds            # how long an idle poll waits for work (the controller caps it)
        self.busy_wait = busy_wait                  # how long a poll waits while a scan runs (cancellations arrive here)
        self.cfg = load_config(self.folder)
        self.stop = stop
        self.say = say
        self._run_scan = run
        self.scope = parse_scope(self.cfg["scope"])
        self.transport = Transport(self.cfg["controller"], self.cfg.get("pin"))
        self.auth = (self.cfg["agent_id"], self.cfg["secret"])
        self.limits = {"hosts": int(self.cfg.get("max_hosts") or DEFAULT_MAX_HOSTS),
                       "seconds": int(self.cfg.get("max_minutes") or DEFAULT_MAX_MINUTES) * 60}
        self.jobs_done = 0

    def _post(self, path: str, body: dict, timeout: float = 30.0) -> dict:
        status, answer = self.transport.post(path, body, self.auth, timeout)
        if status == 401:
            raise Revoked("the controller no longer accepts this agent")
        if status != 200:
            raise AgentError(f"{path}: {answer.get('error') or status}")
        return answer

    def _note(self, event: str, **fields) -> None:
        _note(self.folder, event, agent=self.cfg["name"], **fields)

    def run(self) -> str:
        """Poll until stopped or refused. Returns why it ended: stopped, revoked or pin_mismatch."""
        self.say(f"Agent {self.cfg['name']}: watching {self.cfg['scope']} for {self.transport.url}")
        self._note("started", controller=self.transport.url, scope=self.cfg["scope"])
        failures = 0
        while not self.stop.is_set():
            try:
                reply = self._post("/agent/v1/poll", {"busy": False, "wait": self.poll_seconds}, self.poll_seconds + 15)
                failures = 0
            except Revoked:
                return self._ended("revoked", "The controller has revoked this agent. Stopping.")
            except PinMismatch as err:
                return self._ended("pin_mismatch", f"{err}. Stopping - check the pin, or whether the controller changed.")
            except (OSError, AgentError, ssl.SSLError) as err:
                failures += 1
                jitter = random.uniform(0.5, 1.0)  # noqa: S311 - spreading retries, not security
                delay = min(MAX_BACKOFF, 2 ** min(failures, 6)) * jitter
                if failures in (1, 5) or failures % 20 == 0:
                    self.say(f"Cannot reach the controller ({err}); trying again in {delay:.0f}s")
                self.stop.wait(delay)
                continue
            job = reply.get("job")
            if isinstance(job, dict):
                outcome = self._work(job)
                if outcome:
                    return outcome
        return self._ended("stopped", "Agent stopped.")

    def _ended(self, reason: str, message: str) -> str:
        self.say(message)
        self._note("ended", reason=reason, jobs_done=self.jobs_done)
        return reason

    # -- one job ---------------------------------------------------------------------------------------------

    def _report(self, payload: dict):
        """Send a result, retrying a few times: a finished scan is worth keeping. Returns the controller's answer."""
        body = payload
        for attempt in range(_RESULT_TRIES):
            try:
                return self._post("/agent/v1/result", body, 120)
            except (Revoked, PinMismatch):
                raise
            except AgentError as err:
                self.say(f"The controller did not accept the result: {err}")
                return None
            except OSError as err:
                if self.stop.wait(min(30, 2 ** attempt)):
                    return None
                self.say(f"Sending the result failed ({err.strerror or err}); trying again")
        self.say("Giving up on sending this result.")
        return None

    def _refuse(self, job_id: str, reason: str) -> None:
        self.say(f"Refused job {job_id}: {reason}")
        self._note("job_refused", job=job_id, reason=reason)
        self._report({"job": job_id, "state": "failed", "error": f"refused by the agent: {reason}"})

    def _work(self, job: dict):
        """Run one job. Returns None to carry on, or the reason the agent must end (revoked, pin_mismatch)."""
        job_id = job.get("id")
        if not isinstance(job_id, str) or not protocol.ID.fullmatch(job_id):
            self._note("job_refused", reason="a job without a valid id")
            return None
        try:
            clean = protocol.validate_job({k: job.get(k) for k in ("target", "ports", "options")}, self.limits["hosts"])
            addresses = iter_targets(clean["target"], min(self.limits["hosts"], protocol.MAX_JOB_HOSTS, MAX_HOSTS_HARD))
            check_scope(addresses, self.scope)
            ports = parse_ports(clean["ports"])
            kwargs = scan_kwargs(clean["options"])
        except (protocol.ProtocolError, ScopeError, ValueError) as err:
            try:
                self._refuse(job_id, str(err))
            except (Revoked, PinMismatch) as fatal:
                return "revoked" if isinstance(fatal, Revoked) else "pin_mismatch"
            return None
        self._note("job_received", job=job_id, target=clean["target"], ports=clean["ports"], options=clean["options"])
        try:
            self._post("/agent/v1/ack", {"job": job_id})
        except Revoked:
            return self._ended("revoked", "The controller has revoked this agent. Stopping.")
        except (AgentError, OSError):
            self.say(f"Job {job_id} was withdrawn before it started")
            return None
        self.say(f"Job {job_id}: scanning {clean['target']} ports {clean['ports']}")
        self._note("job_started", job=job_id)
        cancel, outcome = threading.Event(), {}

        def scan():
            try:
                outcome["ok"] = self._run_scan(clean["target"], addresses, ports, cancel=cancel, **kwargs)
            except Exception as err:      # the scan is the risky part: whatever fails becomes a failed job, not a dead agent
                outcome["error"] = f"{type(err).__name__}: {err}"

        worker = threading.Thread(target=scan, daemon=True)
        worker.start()
        deadline = time.monotonic() + self.limits["seconds"]
        why = ""
        while worker.is_alive():
            if self.stop.is_set() and not why:
                cancel.set()
                why = "the agent was stopped"
            if time.monotonic() > deadline and not why:
                cancel.set()
                why = f"the agent's own time limit of {self.limits['seconds'] // 60} minutes was reached"
            try:
                reply = self._post("/agent/v1/poll", {"busy": True, "wait": self.busy_wait}, self.busy_wait + 15)
                if job_id in (reply.get("cancel") or []) and not why:
                    cancel.set()
                    why = "cancelled by the controller"
            except Revoked:
                cancel.set()
                worker.join(30)
                return self._ended("revoked", "The controller has revoked this agent; the scan was stopped and dropped.")
            except PinMismatch:
                cancel.set()
                worker.join(30)
                return self._ended("pin_mismatch", "The controller's certificate changed. Stopping.")
            except (OSError, AgentError):
                self.stop.wait(2)                                    # unreachable: the scan goes on, results wait
            worker.join(0.2)
        payload = self._result_payload(job_id, outcome, why)
        self._note("job_finished", job=job_id, state=payload["state"], error=payload.get("error", ""))
        self.jobs_done += 1
        self.say(f"Job {job_id}: {payload['state']}" + (f" ({payload['error']})" if payload.get("error") else ""))
        try:
            self._report(payload)
        except Revoked:
            return self._ended("revoked", "The controller has revoked this agent. Stopping.")
        except PinMismatch:
            return self._ended("pin_mismatch", "The controller's certificate changed. Stopping.")
        return None

    def _result_payload(self, job_id: str, outcome: dict, why: str) -> dict:
        if "error" in outcome or "ok" not in outcome:
            return {"job": job_id, "state": "failed", "error": outcome.get("error", "the scan produced no result")}
        hosts, meta = outcome["ok"]
        state = "cancelled" if meta.get("cancelled") or why else "done"
        payload = {"job": job_id, "state": state, "error": why if why else "",
                   "meta": {k: meta.get(k) for k in ("scan_time", "duration", "ports_scanned", "udp_ports_scanned", "findings",
                                                     "discovered") if k in meta},
                   "hosts": hosts_for_report(hosts, "en")}
        if why and "time limit" in why:
            payload["state"] = "failed"
        try:
            size = len(json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError):
            return {"job": job_id, "state": "failed", "error": "the result could not be encoded"}
        if size > protocol.MAX_RESULT_BYTES:
            return {"job": job_id, "state": "failed",
                    "error": f"the result is {size // (1024 * 1024)} MiB, more than the "
                             f"{protocol.MAX_RESULT_BYTES // (1024 * 1024)} MiB a controller accepts; scan a smaller range"}
        return payload
