"""Fleet core: jobs and results are data, scopes are enforced by span arithmetic, the registry never forgets a
revocation, and the audit trail is redacted and fails closed."""
import json
import os
import re
import threading
from pathlib import Path

import pytest

from nemla import targets
from nemla.fleet import audit, protocol, registry, scope

posix_only = pytest.mark.skipif(os.name != "posix", reason="owner-only permissions are checked on POSIX")
GOOD_JOB = {"target": "10.0.0.0/30", "ports": "22,80"}


def ts(spec):
    return targets.iter_targets(spec, 1 << 20)


# --------------------------------------------------------------------------
# scope: is every address of a job inside what the agent's owner allowed
# --------------------------------------------------------------------------

@pytest.mark.parametrize("inner, outer, expected", [
    ("10.0.5.0/24", "10.0.0.0/16", True),
    ("10.0.5.9", "10.0.5.0/24", True),
    ("10.1.0.1", "10.0.0.0/16", False),
    ("10.0.0.0/15", "10.0.0.0/16", False),                                   # half of it is outside
    ("10.0.0.5-10.0.0.9", "10.0.0.0/24", True),
    ("10.0.0.250-10.0.1.5", "10.0.0.0/24", False),                           # runs over the edge
    ("10.0.0.5,192.168.1.1", "10.0.0.0/24,192.168.1.0/24", True),
    ("10.0.0.5,172.16.0.1", "10.0.0.0/24,192.168.1.0/24", False),            # one address out of two is enough to refuse
    ("10.0.0.5", "10.0.0.5", True),
    ("2001:db8::5", "2001:db8::/112", True),
    ("2001:db8::5", "10.0.0.0/16", False),               # an IPv6 job in an IPv4 scope
    ("10.0.0.5", "2001:db8::/112", False),
    ("::1", "::1", True),
    ("fe80::1%eth0", "fe80::/112", True),                                     # a zone id does not change the address
    ("fe80::1%eth0", "2001:db8::/112", False),
    ("fe80::1%eth0", "fe80::1%eth0", True),
])
def test_a_target_is_inside_a_scope_only_when_every_address_is(inner, outer, expected):
    assert ts(outer).contains_all(ts(inner)) is expected


def test_containment_is_span_arithmetic_and_never_expands_a_block():
    import time
    started = time.monotonic()
    assert ts("10.0.0.0/12").contains_all(ts("10.1.0.0/16")) and not ts("10.0.0.0/16").contains_all(ts("10.0.0.0/12"))
    assert time.monotonic() - started < 0.5


def test_a_scope_is_addresses_only_and_never_everything():
    for bad in ("example.com", "localhost", "10.0.0.0/24,example.com", "", "0.0.0.0/0", "::/0", None, 7, "10.0.0.0/8"):
        with pytest.raises(scope.ScopeError):
            scope.parse_scope(bad)
    assert scope.parse_scope("10.20.0.0/16,192.168.1.0/24").count() == 65534 + 254


def test_check_scope_refuses_a_job_that_leaves_the_scope():
    allowed = scope.parse_scope("10.20.0.0/16")
    scope.check_scope(ts("10.20.1.0/24"), allowed)
    with pytest.raises(scope.ScopeError):
        scope.check_scope(ts("10.20.1.0/24,10.21.0.1"), allowed)


# --------------------------------------------------------------------------
# jobs: data, never code
# --------------------------------------------------------------------------

def test_a_valid_job_comes_back_clean():
    job = protocol.validate_job({"target": " 10.0.0.0/30 ", "ports": " 22,80 ",
                                 "options": {"threads": 20, "timeout": 1, "no_os": True, "udp_ports": "53,161"}})
    assert job == {"target": "10.0.0.0/30", "ports": "22,80",
                   "options": {"threads": 20, "timeout": 1, "no_os": True, "udp_ports": "53,161"}}


@pytest.mark.parametrize("target", ["example.com", "localhost", "10.0.0.1,example.com", "10.0.0.1 evil.example",
                                    "$(reboot)", "10.0.0.1;id", "10.0.0.1\nfoo", "", "   ", None, 5, ["10.0.0.1"],
                                    "١٠.0.0.1"])
def test_a_job_names_addresses_never_hosts_or_commands(target):
    with pytest.raises(protocol.JobError):
        protocol.validate_job({"target": target, "ports": "22"})


@pytest.mark.parametrize("extra", [{"command": "rm -rf /"}, {"script": "x"}, {"plugin": "evil"}, {"url": "http://x"},
                                   {"file": "/etc/passwd"}, {"lang": "ar"}, {"Target": "10.0.0.1"}])
def test_an_unknown_job_field_is_refused_never_ignored(extra):
    with pytest.raises(protocol.JobError, match="unknown"):
        protocol.validate_job({**GOOD_JOB, **extra})


@pytest.mark.parametrize("options", [
    {"shell": "id"}, {"threads": True}, {"threads": "5"}, {"threads": 1.5}, {"threads": 0}, {"threads": 99999},
    {"timeout": "1"}, {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")}, {"timeout": float("inf")},
    {"timeout": 1e9}, {"no_ping": 1}, {"no_os": "yes"}, {"intensity": 10}, {"rate": -1}, {"max_probes": -5},
    {"per_host": 0}, {"udp_ports": 53}, {"udp_ports": "0"}, {"udp_ports": "abc"}, "threads=5", ["threads"]])
def test_hostile_options_are_refused(options):
    with pytest.raises(protocol.JobError):
        protocol.validate_job({**GOOD_JOB, "options": options})


@pytest.mark.parametrize("ports", ["0", "70000", "abc", "1-99999999999", "", 22, None, ["22"], "80,,x"])
def test_hostile_ports_are_refused(ports):
    with pytest.raises(protocol.JobError):
        protocol.validate_job({"target": "10.0.0.1", "ports": ports})


def test_a_job_cannot_name_more_addresses_than_the_limit_and_an_agent_can_only_lower_it():
    protocol.validate_job({"target": "10.0.0.0/20", "ports": "22"})                       # 4094 addresses
    with pytest.raises(protocol.JobError):
        protocol.validate_job({"target": "10.0.0.0/19", "ports": "22"})                   # 8190
    with pytest.raises(protocol.JobError):
        protocol.validate_job({"target": "10.0.0.0/8", "ports": "22"})
    protocol.validate_job({"target": "10.0.0.0/28", "ports": "22"}, max_hosts=16)
    with pytest.raises(protocol.JobError):
        protocol.validate_job({"target": "10.0.0.0/27", "ports": "22"}, max_hosts=16)
    with pytest.raises(protocol.JobError):                                                # raising the cap does nothing
        protocol.validate_job({"target": "10.0.0.0/19", "ports": "22"}, max_hosts=10 ** 9)


@pytest.mark.parametrize("raw", [None, [], "job", 3, [GOOD_JOB]])
def test_a_job_must_be_an_object(raw):
    with pytest.raises(protocol.JobError):
        protocol.validate_job(raw)


@pytest.mark.parametrize("data, limit", [(b"x" * 20, 10), (b"\xff\xfe", 100), (b"NaN", 100), (b'{"a": Infinity}', 100),
                                         (b"[" * 20000, 100000), (b"", 100), (b"{not json", 100), ("text", 100)])
def test_wire_json_is_bounded_and_strict(data, limit):
    with pytest.raises(protocol.ProtocolError):
        protocol.loads_strict(data, limit)


def test_wire_json_that_is_fine_is_parsed():
    assert protocol.loads_strict(b'{"a": [1, 2.5, "\xc3\xa9"]}', 100) == {"a": [1, 2.5, "é"]}


# --------------------------------------------------------------------------
# results: known fields, sane types
# --------------------------------------------------------------------------

def test_a_result_is_checked_and_its_text_capped():
    result = protocol.validate_result({"job": "0123456789abcdef", "state": "done", "meta": {"x": 1},
                                       "hosts": [{"ip": "10.0.0.1", "open_ports": []}], "error": "e" * 5000})
    assert result["state"] == "done" and len(result["error"]) == protocol.MAX_TEXT and result["hosts"][0]["ip"] == "10.0.0.1"


@pytest.mark.parametrize("bad", [
    None, [], {"job": "zz", "state": "done"}, {"job": "0123456789abcdef", "state": "running"},
    {"job": "0123456789abcdef", "state": "done", "extra": 1}, {"job": "0123456789abcdef", "state": "done", "hosts": {}},
    {"job": "0123456789abcdef", "state": "done", "hosts": [{"no": "ip"}]},
    {"job": "0123456789abcdef", "state": "done", "hosts": ["10.0.0.1"]},
    {"job": "0123456789abcdef", "state": "done", "meta": []}, {"job": "0123456789abcdef", "state": "done", "error": 5},
    {"job": "../../etc", "state": "done"}])
def test_a_malformed_result_is_refused(bad):
    with pytest.raises(protocol.ProtocolError):
        protocol.validate_result(bad)


def test_a_finished_job_never_moves_again():
    assert protocol.can_move("queued", "sent") and protocol.can_move("sent", "running") and protocol.can_move("running", "done")
    assert protocol.can_move("queued", "cancelled") and protocol.can_move("sent", "expired")
    for finished in ("done", "failed", "cancelled", "expired"):
        assert not any(protocol.can_move(finished, other) for other in protocol.JOB_STATES)
    assert not protocol.can_move("queued", "done") and not protocol.can_move("nonsense", "sent")


# --------------------------------------------------------------------------
# secrets and pins
# --------------------------------------------------------------------------

def test_secrets_are_long_random_and_stored_only_as_a_hash():
    first, second = protocol.new_secret(), protocol.new_secret()
    assert first != second and len(first) >= 43
    assert protocol.hash_secret(first) != first and protocol.secret_matches(first, protocol.hash_secret(first))
    assert not protocol.secret_matches(second, protocol.hash_secret(first))


def test_a_certificate_pin_accepts_the_usual_spellings_and_nothing_else():
    digest = protocol.pin_of(b"a certificate")
    assert digest.startswith("sha256:") and len(digest) == 71
    upper_colons = ":".join(digest[7:][i:i + 2].upper() for i in range(0, 64, 2))
    assert protocol.normalize_pin(upper_colons) == digest == protocol.normalize_pin(digest[7:]) == protocol.normalize_pin(digest.upper())
    for bad in ("", "sha256:abc", "zz" * 32, "a" * 63, "a" * 65, None):
        with pytest.raises(protocol.ProtocolError):
            protocol.normalize_pin(bad)
    assert protocol.pins_equal(digest, digest) and not protocol.pins_equal(digest, protocol.pin_of(b"another"))


# --------------------------------------------------------------------------
# the registry
# --------------------------------------------------------------------------

class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def reg(tmp_path, clock):
    return registry.Registry(tmp_path / "fleet", clock=clock)


def enrolled(reg, name="acme-hq", scope_spec="10.20.0.0/16"):
    record, secret = reg.enroll(reg.issue_token(name, operator="alice"), scope_spec)
    return record, secret


def test_an_enrolled_agent_authenticates_and_its_secret_is_not_stored(reg, tmp_path):
    record, secret = enrolled(reg)
    assert record["name"] == "acme-hq" and record["scope"] == "10.20.0.0/16" and record["scope_addresses"] == 65534
    assert "secret_hash" not in record and record["revoked"] is False
    assert reg.authenticate(record["id"], secret)["name"] == "acme-hq"
    stored = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "fleet").iterdir())
    assert secret not in stored and protocol.hash_secret(secret) in stored


def test_an_enrollment_token_works_once(reg):
    token = reg.issue_token("acme-hq")
    reg.enroll(token, "10.20.0.0/16")
    with pytest.raises(registry.RegistryError):
        reg.enroll(token, "10.20.0.0/16")


def test_an_enrollment_token_expires(reg, clock):
    token = reg.issue_token("acme-hq", ttl=60)
    clock.now += 61
    with pytest.raises(registry.RegistryError):
        reg.enroll(token, "10.20.0.0/16")


@pytest.mark.parametrize("token", ["", "not-a-token", None, 5, "x" * 500])
def test_a_token_that_was_never_issued_is_refused(reg, token):
    with pytest.raises(registry.RegistryError):
        reg.enroll(token, "10.20.0.0/16")


def test_a_scope_that_is_not_usable_does_not_spend_the_token(reg):
    token = reg.issue_token("acme-hq")
    for bad in ("example.com", "0.0.0.0/0", ""):
        with pytest.raises(registry.RegistryError):
            reg.enroll(token, bad)
    record, _ = reg.enroll(token, "10.20.0.0/16")
    assert record["name"] == "acme-hq"


@pytest.mark.parametrize("name", ["", "a b", "../x", "-lead", "x" * 65, "spät", None, 5, "a/b", "a;b"])
def test_an_agent_name_is_plain(reg, name):
    with pytest.raises(registry.RegistryError):
        reg.issue_token(name)


def test_a_name_is_taken_until_its_agent_is_revoked(reg):
    enrolled(reg)
    with pytest.raises(registry.RegistryError):
        reg.issue_token("acme-hq")
    assert reg.revoke("acme-hq")["revoked"] is True
    record, _ = enrolled(reg)
    assert record["name"] == "acme-hq" and len(reg.agents()) == 2


def test_the_newest_pending_token_for_a_name_replaces_the_older_one(reg):
    older, newer = reg.issue_token("acme-hq"), reg.issue_token("acme-hq")
    with pytest.raises(registry.RegistryError):
        reg.enroll(older, "10.20.0.0/16")
    reg.enroll(newer, "10.20.0.0/16")


def test_authentication_refuses_wrong_unknown_revoked_and_odd_credentials(reg):
    record, secret = enrolled(reg)
    assert reg.authenticate(record["id"], "wrong") is None
    assert reg.authenticate("nosuchagent", secret) is None
    for odd in (None, 5, b"x", ["a"]):
        assert reg.authenticate(odd, secret) is None and reg.authenticate(record["id"], odd) is None
    assert reg.revoke(record["id"])["revoked"] is True
    assert reg.authenticate(record["id"], secret) is None                         # the right secret no longer works


def test_revocation_is_by_name_or_id_and_only_once(reg):
    record, _ = enrolled(reg)
    assert reg.revoke("no-such-agent") is None
    assert reg.revoke(record["name"])["revoked_at"] is not None
    assert reg.revoke(record["id"]) is None
    assert reg.get(record["id"])["revoked"] is True and reg.get("nobody") is None


def test_the_registry_survives_a_restart_and_a_revocation_stays_revoked(reg, tmp_path, clock):
    record, secret = enrolled(reg)
    other, other_secret = enrolled(reg, "beta-branch", "192.168.7.0/24")
    reg.revoke(record["id"])
    again = registry.Registry(tmp_path / "fleet", clock=clock)
    assert again.authenticate(record["id"], secret) is None
    assert again.authenticate(other["id"], other_secret)["name"] == "beta-branch"
    assert {a["name"]: a["revoked"] for a in again.agents()} == {"acme-hq": True, "beta-branch": False}
    assert again.scope_of(other["id"]) == "192.168.7.0/24"


@pytest.mark.parametrize("content", ["{ nope", "[]", '{"agents": []}', '{"other": {}}', "", "null"])
def test_a_damaged_registry_is_an_error_never_an_empty_one(tmp_path, content):
    folder = tmp_path / "fleet"
    folder.mkdir()
    (folder / "agents.json").write_text(content, encoding="utf-8")
    with pytest.raises(registry.RegistryError):
        registry.Registry(folder)


def test_the_number_of_agents_is_limited(reg, monkeypatch):
    monkeypatch.setattr(registry, "MAX_AGENTS", 2)
    enrolled(reg, "one")
    reg.issue_token("two")
    with pytest.raises(registry.RegistryError, match="at most"):
        reg.issue_token("three")


def test_last_seen_is_saved_at_most_every_half_minute(reg, tmp_path, clock):
    record, _ = enrolled(reg)
    clock.now += 5
    reg.touch(record["id"])
    assert registry.Registry(tmp_path / "fleet", clock=clock).get(record["id"])["last_seen"] is None
    clock.now += 30
    reg.touch(record["id"])
    assert registry.Registry(tmp_path / "fleet", clock=clock).get(record["id"])["last_seen"] == clock.now
    reg.touch("nosuchagent")


def test_enrolling_at_the_same_moment_gives_every_agent_its_own_id(reg):
    tokens = [reg.issue_token(f"site-{i}") for i in range(8)]
    found, errors = [], []

    def go(token):
        try:
            found.append(reg.enroll(token, "10.20.0.0/16")[0]["id"])
        except Exception as err:            # the test reports whatever went wrong
            errors.append(err)
    threads = [threading.Thread(target=go, args=(t,)) for t in tokens]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors and len(set(found)) == 8 and len(reg.agents()) == 8


@posix_only
def test_the_registry_files_and_folder_are_owner_only(reg, tmp_path):
    enrolled(reg)
    assert oct((tmp_path / "fleet").stat().st_mode & 0o777) == "0o700"
    for name in ("agents.json", "enrollment.json"):
        assert oct((tmp_path / "fleet" / name).stat().st_mode & 0o777) == "0o600"


# --------------------------------------------------------------------------
# the audit trail
# --------------------------------------------------------------------------

def test_every_event_is_one_json_line_with_its_time(tmp_path):
    log = audit.AuditLog(tmp_path / "audit.jsonl", clock=lambda: 1_700_000_000.5)
    entry = log.record("dispatch", operator="alice", agent="acme-hq", target="10.20.1.0/24", options={"threads": 20})
    assert entry["time"] == "2023-11-14T22:13:20Z" and entry["epoch"] == 1_700_000_000.5
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and json.loads(lines[0]) == entry
    assert log.tail(10) == [entry]


def test_secrets_never_reach_the_audit_trail(tmp_path):
    log = audit.AuditLog(tmp_path / "audit.jsonl")
    log.record("enroll", token="abc123", secret="s3cret", Authorization="Bearer zzz", api_key="k", password="p",
               private_key="pk", nested={"agent_secret": "deep", "ok": "kept", "list": [{"token": "t2"}]})
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for leaked in ("abc123", "s3cret", "Bearer zzz", "deep", "t2", '"k"', '"p"', '"pk"'):
        assert leaked not in text
    assert "kept" in text and text.count("[redacted]") >= 7


def test_audit_values_are_bounded_and_always_json(tmp_path):
    log = audit.AuditLog(tmp_path / "audit.jsonl")
    deep = current = {}
    for _ in range(20):
        current["x"] = {}
        current = current["x"]
    entry = log.record("odd", long="a" * 5000, obj=object(), bytes=b"raw", deep=deep, items=list(range(500)), pi=3.14, none=None)
    assert len(entry["long"]) < 500 and isinstance(entry["obj"], str) and len(entry["items"]) == 60
    assert "[too deep]" in json.dumps(entry) and entry["pi"] == 3.14 and entry["none"] is None


def test_an_unwritable_audit_trail_is_an_error_not_a_silent_loss(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where a folder is needed", encoding="utf-8")
    with pytest.raises(audit.AuditError):
        audit.AuditLog(blocker / "audit.jsonl").record("dispatch")
    assert issubclass(audit.AuditError, OSError)


def test_a_full_audit_file_rotates_to_a_new_name_and_nothing_is_ever_overwritten(tmp_path):
    log = audit.AuditLog(tmp_path / "audit.jsonl", max_bytes=200, clock=lambda: 1_700_000_000.0)
    for i in range(30):
        log.record("event", index=i, filler="x" * 40)
    files = sorted(p.name for p in tmp_path.iterdir())
    assert len(files) > 2 and "audit.jsonl" in files                          # several rotations in the same second
    total = sum(len(p.read_text(encoding="utf-8").splitlines()) for p in tmp_path.iterdir())
    assert total == 30                                                          # every event survived, none overwritten
    seen = sorted(json.loads(line)["index"] for p in tmp_path.iterdir() for line in p.read_text(encoding="utf-8").splitlines())
    assert seen == list(range(30))


def test_the_tail_skips_damaged_lines_and_reads_nothing_from_a_missing_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    assert audit.AuditLog(path).tail(5) == []
    path.write_text('{"event": "a"}\nnot json\n[1]\n{"event": "b"}\n', encoding="utf-8")
    assert [e["event"] for e in audit.AuditLog(path).tail(10)] == ["a", "b"]
    assert [e["event"] for e in audit.AuditLog(path).tail(1)] == ["b"]


@posix_only
def test_the_audit_file_is_owner_only(tmp_path):
    audit.AuditLog(tmp_path / "new" / "audit.jsonl").record("x")
    assert oct((tmp_path / "new" / "audit.jsonl").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "new").stat().st_mode & 0o777) == "0o700"


# --------------------------------------------------------------------------
# the invariant that keeps this a scanner and not a shell
# --------------------------------------------------------------------------

BANNED = [r"\bsubprocess\b", r"os\.system", r"os\.popen", r"shell\s*=\s*True", r"\beval\(", r"\bexec\(", r"\bpickle\b",
          r"\bmarshal\b", r"__import__", r"\bimportlib\b", r"yaml\.load", r"(?<![\w.])compile\(", r"\bctypes\b", r"os\.exec", r"os\.spawn",
          r"\bpty\b", r"\bpopen\b"]


def test_the_fleet_package_never_starts_a_process_or_executes_text():
    """A job is data; nothing in the fleet package may turn text from the network into a running program."""
    root = Path(protocol.__file__).resolve().parent
    server = root.parent.parent / "nemla_ui" / "fleet_server.py"
    files = [*root.glob("*.py"), *([server] if server.exists() else [])]
    assert len(files) >= 5
    for path in files:
        source = path.read_text(encoding="utf-8")
        for pattern in BANNED:
            assert not re.search(pattern, source), f"{path.name} matches {pattern}"

# --------------------------------------------------------------------------
# more of the same: every literal form, and the pin helper's refusals
# --------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["10.0.0.5-10.0.0.9", "10.0.0.5-9", "2001:db8::1-2001:db8::9", "10.0.0.0/28,10.0.1.5",
                                    "[2001:db8::5]", "fe80::1%eth0", "10.0.0.5,   10.0.0.6", "::1"])
def test_ranges_blocks_and_scoped_addresses_are_accepted_as_literals(target):
    assert protocol.validate_job({"target": target, "ports": "22"})["target"] == target.strip()


@pytest.mark.parametrize("target", ["10.0.0.0/33", "10.0.0.5-", "2001:db8::1-notanaddress", "10.0.0.5-999", "1.2.3.4/x",
                                    "10.0.0.9-10.0.0.5", "-", "10.0.0.5-10.0.0.6-10.0.0.7"])
def test_broken_literals_are_refused(target):
    with pytest.raises(protocol.JobError):
        protocol.validate_job({"target": target, "ports": "22"})


def test_the_pin_of_a_pem_file_needs_a_real_certificate():
    for bad in ("", "no certificate here", "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"):
        with pytest.raises(protocol.ProtocolError):
            protocol.pin_from_pem(bad)


def test_a_registry_file_that_cannot_be_read_is_an_error_not_an_empty_registry(tmp_path):
    folder = tmp_path / "fleet"
    (folder / "agents.json").mkdir(parents=True)                # a folder where the file should be
    with pytest.raises(registry.RegistryError, match="cannot read"):
        registry.Registry(folder)


def test_an_agent_that_took_the_name_meanwhile_blocks_a_second_enrollment(tmp_path):
    reg = registry.Registry(tmp_path / "fleet")
    token = reg.issue_token("acme-hq")
    reg._agents["x"] = {"id": "x", "name": "acme-hq", "secret_hash": "", "scope": "", "scope_addresses": 0, "created": 1.0,
                        "last_seen": None, "revoked": False, "revoked_at": None}
    with pytest.raises(registry.RegistryError, match="already enrolled"):
        reg.enroll(token, "10.20.0.0/16")
