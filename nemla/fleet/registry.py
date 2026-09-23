"""The controller's memory of its agents: who is enrolled, with what scope, and who has been revoked.

Two small files under the Fleet folder (owner-only): `agents.json` and `enrollment.json`. A secret is never stored,
only its SHA-256; an enrollment token is single-use and expires. A registry file that exists but cannot be read is an
error, never an empty registry - otherwise a damaged file would quietly un-revoke an agent.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from ..reports import PRIVATE_DIR, write_atomic
from .protocol import MAX_AGENTS, NAME, hash_secret, new_secret, secret_matches
from .scope import ScopeError, parse_scope

TOKEN_TTL = 900                     # seconds an enrollment token stays valid
_TOUCH_EVERY = 30                   # seconds between writes of an agent's last-seen time
_DUMMY_HASH = hash_secret("no such agent")


class RegistryError(ValueError):
    """A registry operation that is refused (bad name, expired token, damaged file...)."""


def _public(agent: dict) -> dict:
    return {k: agent.get(k) for k in ("id", "name", "scope", "scope_addresses", "created", "last_seen", "revoked",
                                      "revoked_at", "agent_version", "hostname")}


class Registry:
    def __init__(self, folder, clock=time.time):
        self.folder = Path(folder)
        self._clock = clock
        self._lock = threading.RLock()
        self.folder.mkdir(mode=PRIVATE_DIR, parents=True, exist_ok=True)
        self._agents_path = self.folder / "agents.json"
        self._tokens_path = self.folder / "enrollment.json"
        self._agents = self._load(self._agents_path, "agents")
        self._tokens = self._load(self._tokens_path, "tokens")
        self._saved_seen = self._clock()

    @staticmethod
    def _load(path: Path, key: str) -> dict:
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as err:
            raise RegistryError(f"cannot read {path}: {err.strerror or err}") from None
        try:
            data = json.loads(raw)
            table = data[key]
        except (ValueError, KeyError, TypeError, RecursionError):
            raise RegistryError(f"{path} is damaged; refusing to start with an empty registry") from None
        if not isinstance(table, dict):
            raise RegistryError(f"{path} is damaged; refusing to start with an empty registry")
        return table

    def _save(self, path: Path, key: str, table: dict) -> None:
        write_atomic(str(path), json.dumps({"version": 1, key: table}, indent=1, sort_keys=True).encode("utf-8"))

    # -- enrollment ----------------------------------------------------------------------------------------------

    def _purge_tokens(self) -> None:
        now = self._clock()
        for key in [k for k, v in self._tokens.items() if v.get("expires", 0) <= now]:
            del self._tokens[key]

    def _active(self) -> list:
        return [a for a in self._agents.values() if not a.get("revoked")]

    def issue_token(self, name: str, operator: str = "", ttl: int = TOKEN_TTL) -> str:
        """A one-time enrollment token for a new agent called `name`. The token is returned once and stored hashed."""
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise RegistryError("an agent name is 1-64 letters, digits, dots, dashes or underscores")
        with self._lock:
            self._purge_tokens()
            if any(a["name"] == name for a in self._active()):
                raise RegistryError(f"an agent called {name} is already enrolled (revoke it first)")
            for key in [k for k, v in self._tokens.items() if v.get("name") == name]:
                del self._tokens[key]               # one pending token per name: the newest replaces the older
            if len(self._active()) + len(self._tokens) >= MAX_AGENTS:
                raise RegistryError(f"at most {MAX_AGENTS} agents (and pending enrollments) are supported")
            token = new_secret()
            self._tokens[hash_secret(token)] = {"name": name, "expires": self._clock() + max(1, int(ttl)),
                                                "operator": str(operator)[:60]}
            self._save(self._tokens_path, "tokens", self._tokens)
            return token

    def enroll(self, token: str, scope_spec: str, agent_version: str = "", hostname: str = "") -> tuple:
        """Exchange a valid token for an agent: returns (public record, secret). The token is consumed."""
        try:
            scope = parse_scope(scope_spec)
        except ScopeError as err:
            raise RegistryError(f"the agent's scope is not usable: {err}") from None
        if not isinstance(token, str) or not token:
            raise RegistryError("invalid enrollment token")
        with self._lock:
            self._purge_tokens()
            pending = self._tokens.pop(hash_secret(token), None)
            if pending is None:
                raise RegistryError("invalid enrollment token")
            self._save(self._tokens_path, "tokens", self._tokens)        # spent even if what follows fails
            if any(a["name"] == pending["name"] for a in self._active()):
                raise RegistryError(f"an agent called {pending['name']} is already enrolled")
            secret = new_secret()
            now = self._clock()
            agent_id = hash_secret(secret + str(now))[:16]
            self._agents[agent_id] = {
                "id": agent_id, "name": pending["name"], "secret_hash": hash_secret(secret), "scope": scope_spec.strip(),
                "scope_addresses": scope.count(), "created": now, "last_seen": None, "revoked": False,
                "revoked_at": None, "agent_version": str(agent_version)[:40], "hostname": str(hostname)[:80]}
            self._save(self._agents_path, "agents", self._agents)
            return _public(self._agents[agent_id]), secret

    # -- who is who ----------------------------------------------------------------------------------------------

    def authenticate(self, agent_id, secret):
        """The agent's record when the id and secret match and it is not revoked, else None (constant-time)."""
        with self._lock:
            agent = self._agents.get(agent_id) if isinstance(agent_id, str) else None
            stored = agent["secret_hash"] if agent else _DUMMY_HASH
            ok = isinstance(secret, str) and secret_matches(secret, stored)
            if agent is None or not ok or agent.get("revoked"):
                return None
            return dict(agent)

    def touch(self, agent_id: str) -> None:
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent is None:
                return
            now = self._clock()
            agent["last_seen"] = now
            if now - self._saved_seen >= _TOUCH_EVERY:
                self._saved_seen = now
                self._save(self._agents_path, "agents", self._agents)

    def revoke(self, ref: str):
        """Revoke the agent with this id or name; returns its public record, or None if there is no such agent."""
        with self._lock:
            for agent in self._agents.values():
                if ref in (agent["id"], agent["name"]) and not agent.get("revoked"):
                    agent["revoked"], agent["revoked_at"] = True, self._clock()
                    self._save(self._agents_path, "agents", self._agents)
                    return _public(agent)
            return None

    def get(self, ref: str):
        """The public record of the newest agent with this id or name (revoked ones included), or None."""
        with self._lock:
            found = [a for a in self._agents.values() if ref in (a["id"], a["name"])]
            return _public(max(found, key=lambda a: a["created"])) if found else None

    def agents(self) -> list:
        with self._lock:
            return [_public(a) for a in sorted(self._agents.values(), key=lambda a: (a["created"], a["name"]))]

    def scope_of(self, agent_id: str) -> str:
        with self._lock:
            agent = self._agents.get(agent_id)
            return agent["scope"] if agent else ""
