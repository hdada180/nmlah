"""The Fleet audit trail: one JSON line per event, append-only, owner-only, and never silently lost.

Every enrollment, revocation, dispatch (who asked for which target with which options), start, finish and refusal is
recorded. Secrets are redacted by key name before anything is written. A trail that cannot be written is an error
(`AuditError`), and the callers refuse the action instead of carrying on unrecorded. Files rotate to a timestamped
name when they grow past `max_bytes`; nothing is ever deleted or overwritten - keeping or archiving old files is the
operator's decision.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from ..reports import PRIVATE_DIR, open_private_append

_SECRET_KEY = re.compile(r"secret|token|password|passwd|authorization|api[_-]?key|private", re.I)
_MAX_TEXT = 400
_MAX_DEPTH = 6


class AuditError(OSError):
    """The audit trail could not be written."""


def redact(value, depth: int = 0):
    """`value` with anything under a secret-looking key replaced, long text cut, and nesting bounded."""
    if depth > _MAX_DEPTH:
        return "[too deep]"
    if isinstance(value, dict):
        return {str(k)[:60]: "[redacted]" if _SECRET_KEY.search(str(k)) else redact(v, depth + 1)
                for k, v in list(value.items())[:60]}
    if isinstance(value, (list, tuple)):
        return [redact(v, depth + 1) for v in list(value)[:60]]
    if isinstance(value, str):
        return value if len(value) <= _MAX_TEXT else value[:_MAX_TEXT] + "..."
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:_MAX_TEXT]


class AuditLog:
    def __init__(self, path, max_bytes: int = 8 * 1024 * 1024, clock=time.time):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._clock = clock
        self._lock = threading.Lock()

    def record(self, event: str, **fields) -> dict:
        """Append one event and return what was written. Raises AuditError if it cannot be written."""
        now = self._clock()
        entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)), "epoch": round(now, 3),
                 "event": str(event)[:60], **redact(fields)}
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            try:
                self.path.parent.mkdir(mode=PRIVATE_DIR, parents=True, exist_ok=True)
                self._rotate(now)
                with open_private_append(str(self.path)) as fh:
                    fh.write(line)
            except OSError as err:
                raise AuditError(f"cannot write the audit trail {self.path}: {err.strerror or err}") from None
        return entry

    def _rotate(self, now: float) -> None:
        try:
            if self.path.stat().st_size < self.max_bytes:
                return
        except FileNotFoundError:
            return
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
        target = self.path.with_name(f"{self.path.name}.{stamp}")
        counter = 0
        while target.exists():                      # two rotations in one second: never overwrite
            counter += 1
            target = self.path.with_name(f"{self.path.name}.{stamp}.{counter}")
        os.replace(self.path, target)

    def tail(self, count: int = 100) -> list:
        """The newest `count` entries of the current file, oldest first (unreadable lines are skipped)."""
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(0, count):]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                out.append(entry)
        return out
