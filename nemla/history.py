"""Saved scans: the memory behind "what changed since last time".

Every finished scan is written as a JSON file (the same format as --json)
under the Nemla data folder and gets a random UUID as its id. The newest ones
are kept. Ids are validated before they touch the file system, files are
written atomically with private permissions, and oversized files are refused.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .reports import PRIVATE_DIR, PRIVATE_FILE
from .reports.data import json_text

KEEP = 60
MAX_FILE = 32 * 1024 * 1024
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_LEGACY = r"\d{8}-\d{6}-[A-Za-z0-9._-]{1,80}"          # ids written by Nemla 1.x
ID_RE = re.compile(rf"^(?:{_UUID}|{_LEGACY})$")
_UUID_RE = re.compile(rf"^{_UUID}$")


_clock = {"last": 0.0}
_clock_lock = threading.Lock()


def _stamp() -> float:
    """The time a scan is saved, strictly later than the previous stamp of this process: on Windows with Python before
    3.11 the clock ticks about every 15 ms, so two scans saved in a row shared one time and their order was lost."""
    with _clock_lock:
        now = time.time()
        if now <= _clock["last"]:
            now = _clock["last"] + 1e-6
        _clock["last"] = now
        return now


def folder(data_dir) -> Path:
    return Path(data_dir) / "history"


def valid_id(scan_id) -> bool:
    return isinstance(scan_id, str) and bool(ID_RE.match(scan_id))


def save(data_dir, engine, meta: dict, hosts: list) -> str:
    """Store a scan and return its id (a UUID). `engine` is accepted for older callers and unused."""
    directory = folder(data_dir)
    directory.mkdir(mode=PRIVATE_DIR, parents=True, exist_ok=True)
    try:
        os.chmod(directory, PRIVATE_DIR)
    except OSError:
        pass
    scan_id = meta.get("scan_id")
    if not (isinstance(scan_id, str) and _UUID_RE.match(scan_id)) or (directory / f"{scan_id}.json").exists():
        scan_id = str(uuid.uuid4())   # the scan's own id when it has a fresh one, else a new one
    stored = dict(meta, scan_id=scan_id, saved_at=_stamp())
    fd, tmp = tempfile.mkstemp(prefix=".scan-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json_text(stored, hosts))
        try:
            os.chmod(tmp, PRIVATE_FILE)
        except OSError:
            pass
        os.replace(tmp, directory / f"{scan_id}.json")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    prune(directory)
    return scan_id


def _saved_at(path: Path, data: dict) -> float:
    value = data.get("saved_at")
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def prune(directory, keep: int = KEEP) -> None:
    files = []
    for path in Path(directory).glob("*.json"):
        try:
            files.append((path.stat().st_mtime, path))
        except OSError:
            continue
    for _, old in sorted(files)[:-keep] if keep else sorted(files):
        try:
            old.unlink()
        except OSError:
            pass


def _read(path: Path):
    try:
        if path.stat().st_size > MAX_FILE:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):   # RecursionError: JSON nested thousands of levels deep
        return None
    return data if isinstance(data, dict) and isinstance(data.get("hosts"), list) else None


def _entries(data_dir) -> list:
    """[(saved_at, id, data)] for every readable saved scan, newest first."""
    found = []
    for path in folder(data_dir).glob("*.json"):
        if not valid_id(path.stem):
            continue
        data = _read(path)
        if data is not None:
            found.append((_saved_at(path, data), path.stem, data))
    return sorted(found, key=lambda e: e[0], reverse=True)


def list_scans(data_dir, limit: int = 30) -> list:
    """Summaries of the newest saved scans, newest first."""
    out = []
    for _saved, scan_id, data in _entries(data_dir)[:limit]:
        out.append({
            "id": scan_id, "target": data.get("target", ""), "scan_time": data.get("scan_time", ""),
            "hosts": len(data["hosts"]),
            "open_ports": sum(len(h.get("open_ports", [])) for h in data["hosts"]),
            "findings": data.get("findings_summary") or {},
        })
    return out


def load(data_dir, scan_id):
    """A saved scan by id, or None (also for anything that is not a valid id)."""
    if not valid_id(scan_id):
        return None
    root = folder(data_dir).resolve()
    path = (root / f"{scan_id}.json").resolve()
    if path.parent != root:                      # defence in depth: never leave the history folder
        return None
    return _read(path)


def previous_for(data_dir, target: str, before_id: str):
    """Id of the newest saved scan of `target` that is older than scan `before_id`.

    If `before_id` is not a saved scan (or is a placeholder such as '99999999-999999-~'),
    the newest scan of `target` is returned.
    """
    entries = _entries(data_dir)
    limit = next((saved for saved, scan_id, _ in entries if scan_id == before_id), float("inf"))
    for saved, scan_id, data in entries:
        if saved < limit and scan_id != before_id and data.get("target") == target:
            return scan_id
    return None


def meta_of(data: dict) -> dict:
    """The scan metadata (as `run_scan` returns it) of a saved scan, for re-rendering its reports."""
    return {
        "target": data.get("target", ""), "scan_time": data.get("scan_time", ""),
        "duration": data.get("duration_seconds", 0.0), "ports_scanned": data.get("ports_scanned_per_host", 0),
        "udp_ports_scanned": data.get("udp_ports_scanned_per_host", 0),
        "findings": data.get("findings_summary") or {}, "warnings": data.get("warnings", []),
        "options": data.get("options", {}), "capabilities": data.get("capabilities", {}),
        "scan_id": data.get("scan_id"), "cancelled": data.get("cancelled", False),
    }
