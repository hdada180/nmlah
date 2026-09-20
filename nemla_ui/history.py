"""Saved scans: the memory behind "what changed since last time".

Every finished scan is written as a JSON file (the same format as --json)
under the Nemla data folder, and the newest ones are kept.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

KEEP = 60
ID_RE = re.compile(r"^\d{8}-\d{6}-[A-Za-z0-9._-]{1,80}$")


def folder(data_dir) -> Path:
    return Path(data_dir) / "history"


def save(data_dir, engine, meta: dict, hosts: list) -> str:
    """Store a scan and return its id (timestamp plus the target)."""
    directory = folder(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", meta["target"]).strip("._-")[:60] or "scan"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    scan_id, n = f"{stamp}-{slug}", 1
    while (directory / f"{scan_id}.json").exists():
        n += 1
        scan_id = f"{stamp}-{slug}-{n}"
    (directory / f"{scan_id}.json").write_text(engine.json_text(meta, hosts), encoding="utf-8")
    prune(directory)
    return scan_id


def prune(directory, keep: int = KEEP) -> None:
    for old in sorted(Path(directory).glob("*.json"))[:-keep]:
        try:
            old.unlink()
        except OSError:
            pass


def _read(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("hosts"), list) else None


def list_scans(data_dir, limit: int = 30) -> list:
    """Summaries of the newest saved scans, newest first."""
    found = []
    for path in sorted(folder(data_dir).glob("*.json"), reverse=True)[:limit]:
        data = _read(path)
        if data is None:
            continue
        found.append({
            "id": path.stem, "target": data.get("target", ""), "scan_time": data.get("scan_time", ""),
            "hosts": len(data["hosts"]),
            "open_ports": sum(len(h.get("open_ports", [])) for h in data["hosts"]),
            "findings": data.get("findings_summary") or {},
        })
    return found


def load(data_dir, scan_id):
    """A saved scan by id, or None (also for anything that is not a valid id)."""
    if not ID_RE.match(scan_id or ""):
        return None
    return _read(folder(data_dir) / f"{scan_id}.json")


def previous_for(data_dir, target: str, before_id: str):
    """Id of the newest saved scan of `target` that is older than `before_id`, or None."""
    for path in sorted(folder(data_dir).glob("*.json"), reverse=True):
        if path.stem < before_id:
            data = _read(path)
            if data and data.get("target") == target:
                return path.stem
    return None
