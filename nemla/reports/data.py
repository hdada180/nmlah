"""Machine-readable reports: JSON (also what the history stores) and CSV."""
from __future__ import annotations

import csv
import io
import json

from ..config import __version__
from ..findings import summarize_findings
from .common import (SCHEMA_VERSION, base_meta, csv_cell, executive_summary, hosts_for_report, lang_of, open_count,
                     os_text)


def json_text(meta: dict, hosts: list, lang=None) -> str:
    """The full scan as JSON. Older keys are kept; `schema_version` 2 adds the rest."""
    lang = lang_of(lang)
    shown = hosts_for_report(hosts, lang)
    info = base_meta(meta)
    payload = {
        "tool": "nemla", "version": __version__, "schema_version": SCHEMA_VERSION,
        "scan_id": info["scan_id"], "target": info["target"], "scan_time": info["scan_time"],
        "saved_at": meta.get("saved_at"),
        "duration_seconds": round(info["duration"], 2),
        "ports_scanned_per_host": info["ports_scanned"],
        "udp_ports_scanned_per_host": info["udp_ports_scanned"],
        "cancelled": info["cancelled"], "language": lang,
        "options": info["options"], "capabilities": info["capabilities"],
        "summary": {"hosts": len(shown), "open_ports": open_count(shown),
                    "findings": meta.get("findings") or summarize_findings(shown),
                    "executive": executive_summary(meta, shown, lang)},
        "findings_summary": meta.get("findings") or summarize_findings(shown),
        "warnings": info["warnings"],
        "hosts": shown,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


CSV_COLUMNS = ["ip", "mac", "vendor", "os_guess", "ttl", "port", "service", "banner", "product", "version",
               "proto", "state", "confidence", "os_confidence"]


def csv_text(hosts: list, lang=None) -> str:
    """One row per open port. The first ten columns are the ones Nemla 1 wrote; new ones are appended."""
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for h in hosts:
        guess = h.get("os") if isinstance(h.get("os"), dict) else {}
        base = [h["ip"], h.get("mac") or "", h.get("vendor") or "", h.get("os_guess") or os_text(h, lang),
                h.get("ttl") or ""]
        base = [csv_cell(v) for v in base]
        tail = guess.get("confidence", "")
        if not h.get("open_ports"):
            writer.writerow([*base, "", "", "", "", "", "", "", "", tail])
        for p in h.get("open_ports", []):
            writer.writerow([*base[:5], p["port"], csv_cell(p.get("service", "")), csv_cell(p.get("banner", "")),
                             csv_cell(p.get("product", "")), csv_cell(p.get("version", "")),
                             p.get("proto", "tcp"), p.get("state", "open"), p.get("confidence", ""), tail])
    return buf.getvalue()
