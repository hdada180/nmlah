"""SARIF 2.1.0 output, for GitHub code scanning, DefectDojo and other security dashboards."""
from __future__ import annotations

import json

from ..config import __version__
from ..findings import SEV_RANK
from .common import hosts_for_report, lang_of

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}


def _uri(host: str, port, proto: str) -> str:
    bracket = f"[{host}]" if ":" in host else host
    return f"{proto}://{bracket}:{port}" if port else f"host://{bracket}"


def sarif_text(meta: dict, hosts: list, lang=None) -> str:
    """The findings of a scan as a SARIF 2.1.0 log (one run, one result per finding)."""
    shown = hosts_for_report(hosts, lang_of(lang))
    rules, results = {}, []
    for host in shown:
        for f in host["findings"]:
            rules.setdefault(f["id"], {
                "id": f["id"], "name": f["id"], "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["description"]}, "help": {"text": f["remediation"]},
                "defaultConfiguration": {"level": _LEVEL[f["severity"]]},
                "properties": {"tags": ["network", "nemla"], "security-severity": _SECURITY_SEVERITY[f["severity"]]},
            })
            results.append({
                "ruleId": f["id"], "level": _LEVEL[f["severity"]],
                "message": {"text": f"{f['title']} Evidence: {f['evidence']}" if f["evidence"] else f["title"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(f["host"], f["port"], f["proto"])}},
                               "logicalLocations": [{"name": f"{f['host']}:{f['port']}/{f['proto']}" if f["port"] else f["host"],
                                                     "kind": "resource"}]}],
                "properties": {"host": f["host"], "port": f["port"], "protocol": f["proto"], "severity": f["severity"],
                               "confidence": f["confidence"], "evidence": f["evidence"], "remediation": f["remediation"]},
                "partialFingerprints": {"nemla/v1": f"{f['id']}|{f['host']}|{f['port']}|{f['proto']}"},
            })
    results.sort(key=lambda r: (-SEV_RANK[r["properties"]["severity"]], r["properties"]["host"], r["properties"]["port"] or 0))
    log = {
        "$schema": SARIF_SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Nemla", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/hdada180/nmlah",
                                "rules": sorted(rules.values(), key=lambda r: r["id"])}},
            "invocations": [{"executionSuccessful": not meta.get("cancelled", False),
                             "commandLine": f"nemla -t {meta['target']}"}],
            "results": results,
        }],
    }
    return json.dumps(log, ensure_ascii=False, indent=2)
