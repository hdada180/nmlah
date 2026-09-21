"""What changed between two scans of the same target.

Reported: new and vanished hosts, ports that opened or closed (TCP and UDP),
services whose product, version or protocol changed, a different operating
system family, and findings that appeared or were resolved. Scans saved by
older versions (no `proto`, no structured OS) compare fine.
"""
from __future__ import annotations

import re

from .findings import finding_text
from .i18n import STRINGS, t
from .net import ip_sort_key


def _key(port: dict) -> tuple:
    return (port.get("proto", "tcp"), port["port"])


def _label(key: tuple):
    proto, number = key
    return number if proto == "tcp" else f"{number}/{proto}"


def _product_label(port: dict) -> str:
    return " ".join(x for x in (port.get("product"), port.get("version")) if x)


def _os_core(text) -> str:
    return re.sub(r"\s*\(TTL=\d+\)", "", text or "").strip()


def _os_identity(host: dict):
    """(family, name) of a host's OS guess, or None when there is nothing solid to compare."""
    guess = host.get("os")
    unknown = {STRINGS[lang][key] for lang in STRINGS for key in ("os_unknown", "os_skipped")}
    if isinstance(guess, dict) and guess.get("family") not in (None, "unknown"):
        return guess["family"], guess.get("name", "")
    text = _os_core(host.get("os_guess"))
    return (None, text) if text and text not in unknown else None


def _finding_keys(host: dict) -> dict:
    """{(id, port, proto): finding} for the findings that matter (everything above 'info')."""
    return {(f["id"], f.get("port"), f.get("proto", "tcp")): f
            for f in host.get("findings", []) if f["severity"] != "info"}


def _service_changes(old: dict, new: dict) -> list:
    changes = []
    for key in sorted(old.keys() & new.keys(), key=lambda k: (k[0], k[1])):
        o, n = old[key], new[key]
        before, after = _product_label(o), _product_label(n)
        if o.get("product") and n.get("product") and before != after:
            kind = "product" if o["product"] != n["product"] else "version"
        elif (o.get("detected") and n.get("detected") and o["detected"] != n["detected"]
              and not o.get("heuristic") and not n.get("heuristic")):
            kind, before, after = "service", o.get("service", ""), n.get("service", "")
        else:
            continue
        changes.append({"port": _label(key), "from": before, "to": after, "kind": kind})
    return changes


def diff_scans(old_hosts: list, new_hosts: list) -> dict:
    """Compare two scans of the same target."""
    old = {h["ip"]: h for h in old_hosts}
    new = {h["ip"]: h for h in new_hosts}
    out = {"new_hosts": sorted(new.keys() - old.keys(), key=ip_sort_key),
           "gone_hosts": sorted(old.keys() - new.keys(), key=ip_sort_key), "hosts": {}}
    new_findings = sum(len(_finding_keys(new[ip])) for ip in out["new_hosts"])
    opened = closed = changed = resolved = os_changes = 0
    order = lambda key: (key[1] or 0, key[0])  # noqa: E731
    for ip in sorted(old.keys() & new.keys(), key=ip_sort_key):
        o, n = old[ip], new[ip]
        op = {_key(p): p for p in o.get("open_ports", []) if p.get("state", "open") == "open"}
        np_ = {_key(p): p for p in n.get("open_ports", []) if p.get("state", "open") == "open"}
        entry = {
            "opened": [_label(k) for k in sorted(np_.keys() - op.keys())],
            "closed": [_label(k) for k in sorted(op.keys() - np_.keys())],
            "changed": _service_changes(op, np_),
            "os": None,
        }
        before, after = _os_identity(o), _os_identity(n)
        if before and after and before != after and (before[0] != after[0] or before[0] is None):
            entry["os"] = {"from": before[1], "to": after[1]}
        ok, nk = _finding_keys(o), _finding_keys(n)
        entry["new_findings"] = [nk[k] for k in sorted(nk.keys() - ok.keys(), key=order)]
        entry["resolved_findings"] = [ok[k] for k in sorted(ok.keys() - nk.keys(), key=order)]
        if any(entry.values()):
            out["hosts"][ip] = entry
            opened += len(entry["opened"])
            closed += len(entry["closed"])
            changed += len(entry["changed"])
            os_changes += 1 if entry["os"] else 0
            new_findings += len(entry["new_findings"])
            resolved += len(entry["resolved_findings"])
    out["summary"] = {
        "new_hosts": len(out["new_hosts"]), "gone_hosts": len(out["gone_hosts"]),
        "opened_ports": opened, "closed_ports": closed, "changed_services": changed, "os_changes": os_changes,
        "new_findings": new_findings, "resolved_findings": resolved,
    }
    # "worse" means something appeared: a host, an open port or a finding
    out["summary"]["worse"] = bool(out["summary"]["new_hosts"] or opened or new_findings)
    out["summary"]["changed"] = bool(out["new_hosts"] or out["gone_hosts"] or out["hosts"])
    return out


def diff_lines(diff: dict) -> list:
    """The changes as sentences in the active language."""
    if not diff["summary"]["changed"]:
        return [t("d_none")]
    lines = [t("d_summary", **{k: diff["summary"][k] for k in (
        "new_hosts", "gone_hosts", "opened_ports", "closed_ports", "new_findings")})]
    lines += [t("d_new_host", ip=ip) for ip in diff["new_hosts"]]
    lines += [t("d_gone_host", ip=ip) for ip in diff["gone_hosts"]]
    for ip, e in diff["hosts"].items():
        lines += [t("d_opened", ip=ip, port=p) for p in e["opened"]]
        lines += [t("d_closed", ip=ip, port=p) for p in e["closed"]]
        lines += [t("d_service", ip=ip, port=c["port"], old=c["from"], new=c["to"]) for c in e["changed"]]
        if e["os"]:
            lines.append(t("d_os", ip=ip, old=e["os"]["from"], new=e["os"]["to"]))
        for kind, key in (("new_findings", "d_new_finding"), ("resolved_findings", "d_resolved")):
            lines += [t(key, ip=ip, sev=t("sev_" + f["severity"]), text=finding_text(f)) for f in e[kind]]
    return lines
