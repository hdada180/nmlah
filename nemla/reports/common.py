"""What every report format shares: the data model and the escaping rules.

Everything that ends up in a report can come from a remote machine (banners,
page titles, certificate names, host names), so each format has its own
escaping: HTML entities, CSV formula guards, Markdown control characters.
"""
from __future__ import annotations

import html
import re

from ..findings import localized, summarize_findings
from ..i18n import RTL_LANGS, current_lang, t

SCHEMA_VERSION = 2


def lang_of(lang=None) -> str:
    return lang or current_lang()


def open_count(hosts: list) -> int:
    return sum(1 for h in hosts for p in h.get("open_ports", []) if p.get("state", "open") == "open")


def summary_numbers(meta: dict, hosts: list) -> dict:
    counts = meta.get("findings") or summarize_findings(hosts)
    return {"hosts": len(hosts), "open": open_count(hosts), "target": meta["target"],
            "high": counts.get("high", 0), "medium": counts.get("medium", 0), "low": counts.get("low", 0)}


def executive_summary(meta: dict, hosts: list, lang=None) -> str:
    return t("r_exec_text", lang=lang_of(lang), **summary_numbers(meta, hosts))


def os_of(host: dict) -> dict:
    """The structured OS guess of a host record (scans from older versions only have text)."""
    if isinstance(host.get("os"), dict):
        return host["os"]
    return {"name": host.get("os_guess", ""), "family": "unknown", "confidence": None, "label": "", "heuristic": True,
            "evidence": []}


def os_text(host: dict, lang=None) -> str:
    """'Ubuntu Linux - 72% (estimated)' or the plain text of an older scan."""
    guess = os_of(host)
    if guess.get("confidence") is None:
        return host.get("os_guess", "")
    name = guess.get("name") or host.get("os_guess", "")
    if guess.get("family") == "unknown":
        return name
    est = f", {t('r_est', lang=lang_of(lang))}" if guess.get("heuristic") else ""
    return f"{name} ({round(guess['confidence'] * 100)}%{est})"


def scrub(value):
    """Text that came from the network, made safe to print: control characters, terminal escapes and the
    invisible direction controls (which can reorder what is around them) become spaces.

    The scanner already cleans banners when it records them; this is the second line of defence for records
    that come from somewhere else (a history file, a hand-edited or older JSON)."""
    if isinstance(value, str):
        return value if value.isprintable() else "".join(ch if ch.isprintable() else " " for ch in value)
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    return value


def hosts_for_report(hosts: list, lang=None) -> list:
    """Copies of the host records, scrubbed, with findings rendered in the report language (those texts are ours:
    they keep the direction marks the translations use on purpose)."""
    out = []
    for host in hosts:
        copy = {key: scrub(value) for key, value in host.items() if key != "findings"}
        copy["findings"] = localized(host.get("findings", []), lang_of(lang))
        out.append(copy)
    return out


def base_meta(meta: dict) -> dict:
    return {
        "target": meta["target"], "scan_time": meta["scan_time"], "duration": meta.get("duration", 0.0),
        "ports_scanned": meta.get("ports_scanned", 0), "udp_ports_scanned": meta.get("udp_ports_scanned", 0),
        "warnings": meta.get("warnings", []), "options": meta.get("options", {}),
        "capabilities": meta.get("capabilities", {}), "cancelled": meta.get("cancelled", False),
        "scan_id": meta.get("scan_id"),
    }


# -- escaping ----------------------------------------------------------------

def html_escape(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


_FORMULA_START = re.compile(r"^[=+\-@\t\r]")


def csv_cell(value):
    """Guard a CSV cell against spreadsheet formula injection (=, +, -, @ at the start).

    A banner such as `=HYPERLINK(...)` would otherwise run when the file is opened in
    Excel. Numbers are left alone; text starting with a formula character gets a leading '.
    """
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    return "'" + text if _FORMULA_START.match(text) else text


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]#|~])")


def md_escape(value) -> str:
    """Escape Markdown control characters and flatten line breaks (safe inside table cells).

    `<`, `>` and `&` become HTML entities so that no renderer can ever see a tag; the other
    control characters get a backslash.
    """
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", text)


def direction(lang=None) -> str:
    return "rtl" if lang_of(lang) in RTL_LANGS else "ltr"

