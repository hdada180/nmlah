"""The HTML report: one self-contained file (no scripts, no external requests).

Every value that came from a scan is HTML-escaped piece by piece, and the
template is filled in a single pass so that scan text can never be mistaken
for a placeholder.
"""
from __future__ import annotations

import re

from ..config import __version__
from ..findings import SEV_RANK, summarize_findings
from ..i18n import t
from .common import (base_meta, direction, executive_summary, hosts_for_report, html_escape as _e, lang_of, open_count,
                     os_of, os_text)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="@@LANG@@" dir="@@DIR@@">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Nemla @@VERSION@@">
<title>@@TITLE@@ - @@TARGET@@</title>
<style>
:root {
  --bg: #0a0c11; --panel: #10141c; --ant-orange: #ff7a1a;
  --ant-orange-dim: #b84400; --text: #eef0f6; --text-dim: #a2abbe;
  --border: #232a3b; --up: #3ee6b4;
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); margin: 0; padding: 0 0 60px;
  font-family: 'Segoe UI', Tahoma, Arial, sans-serif; }
header { background: radial-gradient(600px 220px at 0% 0%, rgba(255,122,26,.16), transparent 70%),
  linear-gradient(135deg, #141924, #0a0c11);
  border-bottom: 2px solid var(--ant-orange); padding: 28px 32px;
  display: flex; align-items: center; }
header .icon { width: 56px; height: 56px; margin: 0 16px; flex: none; }
header .icon svg, footer svg { width: 100%; height: 100%; display: block; }
footer svg { display: inline-block; width: 16px; height: 16px; vertical-align: -3px; }
header h1 { margin: 0; color: var(--ant-orange); font-size: 26px; }
header p { margin: 4px 0 0; color: var(--text-dim); font-size: 13px; }
.summary { display: flex; flex-wrap: wrap; padding: 16px 24px 0; }
.stat { background: var(--panel); border: 1px solid var(--border);
  border-radius: 10px; padding: 14px 20px; min-width: 140px; margin: 8px; }
.stat .num { font-size: 26px; font-weight: 700; color: var(--ant-orange); }
.stat .label { font-size: 12px; color: var(--text-dim); margin-top: 2px; }
.container { padding: 24px 32px; }
.exec { background: var(--panel); border: 1px solid var(--border); border-inline-start: 4px solid var(--ant-orange);
  border-radius: 10px; padding: 14px 20px; margin-bottom: 18px; font-size: 14px; line-height: 1.6; }
.exec h2, .section h2 { margin: 0 0 6px; font-size: 14px; color: var(--ant-orange); }
.host-card { background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; margin-bottom: 18px; overflow: hidden; }
.host-header { display: flex; justify-content: space-between; align-items: center;
  padding: 14px 20px; background: #141924; border-bottom: 1px solid var(--border);
  flex-wrap: wrap; }
.host-ip { font-size: 17px; font-weight: 700; direction: ltr; unicode-bidi: isolate; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 20px;
  font-size: 11px; font-weight: 600; margin: 0 4px 0 8px; }
.badge.up { background: rgba(111,207,111,.15); color: var(--up); border: 1px solid var(--up); }
.badge.os { background: rgba(255,140,0,.12); color: var(--ant-orange);
  border: 1px solid var(--ant-orange-dim); }
.host-meta { font-size: 12px; color: var(--text-dim); }
.evidence { list-style: none; margin: 0; padding: 10px 20px; border-bottom: 1px solid var(--border);
  color: var(--text-dim); font-size: 11px; font-family: monospace; direction: ltr; text-align: left; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: start; padding: 10px 20px; font-size: 13px; }
th { color: var(--text-dim); font-weight: 600; border-bottom: 1px solid var(--border); }
td { border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }
.port { color: var(--ant-orange); font-weight: 700; font-family: monospace; }
.banner { color: var(--text-dim); font-family: monospace; font-size: 11px;
  word-break: break-all; direction: ltr; unicode-bidi: isolate; text-align: left; }
.empty { padding: 16px 20px; color: var(--text-dim); font-size: 13px; }
.stat.warn .num { color: #ff5d8f; }
.product small, .conf { display: block; color: var(--text-dim); font-size: 11px; margin-top: 2px; }
.findings { list-style: none; margin: 0; padding: 14px 20px 16px; border-top: 1px solid var(--border);
  display: grid; gap: 12px; }
.findings li { display: grid; grid-template-columns: 78px 1fr; gap: 12px; align-items: start; font-size: 13px; }
.findings .why, .findings .fix, .findings .ev { color: var(--text-dim); font-size: 12px; margin-top: 3px; }
.findings .ev { font-family: monospace; direction: ltr; unicode-bidi: isolate; text-align: left; word-break: break-all; }
.sev { flex: none; min-width: 70px; text-align: center; padding: 2px 8px; border-radius: 6px;
  font-size: 11px; font-weight: 700; }
.sev-high .sev { background: rgba(255,93,143,.18); color: #ff5d8f; border: 1px solid rgba(255,93,143,.5); }
.sev-medium .sev { background: rgba(255,194,71,.16); color: #ffc247; border: 1px solid rgba(255,194,71,.5); }
.sev-low .sev { background: rgba(76,194,255,.14); color: #4cc2ff; border: 1px solid rgba(76,194,255,.45); }
.sev-info .sev { background: rgba(143,160,196,.14); color: #8fa0c4; border: 1px solid rgba(143,160,196,.4); }
.sev-info { color: var(--text-dim); }
.section { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 20px;
  margin-bottom: 18px; font-size: 13px; }
.section ul { margin: 6px 0 0; padding-inline-start: 20px; color: var(--text-dim); }
.section code { font-family: monospace; direction: ltr; unicode-bidi: isolate; }
footer { text-align: center; color: var(--text-dim); font-size: 12px; padding: 30px; }
</style>
</head>
<body>
<header>
  <div class="icon">@@MARK@@</div>
  <div>
    <h1>@@TITLE@@</h1>
    <p>@@L_TARGET@@: <bdi>@@TARGET@@</bdi> &nbsp;|&nbsp; @@L_DATE@@: <bdi>@@SCAN_TIME@@</bdi>
       &nbsp;|&nbsp; @@L_DURATION@@: <bdi>@@DURATION@@s</bdi></p>
  </div>
</header>
<div class="summary">
  <div class="stat"><div class="num">@@HOST_COUNT@@</div><div class="label">@@L_HOSTS@@</div></div>
  <div class="stat"><div class="num">@@OPEN_COUNT@@</div><div class="label">@@L_OPEN@@</div></div>
  <div class="stat"><div class="num">@@PORTS_SCANNED@@</div><div class="label">@@L_SCANNED@@</div></div>
  <div class="stat @@WARN@@"><div class="num">@@FINDING_COUNT@@</div><div class="label">@@L_FINDINGS@@</div></div>
</div>
<div class="container">
<div class="exec"><h2>@@L_EXEC@@</h2>@@EXEC@@</div>
@@HOST_CARDS@@
@@WARNINGS@@
</div>
<footer>@@MARK_SMALL@@ @@FOOTER@@</footer>
</body>
</html>
"""

# The Nemla mark (see nemla_ui/web/brand/nemla-mark.svg), inlined so reports stay one file.
BRAND_MARK = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" role="img" aria-label="Nemla">'
    '<defs><linearGradient id="nm-ember@@ID@@" x1="60" y1="20" x2="200" y2="228" gradientUnits="userSpaceOnUse">'
    '<stop offset="0" stop-color="#FFC46B"/><stop offset=".5" stop-color="#FF7A1A"/>'
    '<stop offset="1" stop-color="#E8460C"/></linearGradient></defs>'
    '<g fill="url(#nm-ember@@ID@@)"><ellipse cx="128" cy="62" rx="19" ry="17"/>'
    '<ellipse cx="128" cy="109" rx="16" ry="23"/>'
    '<path d="M128 138c22 0 34 20 34 40 0 24-14 42-34 46-20-4-34-22-34-46 0-20 12-40 34-40z"/>'
    '<circle cx="58" cy="104" r="7"/><circle cx="48" cy="144" r="7"/><circle cx="64" cy="190" r="7"/>'
    '<circle cx="198" cy="104" r="7"/><circle cx="208" cy="144" r="7"/><circle cx="192" cy="190" r="7"/>'
    '<circle cx="82" cy="24" r="6"/><circle cx="174" cy="24" r="6"/></g>'
    '<g fill="none" stroke="url(#nm-ember@@ID@@)" stroke-width="7" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M114 98 80 80 58 104M112 110 72 114 48 144M114 124 80 148 64 190"/>'
    '<path d="M142 98 176 80 198 104M144 110 184 114 208 144M142 124 176 148 192 190"/>'
    '<path d="M119 50 102 28 82 24M137 50 154 28 174 24" stroke-width="5.5"/></g></svg>'
)


def _product_cell(p: dict) -> str:
    name = " ".join(x for x in (p.get("product"), p.get("version")) if x)
    tls = p.get("tls") or {}
    tls_bits = [tls.get("version"), tls.get("subject"),
                ("-> " + tls["not_after"]) if tls.get("not_after") else None]
    small = " | ".join(x for x in (p.get("title"), " ".join(b for b in tls_bits if b)) if x)
    extra = f"<small>{_e(small)}</small>" if small else ""
    return f'<td class="product">{_e(name or "-")}{extra}</td>'


def _confidence_cell(p: dict, lang) -> str:
    if p.get("confidence") is None:
        return "<td>-</td>"
    text = f"{round(p['confidence'] * 100)}%"
    note = f'<span class="conf">{_e(t("r_est", lang=lang))}</span>' if p.get("heuristic") else ""
    return f"<td>{_e(text)}{note}</td>"


def _findings_html(host: dict, lang) -> str:
    items = []
    for f in sorted(host.get("findings", []), key=lambda f: (-SEV_RANK[f["severity"]], f["port"] or 0)):
        detail = ""
        if f["severity"] != "info":
            detail = (f'<div class="why">{_e(f["description"])}</div>'
                      f'<div class="fix"><b>{_e(t("r_remedy", lang=lang))}:</b> {_e(f["remediation"])}</div>')
        if f.get("evidence"):
            detail += (f'<div class="ev">{_e(t("r_evidence", lang=lang))}: {_e(f["evidence"])} '
                       f'({_e(t("r_confidence", lang=lang))} {round(f["confidence"] * 100)}%)</div>')
        items.append(f'<li class="sev-{_e(f["severity"])}"><span class="sev">{_e(t("sev_" + f["severity"], lang=lang))}</span>'
                     f'<div>{_e(f["title"])}{detail}</div></li>')
    return f'<ul class="findings">{"".join(items)}</ul>' if items else ""


def render_host_card(host: dict, lang=None) -> str:
    lang = lang_of(lang)
    if host["open_ports"]:
        rows = "\n".join(
            f'<tr><td class="port">{_e(p["port"])}/{_e(p.get("proto", "tcp"))}</td>'
            f'<td>{_e(p["service"])}</td>'
            f'{_product_cell(p)}{_confidence_cell(p, lang)}'
            f'<td class="banner">{_e(p["banner"] or "-")}</td></tr>'
            for p in host["open_ports"]
        )
        body = (
            '<div class="table-wrap"><table>'
            f'<tr><th>{_e(t("r_port", lang=lang))}</th><th>{_e(t("r_service", lang=lang))}</th>'
            f'<th>{_e(t("r_product", lang=lang))}</th><th>{_e(t("r_confidence", lang=lang))}</th>'
            f'<th>{_e(t("r_banner", lang=lang))}</th></tr>{rows}</table></div>'
        )
    else:
        body = f'<div class="empty">{_e(t("r_no_ports", lang=lang))}</div>'
    if host.get("udp_unconfirmed"):
        ports = ", ".join(str(p["port"]) for p in host["udp_unconfirmed"])
        body += f'<div class="empty">{_e(t("r_udp_unconfirmed", lang=lang))}: <code>{_e(ports)}</code></div>'
    body += _findings_html(host, lang)
    mac = f"MAC: {_e(host['mac'])}" if host.get("mac") else ""
    if mac and host.get("vendor"):
        mac += f" ({_e(host['vendor'])})"
    evidence = "".join(f"<li>{_e(line)}</li>" for line in os_of(host).get("evidence", [])[:6])
    evidence = f'<ul class="evidence">{evidence}</ul>' if evidence else ""
    return (
        '<div class="host-card"><div class="host-header"><div>'
        f'<span class="host-ip">{_e(host["ip"])}</span>'
        f'<span class="badge up">{_e(t("r_active", lang=lang))}</span>'
        f'<span class="badge os">{_e(os_text(host, lang))}</span>'
        f'</div><div class="host-meta">{mac}</div></div>{evidence}{body}</div>'
    )


def _warnings_html(warnings: list, lang) -> str:
    if warnings:
        items = "".join(f"<li><code>{_e(w['code'])}</code> {_e(w['message'])}"
                        + (f" (x{_e(w['count'])})" if w.get("count", 1) > 1 else "") + "</li>" for w in warnings)
    else:
        items = f"<li>{_e(t('r_no_warnings', lang=lang))}</li>"
    return f'<div class="section"><h2>{_e(t("r_warnings", lang=lang))}</h2><ul>{items}</ul></div>'


def render_html(meta: dict, hosts: list, lang=None) -> str:
    lang = lang_of(lang)
    shown = hosts_for_report(hosts, lang)
    info = base_meta(meta)
    cards = "\n".join(render_host_card(h, lang) for h in shown) or (
        f'<p class="empty">{_e(t("r_no_hosts", lang=lang))}</p>')
    counts = meta.get("findings") or summarize_findings(shown)
    values = {
        "LANG": lang, "DIR": direction(lang), "VERSION": _e(__version__),
        "FINDING_COUNT": str(counts["high"] + counts["medium"] + counts["low"]),
        "WARN": "warn" if counts["high"] else "",
        "L_FINDINGS": _e(t("r_findings", lang=lang)),
        "TITLE": _e(t("r_title", lang=lang)),
        "TARGET": _e(info["target"]), "SCAN_TIME": _e(info["scan_time"]),
        "DURATION": _e(f"{info['duration']:.1f}"),
        "HOST_COUNT": str(len(shown)), "OPEN_COUNT": str(open_count(shown)),
        "PORTS_SCANNED": str(info["ports_scanned"]),
        "L_TARGET": _e(t("r_target", lang=lang)), "L_DATE": _e(t("r_date", lang=lang)),
        "L_DURATION": _e(t("r_duration", lang=lang)), "L_HOSTS": _e(t("r_hosts", lang=lang)),
        "L_OPEN": _e(t("r_open", lang=lang)), "L_SCANNED": _e(t("r_scanned", lang=lang)),
        "L_EXEC": _e(t("r_exec", lang=lang)), "EXEC": _e(executive_summary(meta, shown, lang)),
        "FOOTER": _e(t("r_footer", lang=lang, ver=__version__)),
        "HOST_CARDS": cards,                                 # already escaped piece by piece
        "WARNINGS": _warnings_html(info["warnings"], lang),  # ditto
        "MARK": BRAND_MARK.replace("@@ID@@", "a"),           # fixed markup, no scan data
        "MARK_SMALL": BRAND_MARK.replace("@@ID@@", "b"),
    }
    # one pass, so text that came from a scanned host can never be treated as a placeholder
    return re.sub(r"@@([A-Z_]+)@@", lambda m: values.get(m.group(1), m.group(0)), HTML_TEMPLATE)
