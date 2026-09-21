"""A Markdown report: readable in a terminal, a pull request or a wiki."""
from __future__ import annotations

from ..config import __version__
from ..findings import SEV_RANK
from ..i18n import t
from .common import base_meta, executive_summary, hosts_for_report, lang_of, md_escape as e, os_text


def markdown_text(meta: dict, hosts: list, lang=None) -> str:
    lang = lang_of(lang)
    shown = hosts_for_report(hosts, lang)
    info = base_meta(meta)

    def label(key, **kw):
        return t(key, lang=lang, **kw)

    out = [f"# {e(label('r_title'))}", "",
           f"## {e(label('r_exec'))}", "", e(executive_summary(meta, shown, lang)), "",
           f"## {e(label('r_meta'))}", "",
           f"- **{e(label('r_target'))}:** {e(info['target'])}",
           f"- **{e(label('r_date'))}:** {e(info['scan_time'])}",
           f"- **{e(label('r_duration'))}:** {info['duration']:.1f}s",
           f"- **{e(label('r_scanned'))}:** {info['ports_scanned']}"
           + (f" (UDP: {info['udp_ports_scanned']})" if info["udp_ports_scanned"] else ""),
           f"- **{e(label('r_tool'))}:** Nemla {e(__version__)}", ""]

    out += [f"## {e(label('r_findings'))}", ""]
    rows = sorted((f for h in shown for f in h["findings"] if f["severity"] != "info"),
                  key=lambda f: (-SEV_RANK[f["severity"]], f["host"], f["port"] or 0))
    if rows:
        out += [f"| {e(label('r_severity'))} | {e(label('r_host'))} | {e(label('r_port'))} | "
                f"{e(label('r_finding'))} | {e(label('r_confidence'))} | {e(label('r_evidence'))} | {e(label('r_remedy'))} |",
                "|---|---|---|---|---:|---|---|"]
        for f in rows:
            port = f"{f['port']}/{f['proto']}" if f["port"] else "-"
            out.append(f"| {e(label('sev_' + f['severity']))} | {e(f['host'])} | {e(port)} | {e(f['title'])} | "
                       f"{round(f['confidence'] * 100)}% | {e(f['evidence'])} | {e(f['remediation'])} |")
    else:
        out.append(e(label("r_no_findings")))
    out.append("")

    for host in shown:
        mac = f" ({e(host['mac'])}{', ' + e(host['vendor']) if host.get('vendor') else ''})" if host.get("mac") else ""
        out += [f"## {e(host['ip'])}{mac}", "", f"- **{e(label('r_os'))}:** {e(os_text(host, lang))}"]
        guess = host.get("os") if isinstance(host.get("os"), dict) else {}
        for line in guess.get("evidence", [])[:6]:
            out.append(f"  - {e(line)}")
        out.append("")
        if host.get("open_ports"):
            out += [f"| {e(label('r_port'))} | {e(label('r_state'))} | {e(label('r_service'))} | {e(label('r_product'))} | "
                    f"{e(label('r_confidence'))} | {e(label('r_banner'))} |", "|---|---|---|---|---:|---|"]
            for p in host["open_ports"]:
                product = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                conf = ""
                if p.get("confidence") is not None:
                    conf = f"{round(p['confidence'] * 100)}%" + (" ~" if p.get("heuristic") else "")
                out.append(f"| {p['port']}/{e(p.get('proto', 'tcp'))} | {e(p.get('state', 'open'))} | "
                           f"{e(p.get('service', ''))} | {e(product)} | {conf} | {e(p.get('banner', ''))} |")
            out.append("")
        else:
            out += [e(label("r_no_ports")), ""]
        if host.get("udp_unconfirmed"):
            out += [f"{e(label('r_udp_unconfirmed'))}: " + ", ".join(str(p["port"]) for p in host["udp_unconfirmed"]), ""]

    out += [f"## {e(label('r_warnings'))}", ""]
    if info["warnings"]:
        out += [f"- `{e(w['code'])}` {e(w['message'])}" + (f" (x{w['count']})" if w.get("count", 1) > 1 else "")
                for w in info["warnings"]]
    else:
        out.append(e(label("r_no_warnings")))
    out += ["", "---", e(label("r_footer", ver=__version__)), ""]
    return "\n".join(out)
