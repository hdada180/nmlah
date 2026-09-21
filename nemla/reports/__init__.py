"""Reports: HTML, JSON, CSV, Markdown and SARIF from the same scan data."""
from __future__ import annotations

import os
import tempfile

from .common import csv_cell, html_escape, md_escape
from .data import CSV_COLUMNS, csv_text, json_text
from .html import BRAND_MARK, HTML_TEMPLATE, render_host_card, render_html
from .markdown import markdown_text
from .sarif import sarif_text

__all__ = ["BRAND_MARK", "CSV_COLUMNS", "FORMATS", "HTML_TEMPLATE", "csv_cell", "csv_text", "html_escape",
           "json_text", "markdown_text", "md_escape", "render_host_card", "render_html", "report_bytes", "sarif_text",
           "write_atomic", "write_csv", "write_json", "write_report"]

FORMATS = {
    "html": ("text/html; charset=utf-8", "html"),
    "json": ("application/json; charset=utf-8", "json"),
    "csv": ("text/csv; charset=utf-8", "csv"),
    "md": ("text/markdown; charset=utf-8", "md"),
    "sarif": ("application/sarif+json; charset=utf-8", "sarif"),
}


def report_bytes(fmt: str, meta: dict, hosts: list, lang=None) -> tuple:
    """(bytes, content_type, extension) of a report. Unknown formats fall back to HTML."""
    fmt = fmt if fmt in FORMATS else "html"
    if fmt == "json":
        text = json_text(meta, hosts, lang)
    elif fmt == "csv":
        text = csv_text(hosts, lang)
    elif fmt == "md":
        text = markdown_text(meta, hosts, lang)
    elif fmt == "sarif":
        text = sarif_text(meta, hosts, lang)
    else:
        text = render_html(meta, hosts, lang)
    content_type, ext = FORMATS[fmt]
    data = text.encode("utf-8-sig" if fmt == "csv" else "utf-8")  # the BOM makes Excel read UTF-8
    return data, content_type, ext


def write_atomic(path: str, data: bytes, mode: int = 0o644) -> None:
    """Write `data` to `path` through a temporary file in the same folder, then rename it into place.

    A crash or a full disk never leaves half a report behind, and the temporary file is
    created with a random name and 0600 permissions before it is renamed.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".nemla-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_report(path: str, fmt: str, meta: dict, hosts: list, lang=None) -> None:
    data, _, _ = report_bytes(fmt, meta, hosts, lang)
    write_atomic(path, data)


def write_json(path: str, meta: dict, hosts: list, lang=None) -> None:
    write_report(path, "json", meta, hosts, lang)


def write_csv(path: str, hosts: list, lang=None) -> None:
    write_atomic(path, csv_text(hosts, lang).encode("utf-8"))
