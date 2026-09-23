"""Reports: HTML, JSON, CSV, Markdown and SARIF from the same scan data."""
from __future__ import annotations

import os
import sys
import tempfile

from .common import csv_cell, html_escape, md_escape
from .data import CSV_COLUMNS, csv_text, json_text
from .html import BRAND_MARK, HTML_TEMPLATE, render_host_card, render_html
from .markdown import markdown_text
from .sarif import sarif_text

__all__ = ["BRAND_MARK", "CSV_COLUMNS", "FORMATS", "HTML_TEMPLATE", "PRIVATE_DIR", "PRIVATE_FILE", "csv_cell", "csv_text",
           "html_escape", "json_text", "markdown_text", "md_escape", "open_private_append", "render_host_card",
           "render_html", "report_bytes", "sarif_text", "write_atomic", "write_csv", "write_json", "write_report"]

# What a scan found (hosts, open ports, weaknesses) is sensitive: every file Nemla writes is readable by its owner only,
# and every folder it creates is entered by its owner only. (Windows keeps the profile's own access rules.)
PRIVATE_FILE = 0o600
PRIVATE_DIR = 0o700

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


def write_atomic(path: str, data: bytes, mode: int = PRIVATE_FILE) -> None:
    """Write `data` to `path` through a temporary file in the same folder, then rename it into place.

    A crash or a full disk never leaves half a report behind. The temporary file has a random name and is created
    with 0600 permissions, so the content is never readable by others, not even for a moment; `mode` is what the
    finished file gets (owner-only unless the caller asks for more). If `path` is a symbolic link, the link itself is
    replaced: nothing is ever written through it.
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


def open_private_append(path):
    """Open `path` for appending text, creating it owner-only (0600) - and tightening an older file that is not."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, PRIVATE_FILE)
    if sys.platform != "win32":
        try:
            if os.fstat(fd).st_mode & 0o077:
                os.fchmod(fd, PRIVATE_FILE)
        except OSError:
            pass
    return os.fdopen(fd, "a", encoding="utf-8")


def write_report(path: str, fmt: str, meta: dict, hosts: list, lang=None) -> None:
    data, _, _ = report_bytes(fmt, meta, hosts, lang)
    write_atomic(path, data)


def write_json(path: str, meta: dict, hosts: list, lang=None) -> None:
    write_report(path, "json", meta, hosts, lang)


def write_csv(path: str, hosts: list, lang=None) -> None:
    # utf-8-sig, matching report_bytes: the BOM makes Excel read UTF-8. Found by testing this wrapper directly -
    # it disagreed with what --csv (which goes through report_bytes) actually writes.
    write_atomic(path, csv_text(hosts, lang).encode("utf-8-sig"))
