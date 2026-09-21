"""Console output, debug logging and the list of non-fatal problems of a scan."""
from __future__ import annotations

import logging
import threading
from datetime import datetime

logger = logging.getLogger("nemla")
logger.addHandler(logging.NullHandler())

_PRINT_LOCK = threading.Lock()
_LOG_SINK = None  # optional callable(str): the 3D interface mirrors log lines here


def clean_line(text) -> str:
    """One printable line: control characters (terminal escapes, bidi overrides) become spaces."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text)).strip()


def log(msg: str) -> None:
    line = clean_line(msg)
    with _PRINT_LOCK:
        try:
            print(f"[{datetime.now():%H:%M:%S}] {line}", flush=True)
        except (OSError, ValueError):  # no console (desktop launcher) or a closed stream
            pass
    sink = _LOG_SINK
    if sink is not None:
        sink(line)


def set_sink(sink) -> None:
    global _LOG_SINK  # noqa: PLW0603 - one process-wide sink (the web UI's ring buffer), swapped by the launcher
    _LOG_SINK = sink


def get_sink():
    return _LOG_SINK


def enable_debug() -> None:
    """Send the `nemla` debug log to stderr (the --verbose flag)."""
    if not any(getattr(h, "_nemla_debug", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler._nemla_debug = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s nemla: %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)


class Diagnostics:
    """Collects the non-fatal problems of one scan (a detector that crashed, a
    probe budget that ran out, ARP that came back incomplete...).

    They end up in the report as warnings instead of being swallowed, and
    identical problems are counted rather than repeated.
    """

    def __init__(self, limit: int = 50):
        self._lock = threading.Lock()
        self._items: dict = {}
        self._limit = limit

    def warn(self, code: str, message: str = "", **detail) -> None:
        logger.debug("%s: %s %s", code, message, detail or "")
        key = (code, message)
        with self._lock:
            item = self._items.get(key)
            if item is not None:
                item["count"] += 1
            elif len(self._items) < self._limit:
                self._items[key] = {"code": code, "message": clean_line(message)[:300],
                                    "count": 1, **{k: clean_line(v)[:120] for k, v in detail.items()}}

    def as_list(self) -> list:
        with self._lock:
            return sorted((dict(i) for i in self._items.values()), key=lambda i: (i["code"], i["message"]))

    def __len__(self) -> int:
        with self._lock:
            return sum(i["count"] for i in self._items.values())
