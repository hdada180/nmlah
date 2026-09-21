"""Translations (English, Arabic, Hebrew) and the active language.

`t(key, **values)` looks the text up in the language of the current scan
thread (see `use_lang`), then in the process-wide default (`_LANG`, which the
command line sets from --lang), then in English.
"""
from __future__ import annotations

import contextlib
import contextvars

from ._strings_base import STRINGS as _BASE
from .strings_extra import EXTRA

STRINGS = {lang: {**texts, **EXTRA.get(lang, {})} for lang, texts in _BASE.items()}
RTL_LANGS = {"ar", "he"}

_LANG = "en"
_CONTEXT_LANG = contextvars.ContextVar("nemla_lang", default=None)


def current_lang() -> str:
    lang = _CONTEXT_LANG.get() or _LANG
    return lang if lang in STRINGS else "en"


@contextlib.contextmanager
def use_lang(lang):
    """Make `lang` the language of this thread until the block ends (no global state touched)."""
    token = _CONTEXT_LANG.set(lang if lang in STRINGS else None)
    try:
        yield
    finally:
        _CONTEXT_LANG.reset(token)


def t(key: str, *, lang=None, **kw) -> str:
    """Translate `key`; unknown languages and missing keys fall back to English."""
    code = lang if lang in STRINGS else current_lang()
    text = STRINGS[code].get(key) or STRINGS["en"].get(key) or key
    if not kw:
        return text
    try:
        return text.format(**kw)
    except (KeyError, IndexError, ValueError):
        return text
