"""Compatibility: the guard moved to nemla.guard; this name keeps working (same module object)."""
import sys

from nemla import guard as _guard

sys.modules[__name__] = _guard
