"""Compatibility: saved scans moved to nemla.history; this name keeps working (same module object)."""
import sys

from nemla import history as _history

sys.modules[__name__] = _history
