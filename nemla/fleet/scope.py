"""An agent's scope: the addresses its owner allows it to scan.

The scope is set on the agent's own machine when it is enrolled, and the agent checks every job against it itself,
whatever the controller believes; the controller keeps a copy only to refuse an out-of-scope job early. A scope is
addresses, CIDR blocks and ranges (no names) and at most MAX_HOSTS_HARD addresses, so "everything" cannot be typed.
"""
from __future__ import annotations

from ..config import MAX_HOSTS_HARD
from ..targets import TargetSet, iter_targets
from .protocol import JobError, require_literal_targets


class ScopeError(ValueError):
    """A job reaches addresses outside a scope, or a scope is not usable."""


def parse_scope(spec) -> TargetSet:
    try:
        require_literal_targets(spec)
        return iter_targets(spec, MAX_HOSTS_HARD)
    except (JobError, ValueError) as err:
        raise ScopeError(str(err)) from None


def check_scope(target: TargetSet, scope: TargetSet) -> None:
    """Raise ScopeError unless every address of `target` is inside `scope`."""
    if not scope.contains_all(target):
        raise ScopeError("the job reaches addresses outside this agent's scope")
