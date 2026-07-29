# SPDX-License-Identifier: Apache-2.0
"""Deterministic fault injection for recovery-path tests."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field


class InjectedFaultError(RuntimeError):
    """A deliberate, named test failure."""


@dataclass(slots=True)
class FaultPlan:
    """Raise at named checkpoints on predeclared visit counts."""

    fail_on: dict[str, frozenset[int]]
    _visits: Counter[str] = field(default_factory=Counter, init=False)

    def checkpoint(self, name: str) -> None:
        """Record a checkpoint and raise when its planned count is reached."""
        self._visits[name] += 1
        occurrence = self._visits[name]
        if occurrence in self.fail_on.get(name, frozenset()):
            message = f"injected fault at {name} occurrence {occurrence}"
            raise InjectedFaultError(message)

    def visits(self, name: str) -> int:
        """Return the number of visits made to a checkpoint."""
        return self._visits[name]
