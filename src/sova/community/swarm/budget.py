# SPDX-License-Identifier: Apache-2.0
"""One fail-closed effect budget shared by every worker in a SOVA swarm."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.executors import SideEffect
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.executors import ActionRequest
    from sova.runtime.unified_execution import CapabilityBinding


def _bounded_integer(value: object, *, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise FormatError(
            "SOVA-SWARM-AGGREGATE-BUDGET",
            f"{name} must be an integer greater than or equal to {minimum}",
        )
    return value


@dataclass(frozen=True, slots=True)
class SwarmAggregateBudget:
    """Operator ceiling across primary and reproduction effects from all agents."""

    max_total_actions: int
    max_duration_seconds: int
    max_mutations: int
    max_processes: int
    max_files: int
    max_network_requests: int

    def __post_init__(self) -> None:
        _bounded_integer(self.max_total_actions, name="maxTotalActions", minimum=1)
        _bounded_integer(self.max_duration_seconds, name="maxDurationSeconds", minimum=1)
        _bounded_integer(self.max_mutations, name="maxMutations", minimum=0)
        _bounded_integer(self.max_processes, name="maxProcesses", minimum=0)
        _bounded_integer(self.max_files, name="maxFiles", minimum=0)
        _bounded_integer(self.max_network_requests, name="maxNetworkRequests", minimum=0)

    @classmethod
    def from_chamber_document(cls, document: dict[str, Any]) -> SwarmAggregateBudget:
        """Default to the chamber's declared ceilings, never multiply by agent count."""
        budget = document.get("budget")
        if not isinstance(budget, dict):
            raise FormatError(
                "SOVA-SWARM-AGGREGATE-BUDGET",
                "swarm chamber template must declare a budget object",
            )
        fields = {
            "max_total_actions": ("maxTotalActions", 1),
            "max_duration_seconds": ("maxDurationSeconds", 1),
            "max_mutations": ("maxMutations", 0),
            "max_processes": ("maxProcesses", 0),
            "max_files": ("maxFiles", 0),
            "max_network_requests": ("maxNetworkRequests", 0),
        }
        values = {
            attribute: _bounded_integer(budget.get(key), name=key, minimum=minimum)
            for attribute, (key, minimum) in fields.items()
        }
        return cls(**values)

    def to_mapping(self) -> dict[str, int]:
        return {
            "maxTotalActions": self.max_total_actions,
            "maxDurationSeconds": self.max_duration_seconds,
            "maxMutations": self.max_mutations,
            "maxProcesses": self.max_processes,
            "maxFiles": self.max_files,
            "maxNetworkRequests": self.max_network_requests,
        }


class SwarmBudgetLedger:
    """Thread-safe reservation ledger checked before any worker executor dispatch."""

    def __init__(self, budget: SwarmAggregateBudget) -> None:
        if type(budget) is not SwarmAggregateBudget:
            raise FormatError(
                "SOVA-SWARM-AGGREGATE-BUDGET",
                "swarm budget ledger requires one exact aggregate budget",
            )
        self._budget = budget
        self._started = time.monotonic()
        self._lock = threading.Lock()
        self._consumed = {
            "totalActions": 0,
            "mutations": 0,
            "processes": 0,
            "files": 0,
            "networkRequests": 0,
        }
        self._denied_reservations = 0

    def reserve(
        self,
        *,
        agent_id: str,
        phase: str,
        request: ActionRequest,
        binding: CapabilityBinding,
    ) -> None:
        """Atomically reserve exact action cost or reject before authorization/execution."""
        if not agent_id or phase not in {"primary", "reproduction"}:
            raise FormatError(
                "SOVA-SWARM-AGGREGATE-BUDGET",
                "aggregate budget reservation identity is malformed",
            )
        cost = {
            "totalActions": 1,
            "mutations": int(binding.side_effect != SideEffect.READ),
            "processes": int(request.action.startswith("process.")),
            "files": int(request.action.startswith("filesystem.")),
            "networkRequests": int(request.action.startswith(("browser.", "network.", "api."))),
        }
        limits = {
            "totalActions": self._budget.max_total_actions,
            "mutations": self._budget.max_mutations,
            "processes": self._budget.max_processes,
            "files": self._budget.max_files,
            "networkRequests": self._budget.max_network_requests,
        }
        with self._lock:
            elapsed = time.monotonic() - self._started
            if elapsed >= self._budget.max_duration_seconds:
                self._denied_reservations += 1
                raise FormatError(
                    "SOVA-SWARM-AGGREGATE-BUDGET",
                    "swarm aggregate duration budget is exhausted",
                    details={
                        "agentId": agent_id,
                        "phase": phase,
                        "elapsedSeconds": elapsed,
                        "limit": self._budget.max_duration_seconds,
                    },
                )
            exceeded = next(
                (name for name in limits if self._consumed[name] + cost[name] > limits[name]),
                None,
            )
            if exceeded is not None:
                self._denied_reservations += 1
                raise FormatError(
                    "SOVA-SWARM-AGGREGATE-BUDGET",
                    "swarm aggregate effect budget is exhausted",
                    details={
                        "agentId": agent_id,
                        "phase": phase,
                        "dimension": exceeded,
                        "consumed": self._consumed[exceeded],
                        "requested": cost[exceeded],
                        "limit": limits[exceeded],
                    },
                )
            for name, amount in cost.items():
                self._consumed[name] += amount

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            consumed = dict(self._consumed)
            denied = self._denied_reservations
            elapsed_ms = max(0, int((time.monotonic() - self._started) * 1000))
        limits = self._budget.to_mapping()
        return {
            "contract": "sova.swarm-aggregate-budget/0.1.0",
            "limits": limits,
            "consumed": consumed,
            "remaining": {
                "totalActions": max(0, limits["maxTotalActions"] - consumed["totalActions"]),
                "mutations": max(0, limits["maxMutations"] - consumed["mutations"]),
                "processes": max(0, limits["maxProcesses"] - consumed["processes"]),
                "files": max(0, limits["maxFiles"] - consumed["files"]),
                "networkRequests": max(
                    0,
                    limits["maxNetworkRequests"] - consumed["networkRequests"],
                ),
            },
            "elapsedMs": elapsed_ms,
            "deniedReservations": denied,
            "scope": "all-agents-primary-and-reproduction",
        }


__all__ = ["SwarmAggregateBudget", "SwarmBudgetLedger"]
