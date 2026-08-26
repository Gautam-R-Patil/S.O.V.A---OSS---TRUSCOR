# SPDX-License-Identifier: Apache-2.0
"""Swarm-wide effect reservation and fail-closed aggregate ceilings."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import pytest

from sova.community.swarm.budget import SwarmAggregateBudget, SwarmBudgetLedger
from sova.executors import SideEffect
from sova.formats.errors import FormatError


def _document(*, actions: int = 2) -> dict[str, Any]:
    return {
        "budget": {
            "maxTotalActions": actions,
            "maxDurationSeconds": 30,
            "maxMutations": actions,
            "maxProcesses": actions,
            "maxFiles": actions,
            "maxNetworkRequests": actions,
        }
    }


def _reserve(ledger: SwarmBudgetLedger, index: int) -> bool:
    try:
        ledger.reserve(
            agent_id=f"agent-{index:02d}",
            phase="primary",
            request=SimpleNamespace(action="browser.click"),  # type: ignore[arg-type]
            binding=SimpleNamespace(side_effect=SideEffect.MUTATE),  # type: ignore[arg-type]
        )
    except FormatError:
        return False
    return True


def test_default_aggregate_budget_is_not_multiplied_by_agent_count() -> None:
    budget = SwarmAggregateBudget.from_chamber_document(_document(actions=3))
    assert budget.max_total_actions == 3
    assert budget.max_network_requests == 3


def test_concurrent_reservations_cannot_race_past_aggregate_ceiling() -> None:
    ledger = SwarmBudgetLedger(SwarmAggregateBudget.from_chamber_document(_document(actions=2)))
    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(lambda index: _reserve(ledger, index), range(8)))

    assert admitted.count(True) == 2
    assert admitted.count(False) == 6
    snapshot = ledger.snapshot()
    assert snapshot["consumed"]["totalActions"] == 2
    assert snapshot["consumed"]["networkRequests"] == 2
    assert snapshot["deniedReservations"] == 6
    assert snapshot["scope"] == "all-agents-primary-and-reproduction"


def test_zero_process_budget_rejects_before_dispatch() -> None:
    budget = SwarmAggregateBudget.from_chamber_document(_document(actions=1))
    budget = SwarmAggregateBudget(
        max_total_actions=budget.max_total_actions,
        max_duration_seconds=budget.max_duration_seconds,
        max_mutations=budget.max_mutations,
        max_processes=0,
        max_files=budget.max_files,
        max_network_requests=budget.max_network_requests,
    )
    ledger = SwarmBudgetLedger(budget)
    with pytest.raises(FormatError, match="effect budget"):
        ledger.reserve(
            agent_id="agent-01",
            phase="primary",
            request=SimpleNamespace(action="process.exec"),  # type: ignore[arg-type]
            binding=SimpleNamespace(side_effect=SideEffect.MUTATE),  # type: ignore[arg-type]
        )
    assert ledger.snapshot()["consumed"]["totalActions"] == 0


def test_computer_action_consumes_mutation_but_not_network_budget() -> None:
    document = _document(actions=1)
    document["budget"]["maxNetworkRequests"] = 0
    ledger = SwarmBudgetLedger(SwarmAggregateBudget.from_chamber_document(document))
    ledger.reserve(
        agent_id="agent-01",
        phase="primary",
        request=SimpleNamespace(action="computer.click"),  # type: ignore[arg-type]
        binding=SimpleNamespace(side_effect=SideEffect.MUTATE),  # type: ignore[arg-type]
    )
    snapshot = ledger.snapshot()
    assert snapshot["consumed"]["mutations"] == 1
    assert snapshot["consumed"]["networkRequests"] == 0
