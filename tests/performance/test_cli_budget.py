# SPDX-License-Identifier: Apache-2.0
"""Performance-budget smoke tests."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import TypedDict, cast

import pytest

from tests.support.budgets import CommandBudget, run_with_budget


class _BudgetData(TypedDict):
    max_wall_seconds: float
    max_output_bytes: int


@pytest.mark.performance
def test_version_command_stays_within_bootstrap_budget() -> None:
    budget_path = Path(__file__).with_name("budgets.toml")
    data = tomllib.loads(budget_path.read_text(encoding="utf-8"))
    raw_budget = cast("_BudgetData", data["cli_version"])
    budget = CommandBudget(
        max_wall_seconds=float(raw_budget["max_wall_seconds"]),
        max_output_bytes=int(raw_budget["max_output_bytes"]),
    )

    measurement = run_with_budget(
        [sys.executable, "-m", "sova", "--version"],
        budget,
    )

    assert measurement.returncode == 0
    assert measurement.stderr == b""
    assert measurement.wall_seconds <= budget.max_wall_seconds
