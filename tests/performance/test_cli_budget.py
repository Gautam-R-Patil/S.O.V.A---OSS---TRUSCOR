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


def _budget(name: str) -> CommandBudget:
    data = tomllib.loads(Path(__file__).with_name("budgets.toml").read_text(encoding="utf-8"))
    raw_budget = cast("_BudgetData", data[name])
    return CommandBudget(
        max_wall_seconds=float(raw_budget["max_wall_seconds"]),
        max_output_bytes=int(raw_budget["max_output_bytes"]),
    )


@pytest.mark.performance
def test_map_representative_project_stays_below_cold_process_budget(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        '{"mcpServers":{"fixture":{"command":"fixture","tools":[{"name":"read"}]}}}',
        encoding="utf-8",
    )
    output = tmp_path / "map.json"
    budget = _budget("map_small_project")
    measurement = run_with_budget(
        [sys.executable, "-m", "sova", "map", str(project), "-o", str(output)],
        budget,
    )
    assert measurement.returncode == 0
    assert measurement.stderr == b""
    assert measurement.wall_seconds <= budget.max_wall_seconds
    assert output.is_file()


@pytest.mark.performance
def test_complete_demo_stays_within_bounded_run_budget(tmp_path: Path) -> None:
    budget = _budget("complete_demo")
    destination = tmp_path / "demo"
    measurement = run_with_budget(
        [sys.executable, "-m", "sova", "demo", "sleeper", str(destination)],
        budget,
    )
    assert measurement.returncode == 0
    assert measurement.stderr == b""
    assert measurement.wall_seconds <= budget.max_wall_seconds
    assert (destination / "demo-report.json").is_file()
