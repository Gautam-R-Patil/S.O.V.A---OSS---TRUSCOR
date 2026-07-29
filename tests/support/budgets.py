# SPDX-License-Identifier: Apache-2.0
"""Cross-platform subprocess performance and resource budgets."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class CommandBudget:
    """A minimal deterministic budget for a command invocation."""

    max_wall_seconds: float
    max_output_bytes: int


@dataclass(frozen=True, slots=True)
class CommandMeasurement:
    """Observed command result and bounded resources."""

    returncode: int
    wall_seconds: float
    stdout: bytes
    stderr: bytes

    @property
    def output_bytes(self) -> int:
        """Return the combined captured-output size."""
        return len(self.stdout) + len(self.stderr)


def run_with_budget(
    command: Sequence[str],
    budget: CommandBudget,
) -> CommandMeasurement:
    """Run a command once and fail if its wall-time or output budget is exceeded."""
    started = time.perf_counter()
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=budget.max_wall_seconds,
    )
    measurement = CommandMeasurement(
        returncode=result.returncode,
        wall_seconds=time.perf_counter() - started,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    if measurement.output_bytes > budget.max_output_bytes:
        message = (
            f"command emitted {measurement.output_bytes} bytes; budget is {budget.max_output_bytes}"
        )
        raise AssertionError(message)
    return measurement
