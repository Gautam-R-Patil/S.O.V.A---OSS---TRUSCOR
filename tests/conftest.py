# SPDX-License-Identifier: Apache-2.0
"""Shared deterministic test controls."""

from __future__ import annotations

import os
import random
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

DEFAULT_TEST_SEED = 20_260_729


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the explicit SOVA test seed."""
    parser.addoption(
        "--sova-seed",
        action="store",
        default=os.environ.get("SOVA_TEST_SEED", str(DEFAULT_TEST_SEED)),
        help="Integer seed used by deterministic SOVA test fixtures.",
    )


@pytest.fixture(autouse=True)
def deterministic_random_seed(request: pytest.FixtureRequest) -> Generator[int]:
    """Reset Python's process-global pseudo-random generator for every test."""
    seed = int(request.config.getoption("--sova-seed"))
    previous_state = random.getstate()
    random.seed(seed)
    yield seed
    random.setstate(previous_state)


@pytest.fixture
def sova_seed(request: pytest.FixtureRequest) -> int:
    """Expose the active deterministic seed to tests that record it."""
    return int(request.config.getoption("--sova-seed"))
