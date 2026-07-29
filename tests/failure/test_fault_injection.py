# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the deterministic failure-injection harness."""

from __future__ import annotations

import pytest

from tests.support.faults import FaultPlan, InjectedFaultError


@pytest.mark.failure
def test_fault_occurs_only_at_declared_visit() -> None:
    plan = FaultPlan({"seal": frozenset({2})})

    plan.checkpoint("seal")
    with pytest.raises(InjectedFaultError, match="seal occurrence 2"):
        plan.checkpoint("seal")
    plan.checkpoint("seal")

    assert plan.visits("seal") == 3
