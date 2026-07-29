# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for non-destructive finding lifecycle transitions."""

from __future__ import annotations

import pytest

from sova.contracts import (
    ContractError,
    LifecycleAxis,
    allowed_transitions,
    require_transition,
)


@pytest.mark.parametrize(
    ("axis", "source", "destination"),
    [
        (LifecycleAxis.EVIDENCE, "candidate", "observed"),
        (LifecycleAxis.EVIDENCE, "observed", "reproduced"),
        (LifecycleAxis.EVIDENCE, "reproduced", "verified"),
        (LifecycleAxis.DISCLOSURE, "confidential", "embargoed"),
        (LifecycleAxis.DISCLOSURE, "embargoed", "published"),
        (LifecycleAxis.REMEDIATION, "open", "fixed"),
        (LifecycleAxis.REMEDIATION, "fixed", "regressed"),
        (LifecycleAxis.ADJUDICATION, "scanner-disagreement", "resolved"),
        (LifecycleAxis.RECORD, "active", "superseded"),
    ],
)
def test_allowed_lifecycle_transitions(
    axis: LifecycleAxis,
    source: str,
    destination: str,
) -> None:
    require_transition(axis, source, destination)


@pytest.mark.parametrize(
    ("axis", "source", "destination"),
    [
        (LifecycleAxis.EVIDENCE, "verified", "candidate"),
        (LifecycleAxis.DISCLOSURE, "published", "confidential"),
        (LifecycleAxis.REMEDIATION, "fixed", "open"),
        (LifecycleAxis.RECORD, "superseded", "active"),
        (LifecycleAxis.EVIDENCE, "candidate", "published"),
    ],
)
def test_history_rewriting_and_cross_axis_transitions_fail(
    axis: LifecycleAxis,
    source: str,
    destination: str,
) -> None:
    with pytest.raises(ContractError) as caught:
        require_transition(axis, source, destination)
    assert caught.value.code == "SOVA-LIFECYCLE-ILLEGAL-TRANSITION"


def test_unknown_state_is_distinct_from_illegal_transition() -> None:
    with pytest.raises(ContractError) as caught:
        allowed_transitions(LifecycleAxis.EVIDENCE, "safe")
    assert caught.value.code == "SOVA-LIFECYCLE-UNKNOWN-STATE"
