# SPDX-License-Identifier: Apache-2.0
"""P6 preregistration contract tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sova.formats import FormatError, validate_document
from sova.validation import EvaluationBudget, EvaluationLane, LaneKind
from tests.support.p6 import digest, protocol


def test_p6_protocol_is_complete_digest_bound_and_schema_valid() -> None:
    plan = protocol()
    validate_document(plan.to_mapping())
    assert plan.run_count == 32
    assert len(plan.targets) == 8
    assert len(plan.digest) == 71
    assert plan.to_mapping()["answerKeyEmbedded"] is False
    assert plan.to_mapping()["negativeResultsRetained"] is True


def test_p6_budget_and_lane_reject_invalid_values() -> None:
    with pytest.raises(FormatError, match="positive"):
        EvaluationBudget(0, 1, 1, 1, 0)
    with pytest.raises(FormatError, match="cost"):
        EvaluationBudget(1, 1, 1, 1, -1)
    with pytest.raises(FormatError, match="identity"):
        EvaluationLane("", LaneKind.CANDIDATE, "p", "m", "h", digest("config"))
    with pytest.raises(FormatError, match="SHA-256"):
        EvaluationLane("id", LaneKind.CANDIDATE, "p", "m", "h", "bad")
    with pytest.raises(FormatError, match="SHA-256"):
        EvaluationLane("id", LaneKind.CANDIDATE, "p", "m", "h", "sha256:" + ("z" * 64))


def test_p6_protocol_rejects_scope_lane_provider_metric_and_budget_drift() -> None:
    plan = protocol()
    with pytest.raises(FormatError):
        replace(plan, targets=plan.targets[:-1])
    with pytest.raises(FormatError):
        replace(plan, targets=(*plan.targets[:-1], plan.targets[0]))
    with pytest.raises(FormatError):
        replace(plan, lanes=plan.lanes[:-1])
    with pytest.raises(FormatError):
        replace(
            plan, lanes=(*plan.lanes[:-1], replace(plan.lanes[-1], identifier="lane:candidate"))
        )
    with pytest.raises(FormatError):
        replace(
            plan,
            lanes=tuple(replace(lane, provider="one") for lane in plan.lanes),
        )
    with pytest.raises(FormatError, match="matched candidate/baseline"):
        replace(
            plan,
            lanes=(plan.lanes[0], replace(plan.lanes[1], provider="provider-c"), *plan.lanes[2:]),
        )
    with pytest.raises(FormatError):
        replace(plan, repetitions=0)
    with pytest.raises(FormatError):
        replace(plan, metrics=plan.metrics[:-1])
    with pytest.raises(FormatError):
        replace(plan, exclusions=())
    with pytest.raises(FormatError, match="identity"):
        replace(plan, identifier="")
    with pytest.raises(FormatError, match="RFC 3339"):
        replace(plan, registered_at="not-a-time")
    with pytest.raises(FormatError, match="target count"):
        replace(plan, targets=())
    with pytest.raises(FormatError, match="lane count"):
        replace(plan, lanes=())
    with pytest.raises(FormatError, match="unique"):
        replace(plan, lanes=(*plan.lanes, plan.lanes[0]))


def test_p6_target_rejects_unblinded_unlicensed_or_malformed_authority() -> None:
    plan = protocol()
    target = plan.targets[0]
    with pytest.raises(FormatError, match="owned or licensed"):
        replace(target, owned_or_licensed=False)
    with pytest.raises(FormatError, match="blinded"):
        replace(target, blinded=False)
    with pytest.raises(FormatError, match="SHA-256"):
        replace(target, authorization_receipt_digest="bad")
