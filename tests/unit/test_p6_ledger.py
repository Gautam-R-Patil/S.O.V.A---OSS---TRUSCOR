# SPDX-License-Identifier: Apache-2.0
"""Blinded evaluation ledger tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sova.formats import FormatError, validate_document
from sova.validation import ObservationStatus, evaluate_blinded_protocol
from tests.support.p6 import digest, observations, protocol


def test_complete_ledger_accounts_every_metric_and_refuses_generality_claims() -> None:
    plan = protocol()
    rows = observations(plan)
    report = evaluate_blinded_protocol(plan, rows)
    validate_document(report)
    assert report["status"] == "conclusive"
    assert report["expectedRuns"] == 32
    assert len(report["aggregateByTargetClass"]) == 8
    assert report["aggregateByLane"][0]["precision"] == "8/16"
    assert report["aggregateByLane"][0]["workflowCoverage"] == "16/24"
    assert report["harnessContrasts"][0]["pairedRunKeysEqual"] is True
    assert report["claims"]["allVulnerabilitiesFound"] is False
    assert report["claims"]["weakModelMadeExpert"] is False
    assert (
        evaluate_blinded_protocol(plan, tuple(reversed(rows)))["contentDigest"]
        == report["contentDigest"]
    )


def test_ledger_retains_missing_infrastructure_and_unsupported_results() -> None:
    plan = protocol()
    rows = list(observations(plan))
    rows[0] = replace(
        rows[0],
        status=ObservationStatus.INFRASTRUCTURE_FAILURE,
        infrastructure_failures=1,
        containment_passed=None,
    )
    rows[1] = replace(rows[1], status=ObservationStatus.UNSUPPORTED)
    report = evaluate_blinded_protocol(plan, tuple(rows[:-1]))
    assert report["status"] == "incomplete-or-inconclusive"
    assert len(report["missing"]) == 1
    assert report["aggregateByLane"][0]["statusCounts"]["infrastructure-failure"] == 1
    assert report["claims"]["executionComplete"] is False


def test_ledger_preserves_budget_and_containment_failures() -> None:
    plan = protocol()
    rows = list(observations(plan))
    rows[0] = replace(
        rows[0],
        actions_used=plan.budget.maximum_actions + 1,
        duration_ms=(plan.budget.maximum_wall_seconds * 1000) + 1,
        input_bytes=plan.budget.maximum_input_bytes + 1,
        output_bytes=plan.budget.maximum_output_bytes + 1,
        cost_microusd=plan.budget.maximum_cost_microusd + 1,
    )
    rows[1] = replace(rows[1], containment_passed=False)
    report = evaluate_blinded_protocol(plan, tuple(rows))
    assert report["status"] == "incomplete-or-inconclusive"
    assert report["budgetExceedances"] == [
        {
            "laneId": rows[0].lane_id,
            "targetId": rows[0].target_id,
            "repetition": 0,
            "exceeded": ["actions", "wall-time", "input-bytes", "output-bytes", "cost"],
        }
    ]
    assert report["claims"]["resultsConclusive"] is False


def test_ledger_rejects_protocol_drift_duplicate_and_unknown_scope() -> None:
    plan = protocol()
    rows = observations(plan)
    with pytest.raises(FormatError, match="digest drifted"):
        evaluate_blinded_protocol(plan, (replace(rows[0], protocol_digest=digest("other")),))
    with pytest.raises(FormatError, match="duplicated"):
        evaluate_blinded_protocol(plan, (rows[0], rows[0]))
    with pytest.raises(FormatError, match="outside"):
        evaluate_blinded_protocol(plan, (replace(rows[0], lane_id="lane:unknown"),))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_digest", "bad"),
        ("protocol_digest", "sha256:" + ("z" * 64)),
        ("evidence_digest", "bad"),
        ("repetition", False),
        ("repetition", -1),
        ("workflows_observed", -1),
        ("workflows_observed", 4),
        ("surfaces_exercised", 5),
        ("findings_confirmed", 3),
        ("findings_reproduced", 2),
        ("false_positives", 3),
        ("actions_used", -1),
    ],
)
def test_observation_rejects_invalid_identity_and_counters(field: str, value: object) -> None:
    row = observations(protocol())[0]
    with pytest.raises(FormatError):
        replace(row, **{field: value})  # type: ignore[arg-type]


def test_infrastructure_status_requires_failure_count() -> None:
    row = observations(protocol())[0]
    with pytest.raises(FormatError, match="requires"):
        replace(row, status=ObservationStatus.INFRASTRUCTURE_FAILURE)
    with pytest.raises(FormatError, match="confirmed and false-positive"):
        replace(row, findings_reported=1)
