# SPDX-License-Identifier: Apache-2.0
"""Trusted measured swarm coverage derived from engine events."""

from sova.community.swarm.coverage import SwarmCoverageLedger


def test_coverage_counts_actions_states_transitions_and_verified_evidence() -> None:
    ledger = SwarmCoverageLedger()
    ledger.observe(
        "agent-01",
        {
            "kind": "tool.requested",
            "payload": {"action": "computer.click", "grantId": "click-button"},
        },
    )
    ledger.observe(
        "agent-01",
        {
            "kind": "tool.completed",
            "payload": {
                "action": "computer.click",
                "status": "succeeded",
                "observationBeforeContentDigest": "sha256:" + "1" * 64,
                "observationAfterContentDigest": "sha256:" + "2" * 64,
                "verification": {
                    "verified": True,
                    "satisfied_evidence": ["ui-state", "workspace-marker"],
                },
            },
        },
    )
    ledger.observe(
        "agent-01",
        {
            "kind": "oracle.completed",
            "payload": {"status": "pass", "oracleId": "typed-ui-and-file"},
        },
    )

    snapshot = ledger.snapshot()
    assert snapshot["measurementSource"] == "trusted-signed-engine-events"
    assert snapshot["plannerSelfReportsTrusted"] is False
    assert snapshot["completeCoverageClaimed"] is False
    assert snapshot["actionKindsAttempted"] == ["computer.click"]
    assert snapshot["actionKindsVerified"] == ["computer.click"]
    assert snapshot["observedStateCount"] == 2
    assert snapshot["uniqueTransitionCount"] == 1
    assert snapshot["changedTransitionCount"] == 1
    assert snapshot["evidenceRolesSatisfied"] == ["ui-state", "workspace-marker"]
    assert snapshot["oracleIdsPassed"] == ["typed-ui-and-file"]


def test_model_coverage_labels_do_not_change_measured_coverage() -> None:
    ledger = SwarmCoverageLedger()
    ledger.observe(
        "agent-01",
        {
            "kind": "model.response",
            "payload": {"coverage": ["everything-tested"], "status": "continue"},
        },
    )
    snapshot = ledger.snapshot()
    assert snapshot["actionKindsAttempted"] == []
    assert snapshot["observedStateCount"] == 0
    assert snapshot["completeCoverageClaimed"] is False
