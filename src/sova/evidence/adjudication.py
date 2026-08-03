# SPDX-License-Identifier: Apache-2.0
"""Execution-bounded scanner disagreement adjudication."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from sova.evidence.model import (
    AdjudicatedClaim,
    AdjudicationReport,
    AdjudicationState,
    ExecutionObservation,
    ObservationState,
    ScannerFinding,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Sequence


def construct_safe_test_plan(
    findings: Sequence[ScannerFinding],
    *,
    target_owned_or_authorized: bool,
    allowed_action_families: Sequence[str],
) -> dict[str, Any]:
    """Produce an inert plan; never execute a scanner claim or payload."""
    if not target_owned_or_authorized:
        raise FormatError(
            "SOVA-ADJUDICATE-AUTHORIZATION",
            "test-plan construction requires an owned or explicitly authorized target",
        )
    if not allowed_action_families:
        raise FormatError(
            "SOVA-ADJUDICATE-ACTIONS",
            "at least one bounded action family must be declared",
        )
    claims = sorted({finding.claim_key for finding in findings})
    return {
        "artifactType": "sova.adjudication-test-plan",
        "schemaVersion": "0.1.0",
        "claimIds": [sha256_digest(item.encode("utf-8")) for item in claims],
        "allowedActionFamilies": sorted(set(allowed_action_families)),
        "executionMode": "inert-plan-only",
        "requiresFreshAuthorizationBeforeExecution": True,
        "automaticExternalAction": False,
        "limitations": [
            "This plan does not execute scanner-supplied payloads.",
            "A negative observation is bounded by sensor coverage and test conditions.",
        ],
    }


def adjudicate_findings(
    findings: Sequence[ScannerFinding],
    observations: Sequence[ExecutionObservation],
) -> AdjudicationReport:
    """Bound disagreeing scanner claims with separately supplied execution evidence."""
    grouped: dict[str, list[ScannerFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.claim_key].append(finding)
    observation_by_key: dict[str, ExecutionObservation] = {}
    for recorded_observation in observations:
        if recorded_observation.claim_key in observation_by_key:
            raise FormatError(
                "SOVA-ADJUDICATE-DUPLICATE-OBSERVATION",
                "one normalized claim has multiple terminal execution observations",
            )
        observation_by_key[recorded_observation.claim_key] = recorded_observation
    claims: list[AdjudicatedClaim] = []
    for claim_key, claim_findings in sorted(grouped.items()):
        observation = observation_by_key.get(claim_key)
        limitations: list[str] = []
        if observation is None:
            state = AdjudicationState.INCONCLUSIVE
            limitations.append("No execution observation was supplied.")
        elif not observation.safe_and_authorized:
            state = AdjudicationState.INCONCLUSIVE
            limitations.append("Execution evidence was not marked safe and authorized.")
        elif not observation.evidence_complete:
            state = AdjudicationState.INCONCLUSIVE
            limitations.append("Required execution evidence was incomplete.")
        elif observation.state == ObservationState.CONFIRMED:
            state = AdjudicationState.CONFIRMED_POSITIVE
        elif observation.state == ObservationState.CONTRADICTED:
            state = AdjudicationState.FALSE_POSITIVE
            limitations.append("False-positive label applies only to the declared test conditions.")
        elif observation.state == ObservationState.NOT_OBSERVED:
            state = AdjudicationState.NOT_OBSERVED
            limitations.append("Not observed is not evidence that the target is universally safe.")
        else:
            state = AdjudicationState.INCONCLUSIVE
        if len({item.mechanism for item in claim_findings}) < len(claim_findings):
            limitations.append(
                "Some scanner findings may share a mechanism and are not independent votes."
            )
        claims.append(
            AdjudicatedClaim(
                claim_id=sha256_digest(canonical_json_bytes({"claimKey": claim_key})),
                state=state,
                scanner_findings=tuple(claim_findings),
                execution_observation=observation,
                limitations=(*limitations, *(observation.limitations if observation else ())),
            )
        )
    return AdjudicationReport(
        claims=tuple(claims),
        limitations=(
            "Adjudication is bounded by authorization, test construction, sensors, "
            "and environment.",
            "Scanner count is not treated as independent statistical evidence.",
            "Results are self-assessment evidence, not universal ground truth or certification.",
        ),
    )


__all__ = ["adjudicate_findings", "construct_safe_test_plan"]
