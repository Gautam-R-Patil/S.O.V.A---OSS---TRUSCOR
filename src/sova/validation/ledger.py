# SPDX-License-Identifier: Apache-2.0
"""Complete-run accounting for blinded multi-lane security evaluations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.validation.contracts import (
    EvaluationProtocol,
    ObservationStatus,
    TargetClass,
)

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class EvaluationObservation:
    protocol_digest: str
    lane_id: str
    target_id: str
    repetition: int
    status: ObservationStatus
    workflows_observed: int
    workflows_total: int
    surfaces_exercised: int
    surfaces_total: int
    findings_reported: int
    findings_confirmed: int
    findings_reproduced: int
    false_positives: int
    infrastructure_failures: int
    actions_used: int
    input_bytes: int
    output_bytes: int
    duration_ms: int
    cost_microusd: int
    containment_passed: bool | None
    evidence_digest: str
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.protocol_digest) is None:
            raise FormatError("SOVA-P6-OBSERVATION", "protocol digest is invalid")
        if _SHA256.fullmatch(self.evidence_digest) is None:
            raise FormatError("SOVA-P6-OBSERVATION", "evidence digest is invalid")
        if (
            not self.lane_id.strip()
            or not self.target_id.strip()
            or isinstance(self.repetition, bool)
            or self.repetition < 0
        ):
            raise FormatError("SOVA-P6-OBSERVATION", "observation identity is invalid")
        counters = (
            self.workflows_observed,
            self.workflows_total,
            self.surfaces_exercised,
            self.surfaces_total,
            self.findings_reported,
            self.findings_confirmed,
            self.findings_reproduced,
            self.false_positives,
            self.infrastructure_failures,
            self.actions_used,
            self.input_bytes,
            self.output_bytes,
            self.duration_ms,
            self.cost_microusd,
        )
        if any(isinstance(value, bool) or value < 0 for value in counters):
            raise FormatError("SOVA-P6-OBSERVATION", "observation counters cannot be negative")
        if self.workflows_observed > self.workflows_total:
            raise FormatError("SOVA-P6-OBSERVATION", "workflow numerator exceeds denominator")
        if self.surfaces_exercised > self.surfaces_total:
            raise FormatError("SOVA-P6-OBSERVATION", "surface numerator exceeds denominator")
        if self.findings_confirmed > self.findings_reported:
            raise FormatError("SOVA-P6-OBSERVATION", "confirmed findings exceed reported findings")
        if self.findings_reproduced > self.findings_confirmed:
            raise FormatError(
                "SOVA-P6-OBSERVATION", "reproduced findings exceed confirmed findings"
            )
        if self.false_positives > self.findings_reported:
            raise FormatError("SOVA-P6-OBSERVATION", "false positives exceed reported findings")
        if self.findings_confirmed + self.false_positives > self.findings_reported:
            raise FormatError(
                "SOVA-P6-OBSERVATION",
                "confirmed and false-positive findings exceed reported findings",
            )
        if (
            self.status is ObservationStatus.INFRASTRUCTURE_FAILURE
            and self.infrastructure_failures == 0
        ):
            raise FormatError(
                "SOVA-P6-OBSERVATION", "infrastructure-failure status requires a failure count"
            )

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.lane_id, self.target_id, self.repetition)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "laneId": self.lane_id,
            "targetId": self.target_id,
            "repetition": self.repetition,
            "status": self.status.value,
            "workflowCoverage": {
                "observed": self.workflows_observed,
                "total": self.workflows_total,
            },
            "surfaceCoverage": {
                "exercised": self.surfaces_exercised,
                "total": self.surfaces_total,
            },
            "findings": {
                "reported": self.findings_reported,
                "confirmed": self.findings_confirmed,
                "reproduced": self.findings_reproduced,
                "falsePositives": self.false_positives,
            },
            "infrastructureFailures": self.infrastructure_failures,
            "actionsUsed": self.actions_used,
            "inputBytes": self.input_bytes,
            "outputBytes": self.output_bytes,
            "durationMilliseconds": self.duration_ms,
            "costMicrousd": self.cost_microusd,
            "containmentPassed": self.containment_passed,
            "evidenceDigest": self.evidence_digest,
            "limitations": list(self.limitations),
        }


def _expected(protocol: EvaluationProtocol) -> set[tuple[str, str, int]]:
    return {
        (lane.identifier, target.identifier, repetition)
        for lane in protocol.lanes
        for target in protocol.targets
        for repetition in range(protocol.repetitions)
    }


def _ratio(numerator: int, denominator: int) -> str | None:
    return None if denominator == 0 else f"{numerator}/{denominator}"


def _aggregate_rows(
    protocol: EvaluationProtocol, observations: tuple[EvaluationObservation, ...]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lane in protocol.lanes:
        selected = [item for item in observations if item.lane_id == lane.identifier]
        workflow_observed = sum(item.workflows_observed for item in selected)
        workflow_total = sum(item.workflows_total for item in selected)
        surface_exercised = sum(item.surfaces_exercised for item in selected)
        surface_total = sum(item.surfaces_total for item in selected)
        reported = sum(item.findings_reported for item in selected)
        confirmed = sum(item.findings_confirmed for item in selected)
        reproduced = sum(item.findings_reproduced for item in selected)
        false_positives = sum(item.false_positives for item in selected)
        rows.append(
            {
                "laneId": lane.identifier,
                "kind": lane.kind.value,
                "provider": lane.provider,
                "model": lane.model,
                "harness": lane.harness,
                "observedRuns": len(selected),
                "statusCounts": {
                    status.value: sum(item.status is status for item in selected)
                    for status in ObservationStatus
                },
                "workflowCoverage": _ratio(workflow_observed, workflow_total),
                "surfaceCoverage": _ratio(surface_exercised, surface_total),
                "findingsReported": reported,
                "findingsConfirmed": confirmed,
                "findingsReproduced": reproduced,
                "precision": _ratio(confirmed, confirmed + false_positives),
                "reproductionRate": _ratio(reproduced, confirmed),
                "infrastructureFailures": sum(item.infrastructure_failures for item in selected),
                "actionsUsed": sum(item.actions_used for item in selected),
                "inputBytes": sum(item.input_bytes for item in selected),
                "outputBytes": sum(item.output_bytes for item in selected),
                "durationMilliseconds": sum(item.duration_ms for item in selected),
                "costMicrousd": sum(item.cost_microusd for item in selected),
                "containment": {
                    "passed": sum(item.containment_passed is True for item in selected),
                    "failed": sum(item.containment_passed is False for item in selected),
                    "notMeasured": sum(item.containment_passed is None for item in selected),
                },
            }
        )
    return rows


def _class_rows(
    protocol: EvaluationProtocol, observations: tuple[EvaluationObservation, ...]
) -> list[dict[str, Any]]:
    class_by_target = {item.identifier: item.target_class for item in protocol.targets}
    return [
        {
            "targetClass": target_class.value,
            "runs": sum(class_by_target[item.target_id] is target_class for item in observations),
            "confirmedFindings": sum(
                item.findings_confirmed
                for item in observations
                if class_by_target[item.target_id] is target_class
            ),
            "infrastructureFailures": sum(
                item.infrastructure_failures
                for item in observations
                if class_by_target[item.target_id] is target_class
            ),
        }
        for target_class in TargetClass
    ]


def _harness_contrasts(
    protocol: EvaluationProtocol, observations: tuple[EvaluationObservation, ...]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for left_index, left in enumerate(protocol.lanes):
        for right in protocol.lanes[left_index + 1 :]:
            if (
                left.provider != right.provider
                or left.model != right.model
                or left.harness == right.harness
            ):
                continue
            left_rows = [item for item in observations if item.lane_id == left.identifier]
            right_rows = [item for item in observations if item.lane_id == right.identifier]
            rows.append(
                {
                    "provider": left.provider,
                    "model": left.model,
                    "leftLane": left.identifier,
                    "rightLane": right.identifier,
                    "leftConfirmed": sum(item.findings_confirmed for item in left_rows),
                    "rightConfirmed": sum(item.findings_confirmed for item in right_rows),
                    "pairedRunKeysEqual": {(item.target_id, item.repetition) for item in left_rows}
                    == {(item.target_id, item.repetition) for item in right_rows},
                    "harnessContributionCausalClaimed": False,
                }
            )
    return rows


def _budget_exceedances(
    protocol: EvaluationProtocol, observations: tuple[EvaluationObservation, ...]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in observations:
        exceeded: list[str] = []
        if item.actions_used > protocol.budget.maximum_actions:
            exceeded.append("actions")
        if item.duration_ms > protocol.budget.maximum_wall_seconds * 1000:
            exceeded.append("wall-time")
        if item.input_bytes > protocol.budget.maximum_input_bytes:
            exceeded.append("input-bytes")
        if item.output_bytes > protocol.budget.maximum_output_bytes:
            exceeded.append("output-bytes")
        if item.cost_microusd > protocol.budget.maximum_cost_microusd:
            exceeded.append("cost")
        if exceeded:
            rows.append(
                {
                    "laneId": item.lane_id,
                    "targetId": item.target_id,
                    "repetition": item.repetition,
                    "exceeded": exceeded,
                }
            )
    return rows


def evaluate_blinded_protocol(
    protocol: EvaluationProtocol,
    observations: tuple[EvaluationObservation, ...],
) -> dict[str, Any]:
    """Score every predeclared run while preserving failures and unsupported states."""
    if any(item.protocol_digest != protocol.digest for item in observations):
        raise FormatError("SOVA-P6-LEDGER-PROTOCOL", "observation protocol digest drifted")
    keys = [item.key for item in observations]
    if len(keys) != len(set(keys)):
        raise FormatError("SOVA-P6-LEDGER-DUPLICATE", "evaluation observation is duplicated")
    expected = _expected(protocol)
    if set(keys) - expected:
        raise FormatError("SOVA-P6-LEDGER-SCOPE", "evaluation observation is outside protocol")
    ordered_observations = tuple(sorted(observations, key=lambda item: item.key))
    missing = sorted(expected - set(keys))
    execution_complete = not missing
    budget_exceedances = _budget_exceedances(protocol, ordered_observations)
    nonconclusive = {
        ObservationStatus.INCONCLUSIVE,
        ObservationStatus.INFRASTRUCTURE_FAILURE,
        ObservationStatus.BLOCKED,
        ObservationStatus.UNSUPPORTED,
    }
    conclusive = (
        execution_complete
        and not budget_exceedances
        and not any(
            item.status in nonconclusive or item.containment_passed is False
            for item in ordered_observations
        )
    )
    report: dict[str, Any] = {
        "artifactType": "sova.blinded-evaluation-report",
        "schemaVersion": "0.1.0",
        "protocolDigest": protocol.digest,
        "releaseCommit": protocol.release_commit,
        "status": "conclusive" if conclusive else "incomplete-or-inconclusive",
        "expectedRuns": len(expected),
        "observedRuns": len(ordered_observations),
        "missing": [
            {"laneId": lane, "targetId": target, "repetition": repetition}
            for lane, target, repetition in missing
        ],
        "budgetExceedances": budget_exceedances,
        "observations": [item.to_mapping() for item in ordered_observations],
        "aggregateByLane": _aggregate_rows(protocol, ordered_observations),
        "aggregateByTargetClass": _class_rows(protocol, ordered_observations),
        "harnessContrasts": _harness_contrasts(protocol, ordered_observations),
        "claims": {
            "executionComplete": execution_complete,
            "resultsConclusive": conclusive,
            "fieldValidationEstablished": False,
            "independentlyReplicated": False,
            "allVulnerabilitiesFound": False,
            "weakModelMadeExpert": False,
            "generalProviderOrTargetSuperiorityEstablished": False,
        },
        "limitations": [
            "A complete run ledger does not establish representative target sampling.",
            "Harness contrasts are descriptive until a causal design and independent "
            "replication pass.",
            "Not-observed and unsupported results are retained and are not converted to passes.",
        ],
    }
    report["contentDigest"] = sha256_digest(canonical_json_bytes(report))
    return report


__all__ = ["EvaluationObservation", "evaluate_blinded_protocol"]
