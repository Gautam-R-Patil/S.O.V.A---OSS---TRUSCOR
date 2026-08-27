# SPDX-License-Identifier: Apache-2.0
"""Frozen P6 evaluation contracts with explicit scope, authority, and budgets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_TARGETS = 10_000
_MAX_LANES = 100
_MAX_REPETITIONS = 100
_MAX_RUNS = 100_000
_MIN_PROVIDER_FAMILIES = 2
_REQUIRED_METRICS = (
    "workflow-coverage",
    "surface-coverage",
    "confirmed-findings",
    "fresh-reproduction",
    "precision-false-positives",
    "infrastructure-failures",
    "cost",
    "latency",
    "containment",
)


def _digest(value: str, role: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise FormatError("SOVA-P6-DIGEST", f"{role} must be a SHA-256 digest")


class TargetClass(StrEnum):
    WEB = "web"
    API = "api"
    PACKAGE = "package"
    OCI = "oci"
    NETWORK = "network"
    DESKTOP = "desktop"
    AI_AGENT = "ai-model-agent"
    MCP_A2A = "mcp-a2a"


class LaneKind(StrEnum):
    CANDIDATE = "candidate"
    BASELINE = "baseline"
    SCRIPTED = "scripted"
    WEAK_MODEL = "weak-model"


class ObservationStatus(StrEnum):
    CONFIRMED = "confirmed"
    NOT_OBSERVED = "not-observed"
    FALSE_POSITIVE = "false-positive"
    INCONCLUSIVE = "inconclusive"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"


def _has_matched_harness_pair(lanes: tuple[EvaluationLane, ...]) -> bool:
    return any(
        left.kind is LaneKind.CANDIDATE
        and right.kind is LaneKind.BASELINE
        and left.provider == right.provider
        and left.model == right.model
        and left.harness != right.harness
        for left in lanes
        for right in lanes
    )


@dataclass(frozen=True, slots=True)
class EvaluationBudget:
    maximum_actions: int
    maximum_wall_seconds: int
    maximum_input_bytes: int
    maximum_output_bytes: int
    maximum_cost_microusd: int

    def __post_init__(self) -> None:
        values = (
            self.maximum_actions,
            self.maximum_wall_seconds,
            self.maximum_input_bytes,
            self.maximum_output_bytes,
        )
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise FormatError("SOVA-P6-BUDGET", "evaluation budgets must be positive integers")
        if isinstance(self.maximum_cost_microusd, bool) or self.maximum_cost_microusd < 0:
            raise FormatError("SOVA-P6-BUDGET", "cost budget must be a non-negative integer")

    def to_mapping(self) -> dict[str, int]:
        return {
            "maximumActions": self.maximum_actions,
            "maximumWallSeconds": self.maximum_wall_seconds,
            "maximumInputBytes": self.maximum_input_bytes,
            "maximumOutputBytes": self.maximum_output_bytes,
            "maximumCostMicrousd": self.maximum_cost_microusd,
        }


@dataclass(frozen=True, slots=True)
class EvaluationLane:
    identifier: str
    kind: LaneKind
    provider: str
    model: str
    harness: str
    configuration_digest: str

    def __post_init__(self) -> None:
        if any(
            not value.strip()
            for value in (self.identifier, self.provider, self.model, self.harness)
        ):
            raise FormatError("SOVA-P6-LANE", "lane identity fields must be non-empty")
        _digest(self.configuration_digest, "lane configuration")

    def to_mapping(self) -> dict[str, str]:
        return {
            "id": self.identifier,
            "kind": self.kind.value,
            "provider": self.provider,
            "model": self.model,
            "harness": self.harness,
            "configurationDigest": self.configuration_digest,
        }


@dataclass(frozen=True, slots=True)
class BlindedTarget:
    identifier: str
    target_class: TargetClass
    input_digest: str
    answer_key_commitment: str
    authorization_receipt_digest: str
    source_revision: str
    license_identifier: str
    containment_backend: str
    blinded: bool = True
    owned_or_licensed: bool = True

    def __post_init__(self) -> None:
        if any(
            not value.strip()
            for value in (
                self.identifier,
                self.source_revision,
                self.license_identifier,
                self.containment_backend,
            )
        ):
            raise FormatError("SOVA-P6-TARGET", "target identity and provenance are required")
        for value, role in (
            (self.input_digest, "target input"),
            (self.answer_key_commitment, "answer-key commitment"),
            (self.authorization_receipt_digest, "target authorization receipt"),
        ):
            _digest(value, role)
        if not self.blinded or not self.owned_or_licensed:
            raise FormatError(
                "SOVA-P6-TARGET-AUTHORITY",
                "P6 targets must be blinded and explicitly owned or licensed",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "targetClass": self.target_class.value,
            "inputDigest": self.input_digest,
            "answerKeyCommitment": self.answer_key_commitment,
            "authorizationReceiptDigest": self.authorization_receipt_digest,
            "sourceRevision": self.source_revision,
            "licenseIdentifier": self.license_identifier,
            "containmentBackend": self.containment_backend,
            "blinded": self.blinded,
            "ownedOrLicensed": self.owned_or_licensed,
        }


@dataclass(frozen=True, slots=True)
class EvaluationProtocol:
    identifier: str
    registered_at: str
    release_commit: str
    targets: tuple[BlindedTarget, ...]
    lanes: tuple[EvaluationLane, ...]
    repetitions: int
    seed: int
    budget: EvaluationBudget
    scoring_rules_digest: str
    exclusions: tuple[str, ...]
    failure_rules: tuple[str, ...]
    answer_key_custodian: str
    metrics: tuple[str, ...] = _REQUIRED_METRICS

    def __post_init__(  # noqa: PLR0912 - preregistration invariants stay explicit
        self,
    ) -> None:
        if not self.identifier.strip() or not self.release_commit.strip():
            raise FormatError(
                "SOVA-P6-PROTOCOL", "protocol identity, time, and commit are required"
            )
        if _RFC3339_UTC.fullmatch(self.registered_at) is None:
            raise FormatError("SOVA-P6-PROTOCOL", "registration time must be RFC 3339 UTC")
        if not 1 <= len(self.targets) <= _MAX_TARGETS:
            raise FormatError("SOVA-P6-PROTOCOL", "protocol target count is invalid")
        if not 1 <= len(self.lanes) <= _MAX_LANES:
            raise FormatError("SOVA-P6-PROTOCOL", "protocol lane count is invalid")
        if len({item.identifier for item in self.targets}) != len(self.targets):
            raise FormatError("SOVA-P6-PROTOCOL", "target ids must be unique")
        if len({item.identifier for item in self.lanes}) != len(self.lanes):
            raise FormatError("SOVA-P6-PROTOCOL", "lane ids must be unique")
        if {item.target_class for item in self.targets} != set(TargetClass):
            raise FormatError("SOVA-P6-PROTOCOL", "all eight target classes must be predeclared")
        lane_kinds = {item.kind for item in self.lanes}
        if lane_kinds != set(LaneKind):
            raise FormatError(
                "SOVA-P6-PROTOCOL",
                "candidate, baseline, scripted, and weak-model lanes are required",
            )
        provider_families = {
            item.provider
            for item in self.lanes
            if item.kind in {LaneKind.CANDIDATE, LaneKind.WEAK_MODEL}
        }
        if len(provider_families) < _MIN_PROVIDER_FAMILIES:
            raise FormatError(
                "SOVA-P6-PROTOCOL", "at least two model-provider families are required"
            )
        if not _has_matched_harness_pair(self.lanes):
            raise FormatError(
                "SOVA-P6-PROTOCOL",
                "a matched candidate/baseline model pair with different harnesses is required",
            )
        if not 1 <= self.repetitions <= _MAX_REPETITIONS or self.run_count > _MAX_RUNS:
            raise FormatError("SOVA-P6-PROTOCOL", "repetitions or total run budget is invalid")
        _digest(self.scoring_rules_digest, "scoring rules")
        if self.metrics != _REQUIRED_METRICS:
            raise FormatError(
                "SOVA-P6-METRICS", "the complete ordered P6 metric contract is required"
            )
        if not self.exclusions or not self.failure_rules or not self.answer_key_custodian.strip():
            raise FormatError(
                "SOVA-P6-PROTOCOL", "exclusions, failure rules, and answer-key custody are required"
            )

    @property
    def run_count(self) -> int:
        return len(self.targets) * len(self.lanes) * self.repetitions

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.blinded-evaluation-protocol",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "registeredAt": self.registered_at,
            "releaseCommit": self.release_commit,
            "targets": [item.to_mapping() for item in self.targets],
            "lanes": [item.to_mapping() for item in self.lanes],
            "repetitions": self.repetitions,
            "seed": self.seed,
            "runCount": self.run_count,
            "budgetPerRun": self.budget.to_mapping(),
            "scoringRulesDigest": self.scoring_rules_digest,
            "metrics": list(self.metrics),
            "exclusions": list(self.exclusions),
            "failureRules": list(self.failure_rules),
            "answerKeyCustodian": self.answer_key_custodian,
            "answerKeyEmbedded": False,
            "resultsRequiredPublic": True,
            "negativeResultsRetained": True,
        }


__all__ = [
    "BlindedTarget",
    "EvaluationBudget",
    "EvaluationLane",
    "EvaluationProtocol",
    "LaneKind",
    "ObservationStatus",
    "TargetClass",
]
