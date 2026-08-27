# SPDX-License-Identifier: Apache-2.0
"""Strict P4 contracts.

The types in this module deliberately prevent an oracle proposal, tool assertion,
missing observation, or infrastructure error from becoming a confirmed finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

SCHEMA_VERSION = "0.1.0"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,190}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")
_RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_TEXT = 4096
_CONTROL_CHARACTER_BOUND = 0x20
_MAX_ITEMS = 10_000


def _text(value: str, role: str) -> str:
    if (
        not value.strip()
        or len(value) > _MAX_TEXT
        or any(ord(char) < _CONTROL_CHARACTER_BOUND for char in value)
    ):
        raise FormatError("SOVA-ORACLE-LAB-TEXT", f"{role} is invalid")
    return value


def _identifier(value: str, role: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise FormatError("SOVA-ORACLE-LAB-ID", f"{role} identifier is invalid")
    return value


def _digest(value: str, role: str) -> str:
    if _DIGEST.fullmatch(value) is None:
        raise FormatError("SOVA-ORACLE-LAB-DIGEST", f"{role} must be lowercase SHA-256")
    return value


def _unique_text(values: tuple[str, ...], role: str, *, allow_empty: bool = False) -> None:
    if (not values and not allow_empty) or len(values) != len(set(values)):
        raise FormatError("SOVA-ORACLE-LAB-SET", f"{role} must be unique and non-empty")
    for value in values:
        _text(value, role)


def _utc(value: str, role: str) -> datetime:
    if _RFC3339_UTC.fullmatch(value) is None:
        raise FormatError("SOVA-ORACLE-LAB-TIME", f"{role} must be second-precision UTC")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class OracleSource(StrEnum):
    """Evidence class from which a proposal was derived."""

    TARGET_CONTRACT = "target-contract"
    SPECIFICATION = "specification"
    INVARIANT = "invariant"
    DIFFERENTIAL = "differential"
    METAMORPHIC = "metamorphic"
    STATE_EFFECT = "state-effect"
    LOG = "log"
    HUMAN_ACCEPTANCE = "human-acceptance"


class OracleDisposition(StrEnum):
    """Lifecycle state that cannot be confused with an oracle verdict."""

    UNVALIDATED_PROPOSAL = "unvalidated-proposal"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    NO_RELIABLE_ORACLE = "no-reliable-oracle"
    HUMAN_REVIEW_REQUIRED = "human-review-required"


class CalibrationClass(StrEnum):
    KNOWN_POSITIVE = "known-positive"
    KNOWN_NEGATIVE = "known-negative"
    AMBIGUOUS = "ambiguous"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


class OracleVerdict(StrEnum):
    """A result over evidence; it is not a safety conclusion."""

    POSITIVE = "positive"
    NEGATIVE = "negative"
    ABSTAIN = "abstain"
    NOT_OBSERVED = "not-observed"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


@dataclass(frozen=True, slots=True)
class OracleProposal:
    """A typed, non-authorizing oracle hypothesis."""

    identifier: str
    target_profile_digest: str
    source: OracleSource
    statement: str
    evaluator_id: str
    evaluator_version: str
    evaluator_config_digest: str
    positive_signal: str
    negative_signal: str
    ambiguous_state: str
    source_references: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    known_blind_spots: tuple[str, ...]
    disposition: OracleDisposition = OracleDisposition.UNVALIDATED_PROPOSAL

    def __post_init__(self) -> None:
        _identifier(self.identifier, "oracle proposal")
        _digest(self.target_profile_digest, "target profile")
        _identifier(self.evaluator_id, "evaluator")
        _text(self.evaluator_version, "evaluator version")
        _digest(self.evaluator_config_digest, "evaluator configuration")
        for role, value in (
            ("oracle statement", self.statement),
            ("positive signal", self.positive_signal),
            ("negative signal", self.negative_signal),
            ("ambiguous state", self.ambiguous_state),
        ):
            _text(value, role)
        _unique_text(self.source_references, "source references")
        _unique_text(self.evidence_requirements, "evidence requirements")
        _unique_text(self.known_blind_spots, "known blind spots")
        if self.disposition != OracleDisposition.UNVALIDATED_PROPOSAL:
            raise FormatError(
                "SOVA-ORACLE-LAB-LIFECYCLE",
                "new proposals must remain unvalidated until calibration",
            )

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.oracle-proposal",
            "schemaVersion": SCHEMA_VERSION,
            "id": self.identifier,
            "targetProfileDigest": self.target_profile_digest,
            "source": self.source.value,
            "statement": self.statement,
            "evaluator": {
                "id": self.evaluator_id,
                "version": self.evaluator_version,
                "configDigest": self.evaluator_config_digest,
            },
            "signals": {
                "positive": self.positive_signal,
                "negative": self.negative_signal,
                "ambiguous": self.ambiguous_state,
            },
            "sourceReferences": list(self.source_references),
            "evidenceRequirements": list(self.evidence_requirements),
            "knownBlindSpots": list(self.known_blind_spots),
            "disposition": self.disposition.value,
            "claims": {
                "executionAuthorized": False,
                "findingConfirmed": False,
                "universallyReliable": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class CalibrationCase:
    """One label revealed only after a prediction was frozen."""

    identifier: str
    expected_class: CalibrationClass
    verdict: OracleVerdict
    target_generation: str
    environment_fingerprint: str
    prediction_digest: str
    evidence_digests: tuple[str, ...]
    label_revealed_after_prediction: bool = True

    def __post_init__(self) -> None:
        _identifier(self.identifier, "calibration case")
        _identifier(self.target_generation, "target generation")
        _digest(self.environment_fingerprint, "environment fingerprint")
        _digest(self.prediction_digest, "prediction")
        if not self.evidence_digests or len(self.evidence_digests) != len(
            set(self.evidence_digests)
        ):
            raise FormatError("SOVA-ORACLE-LAB-EVIDENCE", "case evidence must be non-empty")
        for value in self.evidence_digests:
            _digest(value, "case evidence")
        if not self.label_revealed_after_prediction:
            raise FormatError(
                "SOVA-ORACLE-LAB-BLINDING", "calibration labels must follow frozen predictions"
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "expectedClass": self.expected_class.value,
            "verdict": self.verdict.value,
            "targetGeneration": self.target_generation,
            "environmentFingerprint": self.environment_fingerprint,
            "predictionDigest": self.prediction_digest,
            "evidenceDigests": list(self.evidence_digests),
            "labelRevealedAfterPrediction": self.label_revealed_after_prediction,
        }


@dataclass(frozen=True, slots=True)
class CalibrationPolicy:
    """Predeclared oracle promotion thresholds."""

    minimum_positive_cases: int = 2
    minimum_negative_cases: int = 2
    maximum_false_positives: int = 0
    maximum_misses: int = 0
    require_ambiguous_abstention: bool = True
    require_infrastructure_separation: bool = True

    def __post_init__(self) -> None:
        if self.minimum_positive_cases < 1 or self.minimum_negative_cases < 1:
            raise FormatError("SOVA-ORACLE-LAB-POLICY", "case minima must be positive")
        if self.maximum_false_positives < 0 or self.maximum_misses < 0:
            raise FormatError("SOVA-ORACLE-LAB-POLICY", "error maxima cannot be negative")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "minimumPositiveCases": self.minimum_positive_cases,
            "minimumNegativeCases": self.minimum_negative_cases,
            "maximumFalsePositives": self.maximum_false_positives,
            "maximumMisses": self.maximum_misses,
            "requireAmbiguousAbstention": self.require_ambiguous_abstention,
            "requireInfrastructureSeparation": self.require_infrastructure_separation,
        }


@dataclass(frozen=True, slots=True)
class OracleCalibration:
    """Measured oracle quality and resulting lifecycle decision."""

    proposal_digest: str
    policy: CalibrationPolicy
    cases: tuple[CalibrationCase, ...]
    disposition: OracleDisposition
    counts: tuple[tuple[str, int], ...]
    sensitivity: str | None
    specificity: str | None
    confidence_interval_low: str
    confidence_interval_high: str
    valid_from: str
    valid_until: str
    known_blind_spots: tuple[str, ...]
    decision_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest(self.proposal_digest, "oracle proposal")
        if not self.cases or len(self.cases) > _MAX_ITEMS:
            raise FormatError("SOVA-ORACLE-LAB-CASES", "calibration case count is invalid")
        identifiers = [case.identifier for case in self.cases]
        if len(identifiers) != len(set(identifiers)):
            raise FormatError("SOVA-ORACLE-LAB-CASES", "calibration case IDs must be unique")
        keys = [key for key, value in self.counts if value >= 0]
        if len(keys) != len(self.counts) or len(keys) != len(set(keys)):
            raise FormatError("SOVA-ORACLE-LAB-METRICS", "calibration counts are invalid")
        for ratio in (self.sensitivity, self.specificity):
            if ratio is not None and re.fullmatch(r"(?:0(?:\.[0-9]+)?|1(?:\.0+)?)", ratio) is None:
                raise FormatError("SOVA-ORACLE-LAB-METRICS", "metric ratio is invalid")
        start = _utc(self.valid_from, "valid from")
        stop = _utc(self.valid_until, "valid until")
        if stop <= start:
            raise FormatError("SOVA-ORACLE-LAB-TIME", "validity window must be increasing")
        _unique_text(self.known_blind_spots, "calibration blind spots")
        _unique_text(self.decision_reasons, "calibration decision reasons", allow_empty=True)
        if self.disposition == OracleDisposition.UNVALIDATED_PROPOSAL:
            raise FormatError("SOVA-ORACLE-LAB-LIFECYCLE", "calibration must make a decision")
        if self.disposition == OracleDisposition.PROMOTED and self.decision_reasons:
            raise FormatError("SOVA-ORACLE-LAB-LIFECYCLE", "promoted oracle has failure reasons")

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.oracle-calibration",
            "schemaVersion": SCHEMA_VERSION,
            "proposalDigest": self.proposal_digest,
            "policy": self.policy.to_mapping(),
            "cases": [case.to_mapping() for case in self.cases],
            "disposition": self.disposition.value,
            "metrics": {
                "counts": dict(self.counts),
                "sensitivity": self.sensitivity,
                "specificity": self.specificity,
                "jointWilson95": {
                    "low": self.confidence_interval_low,
                    "high": self.confidence_interval_high,
                },
            },
            "validity": {"from": self.valid_from, "until": self.valid_until},
            "knownBlindSpots": list(self.known_blind_spots),
            "decisionReasons": list(self.decision_reasons),
            "claims": {
                "findingConfirmed": False,
                "allFutureInputsCovered": False,
                "universallyReliable": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


class ComparisonKind(StrEnum):
    DIFFERENTIAL = "differential"
    METAMORPHIC = "metamorphic"


class ComparisonAxis(StrEnum):
    IDENTITY = "identity"
    ROLE = "role"
    STATE = "state"
    PROVIDER = "provider"
    VERSION = "version"
    CONFIGURATION = "configuration"
    INTERVENTION_PAIR = "intervention-pair"


class ComparisonRelation(StrEnum):
    EQUAL = "equal"
    NOT_EQUAL = "not-equal"
    SUBSET = "subset"
    SUPERSET = "superset"
    NONDECREASING = "nondecreasing"
    NONINCREASING = "nonincreasing"


@dataclass(frozen=True, slots=True)
class ComparisonObservation:
    identifier: str
    kind: ComparisonKind
    axis: ComparisonAxis
    relation: ComparisonRelation
    left_label: str
    right_label: str
    left_value: Any
    right_value: Any
    left_generation: str
    right_generation: str
    evidence_digests: tuple[str, ...]
    evidence_complete: bool
    infrastructure_failure: bool = False

    def __post_init__(self) -> None:
        _identifier(self.identifier, "comparison")
        for role, value in (
            ("left label", self.left_label),
            ("right label", self.right_label),
            ("left generation", self.left_generation),
            ("right generation", self.right_generation),
        ):
            _text(value, role)
        if not self.evidence_digests:
            raise FormatError("SOVA-ORACLE-LAB-EVIDENCE", "comparison evidence is required")
        for value in self.evidence_digests:
            _digest(value, "comparison evidence")


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    observation: ComparisonObservation
    verdict: OracleVerdict
    relation_satisfied: bool | None
    method: str
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        item = self.observation
        body: dict[str, Any] = {
            "artifactType": "sova.oracle-comparison",
            "schemaVersion": SCHEMA_VERSION,
            "id": item.identifier,
            "kind": item.kind.value,
            "axis": item.axis.value,
            "relation": item.relation.value,
            "labels": {"left": item.left_label, "right": item.right_label},
            "valueDigests": {
                "left": sha256_digest(canonical_json_bytes(item.left_value)),
                "right": sha256_digest(canonical_json_bytes(item.right_value)),
            },
            "targetGenerations": {
                "left": item.left_generation,
                "right": item.right_generation,
            },
            "evidenceDigests": list(item.evidence_digests),
            "evidenceComplete": item.evidence_complete,
            "verdict": self.verdict.value,
            "relationSatisfied": self.relation_satisfied,
            "method": self.method,
            "limitations": list(self.limitations),
            "claims": {"causalityEstablished": False, "universalInvariant": False},
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


class EvidenceRole(StrEnum):
    DECISIVE_CUE = "decisive-cue"
    RAW_EVIDENCE = "raw-evidence"
    REPLAY_MEDIA = "replay-media"
    TRACE = "trace"
    CAPSULE = "capsule"


@dataclass(frozen=True, slots=True)
class DecisiveEvidenceBinding:
    role: EvidenceRole
    uri: str
    digest: str
    media_type: str
    verified: bool
    redacted: bool

    def __post_init__(self) -> None:
        _text(self.uri, "evidence URI")
        _digest(self.digest, "decisive evidence")
        if _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise FormatError("SOVA-ORACLE-LAB-MEDIA", "evidence media type is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "uri": self.uri,
            "digest": self.digest,
            "mediaType": self.media_type,
            "verified": self.verified,
            "redacted": self.redacted,
        }


class ReproductionState(StrEnum):
    CONFIRMED = "confirmed"
    NOT_REPRODUCED = "not-reproduced"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


@dataclass(frozen=True, slots=True)
class FreshReproduction:
    finding_digest: str
    promoted_oracle_digest: str
    primary_target_generation: str
    reproduction_target_generation: str
    primary_environment_fingerprint: str
    reproduction_environment_fingerprint: str
    primary_runner_identity: str
    reproduction_runner_identity: str
    primary_trace_digest: str
    reproduction_trace_digest: str
    reset_receipt_digest: str
    causal_evidence_digests: tuple[str, ...]
    evidence_set_digest: str
    oracle_verdict: OracleVerdict
    evaluated_at: str
    state: ReproductionState
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        for role, value in (
            ("finding", self.finding_digest),
            ("promoted oracle", self.promoted_oracle_digest),
            ("primary environment", self.primary_environment_fingerprint),
            ("reproduction environment", self.reproduction_environment_fingerprint),
            ("primary trace", self.primary_trace_digest),
            ("reproduction trace", self.reproduction_trace_digest),
            ("reset receipt", self.reset_receipt_digest),
            ("decisive evidence set", self.evidence_set_digest),
        ):
            _digest(value, role)
        for role, value in (
            ("primary generation", self.primary_target_generation),
            ("reproduction generation", self.reproduction_target_generation),
            ("primary runner", self.primary_runner_identity),
            ("reproduction runner", self.reproduction_runner_identity),
        ):
            _identifier(value, role)
        _utc(self.evaluated_at, "reproduction evaluation time")
        if not self.causal_evidence_digests:
            raise FormatError("SOVA-ORACLE-LAB-CAUSAL", "causal evidence is required")
        for value in self.causal_evidence_digests:
            _digest(value, "causal evidence")
        _unique_text(self.reasons, "reproduction reasons", allow_empty=True)
        if self.state == ReproductionState.CONFIRMED:
            if self.reasons:
                raise FormatError("SOVA-ORACLE-LAB-REPRODUCTION", "confirmed result has reasons")
            if self.oracle_verdict != OracleVerdict.POSITIVE:
                raise FormatError(
                    "SOVA-ORACLE-LAB-REPRODUCTION",
                    "confirmation requires a positive promoted-oracle verdict",
                )
            if self.primary_target_generation == self.reproduction_target_generation:
                raise FormatError(
                    "SOVA-ORACLE-LAB-REPRODUCTION",
                    "confirmation requires a fresh target generation",
                )
            if self.primary_runner_identity == self.reproduction_runner_identity:
                raise FormatError(
                    "SOVA-ORACLE-LAB-REPRODUCTION", "confirmation requires an independent runner"
                )
            if self.primary_trace_digest == self.reproduction_trace_digest:
                raise FormatError(
                    "SOVA-ORACLE-LAB-REPRODUCTION", "confirmation requires a new trace"
                )

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.fresh-reproduction",
            "schemaVersion": SCHEMA_VERSION,
            "findingDigest": self.finding_digest,
            "promotedOracleDigest": self.promoted_oracle_digest,
            "targetGenerations": {
                "primary": self.primary_target_generation,
                "reproduction": self.reproduction_target_generation,
            },
            "environmentFingerprints": {
                "primary": self.primary_environment_fingerprint,
                "reproduction": self.reproduction_environment_fingerprint,
            },
            "runnerIdentities": {
                "primary": self.primary_runner_identity,
                "reproduction": self.reproduction_runner_identity,
            },
            "traceDigests": {
                "primary": self.primary_trace_digest,
                "reproduction": self.reproduction_trace_digest,
            },
            "resetReceiptDigest": self.reset_receipt_digest,
            "causalEvidenceDigests": list(self.causal_evidence_digests),
            "evidenceSetDigest": self.evidence_set_digest,
            "oracleVerdict": self.oracle_verdict.value,
            "evaluatedAt": self.evaluated_at,
            "state": self.state.value,
            "reasons": list(self.reasons),
            "claims": {
                "freshState": self.primary_target_generation != self.reproduction_target_generation,
                "independentRunnerDeclared": self.primary_runner_identity
                != self.reproduction_runner_identity,
                "allConditionsReproduced": False,
                "allVulnerabilitiesFound": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


class CoverageDimension(StrEnum):
    WORKFLOW = "workflow"
    SURFACE = "surface"
    PLAYBOOK = "playbook"
    STATE = "state"
    IDENTITY_ROLE = "identity-role"
    ADAPTER = "adapter"
    ORACLE = "oracle"
    REPRODUCTION = "reproduction"


class CoverageState(StrEnum):
    DECLARED = "declared"
    DISCOVERED = "discovered"
    EXERCISED = "exercised"
    REPRODUCED = "reproduced"
    NOT_OBSERVED = "not-observed"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    dimension: CoverageDimension
    subject: str
    state: CoverageState
    evidence_digests: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        _identifier(self.subject, "coverage subject")
        _text(self.reason, "coverage reason")
        if self.state in {CoverageState.EXERCISED, CoverageState.REPRODUCED} and not (
            self.evidence_digests
        ):
            raise FormatError(
                "SOVA-ORACLE-LAB-COVERAGE", "exercise and reproduction require evidence"
            )
        for value in self.evidence_digests:
            _digest(value, "coverage evidence")


__all__ = [
    "SCHEMA_VERSION",
    "CalibrationCase",
    "CalibrationClass",
    "CalibrationPolicy",
    "ComparisonAxis",
    "ComparisonKind",
    "ComparisonObservation",
    "ComparisonRelation",
    "ComparisonResult",
    "CoverageDimension",
    "CoverageEntry",
    "CoverageState",
    "DecisiveEvidenceBinding",
    "EvidenceRole",
    "FreshReproduction",
    "OracleCalibration",
    "OracleDisposition",
    "OracleProposal",
    "OracleSource",
    "OracleVerdict",
    "ReproductionState",
]
