# SPDX-License-Identifier: Apache-2.0
"""Bounded offline validation for P4 JSON artifacts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.oracle_lab.contracts import (
    CalibrationCase,
    CalibrationClass,
    CalibrationPolicy,
    OracleCalibration,
    OracleDisposition,
    OracleProposal,
    OracleSource,
    OracleVerdict,
)

if TYPE_CHECKING:
    from pathlib import Path

_CONTENT_ADDRESSED_TYPES = frozenset(
    {
        "sova.oracle-proposal",
        "sova.oracle-calibration",
        "sova.oracle-comparison",
        "sova.decisive-evidence-set",
        "sova.fresh-reproduction",
        "sova.assessment-coverage",
    }
)


def validate_oracle_lab_artifact(document: dict[str, Any]) -> None:
    """Validate schema and, where present, the canonical content digest."""
    artifact_type = document.get("artifactType")
    if not isinstance(artifact_type, str):
        raise FormatError("SOVA-ORACLE-LAB-TYPE", "artifact type is required")
    validate_document(document, artifact_type)
    if artifact_type in _CONTENT_ADDRESSED_TYPES:
        supplied = document.get("contentDigest")
        digest_body = dict(document)
        digest_body.pop("contentDigest", None)
        actual = sha256_digest(canonical_json_bytes(digest_body))
        if supplied != actual:
            raise FormatError("SOVA-ORACLE-LAB-DIGEST", "artifact content digest does not match")


def read_oracle_lab_artifact(path: Path) -> dict[str, Any]:
    """Read one bounded UTF-8 JSON artifact without executing target-controlled data."""
    document = strict_json_loads(path.read_bytes(), max_bytes=16 * 1024 * 1024)
    if not isinstance(document, dict):
        raise FormatError("SOVA-ORACLE-LAB-ROOT", "artifact root must be an object")
    validate_oracle_lab_artifact(document)
    return document


def proposal_from_mapping(document: dict[str, Any]) -> OracleProposal:
    """Parse a validated proposal while retaining its unvalidated lifecycle state."""
    validate_oracle_lab_artifact(document)
    if document.get("artifactType") != "sova.oracle-proposal":
        raise FormatError("SOVA-ORACLE-LAB-TYPE", "document is not an oracle proposal")
    evaluator = document["evaluator"]
    signals = document["signals"]
    return OracleProposal(
        identifier=document["id"],
        target_profile_digest=document["targetProfileDigest"],
        source=OracleSource(document["source"]),
        statement=document["statement"],
        evaluator_id=evaluator["id"],
        evaluator_version=evaluator["version"],
        evaluator_config_digest=evaluator["configDigest"],
        positive_signal=signals["positive"],
        negative_signal=signals["negative"],
        ambiguous_state=signals["ambiguous"],
        source_references=tuple(document["sourceReferences"]),
        evidence_requirements=tuple(document["evidenceRequirements"]),
        known_blind_spots=tuple(document["knownBlindSpots"]),
    )


def calibration_from_mapping(document: dict[str, Any]) -> OracleCalibration:
    """Parse a validated calibration for later freshness/reproduction checks."""
    validate_oracle_lab_artifact(document)
    if document.get("artifactType") != "sova.oracle-calibration":
        raise FormatError("SOVA-ORACLE-LAB-TYPE", "document is not an oracle calibration")
    raw_policy = document["policy"]
    policy = CalibrationPolicy(
        minimum_positive_cases=raw_policy["minimumPositiveCases"],
        minimum_negative_cases=raw_policy["minimumNegativeCases"],
        maximum_false_positives=raw_policy["maximumFalsePositives"],
        maximum_misses=raw_policy["maximumMisses"],
        require_ambiguous_abstention=raw_policy["requireAmbiguousAbstention"],
        require_infrastructure_separation=raw_policy["requireInfrastructureSeparation"],
    )
    cases = tuple(
        CalibrationCase(
            identifier=item["id"],
            expected_class=CalibrationClass(item["expectedClass"]),
            verdict=OracleVerdict(item["verdict"]),
            target_generation=item["targetGeneration"],
            environment_fingerprint=item["environmentFingerprint"],
            prediction_digest=item["predictionDigest"],
            evidence_digests=tuple(item["evidenceDigests"]),
            label_revealed_after_prediction=item["labelRevealedAfterPrediction"],
        )
        for item in document["cases"]
    )
    raw_metrics = document["metrics"]
    interval = raw_metrics["jointWilson95"]
    validity = document["validity"]
    return OracleCalibration(
        proposal_digest=document["proposalDigest"],
        policy=policy,
        cases=cases,
        disposition=OracleDisposition(document["disposition"]),
        counts=tuple(raw_metrics["counts"].items()),
        sensitivity=raw_metrics["sensitivity"],
        specificity=raw_metrics["specificity"],
        confidence_interval_low=interval["low"],
        confidence_interval_high=interval["high"],
        valid_from=validity["from"],
        valid_until=validity["until"],
        known_blind_spots=tuple(document["knownBlindSpots"]),
        decision_reasons=tuple(document["decisionReasons"]),
    )


__all__ = [
    "calibration_from_mapping",
    "proposal_from_mapping",
    "read_oracle_lab_artifact",
    "validate_oracle_lab_artifact",
]
