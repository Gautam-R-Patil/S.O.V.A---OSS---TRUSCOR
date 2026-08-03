# SPDX-License-Identifier: Apache-2.0
"""Typed self-assessment evidence and scanner-adjudication records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ObservationState(StrEnum):
    CONFIRMED = "confirmed"
    CONTRADICTED = "contradicted"
    NOT_OBSERVED = "not-observed"
    INCONCLUSIVE = "inconclusive"


class AdjudicationState(StrEnum):
    CONFIRMED_POSITIVE = "confirmed-positive"
    FALSE_POSITIVE = "false-positive-under-declared-test"
    NOT_OBSERVED = "not-observed-under-declared-test"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    role: str
    uri: str
    digest: str | None
    media_type: str
    verified: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "uri": self.uri,
            "digest": self.digest,
            "mediaType": self.media_type,
            "verified": self.verified,
        }


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Shareable finding evidence with an unavoidable self-assessment boundary."""

    finding_id: str
    title: str
    summary: str
    component: str
    version: str
    component_identifiers: tuple[str, ...]
    severity: Severity
    harm_category: str
    references: tuple[EvidenceReference, ...]
    conditions_tested: tuple[str, ...]
    tested_count: int
    coverage_denominator: int | None
    detection_floor: str
    reproduction: dict[str, Any]
    taxonomy_mappings: tuple[dict[str, str], ...]
    methodology: dict[str, str]
    mitigations: tuple[str, ...]
    regression_evidence: tuple[EvidenceReference, ...]
    attachments: tuple[EvidenceReference, ...]
    limitations: tuple[str, ...]
    lifecycle: dict[str, Any]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.evidence",
            "schemaVersion": "0.1.0",
            "finding": {
                "id": self.finding_id,
                "title": self.title,
                "summary": self.summary,
                "affected": {
                    "component": self.component,
                    "version": self.version,
                    "identifiers": list(self.component_identifiers),
                },
                "technicalSeverity": self.severity.value,
                "harmCategory": self.harm_category,
            },
            "evidence": [reference.to_mapping() for reference in self.references],
            "conditionsTested": list(self.conditions_tested),
            "coverage": {
                "testedCount": self.tested_count,
                "denominator": self.coverage_denominator,
                "detectionFloor": self.detection_floor,
                "absenceMeansSafe": False,
            },
            "reproduction": self.reproduction,
            "taxonomyMappings": list(self.taxonomy_mappings),
            "methodology": self.methodology,
            "suggestedMitigations": list(self.mitigations),
            "regressionEvidence": [item.to_mapping() for item in self.regression_evidence],
            "attachments": [item.to_mapping() for item in self.attachments],
            "lifecycle": self.lifecycle,
            "limitations": list(self.limitations),
            "assuranceBoundary": {
                "selfGenerated": True,
                "independentAttestation": False,
                "watermark": "SELF-GENERATED SOVA EVIDENCE - NOT INDEPENDENT ATTESTATION",
            },
        }


@dataclass(frozen=True, slots=True)
class ScannerFinding:
    scanner: str
    scanner_version: str
    rule_id: str
    target_id: str
    location: str
    message: str
    evidence_reference: str
    mechanism: str

    @property
    def claim_key(self) -> str:
        return f"{self.target_id}\x1f{self.rule_id}\x1f{self.location}"

    def to_mapping(self) -> dict[str, str]:
        return {
            "scanner": self.scanner,
            "scannerVersion": self.scanner_version,
            "ruleId": self.rule_id,
            "targetId": self.target_id,
            "location": self.location,
            "message": self.message,
            "evidenceReference": self.evidence_reference,
            "mechanism": self.mechanism,
        }


@dataclass(frozen=True, slots=True)
class ExecutionObservation:
    claim_key: str
    state: ObservationState
    trace_reference: str | None
    oracle_method: str
    evidence_complete: bool
    safe_and_authorized: bool
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AdjudicatedClaim:
    claim_id: str
    state: AdjudicationState
    scanner_findings: tuple[ScannerFinding, ...]
    execution_observation: ExecutionObservation | None
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        observation = self.execution_observation
        return {
            "claimId": self.claim_id,
            "state": self.state.value,
            "scannerFindings": [finding.to_mapping() for finding in self.scanner_findings],
            "executionObservation": (
                None
                if observation is None
                else {
                    "state": observation.state.value,
                    "traceReference": observation.trace_reference,
                    "oracleMethod": observation.oracle_method,
                    "evidenceComplete": observation.evidence_complete,
                    "safeAndAuthorized": observation.safe_and_authorized,
                    "limitations": list(observation.limitations),
                }
            ),
            "universalGroundTruth": False,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class AdjudicationReport:
    claims: tuple[AdjudicatedClaim, ...]
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.adjudication",
            "schemaVersion": "0.1.0",
            "claims": [claim.to_mapping() for claim in self.claims],
            "limitations": list(self.limitations),
        }


__all__ = [
    "AdjudicatedClaim",
    "AdjudicationReport",
    "AdjudicationState",
    "EvidenceBundle",
    "EvidenceReference",
    "ExecutionObservation",
    "ObservationState",
    "ScannerFinding",
    "Severity",
]
