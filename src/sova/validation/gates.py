# SPDX-License-Identifier: Apache-2.0
"""Registry operational readiness and exact-release approval ledgers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_PINNED_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _digest(value: str, role: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise FormatError("SOVA-P6-GATE-DIGEST", f"{role} must be a SHA-256 digest")


class RegistryControl(StrEnum):
    AUTHENTICATION = "authentication-authorization"
    MODERATION = "moderation-abuse-handling"
    MALWARE_SCAN = "malware-screening"
    SENSITIVE_DATA_SCAN = "secret-screening"
    RATE_LIMIT = "rate-and-ddos-controls"
    BACKUP = "encrypted-backup"
    RESTORE = "restore-test"
    ROLLBACK = "rollback-test"
    INCIDENT_RESPONSE = "incident-response"
    MONITORING = "monitoring-alert-escalation"


class ReviewGate(StrEnum):
    FOUNDER = "founder-acceptance"
    INDEPENDENT_TECHNICAL = "independent-technical-validation"
    INDEPENDENT_ISOLATION = "independent-isolation-review"
    LEGAL = "legal-license-public-disclosure"
    SECURITY = "security-signoff"


@dataclass(frozen=True, slots=True)
class RegistryBetaPolicy:
    release_commit: str
    release_artifact_digest: str
    sova_image: str
    edge_image: str
    identity_issuer: str
    identity_audience: str
    authorized_receipt_issuers: tuple[str, ...]
    moderator_roles: tuple[str, ...]
    malware_engine: str
    malware_engine_version: str
    malware_signatures_digest: str
    backup_destination: str
    backup_encrypted: bool
    backup_retention_days: int
    rpo_minutes: int
    rto_minutes: int
    rollback_image_digest: str
    incident_runbook_digest: str
    incident_owner: str
    requests_per_minute: int

    def __post_init__(self) -> None:
        texts = (
            self.release_commit,
            self.identity_issuer,
            self.identity_audience,
            self.malware_engine,
            self.malware_engine_version,
            self.backup_destination,
            self.incident_owner,
        )
        if any(not value.strip() for value in texts):
            raise FormatError(
                "SOVA-P6-REGISTRY-POLICY", "Registry policy identity fields are required"
            )
        for value, role in (
            (self.release_artifact_digest, "release artifact"),
            (self.malware_signatures_digest, "malware signatures"),
            (self.rollback_image_digest, "rollback image"),
            (self.incident_runbook_digest, "incident runbook"),
        ):
            _digest(value, role)
        for image in (self.sova_image, self.edge_image):
            if _DIGEST_PINNED_IMAGE.fullmatch(image) is None:
                raise FormatError("SOVA-P6-REGISTRY-IMAGE", "Registry images must be digest-pinned")
        if not self.moderator_roles or len(set(self.moderator_roles)) != len(self.moderator_roles):
            raise FormatError("SOVA-P6-REGISTRY-POLICY", "unique moderator roles are required")
        if (
            not self.authorized_receipt_issuers
            or len(set(self.authorized_receipt_issuers)) != len(self.authorized_receipt_issuers)
            or any(not item.strip() for item in self.authorized_receipt_issuers)
        ):
            raise FormatError(
                "SOVA-P6-REGISTRY-POLICY", "unique authorized receipt issuers are required"
            )
        counters = (
            self.backup_retention_days,
            self.rpo_minutes,
            self.rto_minutes,
            self.requests_per_minute,
        )
        if any(isinstance(value, bool) or value <= 0 for value in counters):
            raise FormatError("SOVA-P6-REGISTRY-POLICY", "operational limits must be positive")
        if not self.backup_encrypted:
            raise FormatError(
                "SOVA-P6-REGISTRY-POLICY", "production backup policy must require encryption"
            )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "releaseCommit": self.release_commit,
            "releaseArtifactDigest": self.release_artifact_digest,
            "images": {"sova": self.sova_image, "edge": self.edge_image},
            "identity": {
                "issuer": self.identity_issuer,
                "audience": self.identity_audience,
                "receiptIssuers": list(self.authorized_receipt_issuers),
            },
            "moderatorRoles": list(self.moderator_roles),
            "malware": {
                "engine": self.malware_engine,
                "version": self.malware_engine_version,
                "signaturesDigest": self.malware_signatures_digest,
            },
            "backup": {
                "destination": self.backup_destination,
                "encrypted": self.backup_encrypted,
                "retentionDays": self.backup_retention_days,
                "rpoMinutes": self.rpo_minutes,
                "rtoMinutes": self.rto_minutes,
            },
            "rollbackImageDigest": self.rollback_image_digest,
            "incidentRunbookDigest": self.incident_runbook_digest,
            "incidentOwner": self.incident_owner,
            "requestsPerMinute": self.requests_per_minute,
            "secretScreeningRequired": True,
            "operatorModerationRequired": True,
        }


@dataclass(frozen=True, slots=True)
class OperationalReceipt:
    control: RegistryControl
    policy_digest: str
    release_artifact_digest: str
    environment: str
    issuer: str
    issued_at: str
    result: str
    evidence_digest: str
    synthetic: bool = False

    def __post_init__(self) -> None:
        for value, role in (
            (self.policy_digest, "Registry policy"),
            (self.release_artifact_digest, "release artifact"),
            (self.evidence_digest, "operational evidence"),
        ):
            _digest(value, role)
        if self.result not in {"pass", "fail"}:
            raise FormatError("SOVA-P6-REGISTRY-RECEIPT", "operational result is invalid")
        if not self.environment.strip() or not self.issuer.strip() or not self.issued_at.strip():
            raise FormatError("SOVA-P6-REGISTRY-RECEIPT", "receipt identity fields are required")
        if _RFC3339_UTC.fullmatch(self.issued_at) is None:
            raise FormatError("SOVA-P6-REGISTRY-RECEIPT", "receipt time must be RFC 3339 UTC")

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.registry-operational-receipt",
            "schemaVersion": "0.1.0",
            "control": self.control.value,
            "policyDigest": self.policy_digest,
            "releaseArtifactDigest": self.release_artifact_digest,
            "environment": self.environment,
            "issuer": self.issuer,
            "issuedAt": self.issued_at,
            "result": self.result,
            "evidenceDigest": self.evidence_digest,
            "synthetic": self.synthetic,
        }


def evaluate_registry_beta(
    policy: RegistryBetaPolicy, receipts: tuple[OperationalReceipt, ...]
) -> dict[str, Any]:
    if len({item.control for item in receipts}) != len(receipts):
        raise FormatError("SOVA-P6-REGISTRY-DUPLICATE", "Registry control receipt is duplicated")
    if any(item.policy_digest != policy.digest for item in receipts):
        raise FormatError("SOVA-P6-REGISTRY-BINDING", "receipt binds another Registry policy")
    if any(item.release_artifact_digest != policy.release_artifact_digest for item in receipts):
        raise FormatError("SOVA-P6-REGISTRY-BINDING", "receipt binds another release artifact")
    indexed = {item.control: item for item in receipts}
    missing = [control.value for control in RegistryControl if control not in indexed]
    received = [control.value for control in RegistryControl if control in indexed]
    failed = [
        control.value
        for control in RegistryControl
        if control in indexed and indexed[control].result != "pass"
    ]
    synthetic = [
        control.value
        for control in RegistryControl
        if control in indexed and indexed[control].synthetic
    ]
    nonproduction = [
        control.value
        for control in RegistryControl
        if control in indexed and indexed[control].environment != "production"
    ]
    unauthorized = [
        control.value
        for control in RegistryControl
        if control in indexed and indexed[control].issuer not in policy.authorized_receipt_issuers
    ]
    live_ready = (
        not missing and not failed and not synthetic and not nonproduction and not unauthorized
    )
    report: dict[str, Any] = {
        "artifactType": "sova.registry-beta-readiness",
        "schemaVersion": "0.1.0",
        "policyDigest": policy.digest,
        "releaseCommit": policy.release_commit,
        "releaseArtifactDigest": policy.release_artifact_digest,
        "requiredControls": [item.value for item in RegistryControl],
        "receivedControls": received,
        "missingControls": missing,
        "failedControls": failed,
        "syntheticControls": synthetic,
        "nonproductionControls": nonproduction,
        "unauthorizedIssuerControls": unauthorized,
        "liveBetaReady": live_ready,
        "publicDeploymentClaimAllowed": live_ready,
        "claims": {
            "policyStructurallyComplete": True,
            "liveDeploymentObserved": live_ready,
            "backupRestoreProven": live_ready,
            "incidentResponseProven": live_ready,
        },
    }
    report["contentDigest"] = sha256_digest(canonical_json_bytes(report))
    return report


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    release_commit: str
    artifact_manifest_digest: str
    evaluation_report_digest: str
    registry_readiness_digest: str
    claims_register_digest: str
    rollback_test_digest: str
    incident_test_digest: str
    blinded_results_public: bool
    limitations_public: bool

    def __post_init__(self) -> None:
        if not self.release_commit.strip():
            raise FormatError("SOVA-P6-RELEASE", "release commit is required")
        for value, role in (
            (self.artifact_manifest_digest, "artifact manifest"),
            (self.evaluation_report_digest, "evaluation report"),
            (self.registry_readiness_digest, "Registry readiness"),
            (self.claims_register_digest, "claims register"),
            (self.rollback_test_digest, "rollback test"),
            (self.incident_test_digest, "incident test"),
        ):
            _digest(value, role)

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.release-candidate",
            "schemaVersion": "0.1.0",
            "releaseCommit": self.release_commit,
            "artifactManifestDigest": self.artifact_manifest_digest,
            "evaluationReportDigest": self.evaluation_report_digest,
            "registryReadinessDigest": self.registry_readiness_digest,
            "claimsRegisterDigest": self.claims_register_digest,
            "rollbackTestDigest": self.rollback_test_digest,
            "incidentTestDigest": self.incident_test_digest,
            "blindedResultsPublic": self.blinded_results_public,
            "limitationsPublic": self.limitations_public,
        }


@dataclass(frozen=True, slots=True)
class ReviewReceipt:
    gate: ReviewGate
    release_commit: str
    artifact_manifest_digest: str
    reviewer: str
    organization: str
    issued_at: str
    result: str
    independent: bool
    evidence_digest: str
    synthetic: bool = False

    def __post_init__(self) -> None:
        _digest(self.artifact_manifest_digest, "review artifact manifest")
        _digest(self.evidence_digest, "review evidence")
        if self.result not in {"pass", "fail"}:
            raise FormatError("SOVA-P6-REVIEW", "review result is invalid")
        if any(
            not value.strip()
            for value in (
                self.release_commit,
                self.reviewer,
                self.organization,
                self.issued_at,
            )
        ):
            raise FormatError("SOVA-P6-REVIEW", "review receipt identity fields are required")
        if _RFC3339_UTC.fullmatch(self.issued_at) is None:
            raise FormatError("SOVA-P6-REVIEW", "review time must be RFC 3339 UTC")

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.release-review-receipt",
            "schemaVersion": "0.1.0",
            "gate": self.gate.value,
            "releaseCommit": self.release_commit,
            "artifactManifestDigest": self.artifact_manifest_digest,
            "reviewer": self.reviewer,
            "organization": self.organization,
            "issuedAt": self.issued_at,
            "result": self.result,
            "independent": self.independent,
            "evidenceDigest": self.evidence_digest,
            "synthetic": self.synthetic,
        }


def evaluate_release_candidate(  # noqa: PLR0913 - release gates remain independently explicit
    candidate: ReleaseCandidate,
    reviews: tuple[ReviewReceipt, ...],
    *,
    p5_exit_passed: bool,
    blinded_field_validation_passed: bool,
    registry_live_ready: bool,
    deterministic_release_checks_passed: bool,
) -> dict[str, Any]:
    if len({item.gate for item in reviews}) != len(reviews):
        raise FormatError("SOVA-P6-REVIEW-DUPLICATE", "release review gate is duplicated")
    if any(item.release_commit != candidate.release_commit for item in reviews):
        raise FormatError("SOVA-P6-REVIEW-BINDING", "review binds another release commit")
    if any(item.artifact_manifest_digest != candidate.artifact_manifest_digest for item in reviews):
        raise FormatError("SOVA-P6-REVIEW-BINDING", "review binds another artifact manifest")
    indexed = {item.gate: item for item in reviews}
    missing = [gate.value for gate in ReviewGate if gate not in indexed]
    failed = [
        gate.value for gate in ReviewGate if gate in indexed and indexed[gate].result != "pass"
    ]
    synthetic = [gate.value for gate in ReviewGate if gate in indexed and indexed[gate].synthetic]
    founder = indexed.get(ReviewGate.FOUNDER)
    independence_failures = [
        gate.value
        for gate in (ReviewGate.INDEPENDENT_TECHNICAL, ReviewGate.INDEPENDENT_ISOLATION)
        if gate in indexed
        and (
            not indexed[gate].independent
            or (
                founder is not None
                and (
                    indexed[gate].reviewer == founder.reviewer
                    or indexed[gate].organization == founder.organization
                )
            )
        )
    ]
    external_gates = {
        "p5ProductionIsolation": p5_exit_passed,
        "blindedFieldValidation": blinded_field_validation_passed,
        "registryLiveBeta": registry_live_ready,
        "deterministicReleaseChecks": deterministic_release_checks_passed,
        "blindedResultsPublic": candidate.blinded_results_public,
        "limitationsPublic": candidate.limitations_public,
    }
    ready = (
        not missing
        and not failed
        and not synthetic
        and not independence_failures
        and all(external_gates.values())
    )
    report: dict[str, Any] = {
        "artifactType": "sova.release-gate-ledger",
        "schemaVersion": "0.1.0",
        "releaseCommit": candidate.release_commit,
        "artifactManifestDigest": candidate.artifact_manifest_digest,
        "status": "ready" if ready else "hold",
        "missingReviews": missing,
        "failedReviews": failed,
        "syntheticReviews": synthetic,
        "independenceFailures": independence_failures,
        "externalGates": external_gates,
        "tagOrPublishAllowed": ready,
        "automaticPublishPerformed": False,
        "claims": {
            "allMandatoryReceiptsBound": ready,
            "universalSecurityEstablished": False,
            "allVulnerabilitiesFound": False,
            "perfectIsolationEstablished": False,
        },
    }
    report["contentDigest"] = sha256_digest(canonical_json_bytes(report))
    return report


__all__ = [
    "OperationalReceipt",
    "RegistryBetaPolicy",
    "RegistryControl",
    "ReleaseCandidate",
    "ReviewGate",
    "ReviewReceipt",
    "evaluate_registry_beta",
    "evaluate_release_candidate",
]
