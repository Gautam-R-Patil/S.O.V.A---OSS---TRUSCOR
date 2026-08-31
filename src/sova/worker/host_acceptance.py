# SPDX-License-Identifier: Apache-2.0
"""Exact-host containment observations and non-authorizing matrix receipts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.worker.malicious import MaliciousGuestCase

_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
POSITIVE_CONTROL = "positive-control"
_MAX_EXPECTED_CHARACTERS = 1_024
_MAX_OBSERVED_CHARACTERS = 4_096


class HostCaseStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


@dataclass(frozen=True, slots=True)
class ExactHostCaseResult:
    case_id: str
    status: HostCaseStatus
    started_at: str
    completed_at: str
    execution_receipt_digest: str
    network_receipt_digest: str
    evidence_digest: str
    cleanup_complete: bool
    expected: str
    observed: str

    def __post_init__(self) -> None:
        allowed = {POSITIVE_CONTROL, *(item.value for item in MaliciousGuestCase)}
        if self.case_id not in allowed:
            raise FormatError("SOVA-WORKER-HOST-CASE", "host case identifier is unknown")
        for value in (self.started_at, self.completed_at):
            if _RFC3339.fullmatch(value) is None:
                raise FormatError("SOVA-WORKER-HOST-TIME", "case time is invalid")
        if self.completed_at < self.started_at:
            raise FormatError("SOVA-WORKER-HOST-TIME", "case completion precedes start")
        for value in (
            self.execution_receipt_digest,
            self.network_receipt_digest,
            self.evidence_digest,
        ):
            if _DIGEST.fullmatch(value) is None:
                raise FormatError("SOVA-WORKER-HOST-DIGEST", "case digest is invalid")
        if not self.expected.strip() or not self.observed.strip():
            raise FormatError("SOVA-WORKER-HOST-OBSERVATION", "case observations are required")
        if (
            len(self.expected) > _MAX_EXPECTED_CHARACTERS
            or len(self.observed) > _MAX_OBSERVED_CHARACTERS
        ):
            raise FormatError("SOVA-WORKER-HOST-OBSERVATION", "case observation is too large")

    @property
    def passed(self) -> bool:
        return self.status == HostCaseStatus.PASSED and self.cleanup_complete

    def to_mapping(self) -> dict[str, Any]:
        return {
            "caseId": self.case_id,
            "status": self.status.value,
            "startedAt": self.started_at,
            "completedAt": self.completed_at,
            "executionReceiptDigest": self.execution_receipt_digest,
            "networkReceiptDigest": self.network_receipt_digest,
            "evidenceDigest": self.evidence_digest,
            "cleanupComplete": self.cleanup_complete,
            "expected": self.expected,
            "observed": self.observed,
        }

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> ExactHostCaseResult:
        expected_fields = {
            "caseId",
            "status",
            "startedAt",
            "completedAt",
            "executionReceiptDigest",
            "networkReceiptDigest",
            "evidenceDigest",
            "cleanupComplete",
            "expected",
            "observed",
        }
        if set(mapping) != expected_fields:
            raise FormatError("SOVA-WORKER-HOST-CASE", "host case fields must be exact")

        def string(name: str) -> str:
            value = mapping[name]
            if not isinstance(value, str):
                raise FormatError("SOVA-WORKER-HOST-CASE", f"{name} must be a string")
            return value

        cleanup = mapping["cleanupComplete"]
        if not isinstance(cleanup, bool):
            raise FormatError("SOVA-WORKER-HOST-CASE", "cleanupComplete must be boolean")
        try:
            status = HostCaseStatus(string("status"))
        except ValueError as error:
            raise FormatError("SOVA-WORKER-HOST-CASE", "host case status is invalid") from error
        return cls(
            case_id=string("caseId"),
            status=status,
            started_at=string("startedAt"),
            completed_at=string("completedAt"),
            execution_receipt_digest=string("executionReceiptDigest"),
            network_receipt_digest=string("networkReceiptDigest"),
            evidence_digest=string("evidenceDigest"),
            cleanup_complete=cleanup,
            expected=string("expected"),
            observed=string("observed"),
        )


@dataclass(frozen=True, slots=True)
class ExactHostAcceptanceReceipt:
    release_commit: str
    worker_id: str
    measured_at: str
    attestation_digest: str
    preflight_receipt_digest: str
    guest_kernel_digest: str
    root_filesystem_digest: str
    worker_policy_digest: str
    cases: tuple[ExactHostCaseResult, ...]

    def __post_init__(self) -> None:
        if _COMMIT.fullmatch(self.release_commit) is None:
            raise FormatError("SOVA-WORKER-HOST-COMMIT", "release commit is invalid")
        if _RFC3339.fullmatch(self.measured_at) is None:
            raise FormatError("SOVA-WORKER-HOST-TIME", "receipt time is invalid")
        for value in (
            self.attestation_digest,
            self.preflight_receipt_digest,
            self.guest_kernel_digest,
            self.root_filesystem_digest,
            self.worker_policy_digest,
        ):
            if _DIGEST.fullmatch(value) is None:
                raise FormatError("SOVA-WORKER-HOST-DIGEST", "receipt digest is invalid")
        identifiers = [item.case_id for item in self.cases]
        if len(identifiers) != len(set(identifiers)):
            raise FormatError("SOVA-WORKER-HOST-CASE", "host case identifiers must be unique")

    @property
    def required_cases(self) -> frozenset[str]:
        return frozenset({POSITIVE_CONTROL, *(item.value for item in MaliciousGuestCase)})

    @property
    def missing_cases(self) -> tuple[str, ...]:
        observed = {item.case_id for item in self.cases}
        return tuple(sorted(self.required_cases - observed))

    @property
    def failed_cases(self) -> tuple[str, ...]:
        return tuple(sorted(item.case_id for item in self.cases if not item.passed))

    @property
    def matrix_passed(self) -> bool:
        return not self.missing_cases and not self.failed_cases

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-exact-host-acceptance-receipt",
            "schemaVersion": "0.1.0",
            "releaseCommit": self.release_commit,
            "workerId": self.worker_id,
            "measuredAt": self.measured_at,
            "bindings": {
                "attestationDigest": self.attestation_digest,
                "preflightReceiptDigest": self.preflight_receipt_digest,
                "guestKernelDigest": self.guest_kernel_digest,
                "rootFilesystemDigest": self.root_filesystem_digest,
                "workerPolicyDigest": self.worker_policy_digest,
            },
            "requiredCaseIds": sorted(self.required_cases),
            "cases": [
                item.to_mapping() for item in sorted(self.cases, key=lambda item: item.case_id)
            ],
            "missingCaseIds": list(self.missing_cases),
            "failedCaseIds": list(self.failed_cases),
            "status": "passed" if self.matrix_passed else "failed",
            "claims": {
                "exactHostMatrixPassed": self.matrix_passed,
                "selfMeasured": True,
                "independentlyReviewed": False,
                "productionIsolationClaimAllowed": False,
                "futureEscapeImpossible": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


__all__ = [
    "POSITIVE_CONTROL",
    "ExactHostAcceptanceReceipt",
    "ExactHostCaseResult",
    "HostCaseStatus",
]
