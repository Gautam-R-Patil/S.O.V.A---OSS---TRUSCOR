# SPDX-License-Identifier: Apache-2.0
"""Exact-host acceptance receipt completeness and claim-boundary tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sova.formats import FormatError, validate_document
from sova.worker.host_acceptance import (
    POSITIVE_CONTROL,
    ExactHostAcceptanceReceipt,
    ExactHostCaseResult,
    HostCaseStatus,
)
from sova.worker.malicious import MaliciousGuestCase
from tests.support.worker import digest


def _case(case_id: str) -> ExactHostCaseResult:
    return ExactHostCaseResult(
        case_id=case_id,
        status=HostCaseStatus.PASSED,
        started_at="2026-08-28T12:00:00Z",
        completed_at="2026-08-28T12:01:00Z",
        execution_receipt_digest=digest(f"execution:{case_id}"),
        network_receipt_digest=digest(f"network:{case_id}"),
        evidence_digest=digest(f"evidence:{case_id}"),
        cleanup_complete=True,
        expected="The positive action succeeds or the hostile action is contained.",
        observed="Digest-bound exact-host evidence matched the predeclared oracle.",
    )


def _receipt(cases: tuple[ExactHostCaseResult, ...]) -> ExactHostAcceptanceReceipt:
    return ExactHostAcceptanceReceipt(
        release_commit="a" * 40,
        worker_id="worker:exact-host",
        measured_at="2026-08-28T12:30:00Z",
        attestation_digest=digest("attestation"),
        preflight_receipt_digest=digest("preflight"),
        guest_kernel_digest=digest("kernel"),
        root_filesystem_digest=digest("rootfs"),
        worker_policy_digest=digest("policy"),
        cases=cases,
    )


def test_complete_exact_host_matrix_passes_without_promoting_production_claim() -> None:
    case_ids = (POSITIVE_CONTROL, *(item.value for item in MaliciousGuestCase))
    receipt = _receipt(tuple(_case(case_id) for case_id in case_ids))
    mapping = receipt.to_mapping()
    validate_document(mapping)
    assert receipt.matrix_passed is True
    assert mapping["status"] == "passed"
    assert mapping["missingCaseIds"] == []
    assert mapping["failedCaseIds"] == []
    assert mapping["claims"] == {
        "exactHostMatrixPassed": True,
        "selfMeasured": True,
        "independentlyReviewed": False,
        "productionIsolationClaimAllowed": False,
        "futureEscapeImpossible": False,
    }


def test_missing_failed_and_cleanup_failed_cases_cannot_pass() -> None:
    missing = _receipt((_case(POSITIVE_CONTROL),))
    missing_mapping = missing.to_mapping()
    validate_document(missing_mapping)
    assert missing.matrix_passed is False
    assert "cleanup" in missing.missing_cases

    cases = tuple(_case(case_id) for case_id in missing.required_cases)
    failed = replace(
        cases[0],
        status=HostCaseStatus.INFRASTRUCTURE_FAILURE,
        cleanup_complete=False,
    )
    receipt = _receipt((failed, *cases[1:]))
    mapping = receipt.to_mapping()
    validate_document(mapping)
    assert receipt.matrix_passed is False
    assert failed.case_id in mapping["failedCaseIds"]
    assert mapping["claims"]["exactHostMatrixPassed"] is False


def test_duplicate_unknown_and_unbound_case_evidence_are_rejected() -> None:
    case = _case(POSITIVE_CONTROL)
    assert ExactHostCaseResult.from_mapping(case.to_mapping()) == case
    with pytest.raises(FormatError, match="unique"):
        _receipt((case, case))
    with pytest.raises(FormatError, match="unknown"):
        replace(case, case_id="unlisted-escape-test")
    with pytest.raises(FormatError, match="digest"):
        replace(case, evidence_digest="not-a-digest")


def test_case_time_observation_and_mapping_types_fail_closed() -> None:
    case = _case(POSITIVE_CONTROL)
    with pytest.raises(FormatError, match="time"):
        replace(case, started_at="not-a-time")
    with pytest.raises(FormatError, match="precedes"):
        replace(case, completed_at="2026-08-28T11:00:00Z")
    with pytest.raises(FormatError, match="required"):
        replace(case, observed="   ")
    with pytest.raises(FormatError, match="too large"):
        replace(case, expected="x" * 1_025)

    mapping = case.to_mapping()
    mapping["unknown"] = True
    with pytest.raises(FormatError, match="fields"):
        ExactHostCaseResult.from_mapping(mapping)
    mapping = case.to_mapping()
    mapping["cleanupComplete"] = "yes"
    with pytest.raises(FormatError, match="boolean"):
        ExactHostCaseResult.from_mapping(mapping)
    mapping = case.to_mapping()
    mapping["status"] = "unknown"
    with pytest.raises(FormatError, match="status"):
        ExactHostCaseResult.from_mapping(mapping)
    mapping = case.to_mapping()
    mapping["expected"] = 1
    with pytest.raises(FormatError, match="string"):
        ExactHostCaseResult.from_mapping(mapping)


def test_acceptance_receipt_binding_time_and_duplicate_cases_fail_closed() -> None:
    receipt = _receipt((_case(POSITIVE_CONTROL),))
    with pytest.raises(FormatError, match="commit"):
        replace(receipt, release_commit="bad")
    with pytest.raises(FormatError, match="time"):
        replace(receipt, measured_at="bad")
    with pytest.raises(FormatError, match="digest"):
        replace(receipt, worker_policy_digest="bad")
