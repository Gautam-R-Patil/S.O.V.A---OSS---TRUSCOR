# SPDX-License-Identifier: Apache-2.0
"""Registry and release-gate ledger tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sova.formats import FormatError, validate_document
from sova.validation import (
    OperationalReceipt,
    RegistryControl,
    ReleaseCandidate,
    ReviewGate,
    ReviewReceipt,
    evaluate_registry_beta,
    evaluate_release_candidate,
)
from tests.support.p6 import digest, registry_policy


def _ops(*, synthetic: bool, environment: str) -> tuple[OperationalReceipt, ...]:
    policy = registry_policy()
    return tuple(
        OperationalReceipt(
            control=control,
            policy_digest=policy.digest,
            release_artifact_digest=policy.release_artifact_digest,
            environment=environment,
            issuer="fixture-operator",
            issued_at="2026-08-27T13:00:00Z",
            result="pass",
            evidence_digest=digest(f"operation:{control.value}"),
            synthetic=synthetic,
        )
        for control in RegistryControl
    )


def _candidate() -> ReleaseCandidate:
    return ReleaseCandidate(
        release_commit="f2aea32-fixture",
        artifact_manifest_digest=digest("artifact-manifest"),
        evaluation_report_digest=digest("evaluation-report"),
        registry_readiness_digest=digest("registry-readiness"),
        claims_register_digest=digest("claims-register"),
        rollback_test_digest=digest("rollback-test"),
        incident_test_digest=digest("incident-test"),
        blinded_results_public=True,
        limitations_public=True,
    )


def _reviews(*, synthetic: bool = False) -> tuple[ReviewReceipt, ...]:
    candidate = _candidate()
    return tuple(
        ReviewReceipt(
            gate=gate,
            release_commit=candidate.release_commit,
            artifact_manifest_digest=candidate.artifact_manifest_digest,
            reviewer=f"reviewer:{gate.value}",
            organization=f"organization:{gate.value}",
            issued_at="2026-08-27T14:00:00Z",
            result="pass",
            independent=gate
            in {ReviewGate.INDEPENDENT_TECHNICAL, ReviewGate.INDEPENDENT_ISOLATION},
            evidence_digest=digest(f"review:{gate.value}"),
            synthetic=synthetic,
        )
        for gate in ReviewGate
    )


def test_registry_policy_and_production_receipts_can_satisfy_gate() -> None:
    policy = registry_policy()
    receipts = _ops(synthetic=False, environment="production")
    report = evaluate_registry_beta(policy, receipts)
    validate_document(report)
    assert report["liveBetaReady"] is True
    assert report["claims"]["backupRestoreProven"] is True
    assert (
        evaluate_registry_beta(policy, tuple(reversed(receipts)))["contentDigest"]
        == report["contentDigest"]
    )


def test_synthetic_registry_receipts_do_not_claim_live_deployment() -> None:
    policy = registry_policy()
    report = evaluate_registry_beta(policy, _ops(synthetic=True, environment="fixture"))
    assert report["liveBetaReady"] is False
    assert len(report["syntheticControls"]) == 10
    assert len(report["nonproductionControls"]) == 10


def test_registry_gate_exposes_missing_failed_duplicate_and_drift() -> None:
    policy = registry_policy()
    rows = _ops(synthetic=False, environment="production")
    missing = evaluate_registry_beta(policy, rows[:-1])
    assert len(missing["missingControls"]) == 1
    failed = evaluate_registry_beta(policy, (replace(rows[0], result="fail"), *rows[1:]))
    assert failed["failedControls"] == [rows[0].control.value]
    unauthorized = evaluate_registry_beta(
        policy, (replace(rows[0], issuer="untrusted-operator"), *rows[1:])
    )
    assert unauthorized["unauthorizedIssuerControls"] == [rows[0].control.value]
    assert unauthorized["liveBetaReady"] is False
    with pytest.raises(FormatError, match="duplicated"):
        evaluate_registry_beta(policy, (rows[0], rows[0]))
    with pytest.raises(FormatError, match="another Registry policy"):
        evaluate_registry_beta(policy, (replace(rows[0], policy_digest=digest("other")),))
    with pytest.raises(FormatError, match="another release artifact"):
        evaluate_registry_beta(
            policy,
            (replace(rows[0], release_artifact_digest=digest("other")),),
        )


def test_release_ledger_stays_on_hold_without_real_external_gates() -> None:
    candidate = _candidate()
    report = evaluate_release_candidate(
        candidate,
        _reviews(synthetic=True),
        p5_exit_passed=False,
        blinded_field_validation_passed=False,
        registry_live_ready=False,
        deterministic_release_checks_passed=True,
    )
    validate_document(report)
    assert report["status"] == "hold"
    assert report["tagOrPublishAllowed"] is False
    assert len(report["syntheticReviews"]) == 5
    assert report["claims"]["allVulnerabilitiesFound"] is False


def test_release_ledger_can_be_ready_only_with_all_exact_real_receipts() -> None:
    candidate = _candidate()
    reviews = _reviews()
    report = evaluate_release_candidate(
        candidate,
        reviews,
        p5_exit_passed=True,
        blinded_field_validation_passed=True,
        registry_live_ready=True,
        deterministic_release_checks_passed=True,
    )
    assert report["status"] == "ready"
    assert report["tagOrPublishAllowed"] is True
    assert report["automaticPublishPerformed"] is False
    assert (
        evaluate_release_candidate(
            candidate,
            tuple(reversed(reviews)),
            p5_exit_passed=True,
            blinded_field_validation_passed=True,
            registry_live_ready=True,
            deterministic_release_checks_passed=True,
        )["contentDigest"]
        == report["contentDigest"]
    )


def test_release_ledger_rejects_duplicate_binding_and_nonindependent_review() -> None:
    candidate = _candidate()
    rows = _reviews()
    with pytest.raises(FormatError, match="duplicated"):
        evaluate_release_candidate(
            candidate,
            (rows[0], rows[0]),
            p5_exit_passed=True,
            blinded_field_validation_passed=True,
            registry_live_ready=True,
            deterministic_release_checks_passed=True,
        )
    with pytest.raises(FormatError, match="another release commit"):
        evaluate_release_candidate(
            candidate,
            (replace(rows[0], release_commit="other"),),
            p5_exit_passed=True,
            blinded_field_validation_passed=True,
            registry_live_ready=True,
            deterministic_release_checks_passed=True,
        )
    nonindependent = tuple(
        replace(item, independent=False) if item.gate is ReviewGate.INDEPENDENT_TECHNICAL else item
        for item in rows
    )
    report = evaluate_release_candidate(
        candidate,
        nonindependent,
        p5_exit_passed=True,
        blinded_field_validation_passed=True,
        registry_live_ready=True,
        deterministic_release_checks_passed=True,
    )
    assert report["status"] == "hold"
    assert report["independenceFailures"] == [ReviewGate.INDEPENDENT_TECHNICAL.value]
    founder = rows[0]
    conflicted = tuple(
        replace(item, organization=founder.organization)
        if item.gate is ReviewGate.INDEPENDENT_ISOLATION
        else item
        for item in rows
    )
    report = evaluate_release_candidate(
        candidate,
        conflicted,
        p5_exit_passed=True,
        blinded_field_validation_passed=True,
        registry_live_ready=True,
        deterministic_release_checks_passed=True,
    )
    assert report["status"] == "hold"
    assert report["independenceFailures"] == [ReviewGate.INDEPENDENT_ISOLATION.value]


def test_operational_review_and_candidate_contracts_reject_invalid_receipts() -> None:
    operation = _ops(synthetic=False, environment="production")[0]
    with pytest.raises(FormatError, match="result"):
        replace(operation, result="unknown")
    with pytest.raises(FormatError, match="identity"):
        replace(operation, issuer="")
    with pytest.raises(FormatError, match="RFC 3339"):
        replace(operation, issued_at="not-a-time")
    with pytest.raises(FormatError, match="SHA-256"):
        replace(operation, evidence_digest="bad")

    candidate = _candidate()
    with pytest.raises(FormatError, match="commit"):
        replace(candidate, release_commit="")
    with pytest.raises(FormatError, match="SHA-256"):
        replace(candidate, incident_test_digest="bad")

    review = _reviews()[0]
    with pytest.raises(FormatError, match="result"):
        replace(review, result="unknown")
    with pytest.raises(FormatError, match="identity"):
        replace(review, reviewer="")
    with pytest.raises(FormatError, match="RFC 3339"):
        replace(review, issued_at="not-a-time")
    with pytest.raises(FormatError, match="SHA-256"):
        replace(review, artifact_manifest_digest="bad")


def test_registry_policy_rejects_mutable_images_unencrypted_backup_and_bad_limits() -> None:
    policy = registry_policy()
    with pytest.raises(FormatError, match="digest-pinned"):
        replace(policy, sova_image="ghcr.io/example/sova:latest")
    with pytest.raises(FormatError, match="digest-pinned"):
        replace(policy, sova_image="ghcr.io/example/sova@sha256:" + ("z" * 64))
    with pytest.raises(FormatError, match="encryption"):
        replace(policy, backup_encrypted=False)
    with pytest.raises(FormatError, match="positive"):
        replace(policy, requests_per_minute=0)
    with pytest.raises(FormatError, match="identity"):
        replace(policy, identity_issuer="")
    with pytest.raises(FormatError, match="SHA-256"):
        replace(policy, malware_signatures_digest="bad")
    with pytest.raises(FormatError, match="moderator"):
        replace(policy, moderator_roles=())
    with pytest.raises(FormatError, match="receipt issuers"):
        replace(policy, authorized_receipt_issuers=())
