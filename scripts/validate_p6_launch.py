# SPDX-License-Identifier: Apache-2.0
"""Emit a deterministic P6 implementation receipt without fabricating external launch gates."""

from __future__ import annotations

import json
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.validation import (
    BlindedTarget,
    EvaluationBudget,
    EvaluationLane,
    EvaluationObservation,
    EvaluationProtocol,
    LaneKind,
    ObservationStatus,
    OperationalReceipt,
    RegistryBetaPolicy,
    RegistryControl,
    ReleaseCandidate,
    ReviewGate,
    ReviewReceipt,
    TargetClass,
    benchmark_adapter_catalog,
    build_evaluation_work_orders,
    evaluate_blinded_protocol,
    evaluate_registry_beta,
    evaluate_release_candidate,
)


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _protocol() -> EvaluationProtocol:
    targets = tuple(
        BlindedTarget(
            identifier=f"synthetic:{target_class.value}",
            target_class=target_class,
            input_digest=_digest(f"input:{target_class.value}"),
            answer_key_commitment=_digest(f"answer:{target_class.value}"),
            authorization_receipt_digest=_digest(f"authority:{target_class.value}"),
            source_revision=f"synthetic-{target_class.value}-v1",
            license_identifier="Apache-2.0",
            containment_backend="synthetic-no-execution",
        )
        for target_class in TargetClass
    )
    lanes = (
        EvaluationLane(
            "synthetic:candidate",
            LaneKind.CANDIDATE,
            "provider-a",
            "model-strong",
            "sova",
            _digest("candidate-config"),
        ),
        EvaluationLane(
            "synthetic:baseline",
            LaneKind.BASELINE,
            "provider-a",
            "model-strong",
            "reference-agent",
            _digest("baseline-config"),
        ),
        EvaluationLane(
            "synthetic:scripted",
            LaneKind.SCRIPTED,
            "local",
            "deterministic",
            "scripted-tools",
            _digest("scripted-config"),
        ),
        EvaluationLane(
            "synthetic:weak",
            LaneKind.WEAK_MODEL,
            "provider-b",
            "model-small",
            "sova",
            _digest("weak-config"),
        ),
    )
    return EvaluationProtocol(
        identifier="sova:p6:synthetic-acceptance",
        registered_at="2026-08-27T15:00:00Z",
        release_commit="synthetic-not-a-release-commit",
        targets=targets,
        lanes=lanes,
        repetitions=1,
        seed=611,
        budget=EvaluationBudget(100, 600, 1_000_000, 1_000_000, 1_000_000),
        scoring_rules_digest=_digest("synthetic-scoring-rules"),
        exclusions=("No live provider, target, or network execution",),
        failure_rules=("Every non-result state remains explicit",),
        answer_key_custodian="synthetic-fixture",
    )


def _observations(protocol: EvaluationProtocol) -> tuple[EvaluationObservation, ...]:
    return tuple(
        EvaluationObservation(
            protocol_digest=protocol.digest,
            lane_id=lane.identifier,
            target_id=target.identifier,
            repetition=0,
            status=ObservationStatus.NOT_OBSERVED,
            workflows_observed=0,
            workflows_total=1,
            surfaces_exercised=0,
            surfaces_total=1,
            findings_reported=0,
            findings_confirmed=0,
            findings_reproduced=0,
            false_positives=0,
            infrastructure_failures=0,
            actions_used=0,
            input_bytes=0,
            output_bytes=0,
            duration_ms=0,
            cost_microusd=0,
            containment_passed=None,
            evidence_digest=_digest(f"synthetic:{lane.identifier}:{target.identifier}"),
            limitations=("Synthetic contract exercise; no target was executed",),
        )
        for lane in protocol.lanes
        for target in protocol.targets
    )


def _registry() -> tuple[RegistryBetaPolicy, tuple[OperationalReceipt, ...]]:
    policy = RegistryBetaPolicy(
        release_commit="synthetic-not-a-release-commit",
        release_artifact_digest=_digest("synthetic-release"),
        sova_image="ghcr.io/example/sova@" + _digest("sova-image"),
        edge_image="docker.io/library/caddy@" + _digest("edge-image"),
        identity_issuer="https://identity.example.invalid",
        identity_audience="sova-registry",
        authorized_receipt_issuers=("synthetic-operator",),
        moderator_roles=("triage", "publisher"),
        malware_engine="synthetic-scanner",
        malware_engine_version="0.0.0",
        malware_signatures_digest=_digest("synthetic-signatures"),
        backup_destination="encrypted://synthetic",
        backup_encrypted=True,
        backup_retention_days=30,
        rpo_minutes=60,
        rto_minutes=240,
        rollback_image_digest=_digest("rollback-image"),
        incident_runbook_digest=_digest("incident-runbook"),
        incident_owner="synthetic-owner",
        requests_per_minute=60,
    )
    receipts = tuple(
        OperationalReceipt(
            control=control,
            policy_digest=policy.digest,
            release_artifact_digest=policy.release_artifact_digest,
            environment="synthetic",
            issuer="synthetic-fixture",
            issued_at="2026-08-27T15:01:00Z",
            result="pass",
            evidence_digest=_digest(f"synthetic-operation:{control.value}"),
            synthetic=True,
        )
        for control in RegistryControl
    )
    return policy, receipts


def _release(
    evaluation_digest: str, registry_digest: str
) -> tuple[ReleaseCandidate, tuple[ReviewReceipt, ...]]:
    candidate = ReleaseCandidate(
        release_commit="synthetic-not-a-release-commit",
        artifact_manifest_digest=_digest("synthetic-artifact-manifest"),
        evaluation_report_digest=evaluation_digest,
        registry_readiness_digest=registry_digest,
        claims_register_digest=_digest("synthetic-claims-register"),
        public_claims_snapshot_digest=_digest("synthetic-public-claims-snapshot"),
        rollback_test_digest=_digest("synthetic-rollback"),
        incident_test_digest=_digest("synthetic-incident"),
        blinded_results_public=False,
        limitations_public=False,
    )
    reviews = tuple(
        ReviewReceipt(
            gate=gate,
            release_commit=candidate.release_commit,
            artifact_manifest_digest=candidate.artifact_manifest_digest,
            reviewer=f"synthetic:{gate.value}",
            organization="synthetic-fixture",
            issued_at="2026-08-27T15:02:00Z",
            result="pass",
            independent=gate
            in {ReviewGate.INDEPENDENT_TECHNICAL, ReviewGate.INDEPENDENT_ISOLATION},
            evidence_digest=_digest(f"synthetic-review:{gate.value}"),
            synthetic=True,
        )
        for gate in ReviewGate
    )
    return candidate, reviews


def build_acceptance_receipt() -> dict[str, Any]:
    protocol = _protocol()
    validate_document(protocol.to_mapping())
    work_orders = build_evaluation_work_orders(protocol)
    validate_document(work_orders)
    evaluation = evaluate_blinded_protocol(protocol, _observations(protocol))
    validate_document(evaluation)
    policy, operational_receipts = _registry()
    registry = evaluate_registry_beta(policy, operational_receipts)
    validate_document(registry)
    candidate, reviews = _release(evaluation["contentDigest"], registry["contentDigest"])
    release = evaluate_release_candidate(
        candidate,
        reviews,
        p5_exit_passed=False,
        blinded_field_validation_passed=False,
        registry_live_ready=False,
        deterministic_release_checks_passed=True,
        public_claims_reconciled=False,
    )
    validate_document(release)
    receipt: dict[str, Any] = {
        "artifactType": "sova.p6-acceptance-receipt",
        "schemaVersion": "0.1.0",
        "localImplementationAcceptancePassed": True,
        "adapterCount": len(benchmark_adapter_catalog()),
        "targetClassCount": len(protocol.targets),
        "laneKinds": [item.value for item in LaneKind],
        "predeclaredRunCount": protocol.run_count,
        "workOrderCount": len(work_orders["workOrders"]),
        "workOrderSetDigest": work_orders["contentDigest"],
        "evaluationReportDigest": evaluation["contentDigest"],
        "registryReadinessDigest": registry["contentDigest"],
        "releaseGateLedgerDigest": release["contentDigest"],
        "p6ExitGatePassed": False,
        "claims": {
            "liveProvidersExecuted": False,
            "blindedFieldTargetsExecuted": False,
            "strongestBaselinesEstablished": False,
            "registryPubliclyDeployed": False,
            "externalReviewsObtained": False,
            "tagOrPublishAllowed": False,
            "tagOrPublishPerformed": False,
            "allVulnerabilitiesFound": False,
        },
        "controls": {
            "P6-01": (
                "freeze-and-complete-work-order-machinery-passed-real-preregistration-required"
            ),
            "P6-02": "external-provider-runs-required",
            "P6-03": "owned-or-licensed-blinded-field-runs-required",
            "P6-04": "five-provenance-bound-adapter-contracts-passed",
            "P6-05": "actual-matched-baseline-runs-required",
            "P6-06": "complete-metric-ledger-passed",
            "P6-07": "operations-policy-and-local-backup-passed-live-beta-required",
            "P6-08": "exact-final-commit-release-validation-required",
            "P6-09": "five-real-review-receipts-required",
            "P6-10": "exact-claims-binding-passed-live-reconciliation-required",
            "P6-11": "publication-held",
        },
    }
    receipt["contentDigest"] = sha256_digest(canonical_json_bytes(receipt))
    return receipt


def main() -> int:
    print(json.dumps(build_acceptance_receipt(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
