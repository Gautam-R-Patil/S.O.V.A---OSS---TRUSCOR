# SPDX-License-Identifier: Apache-2.0
"""Deterministic P6 contract fixtures."""

from __future__ import annotations

from sova.formats import sha256_digest
from sova.validation import (
    BlindedTarget,
    EvaluationBudget,
    EvaluationLane,
    EvaluationObservation,
    EvaluationProtocol,
    LaneKind,
    ObservationStatus,
    RegistryBetaPolicy,
    TargetClass,
)


def digest(value: str) -> str:
    return sha256_digest(value.encode())


def protocol() -> EvaluationProtocol:
    targets = tuple(
        BlindedTarget(
            identifier=f"target:{target_class.value}",
            target_class=target_class,
            input_digest=digest(f"input:{target_class.value}"),
            answer_key_commitment=digest(f"answer:{target_class.value}"),
            authorization_receipt_digest=digest(f"authority:{target_class.value}"),
            source_revision=f"fixture-{target_class.value}-v1",
            license_identifier="Apache-2.0",
            containment_backend="synthetic-fixture",
        )
        for target_class in TargetClass
    )
    lanes = (
        EvaluationLane(
            "lane:candidate",
            LaneKind.CANDIDATE,
            "provider-a",
            "model-strong",
            "sova",
            digest("candidate-config"),
        ),
        EvaluationLane(
            "lane:baseline",
            LaneKind.BASELINE,
            "provider-a",
            "model-strong",
            "reference-agent",
            digest("baseline-config"),
        ),
        EvaluationLane(
            "lane:scripted",
            LaneKind.SCRIPTED,
            "local",
            "deterministic",
            "scripted-tools",
            digest("scripted-config"),
        ),
        EvaluationLane(
            "lane:weak",
            LaneKind.WEAK_MODEL,
            "provider-b",
            "model-small",
            "sova",
            digest("weak-config"),
        ),
    )
    return EvaluationProtocol(
        identifier="sova:p6:fixture",
        registered_at="2026-08-27T12:00:00Z",
        release_commit="f2aea32-fixture",
        targets=targets,
        lanes=lanes,
        repetitions=1,
        seed=611,
        budget=EvaluationBudget(100, 600, 1_000_000, 1_000_000, 1_000_000),
        scoring_rules_digest=digest("scoring-rules"),
        exclusions=("No Internet targets",),
        failure_rules=("Infrastructure failures remain failures",),
        answer_key_custodian="independent-fixture-custodian",
    )


def observations(plan: EvaluationProtocol) -> tuple[EvaluationObservation, ...]:
    return tuple(
        EvaluationObservation(
            protocol_digest=plan.digest,
            lane_id=lane.identifier,
            target_id=target.identifier,
            repetition=0,
            status=ObservationStatus.CONFIRMED,
            workflows_observed=2,
            workflows_total=3,
            surfaces_exercised=3,
            surfaces_total=4,
            findings_reported=2,
            findings_confirmed=1,
            findings_reproduced=1,
            false_positives=1,
            infrastructure_failures=0,
            actions_used=4,
            input_bytes=1_024,
            output_bytes=2_048,
            duration_ms=100,
            cost_microusd=200,
            containment_passed=True,
            evidence_digest=digest(f"evidence:{lane.identifier}:{target.identifier}"),
        )
        for lane in plan.lanes
        for target in plan.targets
    )


def registry_policy() -> RegistryBetaPolicy:
    return RegistryBetaPolicy(
        release_commit="f2aea32-fixture",
        release_artifact_digest=digest("release-artifacts"),
        sova_image="ghcr.io/example/sova@" + digest("sova-image"),
        edge_image="docker.io/library/caddy@" + digest("edge-image"),
        identity_issuer="https://identity.example.test",
        identity_audience="sova-registry",
        authorized_receipt_issuers=("fixture-operator",),
        moderator_roles=("triage", "publisher"),
        malware_engine="fixture-scanner",
        malware_engine_version="1.0.0",
        malware_signatures_digest=digest("malware-signatures"),
        backup_destination="encrypted://operator-vault/sova",
        backup_encrypted=True,
        backup_retention_days=30,
        rpo_minutes=60,
        rto_minutes=240,
        rollback_image_digest=digest("rollback-image"),
        incident_runbook_digest=digest("incident-runbook"),
        incident_owner="fixture-security-owner",
        requests_per_minute=60,
    )


__all__ = ["digest", "observations", "protocol", "registry_policy"]
