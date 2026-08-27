# SPDX-License-Identifier: Apache-2.0
"""P4 vertical slice from proposal through confirmed fresh reproduction."""

from __future__ import annotations

from sova.formats import sha256_digest, validate_document
from sova.intake import ProfileTargetKind, target_profile_template
from sova.oracle_lab import (
    CoverageDimension,
    CoverageEntry,
    CoverageState,
    DecisiveEvidenceBinding,
    EvidenceRole,
    OracleDisposition,
    OracleSource,
    OracleVerdict,
    ProposalSeed,
    ReproductionState,
    assess_fresh_reproduction,
    bind_answer_key_to_predictions,
    bind_decisive_evidence,
    build_coverage_report,
    build_seeded_blinded_study,
    derive_oracle_proposals,
    predict_blinded_study,
    score_blinded_study,
)


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def test_p4_proposal_calibration_evidence_reproduction_and_coverage() -> None:
    profile = target_profile_template(
        identifier="owned.p4.target",
        title="Owned P4 fixture",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned seeded fixture",
    )
    proposal = derive_oracle_proposals(
        profile,
        (
            ProposalSeed(
                identifier="oracle.owned.authorization",
                source=OracleSource.INVARIANT,
                statement="Unauthorized identity cannot read the protected object.",
                positive_signal="Protected object was returned to unauthorized identity.",
                negative_signal="Unauthorized identity received a denial without protected data.",
                ambiguous_state="Response or identity evidence was incomplete.",
                source_references=("contract:owned.authorization",),
                evidence_requirements=("identity-bound trace", "response receipt"),
                known_blind_spots=("Unobserved secondary channels remain outside the oracle.",),
            ),
        ),
    )[0]
    validate_document(proposal.to_mapping(), "sova.oracle-proposal")
    task, key_draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, key_draft)
    calibration = score_blinded_study(
        task,
        predictions,
        key,
        proposal,
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-11-27T00:00:00Z",
    )
    assert calibration.disposition == OracleDisposition.PROMOTED

    media_types = (
        "application/json",
        "application/octet-stream",
        "video/webm",
        "application/vnd.sova.trace+zip",
        "application/vnd.sova.capsule+zip",
    )
    evidence = bind_decisive_evidence(
        tuple(
            DecisiveEvidenceBinding(
                role=role,
                uri=f"fixture/{role.value}",
                digest=_digest(role.value),
                media_type=media_type,
                verified=True,
                redacted=True,
            )
            for role, media_type in zip(EvidenceRole, media_types, strict=True)
        )
    )
    reproduction = assess_fresh_reproduction(
        finding_digest=_digest("finding"),
        calibration=calibration,
        primary_target_generation="target.primary",
        reproduction_target_generation="target.reproduction",
        primary_environment_fingerprint=_digest("environment-primary"),
        reproduction_environment_fingerprint=_digest("environment-reproduction"),
        primary_runner_identity="runner.primary",
        reproduction_runner_identity="runner.reproduction",
        primary_trace_digest=_digest("trace-primary"),
        reproduction_trace_digest=_digest("trace-reproduction"),
        reset_receipt_digest=_digest("reset-receipt"),
        causal_evidence_digests=(_digest("causal-pair"),),
        evidence_set=evidence,
        oracle_verdict=OracleVerdict.POSITIVE,
        reproduction_evidence_complete=True,
        evaluated_at="2026-08-27T12:00:00Z",
    )
    assert reproduction.state == ReproductionState.CONFIRMED
    validate_document(reproduction.to_mapping(), "sova.fresh-reproduction")

    entries = tuple(
        CoverageEntry(
            dimension=dimension,
            subject=f"{dimension.value}.owned-fixture",
            state=(
                CoverageState.REPRODUCED
                if dimension in {CoverageDimension.ORACLE, CoverageDimension.REPRODUCTION}
                else CoverageState.EXERCISED
            ),
            evidence_digests=(_digest(f"coverage:{dimension.value}"),),
            reason="Bounded owned-fixture evidence exists.",
        )
        for dimension in CoverageDimension
    )
    coverage = build_coverage_report(
        entries,
        target_profile_digest=profile.digest,
        methodology_plan_digest=_digest("methodology-plan"),
    )
    validate_document(coverage, "sova.assessment-coverage")
    assert coverage["gaps"] == []
    assert coverage["claims"]["exhaustive"] is False
