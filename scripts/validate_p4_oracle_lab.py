# SPDX-License-Identifier: Apache-2.0
"""Emit a deterministic P4 oracle-laboratory acceptance receipt."""

from __future__ import annotations

import sys

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.intake import ProfileTargetKind, target_profile_template
from sova.oracle_lab import (
    ComparisonAxis,
    ComparisonKind,
    ComparisonObservation,
    ComparisonRelation,
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
    evaluate_comparison,
    predict_blinded_study,
    score_blinded_study,
    validate_oracle_lab_artifact,
)


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def main() -> int:
    profile = target_profile_template(
        identifier="owned.p4.acceptance",
        title="P4 acceptance fixture",
        target_kinds=(ProfileTargetKind.WEB, ProfileTargetKind.API, ProfileTargetKind.AGENT),
        authorization_scope="owned deterministic fixture",
    )
    proposals = derive_oracle_proposals(
        profile,
        tuple(
            ProposalSeed(
                identifier=f"oracle.acceptance.{source.value}",
                source=source,
                statement=f"Evaluate the reviewed {source.value} criterion.",
                positive_signal="The bounded positive marker is observed.",
                negative_signal="The bounded negative marker is observed.",
                ambiguous_state="Evidence is missing, conflicting, or outside scope.",
                source_references=(f"acceptance:{source.value}",),
                evidence_requirements=("digest-bound evidence", "target generation"),
                known_blind_spots=("The synthetic fixture cannot represent arbitrary targets.",),
                evaluator_config={"source": source.value, "mode": "exact-marker"},
            )
            for source in OracleSource
        ),
    )
    for proposal in proposals:
        validate_oracle_lab_artifact(proposal.to_mapping())
    proposal = proposals[0]

    task, key_draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, key_draft)
    for artifact, artifact_type in (
        (task, "sova.blinded-oracle-study"),
        (predictions, "sova.blinded-oracle-predictions"),
        (key, "sova.blinded-oracle-answer-key"),
    ):
        validate_document(artifact, artifact_type)
    calibration = score_blinded_study(
        task,
        predictions,
        key,
        proposal,
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2027-08-27T00:00:00Z",
    )
    validate_oracle_lab_artifact(calibration.to_mapping())

    adverse = {}
    for label, false_positive, miss in (
        ("false-positive", True, False),
        ("miss", False, True),
    ):
        adverse_task, adverse_draft = build_seeded_blinded_study(
            proposal_digest=proposal.digest,
            inject_false_positive=false_positive,
            inject_miss=miss,
        )
        adverse_predictions = predict_blinded_study(adverse_task)
        adverse_key = bind_answer_key_to_predictions(
            adverse_task, adverse_predictions, adverse_draft
        )
        report = score_blinded_study(
            adverse_task,
            adverse_predictions,
            adverse_key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2027-08-27T00:00:00Z",
        )
        adverse[label] = {
            "disposition": report.disposition.value,
            "counts": dict(report.counts),
            "reasons": list(report.decision_reasons),
        }

    comparisons = []
    for axis in ComparisonAxis:
        result = evaluate_comparison(
            ComparisonObservation(
                identifier=f"comparison.acceptance.{axis.value}",
                kind=(
                    ComparisonKind.METAMORPHIC
                    if axis == ComparisonAxis.INTERVENTION_PAIR
                    else ComparisonKind.DIFFERENTIAL
                ),
                axis=axis,
                relation=ComparisonRelation.EQUAL,
                left_label="baseline",
                right_label="variant",
                left_value={"allowed": False},
                right_value={"allowed": False},
                left_generation="generation.primary",
                right_generation="generation.variant",
                evidence_digests=(_digest(f"comparison:{axis.value}"),),
                evidence_complete=True,
            )
        )
        validate_oracle_lab_artifact(result.to_mapping())
        comparisons.append(result)

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
                uri=f"acceptance/{role.value}",
                digest=_digest(role.value),
                media_type=media_type,
                verified=True,
                redacted=True,
            )
            for role, media_type in zip(EvidenceRole, media_types, strict=True)
        )
    )
    validate_oracle_lab_artifact(evidence)
    reproduction = assess_fresh_reproduction(
        finding_digest=_digest("finding"),
        calibration=calibration,
        primary_target_generation="target.primary",
        reproduction_target_generation="target.fresh",
        primary_environment_fingerprint=_digest("environment:primary"),
        reproduction_environment_fingerprint=_digest("environment:fresh"),
        primary_runner_identity="runner.primary",
        reproduction_runner_identity="runner.independent",
        primary_trace_digest=_digest("trace:primary"),
        reproduction_trace_digest=_digest("trace:fresh"),
        reset_receipt_digest=_digest("reset"),
        causal_evidence_digests=(_digest("causal"),),
        evidence_set=evidence,
        oracle_verdict=OracleVerdict.POSITIVE,
        reproduction_evidence_complete=True,
        evaluated_at="2026-08-27T12:00:00Z",
    )
    validate_oracle_lab_artifact(reproduction.to_mapping())

    terminal_states = (
        CoverageState.EXERCISED,
        CoverageState.REPRODUCED,
        CoverageState.NOT_OBSERVED,
        CoverageState.UNSUPPORTED,
        CoverageState.BLOCKED,
        CoverageState.INCONCLUSIVE,
        CoverageState.INFRASTRUCTURE_FAILURE,
        CoverageState.UNKNOWN,
    )
    entries = tuple(
        CoverageEntry(
            dimension=dimension,
            subject=f"{dimension.value}.acceptance",
            state=state,
            evidence_digests=(
                (_digest(f"coverage:{dimension.value}"),)
                if state in {CoverageState.EXERCISED, CoverageState.REPRODUCED}
                else ()
            ),
            reason=f"Acceptance exercises explicit {state.value} accounting.",
        )
        for dimension, state in zip(CoverageDimension, terminal_states, strict=True)
    )
    coverage = build_coverage_report(
        entries,
        target_profile_digest=profile.digest,
        methodology_plan_digest=_digest("methodology-plan"),
    )
    validate_oracle_lab_artifact(coverage)

    passed = (
        len(proposals) == len(OracleSource)
        and calibration.disposition == OracleDisposition.PROMOTED
        and all(item["disposition"] == OracleDisposition.REJECTED for item in adverse.values())
        and all(result.relation_satisfied is True for result in comparisons)
        and reproduction.state == ReproductionState.CONFIRMED
        and len(coverage["dimensions"]) == len(CoverageDimension)
        and coverage["claims"]["allVulnerabilitiesFound"] is False
    )
    receipt = {
        "artifactType": "sova.p4-acceptance-receipt",
        "schemaVersion": "0.1.0",
        "coreAcceptancePassed": passed,
        "proposalSources": [source.value for source in OracleSource],
        "proposalCount": len(proposals),
        "calibration": {
            "disposition": calibration.disposition.value,
            "counts": dict(calibration.counts),
            "sensitivity": calibration.sensitivity,
            "specificity": calibration.specificity,
        },
        "adverseCalibration": adverse,
        "comparisonAxes": [axis.value for axis in ComparisonAxis],
        "decisiveEvidenceRoles": [role.value for role in EvidenceRole],
        "freshReproductionState": reproduction.state.value,
        "coverageDimensions": [dimension.value for dimension in CoverageDimension],
        "coverageGapCount": len(coverage["gaps"]),
        "claims": {
            "fieldValidated": False,
            "allVulnerabilitiesFound": False,
            "universallyReliableOracle": False,
        },
    }
    receipt["contentDigest"] = sha256_digest(canonical_json_bytes(receipt))
    sys.stdout.buffer.write(canonical_json_bytes(receipt) + b"\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
