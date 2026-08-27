# SPDX-License-Identifier: Apache-2.0
"""P4 oracle lifecycle, comparison, evidence, and coverage contracts."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.intake import ProfileTargetKind, target_profile_template
from sova.oracle_lab import (
    CalibrationCase,
    CalibrationPolicy,
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
    calibrate_oracle,
    calibration_from_mapping,
    derive_oracle_proposals,
    evaluate_comparison,
    predict_blinded_study,
    proposal_from_mapping,
    read_oracle_lab_artifact,
    score_blinded_study,
    validate_oracle_lab_artifact,
)
from sova.oracle_lab.contracts import CalibrationClass, OracleProposal

if TYPE_CHECKING:
    from pathlib import Path

    from sova.intake.contracts import TargetProfile


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _profile() -> TargetProfile:
    return target_profile_template(
        identifier="owned.composite",
        title="Owned composite target",
        target_kinds=(ProfileTargetKind.WEB, ProfileTargetKind.API, ProfileTargetKind.AGENT),
        authorization_scope="owned fixture",
    )


def _proposal(source: OracleSource = OracleSource.INVARIANT) -> OracleProposal:
    seed = ProposalSeed(
        identifier=f"oracle.{source.value}",
        source=source,
        statement="The declared security boundary remains intact.",
        positive_signal="A controlled violation is directly observed.",
        negative_signal="The protected state is unchanged under the declared trial.",
        ambiguous_state="Required observations are absent or disagree.",
        source_references=(f"source:{source.value}",),
        evidence_requirements=("signed trace", "raw effect receipt"),
        known_blind_spots=("Uninstrumented external side effects remain unknown.",),
        evaluator_config={"kind": source.value, "threshold": "exact"},
    )
    return derive_oracle_proposals(_profile(), (seed,))[0]


def _bindings() -> tuple[DecisiveEvidenceBinding, ...]:
    media = {
        EvidenceRole.DECISIVE_CUE: "application/json",
        EvidenceRole.RAW_EVIDENCE: "application/octet-stream",
        EvidenceRole.REPLAY_MEDIA: "video/webm",
        EvidenceRole.TRACE: "application/vnd.sova.trace+zip",
        EvidenceRole.CAPSULE: "application/vnd.sova.capsule+zip",
    }
    return tuple(
        DecisiveEvidenceBinding(
            role=role,
            uri=f"artifact/{role.value}",
            digest=_digest(role.value),
            media_type=media[role],
            verified=True,
            redacted=True,
        )
        for role in EvidenceRole
    )


def test_all_proposal_sources_are_typed_bound_non_authorizing_and_schema_valid() -> None:
    proposals = tuple(_proposal(source) for source in OracleSource)
    assert {item.source for item in proposals} == set(OracleSource)
    for proposal in proposals:
        document = proposal.to_mapping()
        validate_document(document, "sova.oracle-proposal")
        assert document["claims"] == {
            "executionAuthorized": False,
            "findingConfirmed": False,
            "universallyReliable": False,
        }
        assert document["targetProfileDigest"] == _profile().digest
    assert derive_oracle_proposals(_profile(), ()) == ()


def test_calibration_promotes_only_complete_blinded_error_free_cases() -> None:
    proposal = _proposal()
    task, key_draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, key_draft)
    for artifact, kind in (
        (task, "sova.blinded-oracle-study"),
        (predictions, "sova.blinded-oracle-predictions"),
        (key, "sova.blinded-oracle-answer-key"),
    ):
        validate_document(artifact, kind)
    calibration = score_blinded_study(
        task,
        predictions,
        key,
        proposal,
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-11-27T00:00:00Z",
    )
    assert calibration.disposition == OracleDisposition.PROMOTED
    assert calibration.sensitivity == "1"
    assert calibration.specificity == "1"
    assert dict(calibration.counts)["falsePositive"] == 0
    assert dict(calibration.counts)["miss"] == 0
    validate_document(calibration.to_mapping(), "sova.oracle-calibration")


@pytest.mark.parametrize(
    ("injected_error", "reason"),
    (
        ("false-positive", "false-positive-threshold-exceeded"),
        ("miss", "miss-threshold-exceeded"),
    ),
)
def test_blinded_seeded_study_measures_and_rejects_errors(injected_error: str, reason: str) -> None:
    proposal = _proposal()
    task, draft = build_seeded_blinded_study(
        proposal_digest=proposal.digest,
        inject_false_positive=injected_error == "false-positive",
        inject_miss=injected_error == "miss",
    )
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, draft)
    calibration = score_blinded_study(
        task,
        predictions,
        key,
        proposal,
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-11-27T00:00:00Z",
    )
    assert calibration.disposition == OracleDisposition.REJECTED
    assert reason in calibration.decision_reasons


def test_calibration_preserves_no_oracle_and_human_review_outcomes() -> None:
    proposal = _proposal()
    case = CalibrationCase(
        identifier="case.ambiguous",
        expected_class=CalibrationClass.AMBIGUOUS,
        verdict=OracleVerdict.ABSTAIN,
        target_generation="generation.1",
        environment_fingerprint=_digest("environment"),
        prediction_digest=_digest("prediction"),
        evidence_digests=(_digest("evidence"),),
    )
    no_oracle = calibrate_oracle(
        proposal,
        (case,),
        policy=CalibrationPolicy(),
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-09-27T00:00:00Z",
    )
    assert no_oracle.disposition == OracleDisposition.NO_RELIABLE_ORACLE
    human = calibrate_oracle(
        proposal,
        (case,),
        policy=CalibrationPolicy(),
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-09-27T00:00:00Z",
        require_human_review=True,
    )
    assert human.disposition == OracleDisposition.HUMAN_REVIEW_REQUIRED


@pytest.mark.parametrize("axis", list(ComparisonAxis))
def test_comparison_covers_every_required_axis(axis: ComparisonAxis) -> None:
    result = evaluate_comparison(
        ComparisonObservation(
            identifier=f"comparison.{axis.value}",
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
            left_generation="generation-a",
            right_generation="generation-b",
            evidence_digests=(_digest(f"comparison:{axis.value}"),),
            evidence_complete=True,
        )
    )
    assert result.verdict == OracleVerdict.POSITIVE
    assert result.relation_satisfied is True
    validate_document(result.to_mapping(), "sova.oracle-comparison")


def test_comparison_separates_incomplete_infrastructure_and_unsupported() -> None:
    base = ComparisonObservation(
        identifier="comparison.state",
        kind=ComparisonKind.METAMORPHIC,
        axis=ComparisonAxis.STATE,
        relation=ComparisonRelation.SUBSET,
        left_label="baseline",
        right_label="variant",
        left_value=42,
        right_value=43,
        left_generation="generation-a",
        right_generation="generation-b",
        evidence_digests=(_digest("comparison"),),
        evidence_complete=True,
    )
    assert evaluate_comparison(base).verdict == OracleVerdict.UNSUPPORTED
    assert evaluate_comparison(replace(base, evidence_complete=False)).verdict == (
        OracleVerdict.INCONCLUSIVE
    )
    assert evaluate_comparison(replace(base, infrastructure_failure=True)).verdict == (
        OracleVerdict.INFRASTRUCTURE_FAILURE
    )


def test_decisive_evidence_requires_all_digest_verified_roles() -> None:
    evidence = bind_decisive_evidence(_bindings())
    validate_document(evidence, "sova.decisive-evidence-set")
    assert evidence["complete"] is True
    with pytest.raises(FormatError, match="incomplete"):
        bind_decisive_evidence(_bindings()[:-1])
    with pytest.raises(FormatError, match="verified"):
        bind_decisive_evidence((replace(_bindings()[0], verified=False), *_bindings()[1:]))


def test_fresh_reproduction_requires_promoted_oracle_fresh_generation_and_runner() -> None:
    proposal = _proposal()
    task, draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, draft)
    calibration = score_blinded_study(
        task,
        predictions,
        key,
        proposal,
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-11-27T00:00:00Z",
    )
    evidence = bind_decisive_evidence(_bindings())
    confirmed = assess_fresh_reproduction(
        finding_digest=_digest("finding"),
        calibration=calibration,
        primary_target_generation="target.generation.1",
        reproduction_target_generation="target.generation.2",
        primary_environment_fingerprint=_digest("environment:1"),
        reproduction_environment_fingerprint=_digest("environment:2"),
        primary_runner_identity="runner.primary",
        reproduction_runner_identity="runner.independent",
        primary_trace_digest=_digest("trace:1"),
        reproduction_trace_digest=_digest("trace:2"),
        reset_receipt_digest=_digest("reset"),
        causal_evidence_digests=(_digest("causal"),),
        evidence_set=evidence,
        oracle_verdict=OracleVerdict.POSITIVE,
        reproduction_evidence_complete=True,
        evaluated_at="2026-08-27T12:00:00Z",
    )
    assert confirmed.state == ReproductionState.CONFIRMED
    validate_document(confirmed.to_mapping(), "sova.fresh-reproduction")
    stale = assess_fresh_reproduction(
        finding_digest=_digest("finding"),
        calibration=calibration,
        primary_target_generation="target.generation.1",
        reproduction_target_generation="target.generation.1",
        primary_environment_fingerprint=_digest("environment:1"),
        reproduction_environment_fingerprint=_digest("environment:2"),
        primary_runner_identity="runner.primary",
        reproduction_runner_identity="runner.primary",
        primary_trace_digest=_digest("trace:1"),
        reproduction_trace_digest=_digest("trace:2"),
        reset_receipt_digest=_digest("reset"),
        causal_evidence_digests=(_digest("causal"),),
        evidence_set=evidence,
        oracle_verdict=OracleVerdict.POSITIVE,
        reproduction_evidence_complete=True,
        evaluated_at="2026-08-27T12:00:00Z",
    )
    assert stale.state == ReproductionState.INCONCLUSIVE
    assert "target-generation-not-fresh" in stale.reasons
    assert "runner-not-independent" in stale.reasons
    expired = assess_fresh_reproduction(
        finding_digest=_digest("finding"),
        calibration=calibration,
        primary_target_generation="target.generation.1",
        reproduction_target_generation="target.generation.2",
        primary_environment_fingerprint=_digest("environment:1"),
        reproduction_environment_fingerprint=_digest("environment:2"),
        primary_runner_identity="runner.primary",
        reproduction_runner_identity="runner.independent",
        primary_trace_digest=_digest("trace:1"),
        reproduction_trace_digest=_digest("trace:2"),
        reset_receipt_digest=_digest("reset"),
        causal_evidence_digests=(_digest("causal"),),
        evidence_set=evidence,
        oracle_verdict=OracleVerdict.POSITIVE,
        reproduction_evidence_complete=True,
        evaluated_at="2026-11-27T00:00:00Z",
    )
    assert expired.state == ReproductionState.INCONCLUSIVE
    assert expired.reasons == ("oracle-validity-window-expired",)


def test_coverage_preserves_all_dimensions_and_non_success_states() -> None:
    states = tuple(CoverageState)
    entries = tuple(
        CoverageEntry(
            dimension=dimension,
            subject=f"{dimension.value}.subject",
            state=states[index % len(states)],
            evidence_digests=(
                (_digest(f"coverage:{dimension.value}"),)
                if states[index % len(states)]
                in {CoverageState.EXERCISED, CoverageState.REPRODUCED}
                else ()
            ),
            reason=f"Measured {dimension.value} state.",
        )
        for index, dimension in enumerate(CoverageDimension)
    )
    report = build_coverage_report(
        entries,
        target_profile_digest=_profile().digest,
        methodology_plan_digest=_digest("methodology"),
    )
    validate_document(report, "sova.assessment-coverage")
    assert [item["dimension"] for item in report["dimensions"]] == [
        item.value for item in CoverageDimension
    ]
    assert report["claims"]["allVulnerabilitiesFound"] is False
    assert report["claims"]["notObservedIsSafe"] is False
    assert report["claims"]["infrastructureFailureIsPass"] is False
    assert "overallScore" not in report


def test_blinded_study_rejects_changed_key_and_changed_predictions() -> None:
    proposal = _proposal()
    task, draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, draft)
    changed_key = {**key, "answers": [*key["answers"]]}
    changed_key["answers"][0] = {
        **changed_key["answers"][0],
        "expectedClass": CalibrationClass.KNOWN_NEGATIVE.value,
    }
    with pytest.raises(FormatError, match="commitment"):
        score_blinded_study(
            task,
            predictions,
            changed_key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-11-27T00:00:00Z",
        )
    changed_predictions = {**predictions, "predictions": [*predictions["predictions"]]}
    changed_predictions["predictions"][0] = {
        **changed_predictions["predictions"][0],
        "verdict": OracleVerdict.INCONCLUSIVE.value,
    }
    with pytest.raises(FormatError, match="not frozen"):
        score_blinded_study(
            task,
            changed_predictions,
            key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-11-27T00:00:00Z",
        )


def test_contracts_reject_duplicate_seed_bad_validity_and_unblinded_cases() -> None:
    seed = ProposalSeed(
        identifier="oracle.duplicate",
        source=OracleSource.LOG,
        statement="Log signal exists.",
        positive_signal="Signal is present.",
        negative_signal="Signal is absent.",
        ambiguous_state="Log capture failed.",
        source_references=("log:schema",),
        evidence_requirements=("signed trace",),
        known_blind_spots=("Out-of-band logs.",),
    )
    with pytest.raises(FormatError, match="unique"):
        derive_oracle_proposals(_profile(), (seed, seed))
    with pytest.raises(FormatError, match="labels"):
        CalibrationCase(
            identifier="case.bad",
            expected_class=CalibrationClass.KNOWN_NEGATIVE,
            verdict=OracleVerdict.NEGATIVE,
            target_generation="generation.1",
            environment_fingerprint=_digest("environment"),
            prediction_digest=_digest("prediction"),
            evidence_digests=(_digest("evidence"),),
            label_revealed_after_prediction=False,
        )
    proposal = _proposal()
    case = CalibrationCase(
        identifier="case.good",
        expected_class=CalibrationClass.KNOWN_POSITIVE,
        verdict=OracleVerdict.POSITIVE,
        target_generation="generation.1",
        environment_fingerprint=_digest("environment"),
        prediction_digest=_digest("prediction"),
        evidence_digests=(_digest("evidence"),),
    )
    with pytest.raises(FormatError, match="increasing"):
        calibrate_oracle(
            proposal,
            (case,),
            policy=CalibrationPolicy(minimum_positive_cases=1, minimum_negative_cases=1),
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-08-27T00:00:00Z",
        )


def test_content_digests_change_when_evidence_changes() -> None:
    proposal = _proposal()
    original = proposal.to_mapping()
    changed = {**original, "statement": "Different statement."}
    assert original["contentDigest"] != sha256_digest(canonical_json_bytes(changed))
    validate_oracle_lab_artifact(original)
    with pytest.raises(FormatError, match="does not match"):
        validate_oracle_lab_artifact(changed)


def test_serialized_proposal_and_calibration_round_trip_and_file_tamper_rejection(
    tmp_path: Path,
) -> None:
    proposal = _proposal()
    parsed_proposal = proposal_from_mapping(proposal.to_mapping())
    assert parsed_proposal.to_mapping() == proposal.to_mapping()

    task, draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, draft)
    calibration = score_blinded_study(
        task,
        predictions,
        key,
        proposal,
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-11-27T00:00:00Z",
    )
    parsed_calibration = calibration_from_mapping(calibration.to_mapping())
    assert parsed_calibration.to_mapping() == calibration.to_mapping()

    artifact = tmp_path / "proposal.json"
    artifact.write_bytes(canonical_json_bytes(proposal.to_mapping()))
    assert read_oracle_lab_artifact(artifact) == proposal.to_mapping()
    tampered = {**proposal.to_mapping(), "statement": "Tampered after calibration."}
    artifact.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(FormatError, match="does not match"):
        read_oracle_lab_artifact(artifact)


@pytest.mark.parametrize(
    "value",
    (
        "sha256:" + ("g" * 64),
        "sha256:" + ("A" * 64),
        "sha256:" + ("0" * 63),
    ),
)
def test_coverage_rejects_noncanonical_binding_digests(value: str) -> None:
    entry = CoverageEntry(
        dimension=CoverageDimension.WORKFLOW,
        subject="workflow.invalid-digest",
        state=CoverageState.UNKNOWN,
        evidence_digests=(),
        reason="The binding must be canonical lowercase SHA-256.",
    )
    with pytest.raises(FormatError, match="binding digest"):
        build_coverage_report(
            (entry,),
            target_profile_digest=value,
            methodology_plan_digest=_digest("methodology"),
        )
