# SPDX-License-Identifier: Apache-2.0
"""Adverse-path coverage for P4 trust and lifecycle boundaries."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest

from sova.formats import canonical_json_bytes, sha256_digest
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
from sova.oracle_lab.contracts import CalibrationClass, FreshReproduction, OracleCalibration


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _proposal() -> Any:
    profile = target_profile_template(
        identifier="owned.p4.adverse",
        title="Owned P4 adverse fixture",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned deterministic fixture",
    )
    return derive_oracle_proposals(
        profile,
        (
            ProposalSeed(
                identifier="oracle.p4.adverse",
                source=OracleSource.INVARIANT,
                statement="The protected state remains inaccessible.",
                positive_signal="Protected state was exposed.",
                negative_signal="Access remained denied.",
                ambiguous_state="The observation is incomplete.",
                source_references=("contract:p4.adverse",),
                evidence_requirements=("digest-bound trace",),
                known_blind_spots=("Unobserved channels remain unknown.",),
            ),
        ),
    )[0]


def _calibrated() -> tuple[Any, OracleCalibration]:
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
    return proposal, calibration


def _evidence() -> dict[str, Any]:
    media_types = (
        "application/json",
        "application/octet-stream",
        "video/webm",
        "application/vnd.sova.trace+zip",
        "application/vnd.sova.capsule+zip",
    )
    return bind_decisive_evidence(
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


def _reproduction(
    calibration: OracleCalibration,
    evidence: dict[str, Any],
    **overrides: Any,
) -> FreshReproduction:
    values: dict[str, Any] = {
        "finding_digest": _digest("finding"),
        "calibration": calibration,
        "primary_target_generation": "target.primary",
        "reproduction_target_generation": "target.fresh",
        "primary_environment_fingerprint": _digest("environment.primary"),
        "reproduction_environment_fingerprint": _digest("environment.fresh"),
        "primary_runner_identity": "runner.primary",
        "reproduction_runner_identity": "runner.independent",
        "primary_trace_digest": _digest("trace.primary"),
        "reproduction_trace_digest": _digest("trace.fresh"),
        "reset_receipt_digest": _digest("reset"),
        "causal_evidence_digests": (_digest("causal"),),
        "evidence_set": evidence,
        "oracle_verdict": OracleVerdict.POSITIVE,
        "reproduction_evidence_complete": True,
        "evaluated_at": "2026-08-27T12:00:00Z",
    }
    values.update(overrides)
    return assess_fresh_reproduction(**values)


@pytest.mark.parametrize(
    ("relation", "left", "right", "satisfied"),
    (
        (ComparisonRelation.EQUAL, {"x": 1}, {"x": 2}, False),
        (ComparisonRelation.NOT_EQUAL, {"x": 1}, {"x": 2}, True),
        (ComparisonRelation.NOT_EQUAL, {"x": 1}, {"x": 1}, False),
        (ComparisonRelation.SUBSET, ["a"], ["a", "b"], True),
        (ComparisonRelation.SUPERSET, {"a": 1, "b": 2}, {"a": 3}, True),
        (ComparisonRelation.NONDECREASING, 2, 3, True),
        (ComparisonRelation.NONINCREASING, 3, 2, True),
        (ComparisonRelation.NONDECREASING, True, False, None),
        (ComparisonRelation.NONINCREASING, "not-a-number", 2, None),
    ),
)
def test_every_comparison_relation_and_incompatible_value(
    relation: ComparisonRelation,
    left: Any,
    right: Any,
    satisfied: object,
) -> None:
    result = evaluate_comparison(
        ComparisonObservation(
            identifier=f"comparison.{relation.value}",
            kind=ComparisonKind.METAMORPHIC,
            axis=ComparisonAxis.STATE,
            relation=relation,
            left_label="left",
            right_label="right",
            left_value=left,
            right_value=right,
            left_generation="generation.left",
            right_generation="generation.right",
            evidence_digests=(_digest("comparison"),),
            evidence_complete=True,
        )
    )
    assert result.relation_satisfied is satisfied
    assert result.verdict == (
        OracleVerdict.UNSUPPORTED
        if satisfied is None
        else OracleVerdict.POSITIVE
        if satisfied
        else OracleVerdict.NEGATIVE
    )


def test_calibration_records_every_rejection_reason_and_optional_threshold() -> None:
    proposal = _proposal()
    prediction = _digest("prediction")
    cases = (
        CalibrationCase(
            "case.positive",
            CalibrationClass.KNOWN_POSITIVE,
            OracleVerdict.NEGATIVE,
            "generation.positive",
            _digest("environment.positive"),
            prediction,
            (_digest("evidence.positive"),),
        ),
        CalibrationCase(
            "case.negative",
            CalibrationClass.KNOWN_NEGATIVE,
            OracleVerdict.POSITIVE,
            "generation.negative",
            _digest("environment.negative"),
            prediction,
            (_digest("evidence.negative"),),
        ),
        CalibrationCase(
            "case.ambiguous",
            CalibrationClass.AMBIGUOUS,
            OracleVerdict.POSITIVE,
            "generation.ambiguous",
            _digest("environment.ambiguous"),
            prediction,
            (_digest("evidence.ambiguous"),),
        ),
        CalibrationCase(
            "case.infrastructure",
            CalibrationClass.INFRASTRUCTURE_FAILURE,
            OracleVerdict.NEGATIVE,
            "generation.infrastructure",
            _digest("environment.infrastructure"),
            prediction,
            (_digest("evidence.infrastructure"),),
        ),
        CalibrationCase(
            "case.blocked",
            CalibrationClass.KNOWN_NEGATIVE,
            OracleVerdict.BLOCKED,
            "generation.blocked",
            _digest("environment.blocked"),
            prediction,
            (_digest("evidence.blocked"),),
        ),
    )
    calibration = calibrate_oracle(
        proposal,
        cases,
        policy=CalibrationPolicy(minimum_positive_cases=2, minimum_negative_cases=3),
        valid_from="2026-08-27T00:00:00Z",
        valid_until="2026-09-27T00:00:00Z",
        additional_blind_spots=("Fixture threshold coverage only.",),
    )
    assert calibration.disposition == OracleDisposition.NO_RELIABLE_ORACLE
    assert set(calibration.decision_reasons) == {
        "insufficient-known-positive-cases",
        "insufficient-known-negative-cases",
        "false-positive-threshold-exceeded",
        "miss-threshold-exceeded",
        "ambiguous-case-not-abstained",
        "infrastructure-failure-conflated",
        "unsupported-or-blocked-calibration-case",
    }
    assert "Fixture threshold coverage only." in calibration.known_blind_spots


def _rebind_study(task: dict[str, Any], predictions: dict[str, Any], key: dict[str, Any]) -> None:
    task_digest = sha256_digest(canonical_json_bytes(task["core"]))
    predictions["taskDigest"] = task_digest
    key["taskDigest"] = task_digest
    task["answerKeyCommitment"] = sha256_digest(canonical_json_bytes(key["answers"]))
    prediction_core = {"taskDigest": task_digest, "predictions": predictions["predictions"]}
    key["predictionDigest"] = sha256_digest(canonical_json_bytes(prediction_core))


def test_study_rejects_malformed_and_mismatched_materials() -> None:
    proposal = _proposal()
    task, draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    predictions = predict_blinded_study(task)
    key = bind_answer_key_to_predictions(task, predictions, draft)

    with pytest.raises(FormatError, match="malformed"):
        score_blinded_study(
            {},
            predictions,
            key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-09-27T00:00:00Z",
        )
    changed = deepcopy(task)
    changed["core"]["proposalDigest"] = _digest("other-proposal")
    with pytest.raises(FormatError, match="oracle proposal"):
        score_blinded_study(
            changed,
            predictions,
            key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-09-27T00:00:00Z",
        )
    bad_predictions = {**predictions, "taskDigest": _digest("wrong-task")}
    with pytest.raises(FormatError, match="task binding"):
        score_blinded_study(
            task,
            bad_predictions,
            key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-09-27T00:00:00Z",
        )

    duplicate_task = deepcopy(task)
    duplicate_predictions = deepcopy(predictions)
    duplicate_key = deepcopy(key)
    duplicate_task["core"]["cases"].append(deepcopy(duplicate_task["core"]["cases"][0]))
    _rebind_study(duplicate_task, duplicate_predictions, duplicate_key)
    with pytest.raises(FormatError, match="study case IDs"):
        score_blinded_study(
            duplicate_task,
            duplicate_predictions,
            duplicate_key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-09-27T00:00:00Z",
        )

    bad_evidence_task = deepcopy(task)
    bad_evidence_predictions = deepcopy(predictions)
    bad_evidence_key = deepcopy(key)
    bad_evidence_task["core"]["cases"][0]["evidenceDigests"] = "not-a-list"
    _rebind_study(bad_evidence_task, bad_evidence_predictions, bad_evidence_key)
    with pytest.raises(FormatError, match="case evidence"):
        score_blinded_study(
            bad_evidence_task,
            bad_evidence_predictions,
            bad_evidence_key,
            proposal,
            valid_from="2026-08-27T00:00:00Z",
            valid_until="2026-09-27T00:00:00Z",
        )


def test_study_prediction_and_key_binding_reject_bad_inputs() -> None:
    proposal = _proposal()
    task, draft = build_seeded_blinded_study(proposal_digest=proposal.digest)
    with pytest.raises(FormatError, match="label-free"):
        predict_blinded_study({**task, "labelsPresent": True})
    with pytest.raises(FormatError, match="cases"):
        predict_blinded_study({**task, "core": {**task["core"], "cases": None}})

    unknown = deepcopy(task)
    unknown["core"]["cases"][0]["signal"] = {"unexpected": True}
    predicted = predict_blinded_study(unknown)
    assert any(item["verdict"] == "inconclusive" for item in predicted["predictions"])

    predictions = predict_blinded_study(task)
    with pytest.raises(FormatError, match="does not bind"):
        bind_answer_key_to_predictions(task, {**predictions, "answerKeyLoaded": True}, draft)
    with pytest.raises(FormatError, match="does not bind"):
        bind_answer_key_to_predictions(
            task,
            predictions,
            {**draft, "taskDigest": _digest("different-task")},
        )


@pytest.mark.parametrize(
    ("verdict", "expected"),
    (
        (OracleVerdict.INFRASTRUCTURE_FAILURE, ReproductionState.INFRASTRUCTURE_FAILURE),
        (OracleVerdict.BLOCKED, ReproductionState.BLOCKED),
        (OracleVerdict.UNSUPPORTED, ReproductionState.UNSUPPORTED),
        (OracleVerdict.ABSTAIN, ReproductionState.INCONCLUSIVE),
        (OracleVerdict.INCONCLUSIVE, ReproductionState.INCONCLUSIVE),
        (OracleVerdict.NOT_OBSERVED, ReproductionState.INCONCLUSIVE),
        (OracleVerdict.NEGATIVE, ReproductionState.NOT_REPRODUCED),
    ),
)
def test_reproduction_preserves_every_nonpositive_terminal_state(
    verdict: OracleVerdict, expected: ReproductionState
) -> None:
    _, calibration = _calibrated()
    assert _reproduction(calibration, _evidence(), oracle_verdict=verdict).state == expected


def test_reproduction_accumulates_staleness_and_incomplete_evidence_reasons() -> None:
    _, calibration = _calibrated()
    rejected = replace(
        calibration,
        disposition=OracleDisposition.REJECTED,
        decision_reasons=("fixture-rejected",),
    )
    evidence = _evidence()
    result = _reproduction(
        rejected,
        evidence,
        primary_trace_digest=_digest("same-trace"),
        reproduction_trace_digest=_digest("same-trace"),
        reproduction_evidence_complete=False,
    )
    assert result.state == ReproductionState.INCONCLUSIVE
    assert {"oracle-not-promoted", "trace-not-fresh", "reproduction-evidence-incomplete"} <= set(
        result.reasons
    )

    incomplete = {**evidence, "complete": False}
    digest_body = dict(incomplete)
    digest_body.pop("contentDigest")
    incomplete["contentDigest"] = sha256_digest(canonical_json_bytes(digest_body))
    with pytest.raises(FormatError, match="true was expected"):
        _reproduction(calibration, incomplete)
    with pytest.raises(FormatError, match="second-precision"):
        _reproduction(calibration, evidence, evaluated_at="not-a-time")


def test_artifact_io_and_type_guards_reject_wrong_roots_and_types(tmp_path: Any) -> None:
    with pytest.raises(FormatError, match="artifact type"):
        validate_oracle_lab_artifact({})
    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="root"):
        read_oracle_lab_artifact(scalar)

    proposal, calibration = _calibrated()
    with pytest.raises(FormatError, match="not an oracle proposal"):
        proposal_from_mapping(calibration.to_mapping())
    with pytest.raises(FormatError, match="not an oracle calibration"):
        calibration_from_mapping(proposal.to_mapping())


def test_contract_and_coverage_guards_reject_ambiguous_or_invalid_inputs() -> None:
    with pytest.raises(FormatError, match="case minima"):
        CalibrationPolicy(minimum_positive_cases=0)
    with pytest.raises(FormatError, match="error maxima"):
        CalibrationPolicy(maximum_misses=-1)
    with pytest.raises(FormatError, match="non-empty"):
        CalibrationCase(
            "case.no-evidence",
            CalibrationClass.KNOWN_POSITIVE,
            OracleVerdict.POSITIVE,
            "generation.one",
            _digest("environment"),
            _digest("prediction"),
            (),
        )
    with pytest.raises(FormatError, match="media type"):
        DecisiveEvidenceBinding(
            role=EvidenceRole.RAW_EVIDENCE,
            uri="fixture/raw",
            digest=_digest("raw"),
            media_type="invalid media type",
            verified=True,
            redacted=True,
        )
    bindings = tuple(
        DecisiveEvidenceBinding(
            role=role,
            uri=f"fixture/{role.value}",
            digest=_digest(role.value),
            media_type="application/json",
            verified=True,
            redacted=True,
        )
        for role in EvidenceRole
    )
    with pytest.raises(FormatError, match="unique"):
        bind_decisive_evidence((*bindings, bindings[0]))

    with pytest.raises(FormatError, match="required"):
        build_coverage_report(
            (), target_profile_digest=_digest("target"), methodology_plan_digest=_digest("plan")
        )
    duplicate = CoverageEntry(
        CoverageDimension.WORKFLOW,
        "workflow.one",
        CoverageState.UNKNOWN,
        (),
        "No observation exists.",
    )
    with pytest.raises(FormatError, match="terminal state"):
        build_coverage_report(
            (duplicate, duplicate),
            target_profile_digest=_digest("target"),
            methodology_plan_digest=_digest("plan"),
        )
    with pytest.raises(FormatError, match="require evidence"):
        CoverageEntry(
            CoverageDimension.WORKFLOW,
            "workflow.exercised",
            CoverageState.EXERCISED,
            (),
            "Evidence was omitted.",
        )
