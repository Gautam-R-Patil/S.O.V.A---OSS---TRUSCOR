# SPDX-License-Identifier: Apache-2.0
"""Fail-closed oracle calibration and blinded-study scoring."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.oracle_lab.contracts import (
    CalibrationCase,
    CalibrationClass,
    CalibrationPolicy,
    OracleCalibration,
    OracleDisposition,
    OracleProposal,
    OracleVerdict,
)
from sova.replay import wilson_interval

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


_EXPECTED = {
    CalibrationClass.KNOWN_POSITIVE: OracleVerdict.POSITIVE,
    CalibrationClass.KNOWN_NEGATIVE: OracleVerdict.NEGATIVE,
    CalibrationClass.AMBIGUOUS: OracleVerdict.ABSTAIN,
    CalibrationClass.INFRASTRUCTURE_FAILURE: OracleVerdict.INFRASTRUCTURE_FAILURE,
}


def _ratio(numerator: int, denominator: int) -> str | None:
    if not denominator:
        return None
    return format(numerator / denominator, ".12g")


def calibrate_oracle(  # noqa: PLR0913 - all promotion inputs remain explicit
    proposal: OracleProposal,
    cases: Sequence[CalibrationCase],
    *,
    policy: CalibrationPolicy,
    valid_from: str,
    valid_until: str,
    additional_blind_spots: Sequence[str] = (),
    require_human_review: bool = False,
) -> OracleCalibration:
    """Measure false positives and misses before choosing an oracle disposition."""
    if not cases:
        raise FormatError("SOVA-ORACLE-LAB-CASES", "calibration requires labeled cases")
    expected_counts = Counter(case.expected_class for case in cases)
    false_positives = sum(
        case.expected_class == CalibrationClass.KNOWN_NEGATIVE
        and case.verdict == OracleVerdict.POSITIVE
        for case in cases
    )
    misses = sum(
        case.expected_class == CalibrationClass.KNOWN_POSITIVE
        and case.verdict != OracleVerdict.POSITIVE
        for case in cases
    )
    true_positives = sum(
        case.expected_class == CalibrationClass.KNOWN_POSITIVE
        and case.verdict == OracleVerdict.POSITIVE
        for case in cases
    )
    true_negatives = sum(
        case.expected_class == CalibrationClass.KNOWN_NEGATIVE
        and case.verdict == OracleVerdict.NEGATIVE
        for case in cases
    )
    ambiguous_failures = sum(
        case.expected_class == CalibrationClass.AMBIGUOUS and case.verdict != OracleVerdict.ABSTAIN
        for case in cases
    )
    infrastructure_conflations = sum(
        case.expected_class == CalibrationClass.INFRASTRUCTURE_FAILURE
        and case.verdict != OracleVerdict.INFRASTRUCTURE_FAILURE
        for case in cases
    )
    unsupported_or_blocked = sum(
        case.verdict in {OracleVerdict.UNSUPPORTED, OracleVerdict.BLOCKED} for case in cases
    )
    reasons: list[str] = []
    if expected_counts[CalibrationClass.KNOWN_POSITIVE] < policy.minimum_positive_cases:
        reasons.append("insufficient-known-positive-cases")
    if expected_counts[CalibrationClass.KNOWN_NEGATIVE] < policy.minimum_negative_cases:
        reasons.append("insufficient-known-negative-cases")
    if false_positives > policy.maximum_false_positives:
        reasons.append("false-positive-threshold-exceeded")
    if misses > policy.maximum_misses:
        reasons.append("miss-threshold-exceeded")
    if policy.require_ambiguous_abstention and ambiguous_failures:
        reasons.append("ambiguous-case-not-abstained")
    if policy.require_infrastructure_separation and infrastructure_conflations:
        reasons.append("infrastructure-failure-conflated")
    if unsupported_or_blocked:
        reasons.append("unsupported-or-blocked-calibration-case")

    if require_human_review:
        disposition = OracleDisposition.HUMAN_REVIEW_REQUIRED
        reasons.append("human-review-predeclared")
    elif reasons:
        disposition = (
            OracleDisposition.NO_RELIABLE_ORACLE
            if not true_positives or not true_negatives
            else OracleDisposition.REJECTED
        )
    else:
        disposition = OracleDisposition.PROMOTED

    eligible = (
        expected_counts[CalibrationClass.KNOWN_POSITIVE]
        + expected_counts[CalibrationClass.KNOWN_NEGATIVE]
    )
    correct = true_positives + true_negatives
    low, high = wilson_interval(correct, eligible)
    counts = (
        ("knownPositive", expected_counts[CalibrationClass.KNOWN_POSITIVE]),
        ("knownNegative", expected_counts[CalibrationClass.KNOWN_NEGATIVE]),
        ("ambiguous", expected_counts[CalibrationClass.AMBIGUOUS]),
        ("infrastructureFailure", expected_counts[CalibrationClass.INFRASTRUCTURE_FAILURE]),
        ("truePositive", true_positives),
        ("trueNegative", true_negatives),
        ("falsePositive", false_positives),
        ("miss", misses),
        ("ambiguousFailure", ambiguous_failures),
        ("infrastructureConflation", infrastructure_conflations),
        ("unsupportedOrBlocked", unsupported_or_blocked),
    )
    blind_spots = tuple(dict.fromkeys((*proposal.known_blind_spots, *additional_blind_spots)))
    return OracleCalibration(
        proposal_digest=proposal.digest,
        policy=policy,
        cases=tuple(sorted(cases, key=lambda item: item.identifier)),
        disposition=disposition,
        counts=counts,
        sensitivity=_ratio(true_positives, expected_counts[CalibrationClass.KNOWN_POSITIVE]),
        specificity=_ratio(true_negatives, expected_counts[CalibrationClass.KNOWN_NEGATIVE]),
        confidence_interval_low=format(low, ".12g"),
        confidence_interval_high=format(high, ".12g"),
        valid_from=valid_from,
        valid_until=valid_until,
        known_blind_spots=blind_spots,
        decision_reasons=tuple(dict.fromkeys(reasons)),
    )


def _indexed_records(
    records: list[Any],
    *,
    role: str,
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise FormatError("SOVA-ORACLE-LAB-STUDY", f"{role} is malformed")
        indexed[item["id"]] = item
    if len(indexed) != len(records):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", f"{role} IDs must be unique")
    return indexed


def _verified_study_materials(
    task: Mapping[str, Any],
    predictions: Mapping[str, Any],
    answer_key: Mapping[str, Any],
    proposal: OracleProposal,
) -> tuple[dict[str, Any], list[Any], list[Any], str]:
    """Verify task, answer, prediction, and proposal commitments before unblinding."""
    task_core = task.get("core")
    answers = answer_key.get("answers")
    predicted = predictions.get("predictions")
    if (
        not isinstance(task_core, dict)
        or not isinstance(answers, list)
        or not isinstance(predicted, list)
    ):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study artifacts are malformed")
    task_digest = sha256_digest(canonical_json_bytes(task_core))
    if task_core.get("proposalDigest") != proposal.digest:
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study does not bind to oracle proposal")
    if predictions.get("taskDigest") != task_digest or answer_key.get("taskDigest") != task_digest:
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study task binding failed")
    if task.get("answerKeyCommitment") != sha256_digest(canonical_json_bytes(answers)):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "answer-key commitment does not match")
    prediction_core = {"taskDigest": task_digest, "predictions": predicted}
    if answer_key.get("predictionDigest") != sha256_digest(canonical_json_bytes(prediction_core)):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "predictions were not frozen before unblinding")
    return task_core, answers, predicted, sha256_digest(canonical_json_bytes(prediction_core))


def _policy_from_study(task_core: Mapping[str, Any]) -> CalibrationPolicy:
    policy_raw = task_core.get("policy")
    if not isinstance(policy_raw, dict):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study policy is missing")
    return CalibrationPolicy(
        minimum_positive_cases=int(policy_raw["minimumPositiveCases"]),
        minimum_negative_cases=int(policy_raw["minimumNegativeCases"]),
        maximum_false_positives=int(policy_raw["maximumFalsePositives"]),
        maximum_misses=int(policy_raw["maximumMisses"]),
        require_ambiguous_abstention=bool(policy_raw["requireAmbiguousAbstention"]),
        require_infrastructure_separation=bool(policy_raw["requireInfrastructureSeparation"]),
    )


def _cases_from_study(
    task_core: Mapping[str, Any],
    answers: list[Any],
    predicted: list[Any],
    prediction_digest: str,
) -> list[CalibrationCase]:
    raw_cases = task_core.get("cases")
    if not isinstance(raw_cases, list):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study cases are malformed")
    case_by_id = _indexed_records(raw_cases, role="study case")
    prediction_by_id = _indexed_records(predicted, role="prediction")
    answer_by_id = _indexed_records(answers, role="answer")
    verdict_by_id = {
        identifier: item.get("verdict") for identifier, item in prediction_by_id.items()
    }
    label_by_id = {
        identifier: item.get("expectedClass") for identifier, item in answer_by_id.items()
    }
    if set(case_by_id) != set(verdict_by_id):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "prediction case set differs from task")
    if set(case_by_id) != set(label_by_id):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "answer case set differs from task")
    cases: list[CalibrationCase] = []
    for identifier in sorted(case_by_id):
        item = case_by_id[identifier]
        evidence = item.get("evidenceDigests")
        if not isinstance(evidence, list) or not all(isinstance(value, str) for value in evidence):
            raise FormatError("SOVA-ORACLE-LAB-STUDY", "case evidence is malformed")
        try:
            expected = CalibrationClass(str(label_by_id[identifier]))
            verdict = OracleVerdict(str(verdict_by_id[identifier]))
        except ValueError as error:
            raise FormatError("SOVA-ORACLE-LAB-STUDY", "study contains an unknown state") from error
        cases.append(
            CalibrationCase(
                identifier=str(identifier),
                expected_class=expected,
                verdict=verdict,
                target_generation=str(item["targetGeneration"]),
                environment_fingerprint=str(item["environmentFingerprint"]),
                prediction_digest=prediction_digest,
                evidence_digests=tuple(evidence),
            )
        )
    return cases


def score_blinded_study(  # noqa: PLR0913 - trust-relevant study inputs stay explicit
    task: Mapping[str, Any],
    predictions: Mapping[str, Any],
    answer_key: Mapping[str, Any],
    proposal: OracleProposal,
    *,
    valid_from: str,
    valid_until: str,
) -> OracleCalibration:
    """Unblind only after exact task and prediction commitments are verified."""
    task_core, answers, predicted, prediction_digest = _verified_study_materials(
        task,
        predictions,
        answer_key,
        proposal,
    )
    cases = _cases_from_study(task_core, answers, predicted, prediction_digest)
    return calibrate_oracle(
        proposal,
        cases,
        policy=_policy_from_study(task_core),
        valid_from=valid_from,
        valid_until=valid_until,
        additional_blind_spots=(
            "Seeded study cases do not establish performance on arbitrary targets.",
        ),
    )


__all__ = ["calibrate_oracle", "score_blinded_study"]
