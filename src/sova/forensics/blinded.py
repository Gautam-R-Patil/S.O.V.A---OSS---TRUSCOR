# SPDX-License-Identifier: Apache-2.0
"""Blinded, commitment-bound validation for intervention-based attribution."""

from __future__ import annotations

import copy
import math
import os
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from sova.forensics.attribution import assess_counterfactuals
from sova.forensics.model import AttributionState, CausalLayer, CounterfactualTrial
from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.trace.integrity import (
    Ed25519Keypair,
    generate_ed25519_keypair,
    sign_dsse_payload,
    verify_dsse_payload,
)

_TASK_FIELDS = {
    "artifactType",
    "schemaVersion",
    "studyId",
    "title",
    "randomization",
    "answerCommitment",
    "thresholds",
    "cases",
    "limitations",
}
_CASE_FIELDS = {"caseId", "originalTrace", "candidateLayers", "trials"}
_TRIAL_FIELDS = {
    "trialId",
    "layer",
    "changedLayers",
    "baselineOutcome",
    "interventionOutcome",
    "contextEquivalent",
    "evidenceComplete",
    "originalTrace",
    "counterfactualTrace",
    "executionStatus",
    "limitation",
}
_KEY_FIELDS = {
    "artifactType",
    "schemaVersion",
    "studyId",
    "taskDigest",
    "answerCommitment",
    "labels",
    "reviewer",
    "attestation",
}
_LABEL_FIELDS = {"caseId", "groundTruth", "expectedAbstention"}
_REVIEWER_FIELDS = {"kind", "name", "organization", "independenceDeclared"}
_PREDICTION_FIELDS = {
    "caseId",
    "predictedLayer",
    "supportedLayers",
    "confidence",
    "abstained",
    "report",
}
_PREDICTIONS_FIELDS = {
    "artifactType",
    "schemaVersion",
    "studyId",
    "taskDigest",
    "answerCommitment",
    "method",
    "answerKeyLoaded",
    "predictions",
    "limitations",
}
_THRESHOLD_FIELDS = {
    "minimumCases",
    "minimumDecisionAccuracy",
    "maximumFalseAttributionRate",
    "minimumCoverage",
}
_ELIGIBLE_LAYERS = tuple(
    layer for layer in CausalLayer if layer not in {CausalLayer.MULTIPLE, CausalLayer.UNKNOWN}
)
_MAX_RANDOMIZATION_BYTES = 16_384
_MAX_CASES = 10_000
_MAX_TRIALS_PER_CASE = 10_000
_MAX_TOTAL_TRIALS = 100_000
_MAX_LIMITATIONS = 64
_MIN_FIXTURE_CASES = 8
_MAX_FIXTURE_CASES = 256
_MIN_FIXTURE_TRIALS = 8
_MAX_FIXTURE_TRIALS = 128
_ABSTENTION_PERIOD = 5
_ABSTENTION_REMAINDER = 4
_BASELINE_PROBABILITY = 0.88
_CAUSAL_INTERVENTION_PROBABILITY = 0.06
_NONCAUSAL_INTERVENTION_PROBABILITY = 0.82
_ANSWER_KEY_PAYLOAD_TYPE = "application/vnd.sova.blinded-causal-answer-key+json;version=0.1"
_ED25519_KEY_BYTES = 32
_SHORT_KEY_WRITE = "short reviewer key write"
_BINARY_FLAG = getattr(os, "O_BINARY", 0)


@dataclass(frozen=True, slots=True)
class BlindedCase:
    case_id: str
    original_trace: str
    candidate_layers: tuple[CausalLayer, ...]
    trials: tuple[CounterfactualTrial, ...]


@dataclass(frozen=True, slots=True)
class BlindedStudy:
    study_id: str
    title: str
    randomization: dict[str, Any]
    answer_commitment: str
    thresholds: dict[str, Any]
    cases: tuple[BlindedCase, ...]
    limitations: tuple[str, ...]
    source: dict[str, Any]

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.source))


def _object(value: object, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatError(code, "value must be an object")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], code: str) -> None:
    if set(value) != fields:
        raise FormatError(code, "object fields are not exact")


def _text(value: object, code: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise FormatError(code, "text value is invalid")
    return value


def _layer(value: object) -> CausalLayer:
    try:
        layer = CausalLayer(_text(value, "SOVA-BLIND-LAYER", maximum=128))
    except ValueError as error:
        raise FormatError("SOVA-BLIND-LAYER", "causal layer is unsupported") from error
    if layer in {CausalLayer.MULTIPLE, CausalLayer.UNKNOWN}:
        raise FormatError("SOVA-BLIND-LAYER", "aggregate causal layer is not a candidate")
    return layer


def _optional_bool(value: object, code: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise FormatError(code, "outcome must be boolean or null")


def _trial(value: object) -> CounterfactualTrial:
    item = _object(value, "SOVA-BLIND-TRIAL")
    _exact(item, _TRIAL_FIELDS, "SOVA-BLIND-TRIAL-FIELDS")
    changed = item["changedLayers"]
    if not isinstance(changed, list) or not 1 <= len(changed) <= len(_ELIGIBLE_LAYERS):
        raise FormatError("SOVA-BLIND-TRIAL-LAYERS", "changed layers are invalid")
    execution = _text(item["executionStatus"], "SOVA-BLIND-EXECUTION", maximum=32)
    if execution not in {"completed", "impossible"}:
        raise FormatError("SOVA-BLIND-EXECUTION", "execution status is unsupported")
    if not isinstance(item["contextEquivalent"], bool) or not isinstance(
        item["evidenceComplete"], bool
    ):
        raise FormatError("SOVA-BLIND-TRIAL-BOOLEAN", "trial flags must be boolean")
    limitation = item["limitation"]
    if limitation is not None:
        limitation = _text(limitation, "SOVA-BLIND-LIMITATION", maximum=1024)
    original = item["originalTrace"]
    counterfactual = item["counterfactualTrace"]
    for candidate in (original, counterfactual):
        if candidate is not None:
            _text(candidate, "SOVA-BLIND-TRACE", maximum=1024)
    return CounterfactualTrial(
        trial_id=_text(item["trialId"], "SOVA-BLIND-TRIAL-ID", maximum=256),
        layer=_layer(item["layer"]),
        changed_layers=tuple(_layer(entry) for entry in changed),
        baseline_outcome=_optional_bool(item["baselineOutcome"], "SOVA-BLIND-BASELINE"),
        intervention_outcome=_optional_bool(item["interventionOutcome"], "SOVA-BLIND-INTERVENTION"),
        context_equivalent=item["contextEquivalent"],
        evidence_complete=item["evidenceComplete"],
        original_trace=original,
        counterfactual_trace=counterfactual,
        execution_status=execution,
        limitation=limitation,
    )


def _ratio(value: object, code: str) -> Decimal:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise FormatError(code, "threshold must be a decimal between zero and one")
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as error:
        raise FormatError(code, "threshold is not decimal") from error
    if not Decimal(0) <= parsed <= Decimal(1):
        raise FormatError(code, "threshold must be between zero and one")
    return parsed


def blinded_study_from_mapping(  # noqa: PLR0912, PLR0915 - exact hostile-input parser
    value: Mapping[str, Any],
) -> BlindedStudy:
    """Parse the label-free study task with exact bounded fields."""
    _exact(value, _TASK_FIELDS, "SOVA-BLIND-TASK-FIELDS")
    if (
        value.get("artifactType") != "sova.blinded-causal-study"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-BLIND-TASK-VERSION", "blinded study type is unsupported")
    randomization = dict(_object(value["randomization"], "SOVA-BLIND-RANDOMIZATION"))
    if len(canonical_json_bytes(randomization)) > _MAX_RANDOMIZATION_BYTES:
        raise FormatError("SOVA-BLIND-RANDOMIZATION", "randomization metadata is too large")
    thresholds = dict(_object(value["thresholds"], "SOVA-BLIND-THRESHOLDS"))
    _exact(thresholds, _THRESHOLD_FIELDS, "SOVA-BLIND-THRESHOLD-FIELDS")
    minimum_cases = thresholds["minimumCases"]
    if not isinstance(minimum_cases, int) or isinstance(minimum_cases, bool):
        raise FormatError("SOVA-BLIND-MINIMUM", "minimum case count must be an integer")
    if not 1 <= minimum_cases <= _MAX_CASES:
        raise FormatError("SOVA-BLIND-MINIMUM", "minimum case count is outside bounds")
    _ratio(thresholds["minimumDecisionAccuracy"], "SOVA-BLIND-DECISION-THRESHOLD")
    _ratio(thresholds["maximumFalseAttributionRate"], "SOVA-BLIND-FALSE-THRESHOLD")
    _ratio(thresholds["minimumCoverage"], "SOVA-BLIND-COVERAGE-THRESHOLD")
    cases_value = value["cases"]
    if not isinstance(cases_value, list) or not 1 <= len(cases_value) <= _MAX_CASES:
        raise FormatError("SOVA-BLIND-CASES", "case array is outside bounds")
    cases: list[BlindedCase] = []
    case_ids: set[str] = set()
    total_trials = 0
    for raw_case in cases_value:
        item = _object(raw_case, "SOVA-BLIND-CASE")
        _exact(item, _CASE_FIELDS, "SOVA-BLIND-CASE-FIELDS")
        case_id = _text(item["caseId"], "SOVA-BLIND-CASE-ID", maximum=256)
        if case_id in case_ids:
            raise FormatError("SOVA-BLIND-CASE-ID", "case id is duplicated")
        layers_value = item["candidateLayers"]
        if not isinstance(layers_value, list) or not layers_value:
            raise FormatError("SOVA-BLIND-CANDIDATES", "candidate layers are required")
        layers = tuple(_layer(entry) for entry in layers_value)
        if len(set(layers)) != len(layers):
            raise FormatError("SOVA-BLIND-CANDIDATES", "candidate layers are duplicated")
        trials_value = item["trials"]
        if not isinstance(trials_value, list) or not 1 <= len(trials_value) <= _MAX_TRIALS_PER_CASE:
            raise FormatError("SOVA-BLIND-TRIALS", "trial array is outside bounds")
        trials = tuple(_trial(entry) for entry in trials_value)
        if any(trial.layer not in layers for trial in trials):
            raise FormatError("SOVA-BLIND-CANDIDATES", "trial layer was not declared")
        trial_ids = {trial.trial_id for trial in trials}
        if len(trial_ids) != len(trials):
            raise FormatError("SOVA-BLIND-TRIAL-ID", "trial id is duplicated within a case")
        total_trials += len(trials)
        if total_trials > _MAX_TOTAL_TRIALS:
            raise FormatError("SOVA-BLIND-TRIALS", "study exceeds 100,000 trials")
        cases.append(
            BlindedCase(
                case_id=case_id,
                original_trace=_text(item["originalTrace"], "SOVA-BLIND-ORIGINAL", maximum=1024),
                candidate_layers=layers,
                trials=trials,
            )
        )
        case_ids.add(case_id)
    limitations_value = value["limitations"]
    if not isinstance(limitations_value, list) or len(limitations_value) > _MAX_LIMITATIONS:
        raise FormatError("SOVA-BLIND-LIMITATIONS", "limitations array is invalid")
    limitations = tuple(
        _text(item, "SOVA-BLIND-LIMITATION", maximum=1024) for item in limitations_value
    )
    validate_document(dict(value), "sova.blinded-causal-study")
    return BlindedStudy(
        study_id=_text(value["studyId"], "SOVA-BLIND-STUDY-ID", maximum=256),
        title=_text(value["title"], "SOVA-BLIND-TITLE", maximum=512),
        randomization=randomization,
        answer_commitment=_text(value["answerCommitment"], "SOVA-BLIND-COMMITMENT", maximum=80),
        thresholds=thresholds,
        cases=tuple(cases),
        limitations=limitations,
        source=dict(value),
    )


def run_blinded_attribution_study(study: BlindedStudy) -> dict[str, Any]:
    """Produce predictions without accepting or loading an answer key."""
    predictions: list[dict[str, Any]] = []
    for case in study.cases:
        report = assess_counterfactuals(
            case.original_trace, case.trials, layers=case.candidate_layers
        )
        supported = [
            item for item in report.assessments if item.state == AttributionState.SUPPORTED
        ]
        predicted = supported[0].layer.value if supported else None
        confidence = supported[0].interval_low if supported else None
        predictions.append(
            {
                "caseId": case.case_id,
                "predictedLayer": predicted,
                "supportedLayers": [item.layer.value for item in supported],
                "confidence": confidence,
                "abstained": predicted is None,
                "report": report.to_mapping(),
            }
        )
    return {
        "artifactType": "sova.blinded-causal-predictions",
        "schemaVersion": "0.1.0",
        "studyId": study.study_id,
        "taskDigest": study.digest,
        "answerCommitment": study.answer_commitment,
        "method": "sova.paired-intervention-attribution/0.1.0",
        "answerKeyLoaded": False,
        "predictions": predictions,
        "limitations": [
            "Format separation prevents accidental label loading, not malicious access.",
            "Predictions concern declared observable interventions, not hidden reasoning.",
        ],
    }


def _answer_core(study_id: str, labels: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"studyId": study_id, "labels": [dict(item) for item in labels]}


def _decimal(value: float) -> str:
    return format(value, ".6f").rstrip("0").rstrip(".") or "0"


def _wilson(successes: int, total: int) -> dict[str, str] | None:
    if total <= 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    centre = p + z * z / (2 * total)
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)
    return {
        "method": "wilson-95",
        "low": _decimal(max(0.0, (centre - margin) / denominator)),
        "high": _decimal(min(1.0, (centre + margin) / denominator)),
    }


def _prediction_rows(value: Mapping[str, Any], study: BlindedStudy) -> list[Mapping[str, Any]]:
    _exact(value, _PREDICTIONS_FIELDS, "SOVA-BLIND-PREDICTION-FIELDS")
    if (
        value.get("artifactType") != "sova.blinded-causal-predictions"
        or value.get("schemaVersion") != "0.1.0"
        or value.get("studyId") != study.study_id
        or value.get("taskDigest") != study.digest
        or value.get("answerCommitment") != study.answer_commitment
        or value.get("answerKeyLoaded") is not False
    ):
        raise FormatError("SOVA-BLIND-PREDICTIONS", "prediction binding is invalid")
    rows = value.get("predictions")
    if not isinstance(rows, list) or len(rows) != len(study.cases):
        raise FormatError("SOVA-BLIND-PREDICTIONS", "prediction row count is invalid")
    parsed = [_object(row, "SOVA-BLIND-PREDICTION") for row in rows]
    for row in parsed:
        _exact(row, _PREDICTION_FIELDS, "SOVA-BLIND-PREDICTION-FIELDS")
        predicted = row["predictedLayer"]
        supported = row["supportedLayers"]
        abstained = row["abstained"]
        confidence = row["confidence"]
        if not isinstance(supported, list) or len(supported) > len(_ELIGIBLE_LAYERS):
            raise FormatError("SOVA-BLIND-PREDICTION", "supported layers are invalid")
        supported_layers = tuple(_layer(item).value for item in supported)
        if len(set(supported_layers)) != len(supported_layers):
            raise FormatError("SOVA-BLIND-PREDICTION", "supported layers are duplicated")
        if not isinstance(abstained, bool):
            raise FormatError("SOVA-BLIND-PREDICTION", "abstained must be boolean")
        if predicted is None:
            if not abstained or supported_layers or confidence is not None:
                raise FormatError("SOVA-BLIND-PREDICTION", "abstention fields are inconsistent")
        else:
            selected = _layer(predicted).value
            if abstained or selected not in supported_layers or confidence is None:
                raise FormatError("SOVA-BLIND-PREDICTION", "supported prediction is inconsistent")
            _ratio(confidence, "SOVA-BLIND-CONFIDENCE")
        _object(row["report"], "SOVA-BLIND-PREDICTION-REPORT")
    ids = [row.get("caseId") for row in parsed]
    if len(set(ids)) != len(ids) or set(ids) != {case.case_id for case in study.cases}:
        raise FormatError("SOVA-BLIND-PREDICTIONS", "prediction case binding is invalid")
    validate_document(dict(value), "sova.blinded-causal-predictions")
    return parsed


def _unsigned_answer_key(answer_key: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(answer_key))
    value["attestation"] = None
    return value


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError(_SHORT_KEY_WRITE)
        offset += written


def create_blinded_reviewer_keypair(private_path: Path, public_path: Path) -> dict[str, Any]:
    """Create separate exclusive reviewer-key files without printing private bytes."""
    if private_path.resolve() == public_path.resolve():
        raise FormatError("SOVA-BLIND-KEY-PATH", "private and public key paths must differ")
    if private_path.exists() or public_path.exists():
        raise FormatError("SOVA-BLIND-KEY-PATH", "reviewer key destination already exists")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    keypair = generate_ed25519_keypair()
    private_created = False
    try:
        descriptor = os.open(
            private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG, 0o600
        )
        private_created = True
        try:
            _write_all(descriptor, keypair.private_key)
        finally:
            os.close(descriptor)
        descriptor = os.open(
            public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG, 0o644
        )
        try:
            _write_all(descriptor, keypair.public_key)
        finally:
            os.close(descriptor)
    except BaseException:
        # Do not strand half a keypair if the public-key destination races or fails.
        if private_created:
            private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise
    return {
        "artifactType": "sova.blinded-reviewer-key-created",
        "schemaVersion": "0.1.0",
        "keyId": keypair.key_id,
        "privateKeyPrinted": False,
        "publicKeyPrinted": False,
    }


def sign_blinded_answer_key(
    answer_key: Mapping[str, Any], private_key: bytes, public_key: bytes
) -> dict[str, Any]:
    """Bind an answer key to a reviewer-held Ed25519 key through DSSE."""
    _exact(answer_key, _KEY_FIELDS, "SOVA-BLIND-KEY-FIELDS")
    validate_document(dict(answer_key), "sova.blinded-causal-answer-key")
    if answer_key.get("attestation") is not None:
        raise FormatError("SOVA-BLIND-ATTESTATION", "answer key is already signed")
    if len(private_key) != _ED25519_KEY_BYTES or len(public_key) != _ED25519_KEY_BYTES:
        raise FormatError("SOVA-BLIND-KEY-BYTES", "reviewer keys must be raw Ed25519 bytes")
    keypair = Ed25519Keypair(private_key, public_key, sha256_digest(public_key))
    payload = canonical_json_bytes(_unsigned_answer_key(answer_key))
    envelope = sign_dsse_payload(_ANSWER_KEY_PAYLOAD_TYPE, payload, keypair)
    verify_dsse_payload(envelope, public_key, expected_payload_type=_ANSWER_KEY_PAYLOAD_TYPE)
    signed = dict(answer_key)
    signed["attestation"] = envelope
    return signed


def _verify_answer_key_attestation(
    answer_key: Mapping[str, Any], public_key: bytes | None, required_key_id: str | None
) -> tuple[bool, str | None]:
    attestation = answer_key.get("attestation")
    if public_key is None:
        if required_key_id is not None:
            raise FormatError(
                "SOVA-BLIND-KEY-PIN", "a required reviewer key id needs public key bytes"
            )
        return False, None
    if len(public_key) != _ED25519_KEY_BYTES:
        raise FormatError("SOVA-BLIND-KEY-BYTES", "reviewer public key must be 32 bytes")
    if not isinstance(attestation, dict):
        raise FormatError("SOVA-BLIND-ATTESTATION", "signed reviewer answer key is required")
    key_id = sha256_digest(public_key)
    if required_key_id is not None and key_id != required_key_id:
        raise FormatError("SOVA-BLIND-KEY-PIN", "reviewer public key does not match the pin")
    payload = verify_dsse_payload(
        attestation, public_key, expected_payload_type=_ANSWER_KEY_PAYLOAD_TYPE
    )
    if payload != canonical_json_bytes(_unsigned_answer_key(answer_key)):
        raise FormatError("SOVA-BLIND-ATTESTATION", "signed answer-key payload is not exact")
    return True, key_id


def score_blinded_attribution_study(  # noqa: PLR0912, PLR0915 - auditable scorer
    study: BlindedStudy,
    predictions: Mapping[str, Any],
    answer_key: Mapping[str, Any],
    *,
    reviewer_public_key: bytes | None = None,
    required_reviewer_key_id: str | None = None,
) -> dict[str, Any]:
    """Unblind only after prediction, verify commitments, and score limitations."""
    _exact(answer_key, _KEY_FIELDS, "SOVA-BLIND-KEY-FIELDS")
    if (
        answer_key.get("artifactType") != "sova.blinded-causal-answer-key"
        or answer_key.get("schemaVersion") != "0.1.0"
        or answer_key.get("studyId") != study.study_id
        or answer_key.get("taskDigest") != study.digest
        or answer_key.get("answerCommitment") != study.answer_commitment
    ):
        raise FormatError("SOVA-BLIND-KEY", "answer key binding is invalid")
    labels_value = answer_key.get("labels")
    if not isinstance(labels_value, list) or len(labels_value) != len(study.cases):
        raise FormatError("SOVA-BLIND-LABELS", "answer label count is invalid")
    labels: list[Mapping[str, Any]] = []
    for raw in labels_value:
        label = _object(raw, "SOVA-BLIND-LABEL")
        _exact(label, _LABEL_FIELDS, "SOVA-BLIND-LABEL-FIELDS")
        truth = label["groundTruth"]
        if not isinstance(truth, list) or not truth:
            raise FormatError("SOVA-BLIND-GROUND-TRUTH", "ground truth is required")
        ground_truth = tuple(_layer(item) for item in truth)
        if len(set(ground_truth)) != len(ground_truth):
            raise FormatError("SOVA-BLIND-GROUND-TRUTH", "ground-truth layers are duplicated")
        if not isinstance(label["expectedAbstention"], bool):
            raise FormatError("SOVA-BLIND-ABSTENTION", "abstention label must be boolean")
        labels.append(label)
    label_ids = [label.get("caseId") for label in labels]
    if len(set(label_ids)) != len(label_ids) or set(label_ids) != {
        case.case_id for case in study.cases
    }:
        raise FormatError("SOVA-BLIND-LABELS", "answer label case binding is invalid")
    commitment = sha256_digest(canonical_json_bytes(_answer_core(study.study_id, labels)))
    if commitment != study.answer_commitment:
        raise FormatError("SOVA-BLIND-COMMITMENT", "answer commitment verification failed")
    reviewer = _object(answer_key.get("reviewer"), "SOVA-BLIND-REVIEWER")
    _exact(reviewer, _REVIEWER_FIELDS, "SOVA-BLIND-REVIEWER-FIELDS")
    validate_document(dict(answer_key), "sova.blinded-causal-answer-key")
    reviewer_key_verified, reviewer_key_id = _verify_answer_key_attestation(
        answer_key, reviewer_public_key, required_reviewer_key_id
    )
    rows = _prediction_rows(predictions, study)
    row_by_id = {str(row["caseId"]): row for row in rows}
    truth_by_id = {str(label["caseId"]): label for label in labels}
    top1_correct = decision_correct = wrong_non_abstain = non_abstain = 0
    expected_abstentions = correct_abstentions = 0
    brier_total = 0.0
    brier_count = 0
    errors: list[dict[str, Any]] = []
    class_counts: dict[str, dict[str, int]] = {
        layer.value: {"tp": 0, "fp": 0, "fn": 0} for layer in _ELIGIBLE_LAYERS
    }
    for case in study.cases:
        row = row_by_id[case.case_id]
        label = truth_by_id[case.case_id]
        truth = {str(item) for item in label["groundTruth"]}
        predicted = row.get("predictedLayer")
        if predicted is not None:
            predicted = _layer(predicted).value
            non_abstain += 1
        expected_abstention = bool(label["expectedAbstention"])
        if expected_abstention:
            expected_abstentions += 1
        correct = predicted in truth if predicted is not None else False
        if correct:
            top1_correct += 1
        if (expected_abstention and predicted is None) or (not expected_abstention and correct):
            decision_correct += 1
            if expected_abstention:
                correct_abstentions += 1
        elif predicted is not None and not correct:
            wrong_non_abstain += 1
        if not expected_abstention:
            for layer, counts in class_counts.items():
                if predicted == layer and layer in truth:
                    counts["tp"] += 1
                elif predicted == layer:
                    counts["fp"] += 1
                elif layer in truth:
                    counts["fn"] += 1
        confidence = row.get("confidence")
        if predicted is not None and confidence is not None:
            score = float(_ratio(confidence, "SOVA-BLIND-CONFIDENCE"))
            brier_total += (score - float(correct)) ** 2
            brier_count += 1
        decision_is_correct = (expected_abstention and predicted is None) or (
            not expected_abstention and correct
        )
        if not decision_is_correct:
            errors.append(
                {
                    "caseId": case.case_id,
                    "groundTruth": sorted(truth),
                    "expectedAbstention": expected_abstention,
                    "predictedLayer": predicted,
                }
            )
    total = len(study.cases)
    decision_accuracy = decision_correct / total
    false_rate = wrong_non_abstain / total
    coverage = non_abstain / total
    selective = (top1_correct / non_abstain) if non_abstain else 0.0
    f1_values: list[float] = []
    per_layer: list[dict[str, Any]] = []
    for layer, counts in class_counts.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        if tp + fn:
            f1_values.append(f1)
        per_layer.append(
            {
                "layer": layer,
                "truePositive": tp,
                "falsePositive": fp,
                "falseNegative": fn,
                "precision": _decimal(precision),
                "recall": _decimal(recall),
                "f1": _decimal(f1),
            }
        )
    thresholds = study.thresholds
    gates = {
        "minimumCases": total >= int(thresholds["minimumCases"]),
        "minimumDecisionAccuracy": Decimal(str(decision_accuracy))
        >= _ratio(thresholds["minimumDecisionAccuracy"], "SOVA-BLIND-DECISION-THRESHOLD"),
        "maximumFalseAttributionRate": Decimal(str(false_rate))
        <= _ratio(thresholds["maximumFalseAttributionRate"], "SOVA-BLIND-FALSE-THRESHOLD"),
        "minimumCoverage": Decimal(str(coverage))
        >= _ratio(thresholds["minimumCoverage"], "SOVA-BLIND-COVERAGE-THRESHOLD"),
    }
    result = {
        "artifactType": "sova.blinded-causal-score",
        "schemaVersion": "0.1.0",
        "studyId": study.study_id,
        "taskDigest": study.digest,
        "answerCommitment": commitment,
        "answerCommitmentVerified": True,
        "evaluatedCases": total,
        "top1Correct": top1_correct,
        "top1Accuracy": _decimal(top1_correct / total),
        "top1Interval": _wilson(top1_correct, total),
        "decisionCorrect": decision_correct,
        "decisionAccuracy": _decimal(decision_accuracy),
        "decisionInterval": _wilson(decision_correct, total),
        "coverage": _decimal(coverage),
        "selectiveAccuracy": _decimal(selective),
        "falseAttributionRate": _decimal(false_rate),
        "expectedAbstentions": expected_abstentions,
        "correctAbstentions": correct_abstentions,
        "macroF1": _decimal(sum(f1_values) / len(f1_values)) if f1_values else None,
        "brierScoreSupportedPredictions": (
            _decimal(brier_total / brier_count) if brier_count else None
        ),
        "perLayer": per_layer,
        "thresholds": thresholds,
        "gates": gates,
        "passed": all(gates.values()),
        "reviewer": dict(reviewer),
        "answerKeyAttestationPresent": answer_key.get("attestation") is not None,
        "reviewerKeyPinVerified": reviewer_key_verified,
        "reviewerKeyId": reviewer_key_id,
        "independentReviewerIdentityCryptographicallyVerified": False,
        "errors": errors,
        "limitations": [
            "A commitment proves the answer key did not change after task publication; "
            "it does not prove label correctness.",
            "A self-declared reviewer identity or independence is not cryptographically verified.",
            "Synthetic stochastic cases validate the method implementation, not real-agent "
            "causal accuracy.",
            "Unmeasured common causes, intervention drift, and incomplete sensors can "
            "invalidate causal interpretation.",
        ],
    }
    validate_document(result, "sova.blinded-causal-score")
    return result


def _trial_mapping(  # noqa: PLR0913 - explicit paired outcomes are safer
    case_id: str,
    layer: CausalLayer,
    index: int,
    *,
    baseline: bool | None,
    intervention: bool | None,
    evidence_complete: bool,
) -> dict[str, Any]:
    return {
        "trialId": f"{case_id}:{layer.value}:{index:03d}",
        "layer": layer.value,
        "changedLayers": [layer.value],
        "baselineOutcome": baseline,
        "interventionOutcome": intervention,
        "contextEquivalent": True,
        "evidenceComplete": evidence_complete,
        "originalTrace": f"fixture:{case_id}:baseline:{index:03d}",
        "counterfactualTrace": f"fixture:{case_id}:{layer.value}:{index:03d}",
        "executionStatus": "completed",
        "limitation": None if evidence_complete else "fixture-declared missing observation",
    }


def create_stochastic_blinded_fixture(
    *, seed: int = 20260809, case_count: int = 16, trials_per_layer: int = 16
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a reproducible stochastic simulator fixture, never field evidence."""
    if not _MIN_FIXTURE_CASES <= case_count <= _MAX_FIXTURE_CASES:
        raise FormatError("SOVA-BLIND-FIXTURE-CASES", "fixture cases must be between 8 and 256")
    if not _MIN_FIXTURE_TRIALS <= trials_per_layer <= _MAX_FIXTURE_TRIALS:
        raise FormatError("SOVA-BLIND-FIXTURE-TRIALS", "fixture trials per layer must be 8 to 128")
    rng = random.Random(seed)  # noqa: S311 - reproducible simulation, never security
    study_id = f"sova:blinded-study:{sha256_digest(str(seed).encode())[7:31]}"
    cases: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    for case_index in range(case_count):
        case_id = f"stochastic-{case_index:03d}"
        ground_truth = _ELIGIBLE_LAYERS[case_index % len(_ELIGIBLE_LAYERS)]
        expected_abstention = case_index % _ABSTENTION_PERIOD == _ABSTENTION_REMAINDER
        trials: list[dict[str, Any]] = []
        for layer in _ELIGIBLE_LAYERS:
            for trial_index in range(trials_per_layer):
                if expected_abstention:
                    baseline = intervention = None
                    complete = False
                else:
                    baseline = rng.random() < _BASELINE_PROBABILITY
                    probability = (
                        _CAUSAL_INTERVENTION_PROBABILITY
                        if layer == ground_truth
                        else _NONCAUSAL_INTERVENTION_PROBABILITY
                    )
                    intervention = rng.random() < probability
                    complete = True
                trials.append(
                    _trial_mapping(
                        case_id,
                        layer,
                        trial_index,
                        baseline=baseline,
                        intervention=intervention,
                        evidence_complete=complete,
                    )
                )
        rng.shuffle(trials)
        cases.append(
            {
                "caseId": case_id,
                "originalTrace": f"fixture:{case_id}:original",
                "candidateLayers": [layer.value for layer in _ELIGIBLE_LAYERS],
                "trials": trials,
            }
        )
        labels.append(
            {
                "caseId": case_id,
                "groundTruth": [ground_truth.value],
                "expectedAbstention": expected_abstention,
            }
        )
    rng.shuffle(cases)
    answer_commitment = sha256_digest(canonical_json_bytes(_answer_core(study_id, labels)))
    task: dict[str, Any] = {
        "artifactType": "sova.blinded-causal-study",
        "schemaVersion": "0.1.0",
        "studyId": study_id,
        "title": "Synthetic stochastic intervention fixture",
        "randomization": {
            "design": "randomized paired intervention order",
            "generator": "python-mt19937-fixture-only",
            "seedCommitment": sha256_digest(str(seed).encode()),
            "labelsAbsentFromTask": True,
        },
        "answerCommitment": answer_commitment,
        "thresholds": {
            "minimumCases": case_count,
            "minimumDecisionAccuracy": "0.8",
            "maximumFalseAttributionRate": "0.1",
            "minimumCoverage": "0.5",
        },
        "cases": cases,
        "limitations": [
            "Generated Bernoulli outcomes are not real model or agent evidence.",
            "The fixed PRNG seed supports reproducibility, not unpredictable allocation.",
        ],
    }
    key = {
        "artifactType": "sova.blinded-causal-answer-key",
        "schemaVersion": "0.1.0",
        "studyId": study_id,
        "taskDigest": sha256_digest(canonical_json_bytes(task)),
        "answerCommitment": answer_commitment,
        "labels": labels,
        "reviewer": {
            "kind": "synthetic-generator",
            "name": "SOVA stochastic fixture",
            "organization": "not-applicable",
            "independenceDeclared": False,
        },
        "attestation": None,
    }
    return task, key


__all__ = [
    "BlindedCase",
    "BlindedStudy",
    "blinded_study_from_mapping",
    "create_blinded_reviewer_keypair",
    "create_stochastic_blinded_fixture",
    "run_blinded_attribution_study",
    "score_blinded_attribution_study",
    "sign_blinded_answer_key",
]
