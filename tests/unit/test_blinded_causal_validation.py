# SPDX-License-Identifier: Apache-2.0
"""Blinded stochastic causal-validation protocol acceptance tests."""

from __future__ import annotations

import copy
import json
import os
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.cli as cli_module
from sova.cli import main
from sova.forensics import blinded as blinded_module
from sova.forensics import (
    blinded_study_from_mapping,
    create_blinded_reviewer_keypair,
    create_stochastic_blinded_fixture,
    run_blinded_attribution_study,
    score_blinded_attribution_study,
    sign_blinded_answer_key,
)
from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.trace.integrity import Ed25519Keypair

if TYPE_CHECKING:
    from pathlib import Path

_SIMULATED_RACE = "simulated public-key destination race"


def _run() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    task, key = create_stochastic_blinded_fixture()
    study = blinded_study_from_mapping(task)
    predictions = run_blinded_attribution_study(study)
    return task, key, score_blinded_attribution_study(study, predictions, key)


def test_stochastic_fixture_blinds_labels_scores_accuracy_and_abstention() -> None:
    task, key, result = _run()
    study = blinded_study_from_mapping(task)
    predictions = run_blinded_attribution_study(study)
    for document in (task, key, predictions, result):
        validate_document(document)
    serialized_task = json.dumps(task, sort_keys=True)
    assert "groundTruth" not in serialized_task
    assert key["taskDigest"]
    assert result["answerCommitmentVerified"] is True
    assert result["passed"] is True
    assert result["decisionAccuracy"] == "1"
    assert result["falseAttributionRate"] == "0"
    assert result["coverage"] == "0.8125"
    assert result["correctAbstentions"] == result["expectedAbstentions"] == 3
    assert result["macroF1"] == "1"
    assert result["independentReviewerIdentityCryptographicallyVerified"] is False


def test_reviewer_key_creation_rolls_back_a_raced_partial_keypair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_path = tmp_path / "reviewer.key"
    public_path = tmp_path / "reviewer.pub"
    original_open = os.open

    def raced_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
        if os.fspath(path) == os.fspath(public_path):
            raise FileExistsError(_SIMULATED_RACE)
        return original_open(path, flags, mode)

    monkeypatch.setattr(os, "open", raced_open)
    with pytest.raises(FileExistsError, match="simulated"):
        create_blinded_reviewer_keypair(private_path, public_path)
    assert not private_path.exists()
    assert not public_path.exists()


def test_reviewer_raw_key_files_are_binary_exact_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_bytes = b"\n" * 32
    public_bytes = b"\r\n" * 16
    keypair = Ed25519Keypair(private_bytes, public_bytes, sha256_digest(public_bytes))
    monkeypatch.setattr(blinded_module, "generate_ed25519_keypair", lambda: keypair)
    private_path = tmp_path / "binary.key"
    public_path = tmp_path / "binary.pub"
    create_blinded_reviewer_keypair(private_path, public_path)
    assert private_path.read_bytes() == private_bytes
    assert public_path.read_bytes() == public_bytes


def test_predictions_are_bound_and_answer_key_is_never_loaded_by_runner() -> None:
    task, key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    study = blinded_study_from_mapping(task)
    predictions = run_blinded_attribution_study(study)
    assert predictions["answerKeyLoaded"] is False
    assert "groundTruth" not in json.dumps(predictions, sort_keys=True)

    tampered_predictions = copy.deepcopy(predictions)
    tampered_predictions["taskDigest"] = "sha256:" + "0" * 64
    with pytest.raises(FormatError, match="prediction binding"):
        score_blinded_attribution_study(study, tampered_predictions, key)

    tampered_key = copy.deepcopy(key)
    tampered_key["labels"][0]["groundTruth"] = ["tool-description-or-implementation"]
    with pytest.raises(FormatError, match="commitment"):
        score_blinded_attribution_study(study, predictions, tampered_key)


def test_task_parser_refuses_unknown_fields_duplicates_and_bad_bounds() -> None:
    task, _key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    unknown = copy.deepcopy(task)
    unknown["unexpected"] = True
    with pytest.raises(FormatError, match="fields"):
        blinded_study_from_mapping(unknown)

    duplicate = copy.deepcopy(task)
    duplicate["cases"].append(copy.deepcopy(duplicate["cases"][0]))
    with pytest.raises(FormatError, match="duplicated"):
        blinded_study_from_mapping(duplicate)

    aggregate = copy.deepcopy(task)
    aggregate["cases"][0]["candidateLayers"][0] = "unknown"
    with pytest.raises(FormatError, match="aggregate"):
        blinded_study_from_mapping(aggregate)

    with pytest.raises(FormatError, match="between 8 and 256"):
        create_stochastic_blinded_fixture(case_count=7)
    with pytest.raises(FormatError, match="8 to 128"):
        create_stochastic_blinded_fixture(trials_per_layer=7)


def test_cli_fixture_run_score_is_three_phase_and_refuses_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    task = tmp_path / "task.json"
    key = tmp_path / "key.json"
    predictions = tmp_path / "predictions.json"
    score = tmp_path / "score.json"
    assert (
        main(
            [
                "forensics",
                "blind-fixture",
                str(task),
                str(key),
                "--cases",
                "8",
                "--trials-per-layer",
                "8",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["answerKeyLoadedDuringPrediction"] is False
    assert main(["forensics", "blind-run", str(task), str(predictions)]) == 0
    frozen = json.loads(capsys.readouterr().out)
    assert frozen["answerKeyLoaded"] is False
    assert (
        main(["forensics", "blind-score", str(task), str(predictions), str(key), str(score)]) == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["passed"] is True
    assert score.exists()
    assert main(["forensics", "blind-run", str(task), str(predictions)]) == 2
    assert "destination already exists" in capsys.readouterr().err


def test_blind_fixture_rolls_back_task_if_answer_destination_is_occupied(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    task = tmp_path / "task.json"
    key = tmp_path / "occupied-key.json"
    key.write_bytes(b"operator-owned")
    assert main(["forensics", "blind-fixture", str(task), str(key)]) == 2
    assert not task.exists()
    assert key.read_bytes() == b"operator-owned"
    assert "destination already exists" in capsys.readouterr().err


def test_exclusive_document_writer_cleans_partial_short_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "partial.json"
    monkeypatch.setattr(os, "write", lambda _descriptor, _value: 0)
    with pytest.raises(OSError):
        cli_module._write_new_document(destination, {"safe": True})
    assert not destination.exists()


def test_nonpassing_predeclared_gate_returns_visible_result() -> None:
    task, key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    task["thresholds"]["minimumCoverage"] = "1"
    key["taskDigest"] = sha256_digest(canonical_json_bytes(task))
    study = blinded_study_from_mapping(task)
    result = score_blinded_attribution_study(study, run_blinded_attribution_study(study), key)
    assert result["passed"] is False
    assert result["gates"]["minimumCoverage"] is False


def test_reviewer_key_pin_dsse_signature_and_tampering_are_verified(tmp_path: Path) -> None:
    task, key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    study = blinded_study_from_mapping(task)
    predictions = run_blinded_attribution_study(study)
    private_path = tmp_path / "reviewer.key"
    public_path = tmp_path / "reviewer.pub"
    created = create_blinded_reviewer_keypair(private_path, public_path)
    assert created["privateKeyPrinted"] is False
    signed = sign_blinded_answer_key(key, private_path.read_bytes(), public_path.read_bytes())
    result = score_blinded_attribution_study(
        study,
        predictions,
        signed,
        reviewer_public_key=public_path.read_bytes(),
        required_reviewer_key_id=created["keyId"],
    )
    assert result["answerKeyAttestationPresent"] is True
    assert result["reviewerKeyPinVerified"] is True
    assert result["reviewerKeyId"] == created["keyId"]
    assert result["independentReviewerIdentityCryptographicallyVerified"] is False

    tampered = copy.deepcopy(signed)
    tampered["labels"][0]["expectedAbstention"] = not tampered["labels"][0]["expectedAbstention"]
    with pytest.raises(FormatError):
        score_blinded_attribution_study(
            study, predictions, tampered, reviewer_public_key=public_path.read_bytes()
        )


def test_reviewer_key_cli_never_prints_private_material(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    task, key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    task_path = tmp_path / "task.json"
    key_path = tmp_path / "key.json"
    predictions = tmp_path / "predictions.json"
    private_path = tmp_path / "reviewer.key"
    public_path = tmp_path / "reviewer.pub"
    signed_path = tmp_path / "signed-key.json"
    score_path = tmp_path / "score.json"
    task_path.write_bytes(canonical_json_bytes(task))
    key_path.write_bytes(canonical_json_bytes(key))
    assert main(["forensics", "blind-keygen", str(private_path), str(public_path)]) == 0
    keygen = json.loads(capsys.readouterr().out)
    assert keygen["privateKeyPrinted"] is False
    assert private_path.read_bytes().hex() not in json.dumps(keygen)
    assert main(["forensics", "blind-run", str(task_path), str(predictions)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "forensics",
                "blind-sign-key",
                str(key_path),
                str(private_path),
                str(public_path),
                str(signed_path),
            ]
        )
        == 0
    )
    signed_report = json.loads(capsys.readouterr().out)
    assert signed_report["privateKeyPrinted"] is False
    assert (
        main(
            [
                "forensics",
                "blind-score",
                str(task_path),
                str(predictions),
                str(signed_path),
                str(score_path),
                "--reviewer-public-key",
                str(public_path),
                "--required-reviewer-key-id",
                keygen["keyId"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["reviewerKeyPinVerified"] is True


def test_blinded_task_parser_rejects_hostile_types_fields_and_trial_semantics(  # noqa: PLR0915 - mutation matrix is intentionally explicit
) -> None:
    task, _key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    invalid: list[dict[str, Any]] = []

    wrong_version = copy.deepcopy(task)
    wrong_version["schemaVersion"] = "9.9.9"
    invalid.append(wrong_version)
    randomization_type = copy.deepcopy(task)
    randomization_type["randomization"] = []
    invalid.append(randomization_type)
    randomization_size = copy.deepcopy(task)
    randomization_size["randomization"] = {"padding": "x" * 16_500}
    invalid.append(randomization_size)
    threshold_fields = copy.deepcopy(task)
    threshold_fields["thresholds"]["unexpected"] = True
    invalid.append(threshold_fields)
    minimum_type = copy.deepcopy(task)
    minimum_type["thresholds"]["minimumCases"] = True
    invalid.append(minimum_type)
    minimum_range = copy.deepcopy(task)
    minimum_range["thresholds"]["minimumCases"] = 0
    invalid.append(minimum_range)
    ratio_type = copy.deepcopy(task)
    ratio_type["thresholds"]["minimumCoverage"] = True
    invalid.append(ratio_type)
    ratio_nan = copy.deepcopy(task)
    ratio_nan["thresholds"]["minimumCoverage"] = "not-decimal"
    invalid.append(ratio_nan)
    ratio_range = copy.deepcopy(task)
    ratio_range["thresholds"]["minimumCoverage"] = "2"
    invalid.append(ratio_range)
    cases_type = copy.deepcopy(task)
    cases_type["cases"] = {}
    invalid.append(cases_type)
    case_type = copy.deepcopy(task)
    case_type["cases"][0] = []
    invalid.append(case_type)
    candidate_empty = copy.deepcopy(task)
    candidate_empty["cases"][0]["candidateLayers"] = []
    invalid.append(candidate_empty)
    candidate_duplicate = copy.deepcopy(task)
    candidate_duplicate["cases"][0]["candidateLayers"][1] = candidate_duplicate["cases"][0][
        "candidateLayers"
    ][0]
    invalid.append(candidate_duplicate)
    trials_empty = copy.deepcopy(task)
    trials_empty["cases"][0]["trials"] = []
    invalid.append(trials_empty)
    trial_type = copy.deepcopy(task)
    trial_type["cases"][0]["trials"][0] = []
    invalid.append(trial_type)
    trial_fields = copy.deepcopy(task)
    del trial_fields["cases"][0]["trials"][0]["limitation"]
    invalid.append(trial_fields)
    changed_empty = copy.deepcopy(task)
    changed_empty["cases"][0]["trials"][0]["changedLayers"] = []
    invalid.append(changed_empty)
    execution_bad = copy.deepcopy(task)
    execution_bad["cases"][0]["trials"][0]["executionStatus"] = "unknown"
    invalid.append(execution_bad)
    flags_bad = copy.deepcopy(task)
    flags_bad["cases"][0]["trials"][0]["contextEquivalent"] = "yes"
    invalid.append(flags_bad)
    limitation_bad = copy.deepcopy(task)
    limitation_bad["cases"][0]["trials"][0]["limitation"] = 42
    invalid.append(limitation_bad)
    trace_bad = copy.deepcopy(task)
    trace_bad["cases"][0]["trials"][0]["originalTrace"] = 42
    invalid.append(trace_bad)
    outcome_bad = copy.deepcopy(task)
    outcome_bad["cases"][0]["trials"][0]["baselineOutcome"] = "true"
    invalid.append(outcome_bad)
    undeclared_layer = copy.deepcopy(task)
    declared = undeclared_layer["cases"][0]["candidateLayers"]
    removed = declared.pop()
    for trial in undeclared_layer["cases"][0]["trials"]:
        if trial["layer"] == removed:
            trial["layer"] = declared[0]
            trial["changedLayers"] = [removed]
            break
    invalid.append(undeclared_layer)
    duplicate_trial = copy.deepcopy(task)
    duplicate_trial["cases"][0]["trials"][1]["trialId"] = duplicate_trial["cases"][0]["trials"][0][
        "trialId"
    ]
    invalid.append(duplicate_trial)
    limitations_type = copy.deepcopy(task)
    limitations_type["limitations"] = {}
    invalid.append(limitations_type)

    with pytest.raises(FormatError, match="fields"):
        blinded_study_from_mapping(cast("Any", []))
    for document in invalid:
        with pytest.raises(FormatError):
            blinded_study_from_mapping(document)


def test_blinded_scoring_rejects_malformed_keys_predictions_and_reviewer_pins(  # noqa: PLR0915 - fail-closed cases share one frozen study
    tmp_path: Path,
) -> None:
    task, key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    study = blinded_study_from_mapping(task)
    predictions = run_blinded_attribution_study(study)

    label_count = copy.deepcopy(key)
    label_count["labels"] = []
    label_type = copy.deepcopy(key)
    label_type["labels"][0] = []
    label_fields = copy.deepcopy(key)
    del label_fields["labels"][0]["expectedAbstention"]
    ground_truth = copy.deepcopy(key)
    ground_truth["labels"][0]["groundTruth"] = []
    abstention_type = copy.deepcopy(key)
    abstention_type["labels"][0]["expectedAbstention"] = "false"
    duplicate_label = copy.deepcopy(key)
    duplicate_label["labels"][1]["caseId"] = duplicate_label["labels"][0]["caseId"]
    reviewer_type = copy.deepcopy(key)
    reviewer_type["reviewer"] = []
    for malformed in (
        label_count,
        label_type,
        label_fields,
        ground_truth,
        abstention_type,
        duplicate_label,
        reviewer_type,
    ):
        with pytest.raises(FormatError):
            score_blinded_attribution_study(study, predictions, malformed)

    rows_missing = copy.deepcopy(predictions)
    rows_missing["predictions"] = []
    rows_duplicate = copy.deepcopy(predictions)
    rows_duplicate["predictions"][1]["caseId"] = rows_duplicate["predictions"][0]["caseId"]
    root_extra = copy.deepcopy(predictions)
    root_extra["unexpected"] = True
    row_extra = copy.deepcopy(predictions)
    row_extra["predictions"][0]["unexpected"] = True
    supported_type = copy.deepcopy(predictions)
    supported_type["predictions"][0]["supportedLayers"] = {}
    supported_duplicate = copy.deepcopy(predictions)
    first_supported = supported_duplicate["predictions"][0]["supportedLayers"]
    if first_supported:
        first_supported.append(first_supported[0])
    abstained_type = copy.deepcopy(predictions)
    abstained_type["predictions"][0]["abstained"] = "false"
    inconsistent_abstention = copy.deepcopy(predictions)
    abstained_row = next(row for row in inconsistent_abstention["predictions"] if row["abstained"])
    abstained_row["confidence"] = "0.5"
    inconsistent_support = copy.deepcopy(predictions)
    supported_row = next(row for row in inconsistent_support["predictions"] if not row["abstained"])
    supported_row["supportedLayers"] = []
    report_type = copy.deepcopy(predictions)
    report_type["predictions"][0]["report"] = []
    for malformed in (
        rows_missing,
        rows_duplicate,
        root_extra,
        row_extra,
        supported_type,
        supported_duplicate,
        abstained_type,
        inconsistent_abstention,
        inconsistent_support,
        report_type,
    ):
        with pytest.raises(FormatError):
            score_blinded_attribution_study(study, malformed, key)

    with pytest.raises(FormatError, match="needs public key"):
        score_blinded_attribution_study(
            study, predictions, key, required_reviewer_key_id="sha256:" + "0" * 64
        )
    with pytest.raises(FormatError, match="32 bytes"):
        score_blinded_attribution_study(study, predictions, key, reviewer_public_key=b"short")

    private_path = tmp_path / "reviewer.key"
    public_path = tmp_path / "reviewer.pub"
    created = create_blinded_reviewer_keypair(private_path, public_path)
    with pytest.raises(FormatError, match="signed reviewer"):
        score_blinded_attribution_study(
            study, predictions, key, reviewer_public_key=public_path.read_bytes()
        )
    with pytest.raises(FormatError, match="must be raw"):
        sign_blinded_answer_key(key, b"short", public_path.read_bytes())
    signed = sign_blinded_answer_key(key, private_path.read_bytes(), public_path.read_bytes())
    with pytest.raises(FormatError, match="already signed"):
        sign_blinded_answer_key(signed, private_path.read_bytes(), public_path.read_bytes())
    with pytest.raises(FormatError, match="does not match the pin"):
        score_blinded_attribution_study(
            study,
            predictions,
            signed,
            reviewer_public_key=public_path.read_bytes(),
            required_reviewer_key_id="sha256:" + "0" * 64,
        )
    assert created["keyId"] != "sha256:" + "0" * 64

    changed_reviewer = copy.deepcopy(signed)
    changed_reviewer["reviewer"]["name"] = "substituted after signing"
    with pytest.raises(FormatError, match="signed answer-key payload"):
        score_blinded_attribution_study(
            study,
            predictions,
            changed_reviewer,
            reviewer_public_key=public_path.read_bytes(),
        )

    with pytest.raises(FormatError, match="paths must differ"):
        create_blinded_reviewer_keypair(tmp_path / "same.key", tmp_path / "same.key")
    existing = tmp_path / "existing.key"
    existing.write_bytes(b"occupied")
    with pytest.raises(FormatError, match="already exists"):
        create_blinded_reviewer_keypair(existing, tmp_path / "new.pub")


def test_blinded_metrics_make_wrong_predictions_and_full_abstention_visible() -> None:
    task, key = create_stochastic_blinded_fixture(case_count=8, trials_per_layer=8)
    study = blinded_study_from_mapping(task)
    predictions = run_blinded_attribution_study(study)
    label_by_case = {item["caseId"]: item for item in key["labels"]}

    wrong = copy.deepcopy(predictions)
    row = next(item for item in wrong["predictions"] if not item["abstained"])
    truth = set(label_by_case[row["caseId"]]["groundTruth"])
    row["predictedLayer"] = next(
        layer for layer in task["cases"][0]["candidateLayers"] if layer not in truth
    )
    row["supportedLayers"] = [row["predictedLayer"]]
    row["confidence"] = "0.2"
    wrong_result = score_blinded_attribution_study(study, wrong, key)
    assert wrong_result["errors"]
    assert float(wrong_result["falseAttributionRate"]) > 0
    assert wrong_result["brierScoreSupportedPredictions"] is not None

    abstained = copy.deepcopy(predictions)
    for item in abstained["predictions"]:
        item["predictedLayer"] = None
        item["supportedLayers"] = []
        item["confidence"] = None
        item["abstained"] = True
    abstained_result = score_blinded_attribution_study(study, abstained, key)
    assert abstained_result["coverage"] == "0"
    assert abstained_result["brierScoreSupportedPredictions"] is None
    assert abstained_result["passed"] is False
