# SPDX-License-Identifier: Apache-2.0
"""Deterministic blinded seeded-study fixture for P4 software validation."""

from __future__ import annotations

import random
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.oracle_lab.contracts import CalibrationClass, CalibrationPolicy, OracleVerdict


def _digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def build_seeded_blinded_study(
    *,
    proposal_digest: str,
    seed: int = 2417,
    inject_false_positive: bool = False,
    inject_miss: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a label-free task and separate answer-key draft.

    The key intentionally omits a prediction commitment. Call
    ``predict_blinded_study`` to freeze predictions and complete the key before
    scoring. This fixture validates machinery; it is not field evidence.
    """
    policy = CalibrationPolicy()
    cases = []
    answers = []
    classes = (
        *(CalibrationClass.KNOWN_POSITIVE for _ in range(4)),
        *(CalibrationClass.KNOWN_NEGATIVE for _ in range(4)),
        *(CalibrationClass.AMBIGUOUS for _ in range(2)),
        *(CalibrationClass.INFRASTRUCTURE_FAILURE for _ in range(2)),
    )
    for index, expected in enumerate(classes):
        identifier = f"seed.case.{index:02d}"
        signal = {
            CalibrationClass.KNOWN_POSITIVE: "positive-marker",
            CalibrationClass.KNOWN_NEGATIVE: "negative-marker",
            CalibrationClass.AMBIGUOUS: "ambiguous-marker",
            CalibrationClass.INFRASTRUCTURE_FAILURE: "infrastructure-marker",
        }[expected]
        if (
            inject_false_positive
            and expected == CalibrationClass.KNOWN_NEGATIVE
            and identifier == "seed.case.04"
        ):
            signal = "positive-marker"
        if inject_miss and expected == CalibrationClass.KNOWN_POSITIVE and index == 0:
            signal = "negative-marker"
        cases.append(
            {
                "id": identifier,
                "signal": signal,
                "targetGeneration": f"seed-generation-{index:02d}",
                "environmentFingerprint": _digest(f"environment:{index}"),
                "evidenceDigests": [_digest(f"evidence:{index}")],
            }
        )
        answers.append({"id": identifier, "expectedClass": expected.value})
    random.Random(seed).shuffle(cases)  # noqa: S311 - deterministic non-secret fixture ordering
    core = {
        "proposalDigest": proposal_digest,
        "seed": seed,
        "policy": policy.to_mapping(),
        "cases": cases,
        "limitations": [
            "Synthetic labels validate scoring mechanics only.",
            "The fixed seed is unsuitable for concealed empirical allocation.",
        ],
    }
    task_digest = sha256_digest(canonical_json_bytes(core))
    task = {
        "artifactType": "sova.blinded-oracle-study",
        "schemaVersion": "0.1.0",
        "core": core,
        "answerKeyCommitment": sha256_digest(canonical_json_bytes(answers)),
        "labelsPresent": False,
    }
    answer_key = {
        "artifactType": "sova.blinded-oracle-answer-key",
        "schemaVersion": "0.1.0",
        "taskDigest": task_digest,
        "answers": answers,
        "predictionDigest": None,
    }
    return task, answer_key


def predict_blinded_study(task: dict[str, Any]) -> dict[str, Any]:
    """Freeze deterministic predictions with no answer-key input."""
    core = task.get("core")
    if not isinstance(core, dict) or task.get("labelsPresent") is not False:
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "task is not a label-free study")
    cases = core.get("cases")
    if not isinstance(cases, list):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study cases are malformed")
    mapping = {
        "positive-marker": OracleVerdict.POSITIVE,
        "negative-marker": OracleVerdict.NEGATIVE,
        "ambiguous-marker": OracleVerdict.ABSTAIN,
        "infrastructure-marker": OracleVerdict.INFRASTRUCTURE_FAILURE,
    }
    predictions = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise FormatError("SOVA-ORACLE-LAB-STUDY", "study case is malformed")
        signal = case.get("signal")
        verdict = (
            mapping.get(signal, OracleVerdict.INCONCLUSIVE)
            if isinstance(signal, str)
            else OracleVerdict.INCONCLUSIVE
        )
        predictions.append({"id": case["id"], "verdict": verdict.value})
    predictions.sort(key=lambda item: str(item["id"]))
    task_digest = sha256_digest(canonical_json_bytes(core))
    prediction_core = {"taskDigest": task_digest, "predictions": predictions}
    return {
        "artifactType": "sova.blinded-oracle-predictions",
        "schemaVersion": "0.1.0",
        **prediction_core,
        "answerKeyLoaded": False,
    }


def bind_answer_key_to_predictions(
    task: dict[str, Any],
    predictions: dict[str, Any],
    answer_key_draft: dict[str, Any],
) -> dict[str, Any]:
    """Bind the held-out key only after the prediction artifact exists."""
    core = task.get("core")
    if not isinstance(core, dict):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "study core is missing")
    task_digest = sha256_digest(canonical_json_bytes(core))
    raw_predictions = predictions.get("predictions")
    if (
        predictions.get("taskDigest") != task_digest
        or predictions.get("answerKeyLoaded") is not False
        or not isinstance(raw_predictions, list)
    ):
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "prediction artifact does not bind to task")
    prediction_core = {"taskDigest": task_digest, "predictions": raw_predictions}
    answer_key = dict(answer_key_draft)
    answer_key["predictionDigest"] = sha256_digest(canonical_json_bytes(prediction_core))
    if answer_key.get("taskDigest") != task_digest:
        raise FormatError("SOVA-ORACLE-LAB-STUDY", "answer key draft does not bind to task")
    return answer_key


__all__ = [
    "bind_answer_key_to_predictions",
    "build_seeded_blinded_study",
    "predict_blinded_study",
]
