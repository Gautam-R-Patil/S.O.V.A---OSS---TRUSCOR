# SPDX-License-Identifier: Apache-2.0
"""Observable-outcome semantic reproduction and judge calibration."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import TYPE_CHECKING, Protocol

from sova.formats.errors import FormatError
from sova.replay.model import (
    JudgeCalibration,
    ReplayMode,
    ReproductionClass,
    SemanticReproductionReport,
    SemanticTrial,
    SensitivityResult,
)
from sova.reproduction import compare_observable_outcomes

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


class SemanticJudge(Protocol):
    """Optional isolated judge; deterministic oracle evidence takes priority."""

    def __call__(self, reference: Path, candidate: Path) -> bool | None: ...


_MIN_STRUCTURAL_TRIALS = 3


def wilson_interval(
    successes: int,
    total: int,
    *,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    """Return the two-sided Wilson score interval without external dependencies."""
    if total < 0 or successes < 0 or successes > total:
        raise FormatError("SOVA-SEMANTIC-COUNTS", "invalid reproduction counts")
    if total == 0:
        return 0.0, 1.0
    proportion = successes / total
    denominator = 1 + (z * z) / total
    centre = proportion + (z * z) / (2 * total)
    spread = z * math.sqrt((proportion * (1 - proportion) + (z * z) / (4 * total)) / total)
    return max(0.0, (centre - spread) / denominator), min(1.0, (centre + spread) / denominator)


def _trial(
    reference: Path,
    candidate: Path,
    condition: str,
    judge: SemanticJudge | None,
) -> SemanticTrial:
    comparison = compare_observable_outcomes(
        reference,
        candidate,
        kinds=("oracle.completed",),
    )
    if comparison.status == "equivalent":
        return SemanticTrial(
            trace=str(candidate),
            condition=condition,
            status="eligible",
            reproduced=True,
            method="deterministic-oracle",
        )
    if comparison.status == "divergent":
        return SemanticTrial(
            trace=str(candidate),
            condition=condition,
            status="eligible",
            reproduced=False,
            method="deterministic-oracle",
        )
    if judge is None:
        return SemanticTrial(
            str(candidate),
            condition,
            "inconclusive",
            None,
            "deterministic-oracle",
            comparison.limitations,
        )
    judged = judge(reference, candidate)
    if judged is None:
        return SemanticTrial(
            str(candidate),
            condition,
            "inconclusive",
            None,
            "isolated-model-judge",
            ("The optional judge declined or could not decide.",),
        )
    return SemanticTrial(
        str(candidate),
        condition,
        "eligible",
        judged,
        "isolated-model-judge",
        ("Model judgment is not deterministic execution evidence.",),
    )


def semantic_reproduction_study(
    reference: Path,
    candidates: Sequence[Path],
    *,
    conditions: Sequence[str] | None = None,
    judge: SemanticJudge | None = None,
) -> SemanticReproductionReport:
    """Evaluate independent traces using declared observable effects, not exact tokens."""
    if not candidates:
        raise FormatError("SOVA-SEMANTIC-TRIALS", "at least one trial is required")
    labels = tuple(conditions or ("declared-baseline",) * len(candidates))
    if len(labels) != len(candidates) or any(not label for label in labels):
        raise FormatError(
            "SOVA-SEMANTIC-CONDITIONS",
            "conditions must provide one non-empty label per trial",
        )
    trials = tuple(
        _trial(reference, candidate, condition, judge)
        for candidate, condition in zip(candidates, labels, strict=True)
    )
    eligible = sum(trial.reproduced is not None for trial in trials)
    reproduced = sum(trial.reproduced is True for trial in trials)
    inconclusive = len(trials) - eligible
    low, high = wilson_interval(reproduced, eligible)
    if eligible == 0 or inconclusive:
        classification = ReproductionClass.INCONCLUSIVE
    elif reproduced == 0:
        classification = ReproductionClass.NOT_REPRODUCED
    elif reproduced == eligible and eligible >= _MIN_STRUCTURAL_TRIALS:
        classification = ReproductionClass.STRUCTURAL
    else:
        classification = ReproductionClass.FLAKY
    grouped: dict[str, list[SemanticTrial]] = defaultdict(list)
    for trial in trials:
        grouped[trial.condition].append(trial)
    sensitivity: list[SensitivityResult] = []
    for condition, group in sorted(grouped.items()):
        condition_eligible = sum(item.reproduced is not None for item in group)
        condition_reproduced = sum(item.reproduced is True for item in group)
        condition_low, condition_high = wilson_interval(condition_reproduced, condition_eligible)
        sensitivity.append(
            SensitivityResult(
                condition,
                condition_reproduced,
                condition_eligible,
                len(group) - condition_eligible,
                condition_low,
                condition_high,
            )
        )
    return SemanticReproductionReport(
        ReplayMode.SEMANTIC_REPRODUCTION,
        classification,
        reproduced,
        eligible,
        len(trials),
        inconclusive,
        low,
        high,
        trials,
        tuple(sensitivity),
        (
            "Classification describes only the declared conditions and observed trials.",
            "A 95% Wilson interval quantifies binomial sampling uncertainty, not all model drift.",
            "Exact token equality and private chain-of-thought are outside the outcome definition.",
        ),
    )


def calibrate_judge(
    expected: Sequence[bool],
    observed: Sequence[bool | None],
) -> JudgeCalibration:
    """Measure an optional judge against labeled cases; abstentions count as incorrect."""
    if not expected or len(expected) != len(observed):
        raise FormatError(
            "SOVA-JUDGE-CALIBRATION",
            "expected and observed labels must be non-empty and equal length",
        )
    pairs = tuple(zip(expected, observed, strict=True))
    correct = sum(actual is expected_value for expected_value, actual in pairs)
    false_positive = sum(
        expected_value is False and actual is True for expected_value, actual in pairs
    )
    false_negative = sum(
        expected_value is True and actual is False for expected_value, actual in pairs
    )
    return JudgeCalibration(
        len(expected),
        correct,
        correct / len(expected),
        false_positive,
        false_negative,
    )


__all__ = [
    "SemanticJudge",
    "calibrate_judge",
    "semantic_reproduction_study",
    "wilson_interval",
]
