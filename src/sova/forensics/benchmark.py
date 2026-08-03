# SPDX-License-Identifier: Apache-2.0
"""Deterministic ground-truth metrics for counterfactual attribution studies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.forensics.model import AttributionReport, AttributionState, CausalLayer

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class AttributionBenchmarkCase:
    """One labeled synthetic or independently reviewed attribution case."""

    case_id: str
    ground_truth: tuple[CausalLayer, ...]
    report: AttributionReport
    passive_ranking: tuple[CausalLayer, ...]
    known_ground_truth: bool = True
    expected_abstention: bool = False


@dataclass(frozen=True, slots=True)
class AttributionBenchmarkResult:
    evaluated_cases: int
    top1_correct: int
    top1_accuracy: str | None
    supported_coverage: str | None
    passive_top1_accuracy: str | None
    selective_accuracy: str | None
    decision_accuracy: str | None
    abstentions: int
    correct_abstentions: int
    errors: tuple[dict[str, Any], ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.attribution-benchmark",
            "schemaVersion": "0.1.0",
            "evaluatedCases": self.evaluated_cases,
            "top1Correct": self.top1_correct,
            "top1Accuracy": self.top1_accuracy,
            "supportedCoverage": self.supported_coverage,
            "passiveTop1Accuracy": self.passive_top1_accuracy,
            "selectiveAccuracy": self.selective_accuracy,
            "decisionAccuracy": self.decision_accuracy,
            "abstentions": self.abstentions,
            "correctAbstentions": self.correct_abstentions,
            "errors": list(self.errors),
            "limitations": [
                "Synthetic ground truth measures implementation behavior, not field validity.",
                "Passive frequency is a transparent non-causal baseline, not a strongest "
                "LLM baseline.",
                "Unknown or multi-cause incidents require separately labeled evaluation cases.",
            ],
        }


def _ratio(numerator: int, denominator: int) -> str | None:
    if denominator == 0:
        return None
    return format(numerator / denominator, ".6f").rstrip("0").rstrip(".")


def evaluate_attribution_benchmark(
    cases: Sequence[AttributionBenchmarkCase],
) -> AttributionBenchmarkResult:
    """Measure top-one attribution, abstention, coverage, and a passive baseline."""
    eligible = [case for case in cases if case.known_ground_truth and case.ground_truth]
    correct = passive_correct = supported = abstentions = 0
    selective_correct = decision_correct = correct_abstentions = 0
    errors: list[dict[str, Any]] = []
    for case in eligible:
        supported_rows = tuple(
            item for item in case.report.assessments if item.state == AttributionState.SUPPORTED
        )
        predicted = supported_rows[0].layer if supported_rows else None
        if predicted is None:
            abstentions += 1
            if case.expected_abstention:
                correct_abstentions += 1
                decision_correct += 1
        else:
            supported += 1
        if predicted in case.ground_truth:
            correct += 1
            selective_correct += 1
            if not case.expected_abstention:
                decision_correct += 1
        else:
            errors.append(
                {
                    "caseId": case.case_id,
                    "expected": [item.value for item in case.ground_truth],
                    "predicted": None if predicted is None else predicted.value,
                }
            )
        if case.passive_ranking and case.passive_ranking[0] in case.ground_truth:
            passive_correct += 1
    return AttributionBenchmarkResult(
        evaluated_cases=len(eligible),
        top1_correct=correct,
        top1_accuracy=_ratio(correct, len(eligible)),
        supported_coverage=_ratio(supported, len(eligible)),
        passive_top1_accuracy=_ratio(passive_correct, len(eligible)),
        selective_accuracy=_ratio(selective_correct, supported),
        decision_accuracy=_ratio(decision_correct, len(eligible)),
        abstentions=abstentions,
        correct_abstentions=correct_abstentions,
        errors=tuple(errors),
    )


_PASSIVE_PREFIX_LAYER: tuple[tuple[str, CausalLayer], ...] = (
    ("model.", CausalLayer.BASE_MODEL),
    ("policy.", CausalLayer.SYSTEM_POLICY),
    ("orchestration.", CausalLayer.ORCHESTRATION),
    ("tool.", CausalLayer.TOOL),
    ("authorization.", CausalLayer.AUTHORIZATION),
    ("approval.", CausalLayer.AUTHORIZATION),
    ("memory.", CausalLayer.MEMORY),
    ("retrieval.", CausalLayer.MEMORY),
    ("inter-agent.", CausalLayer.HANDOFF),
    ("network.", CausalLayer.ENVIRONMENT),
)


def passive_frequency_ranking(events: Sequence[Mapping[str, Any]]) -> tuple[CausalLayer, ...]:
    """Return an auditable occurrence-count baseline with no causal interpretation."""
    counts: dict[CausalLayer, int] = dict.fromkeys(
        (
            layer
            for layer in CausalLayer
            if layer not in {CausalLayer.MULTIPLE, CausalLayer.UNKNOWN}
        ),
        0,
    )
    for event in events:
        kind = event.get("kind")
        if not isinstance(kind, str):
            continue
        for prefix, layer in _PASSIVE_PREFIX_LAYER:
            if kind.startswith(prefix):
                counts[layer] += 1
                break
    return tuple(sorted(counts, key=lambda layer: (-counts[layer], layer.value)))


__all__ = [
    "AttributionBenchmarkCase",
    "AttributionBenchmarkResult",
    "evaluate_attribution_benchmark",
    "passive_frequency_ranking",
]
