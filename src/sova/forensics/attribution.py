# SPDX-License-Identifier: Apache-2.0
"""Paired counterfactual assessment with explicit confounding and uncertainty."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import TYPE_CHECKING

from sova.forensics.model import (
    AttributionReport,
    AttributionState,
    CausalLayer,
    CounterfactualTrial,
    HypothesisAssessment,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_MIN_SUPPORTING_TRIALS = 3
_DECISION_THRESHOLD = 0.5


def _decimal(value: float) -> str:
    return format(value, ".6f").rstrip("0").rstrip(".") or "0"


def _wilson(successes: int, total: int) -> tuple[str, str]:
    if total <= 0:
        return "0", "1"
    z = 1.959963984540054
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    margin = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total)
    return _decimal(max(0.0, (centre - margin) / denominator)), _decimal(
        min(1.0, (centre + margin) / denominator)
    )


def assess_counterfactuals(  # noqa: PLR0912, PLR0915
    original_trace: str,
    trials: Sequence[CounterfactualTrial],
    *,
    layers: Iterable[CausalLayer] | None = None,
) -> AttributionReport:
    """Assess intervention evidence without converting one rerun into causal proof."""
    selected = (
        tuple(layers)
        if layers is not None
        else tuple(
            layer
            for layer in CausalLayer
            if layer not in {CausalLayer.MULTIPLE, CausalLayer.UNKNOWN}
        )
    )
    grouped: dict[CausalLayer, list[CounterfactualTrial]] = defaultdict(list)
    for trial in trials:
        grouped[trial.layer].append(trial)
    assessments: list[HypothesisAssessment] = []
    for layer in selected:
        low: str | None
        high: str | None
        rate: str | None
        eligible = prevented = persisted = confounded = inconclusive = impossible = 0
        links: list[str] = []
        limitations: list[str] = []
        for trial in grouped.get(layer, []):
            if trial.execution_status == "impossible":
                impossible += 1
                if trial.limitation:
                    limitations.append(trial.limitation)
                continue
            if not trial.context_equivalent or set(trial.changed_layers) != {layer}:
                confounded += 1
                continue
            if (
                not trial.evidence_complete
                or trial.baseline_outcome is None
                or trial.intervention_outcome is None
            ):
                inconclusive += 1
                continue
            if not trial.baseline_outcome:
                inconclusive += 1
                limitations.append(f"{trial.trial_id}: baseline behavior was not reproduced")
                continue
            eligible += 1
            if trial.intervention_outcome:
                persisted += 1
            else:
                prevented += 1
            if trial.original_trace:
                links.append(trial.original_trace)
            if trial.counterfactual_trace:
                links.append(trial.counterfactual_trace)
        if eligible:
            low, high = _wilson(prevented, eligible)
            rate = _decimal(prevented / eligible)
            low_value = float(low)
            high_value = float(high)
            if eligible >= _MIN_SUPPORTING_TRIALS and low_value > _DECISION_THRESHOLD:
                state = AttributionState.SUPPORTED
            elif eligible >= _MIN_SUPPORTING_TRIALS and high_value < _DECISION_THRESHOLD:
                state = AttributionState.CONTRADICTED
            else:
                state = AttributionState.INCONCLUSIVE
        else:
            low = None
            high = None
            rate = None
            if impossible and not (confounded or inconclusive):
                state = AttributionState.IMPOSSIBLE
            elif confounded:
                state = AttributionState.CONFOUNDED
            else:
                state = AttributionState.INCONCLUSIVE
        if confounded:
            limitations.append("One or more trials changed context or multiple candidate layers.")
        if inconclusive:
            limitations.append(
                "One or more trials lacked a reproduced baseline or complete evidence."
            )
        assessments.append(
            HypothesisAssessment(
                layer=layer,
                state=state,
                eligible_trials=eligible,
                prevented=prevented,
                persisted=persisted,
                confounded=confounded,
                inconclusive=inconclusive,
                prevention_rate=rate,
                interval_low=low,
                interval_high=high,
                evidence_links=tuple(dict.fromkeys(links)),
                limitations=tuple(dict.fromkeys(limitations)),
            )
        )
    state_order = {
        AttributionState.SUPPORTED: 0,
        AttributionState.INCONCLUSIVE: 1,
        AttributionState.CONFOUNDED: 2,
        AttributionState.CONTRADICTED: 3,
        AttributionState.IMPOSSIBLE: 4,
    }
    assessments.sort(
        key=lambda item: (
            state_order[item.state],
            -(float(item.interval_low) if item.interval_low is not None else -1.0),
            item.layer.value,
        )
    )
    return AttributionReport(
        original_trace=original_trace,
        assessments=tuple(assessments),
        trial_count=len(trials),
        limitations=(
            "This report ranks candidate layers under declared interventions; it is not "
            "causal certainty.",
            "Unmeasured common causes, observer error, and model nondeterminism may remain.",
            "A supported layer is not an assignment of legal, human, or organizational blame.",
            "At least three eligible paired trials and a Wilson lower bound above 0.5 are "
            "required for support.",
        ),
    )


__all__ = ["assess_counterfactuals"]
