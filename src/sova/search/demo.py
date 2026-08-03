# SPDX-License-Identifier: Apache-2.0
"""Deterministic trigger-search proof where fixed lists and one pass miss."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from sova.search.engine import TriggerSearchEngine
from sova.search.model import (
    SearchBudget,
    SearchObservation,
    SearchSpace,
    TriggerCandidate,
    TriggerDimension,
)
from sova.search.portable import candidate_to_scenario_fragment

_TRIGGER_SESSION_COUNT = 3


def _space() -> SearchSpace:
    return SearchSpace(
        domains={
            "message": ("hello", "status", "blue-owl"),
            "mode": ("default", "staging", "research"),
            "sessionCount": (1, 2, 3),
        },
        dimensions={
            "message": TriggerDimension.CONTENT,
            "mode": TriggerDimension.ENVIRONMENT,
            "sessionCount": TriggerDimension.INVOCATION,
        },
        defaults={"message": "hello", "mode": "default", "sessionCount": 1},
    )


def _evaluate(candidate: TriggerCandidate) -> SearchObservation:
    conditions = {
        "content": candidate.values.get("message") == "blue-owl",
        "environment": candidate.values.get("mode") == "research",
        "invocation": candidate.values.get("sessionCount") == _TRIGGER_SESSION_COUNT,
    }
    coverage = frozenset(
        {"branch:" + name + ":" + str(value).casefold() for name, value in conditions.items()}
    )
    matched = sum(conditions.values())
    return SearchObservation(
        triggered=matched == len(conditions),
        score=matched / len(conditions),
        coverage=coverage,
        effects=("canary.read", "sink-only-egress") if matched == len(conditions) else (),
        evidence_ids=("sova:synthetic:oracle",),
        duration_ms=1,
        status="confirmed" if matched == len(conditions) else "not-confirmed",
    )


def run_trigger_search_demo() -> dict[str, Any]:
    """Run fixed, one-pass, and adaptive lanes against one owned inert target."""
    space = _space()
    engine = TriggerSearchEngine(
        space,
        SearchBudget(
            max_attempts=80,
            max_mutations=200,
            max_generations=12,
            population_size=12,
            max_duration_ms=10_000,
            stagnation_generations=5,
        ),
        seed=19,
    )
    baseline = TriggerCandidate(dict(space.defaults))
    fixed = engine.signature(
        (
            baseline,
            TriggerCandidate({"message": "status", "mode": "default", "sessionCount": 1}),
        ),
        _evaluate,
    )
    one_pass = engine.human((baseline,), _evaluate)
    adaptive = engine.adaptive((baseline,), _evaluate)
    if adaptive.minimized is not None:
        repeated = [_evaluate(adaptive.minimized).triggered for _ in range(5)]
        adaptive = replace(adaptive, reproduction_rate=sum(repeated) / len(repeated))
    return {
        "artifactType": "sova.trigger-search-comparison",
        "schemaVersion": "0.1.0",
        "target": "owned-inert-conditional-fixture",
        "fixedList": fixed.to_mapping(),
        "onePass": one_pass.to_mapping(),
        "adaptive": adaptive.to_mapping(),
        "portableTrigger": (
            None
            if adaptive.minimized is None
            else candidate_to_scenario_fragment(adaptive.minimized, space)
        ),
        "claims": {
            "realSystemSuperiority": False,
            "novelAlgorithm": False,
            "paperOrPatentDecisionDeferred": True,
        },
    }


__all__ = ["run_trigger_search_demo"]
