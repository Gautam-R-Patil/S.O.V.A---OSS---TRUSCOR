# SPDX-License-Identifier: Apache-2.0
"""Safe deterministic ground-truth attribution acceptance fixture."""

from __future__ import annotations

from sova.forensics.attribution import assess_counterfactuals
from sova.forensics.benchmark import (
    AttributionBenchmarkCase,
    AttributionBenchmarkResult,
    evaluate_attribution_benchmark,
)
from sova.forensics.model import CausalLayer, CounterfactualTrial


def _trials(
    layer: CausalLayer,
    outcomes: tuple[bool | None, ...],
    *,
    changed: tuple[CausalLayer, ...] | None = None,
    evidence_complete: bool = True,
) -> tuple[CounterfactualTrial, ...]:
    return tuple(
        CounterfactualTrial(
            trial_id=f"{layer.value}-{index}",
            layer=layer,
            changed_layers=changed or (layer,),
            baseline_outcome=True,
            intervention_outcome=outcome,
            context_equivalent=True,
            evidence_complete=evidence_complete,
            original_trace=f"fixture:{layer.value}:original",
            counterfactual_trace=f"fixture:{layer.value}:{index}",
        )
        for index, outcome in enumerate(outcomes)
    )


def run_attribution_ground_truth_fixture() -> AttributionBenchmarkResult:
    """Run clean, confounded, stochastic, and missing-sensor labeled cases."""
    passive = (CausalLayer.BASE_MODEL,)
    cases = (
        AttributionBenchmarkCase(
            "clean-tool",
            (CausalLayer.TOOL,),
            assess_counterfactuals(
                "fixture:tool:original", _trials(CausalLayer.TOOL, (False,) * 4)
            ),
            passive,
        ),
        AttributionBenchmarkCase(
            "clean-authorization",
            (CausalLayer.AUTHORIZATION,),
            assess_counterfactuals(
                "fixture:authorization:original",
                _trials(CausalLayer.AUTHORIZATION, (False,) * 4),
            ),
            passive,
        ),
        AttributionBenchmarkCase(
            "confounded-memory-policy",
            (CausalLayer.MEMORY,),
            assess_counterfactuals(
                "fixture:memory:original",
                _trials(
                    CausalLayer.MEMORY,
                    (False,) * 4,
                    changed=(CausalLayer.MEMORY, CausalLayer.SYSTEM_POLICY),
                ),
            ),
            passive,
            expected_abstention=True,
        ),
        AttributionBenchmarkCase(
            "stochastic-environment",
            (CausalLayer.ENVIRONMENT,),
            assess_counterfactuals(
                "fixture:environment:original",
                _trials(CausalLayer.ENVIRONMENT, (False, True, False, True)),
            ),
            passive,
            expected_abstention=True,
        ),
        AttributionBenchmarkCase(
            "missing-orchestration-sensor",
            (CausalLayer.ORCHESTRATION,),
            assess_counterfactuals(
                "fixture:orchestration:original",
                _trials(
                    CausalLayer.ORCHESTRATION,
                    (None,) * 4,
                    evidence_complete=False,
                ),
            ),
            passive,
            expected_abstention=True,
        ),
    )
    return evaluate_attribution_benchmark(cases)


__all__ = ["run_attribution_ground_truth_fixture"]
