# SPDX-License-Identifier: Apache-2.0
"""Forensic reconstruction, counterfactual attribution, and benchmark contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sova.forensics import (
    AttributionBenchmarkCase,
    AttributionState,
    CausalLayer,
    CounterfactualTrial,
    assess_counterfactuals,
    evaluate_attribution_benchmark,
    passive_frequency_ranking,
    reconstruct_events,
    reconstruct_trace,
    run_attribution_ground_truth_fixture,
)
from sova.formats import validate_document
from sova.formats.errors import FormatError
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from pathlib import Path


def _event(
    event_id: str,
    sequence: int,
    kind: str,
    *,
    parents: tuple[str, ...] = (),
    clock_domain: str = "fixture",
) -> dict[str, object]:
    return {
        "id": event_id,
        "sequence": sequence,
        "kind": kind,
        "phase": "test",
        "actor": {"name": "fixture actor"},
        "target": {"name": "fixture target"},
        "parents": list(parents),
        "clockDomain": clock_domain,
        "monotonicNs": sequence,
        "clock": {"trusted": True, "skewEstimateNs": 0},
        "eventHash": "sha256:" + f"{sequence:x}".zfill(64),
    }


def _trial(  # noqa: PLR0913
    trial_id: str,
    layer: CausalLayer,
    *,
    intervention: bool | None,
    changed: tuple[CausalLayer, ...] | None = None,
    status: str = "completed",
    equivalent: bool = True,
    complete: bool = True,
    baseline: bool | None = True,
) -> CounterfactualTrial:
    return CounterfactualTrial(
        trial_id,
        layer,
        changed or (layer,),
        baseline,
        intervention,
        equivalent,
        complete,
        "trace:original",
        f"trace:{trial_id}",
        status,
        "fixture limitation" if status == "impossible" else None,
    )


def test_reconstruction_preserves_causality_uncertainty_and_missing_sensors() -> None:
    events = [
        _event("b", 1, "model.response", parents=("a",)),
        _event("a", 0, "prompt.sent"),
        {**_event("c", 2, "tool.request", clock_domain="other"), "payloadOmitted": True},
        _event("d", 3, "network.request", parents=("missing",)),
    ]
    report = reconstruct_events(events, source_type="fixture", source_id="case-1")
    assert [item.event_id for item in report.entries][:2] == ["a", "b"]
    assert report.entries[1].decision_point
    assert report.entries[-1].order_basis == "missing-causal-parent"
    assert ("a", "b") in report.causal_edges
    assert report.uncertain_order_pairs
    assert any("redacted" in item for item in report.missing_sensor_markers)
    assert any("missing causal parent" in item for item in report.missing_sensor_markers)
    validate_document(report.to_mapping(), "sova.forensic-reconstruction")


def test_reconstruction_rejects_duplicate_cycles_and_bad_parents() -> None:
    with pytest.raises(FormatError, match="duplicated"):
        reconstruct_events(
            [_event("a", 0, "run.started"), _event("a", 1, "run.completed")],
            source_type="fixture",
            source_id="duplicate",
        )
    with pytest.raises(FormatError, match="cycle"):
        reconstruct_events(
            [
                _event("a", 0, "run.started", parents=("b",)),
                _event("b", 1, "run.completed", parents=("a",)),
            ],
            source_type="fixture",
            source_id="cycle",
        )
    malformed = _event("a", 0, "run.started")
    malformed["parents"] = "not-an-array"
    with pytest.raises(FormatError, match="parents"):
        reconstruct_events([malformed], source_type="fixture", source_id="bad")


def test_native_trace_reconstruction_verifies_source(tmp_path: Path) -> None:
    path = tmp_path / "forensics.sova-trace"
    writer = TraceWriter(path)
    start = writer.append("run.started", {"objective": "safe fixture"})
    writer.append("model.response", {"text": "observable"}, parents=[start] if start else [])
    writer.finalize()
    report = reconstruct_trace(path)
    assert report.source_type == "sova.trace"
    assert report.source_digest is not None
    assert len(report.entries) == 2


def test_counterfactual_states_and_uncertainty_are_explicit() -> None:
    trials = tuple(
        _trial(f"tool-{index}", CausalLayer.TOOL, intervention=False) for index in range(4)
    ) + tuple(
        _trial(f"model-{index}", CausalLayer.BASE_MODEL, intervention=True) for index in range(4)
    )
    trials += (
        _trial(
            "confounded",
            CausalLayer.MEMORY,
            intervention=False,
            changed=(CausalLayer.MEMORY, CausalLayer.SYSTEM_POLICY),
        ),
        _trial(
            "impossible",
            CausalLayer.AUTHORIZATION,
            intervention=None,
            status="impossible",
        ),
        _trial(
            "incomplete",
            CausalLayer.ENVIRONMENT,
            intervention=None,
            complete=False,
        ),
    )
    report = assess_counterfactuals("trace:original", trials)
    states = {item.layer: item.state for item in report.assessments}
    assert states[CausalLayer.TOOL] == AttributionState.SUPPORTED
    assert states[CausalLayer.BASE_MODEL] == AttributionState.CONTRADICTED
    assert states[CausalLayer.MEMORY] == AttributionState.CONFOUNDED
    assert states[CausalLayer.AUTHORIZATION] == AttributionState.IMPOSSIBLE
    assert states[CausalLayer.ENVIRONMENT] == AttributionState.INCONCLUSIVE
    assert report.to_mapping()["authoritativeBlame"] is False


def test_known_ground_truth_benchmark_and_passive_baseline() -> None:
    report = assess_counterfactuals(
        "trace:case",
        tuple(_trial(str(index), CausalLayer.TOOL, intervention=False) for index in range(4)),
    )
    ranking = passive_frequency_ranking(
        [{"kind": "model.response"}, {"kind": "tool.request"}, {"kind": "tool.completed"}]
    )
    result = evaluate_attribution_benchmark(
        (
            AttributionBenchmarkCase(
                "case",
                (CausalLayer.TOOL,),
                report,
                ranking,
            ),
        )
    )
    assert result.top1_accuracy == "1"
    assert result.supported_coverage == "1"
    assert result.passive_top1_accuracy == "1"
    assert evaluate_attribution_benchmark(()).top1_accuracy is None


def test_ground_truth_acceptance_fixture_measures_accuracy_and_abstention() -> None:
    result = run_attribution_ground_truth_fixture()
    assert result.evaluated_cases == 5
    assert result.top1_accuracy == "0.4"
    assert result.selective_accuracy == "1"
    assert result.decision_accuracy == "1"
    assert result.supported_coverage == "0.4"
    assert result.correct_abstentions == 3
    assert result.passive_top1_accuracy == "0"
