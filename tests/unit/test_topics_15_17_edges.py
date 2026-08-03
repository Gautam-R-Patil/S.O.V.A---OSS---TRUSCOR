# SPDX-License-Identifier: Apache-2.0
"""Hostile-input and boundary coverage for Topics 15 through 17."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

import sova.composition.graph as graph_module
import sova.forensics.attribution as attribution_module
import sova.forensics.reconstruct as reconstruct_module
from sova.composition import (
    ComponentNode,
    CompositionBudget,
    CompositionCandidate,
    CompositionGraph,
    CompositionObservation,
    CompositionSearchEngine,
    CompositionStrategy,
    DependencyEdge,
    EdgeKind,
    NodeKind,
    graph_from_mapping,
    minimize_composition,
    planted_composition_graph,
    risk_guided_candidates,
    t_wise_candidates,
)
from sova.evidence import (
    ExecutionObservation,
    ObservationState,
    ScannerFinding,
    adjudicate_findings,
    build_evidence_bundle,
    construct_safe_test_plan,
    import_sarif,
)
from sova.forensics import (
    AttributionBenchmarkCase,
    CausalLayer,
    CounterfactualTrial,
    assess_counterfactuals,
    evaluate_attribution_benchmark,
    passive_frequency_ranking,
    reconstruct_events,
)
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable

    from _pytest.monkeypatch import MonkeyPatch


def _graph_mapping() -> dict[str, Any]:
    return planted_composition_graph().to_mapping()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(nodes="bad"), "nodes"),
        (lambda value: value.update(edges="bad"), "edges"),
        (lambda value: value["nodes"].__setitem__(0, "bad"), "node must"),
        (lambda value: value["nodes"].append(dict(value["nodes"][0])), "duplicated"),
        (lambda value: value["nodes"][0].update(kind="unknown"), "node kind"),
        (lambda value: value["nodes"][0].update(name=""), "bounded"),
        (lambda value: value["edges"].__setitem__(0, "bad"), "edge must"),
        (lambda value: value["edges"].append(dict(value["edges"][0])), "duplicated"),
        (lambda value: value["edges"][0].update(riskWeight=True), "riskWeight"),
        (lambda value: value["edges"][0].update(order=-1), "order"),
        (lambda value: value["edges"][0].update(kind="unknown"), "edge kind"),
        (lambda value: value["edges"][0].update(observed="false"), "observed"),
    ],
)
def test_composition_graph_rejects_malformed_fields(
    mutate: Callable[[dict[str, Any]], None], message: str
) -> None:
    value = _graph_mapping()
    mutate(value)
    with pytest.raises(FormatError, match=message):
        graph_from_mapping(value)


def test_composition_graph_limit_and_nested_secret_rejection(monkeypatch: MonkeyPatch) -> None:
    value = _graph_mapping()
    value["nodes"][0]["metadata"] = [{"Authorization": "Bearer must-not-survive"}]
    with pytest.raises(FormatError, match="credential metadata"):
        graph_from_mapping(value)
    monkeypatch.setattr(graph_module, "_MAX_NODES", 0)
    with pytest.raises(FormatError, match="limit"):
        graph_from_mapping(_graph_mapping())


def _observation(*, triggered: bool | None, complete: bool = True) -> CompositionObservation:
    return CompositionObservation(
        triggered=triggered,
        evidence_complete=complete,
        oracle_state="fixture",
        trace_references=(),
        individual_outcomes=(),
    )


def test_composition_search_edge_paths_budgets_and_strategy_dispatch(
    monkeypatch: MonkeyPatch,
) -> None:
    graph = planted_composition_graph()
    assert len(t_wise_candidates(graph, 2, limit=1)) == 1
    with pytest.raises(FormatError, match="positive"):
        t_wise_candidates(graph, 2, limit=0)
    cyclic = CompositionGraph(
        graph.nodes,
        (
            *graph.edges,
            DependencyEdge(
                "cycle",
                "tool",
                "memory",
                EdgeKind.DECLARED_DEPENDENCY,
                "fixture",
                observed=False,
                risk_weight=1,
            ),
        ),
    )
    assert len(risk_guided_candidates(cyclic, max_path_nodes=4, limit=1)) == 1
    engine = CompositionSearchEngine(graph)
    assert engine.candidates(CompositionStrategy.T_WISE)
    assert engine.candidates(CompositionStrategy.RISK_GUIDED)

    ticks = iter((0.0, 31.0))
    monkeypatch.setattr("sova.composition.search.time.monotonic", lambda: next(ticks))
    report = CompositionSearchEngine(
        graph, CompositionBudget(max_duration_ms=1, max_candidates=10)
    ).search(CompositionStrategy.PAIRWISE, lambda _candidate: _observation(triggered=False))
    assert report.stop_reason == "duration-budget"


def test_minimization_accepts_confirmed_reductions_and_stops_at_budget() -> None:
    graph = CompositionGraph(
        (
            ComponentNode("a", NodeKind.AGENT, "A", "1"),
            ComponentNode("b", NodeKind.TOOL, "B", "1"),
            ComponentNode("c", NodeKind.DATA_STORE, "C", "1"),
        ),
        (
            DependencyEdge(
                "ab",
                "a",
                "b",
                EdgeKind.PERMISSION,
                "fixture",
                observed=True,
                risk_weight=1,
            ),
            DependencyEdge(
                "bc",
                "b",
                "c",
                EdgeKind.SHARED_MEMORY,
                "fixture",
                observed=True,
                risk_weight=1,
            ),
        ),
    )
    candidate = CompositionCandidate(("a", "b", "c"), ("ab", "bc"), ("ab", "bc"))
    minimized, used = minimize_composition(
        candidate,
        graph,
        lambda reduced: _observation(triggered=len(reduced.edge_ids) >= 1),
        budget=1,
    )
    assert used == 1
    assert len(minimized.edge_ids) == 1


def _finding(rule: str = "R1", mechanism: str = "m1") -> ScannerFinding:
    return ScannerFinding("scanner", "1", rule, "target", "file:1", "message", "ev", mechanism)


def test_adjudication_failure_and_abstention_paths() -> None:
    finding = _finding()
    with pytest.raises(FormatError, match="action family"):
        construct_safe_test_plan(
            (finding,), target_owned_or_authorized=True, allowed_action_families=()
        )
    duplicate = ExecutionObservation(
        claim_key=finding.claim_key,
        state=ObservationState.CONFIRMED,
        trace_reference=None,
        oracle_method="oracle",
        evidence_complete=True,
        safe_and_authorized=True,
    )
    with pytest.raises(FormatError, match="multiple terminal"):
        adjudicate_findings((finding,), (duplicate, duplicate))
    missing = adjudicate_findings((finding,), ())
    assert missing.claims[0].state.value == "inconclusive"
    unsafe = ExecutionObservation(
        claim_key=finding.claim_key,
        state=ObservationState.CONFIRMED,
        trace_reference=None,
        oracle_method="oracle",
        evidence_complete=True,
        safe_and_authorized=False,
    )
    assert adjudicate_findings((finding,), (unsafe,)).claims[0].state.value == "inconclusive"
    repeated_mechanism = adjudicate_findings((finding, _finding(mechanism="m1")), (duplicate,))
    assert any("not independent" in item for item in repeated_mechanism.claims[0].limitations)


def _valid_evidence() -> dict[str, Any]:
    digest = "sha256:" + "a" * 64
    return {
        "finding": {
            "id": "F1",
            "title": "Title",
            "summary": "Summary",
            "affected": {"component": "component", "version": "1", "identifiers": []},
            "technicalSeverity": "low",
            "harmCategory": "fixture",
        },
        "evidence": [
            {
                "role": "capsule",
                "uri": "a.sova",
                "digest": digest,
                "mediaType": "x",
                "verified": False,
            },
            {
                "role": "trace",
                "uri": "a.sova-trace",
                "digest": digest,
                "mediaType": "x",
                "verified": False,
            },
        ],
        "conditionsTested": [],
        "coverage": {"testedCount": 1, "denominator": None, "detectionFloor": "fixture"},
        "reproduction": {},
        "taxonomyMappings": [],
        "methodology": {"method": "fixture"},
        "suggestedMitigations": [],
        "regressionEvidence": [],
        "attachments": [],
        "limitations": ["fixture"],
        "lifecycle": {"state": "draft"},
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.pop("finding"), "finding"),
        (lambda value: value["finding"].pop("affected"), "affected"),
        (lambda value: value.pop("coverage"), "coverage object"),
        (lambda value: value["coverage"].update(testedCount=True), "testedCount"),
        (lambda value: value["finding"].update(technicalSeverity="bad"), "severity"),
        (lambda value: value.update(reproduction=[]), "reproduction"),
        (lambda value: value.update(methodology=[]), "methodology"),
        (lambda value: value.update(taxonomyMappings="bad"), "taxonomyMappings"),
        (lambda value: value.update(taxonomyMappings=[{"id": 1}]), "taxonomy mapping"),
        (lambda value: value.update(lifecycle=[]), "lifecycle"),
        (lambda value: value.update(limitations=[]), "limitation"),
        (lambda value: value.update(conditionsTested="bad"), "array"),
        (lambda value: value.update(attachments=["bad"]), "objects"),
        (lambda value: value["evidence"][0].update(verified="false"), "verified"),
    ],
)
def test_evidence_rejects_malformed_fields(
    mutate: Callable[[dict[str, Any]], Any], message: str
) -> None:
    value = _valid_evidence()
    mutate(value)
    with pytest.raises(FormatError, match=message):
        build_evidence_bundle(value)


@pytest.mark.parametrize(
    "document",
    [
        {"runs": ["bad"]},
        {"runs": [{"tool": {"driver": {"name": "s"}}, "results": "bad"}]},
        {"runs": [{"tool": {"driver": {"name": "s"}}, "results": ["bad"]}]},
    ],
)
def test_sarif_rejects_malformed_runs(document: dict[str, Any]) -> None:
    with pytest.raises(FormatError):
        import_sarif(document)


def test_attribution_baseline_and_benchmark_abstention_edges() -> None:
    assert attribution_module._wilson(0, 0) == ("0", "1")
    trial = CounterfactualTrial(
        trial_id="baseline-missing",
        layer=CausalLayer.TOOL,
        changed_layers=(CausalLayer.TOOL,),
        baseline_outcome=False,
        intervention_outcome=False,
        context_equivalent=True,
        evidence_complete=True,
        original_trace=None,
        counterfactual_trace=None,
    )
    report = assess_counterfactuals("trace", (trial,), layers=(CausalLayer.TOOL,))
    assert report.assessments[0].state.value == "inconclusive"
    result = evaluate_attribution_benchmark(
        (
            AttributionBenchmarkCase(
                "abstain",
                (CausalLayer.TOOL,),
                report,
                (CausalLayer.BASE_MODEL,),
            ),
            AttributionBenchmarkCase("unknown", (), report, (), known_ground_truth=False),
        )
    )
    assert result.abstentions == 1
    assert result.errors[0]["predicted"] is None
    assert result.to_mapping()["artifactType"] == "sova.attribution-benchmark"
    ranking = passive_frequency_ranking(
        ({"kind": 1}, {"kind": "unknown.kind"}, {"kind": "authorization.decision"})
    )
    assert ranking[0] == CausalLayer.AUTHORIZATION


def test_reconstruction_event_limit_fallbacks_and_dropped_markers(
    monkeypatch: MonkeyPatch,
) -> None:
    event = {
        "sequence": 0,
        "kind": "run.started",
        "actor": "invalid-actor",
        "target": None,
        "parents": [],
        "payload": {"$redacted": "secret"},
    }
    report = reconstruct_events(
        (event,), source_type="external", source_id="fallback", dropped_event_count=2
    )
    assert report.entries[0].actor == "unknown actor"
    assert report.entries[0].missing_or_redacted
    assert any("dropped" in item for item in report.missing_sensor_markers)
    malformed = dict(event)
    malformed["sequence"] = True
    with pytest.raises(FormatError, match="sequence"):
        reconstruct_events((malformed,), source_type="external", source_id="bad")
    monkeypatch.setattr(reconstruct_module, "_MAX_EVENTS", 0)
    with pytest.raises(FormatError, match="limit"):
        reconstruct_events((event,), source_type="external", source_id="limit")
