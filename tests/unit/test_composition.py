# SPDX-License-Identifier: Apache-2.0
"""Composition graph, search, minimization, and attribution contracts."""

from __future__ import annotations

import pytest

from sova.composition import (
    CompositionBudget,
    CompositionCandidate,
    CompositionObservation,
    CompositionSearchEngine,
    CompositionStrategy,
    PlantedCompositionEvaluator,
    composition_to_scenario_fragment,
    graph_from_mapping,
    minimize_composition,
    pairwise_candidates,
    planted_composition_graph,
    risk_guided_candidates,
    t_wise_candidates,
    trigger_aware_candidates,
)
from sova.formats import validate_document
from sova.formats.errors import FormatError


def test_graph_round_trip_and_secret_material_rejection() -> None:
    graph = planted_composition_graph()
    parsed = graph_from_mapping(graph.to_mapping())
    assert parsed == graph
    hostile = graph.to_mapping()
    hostile["nodes"][0]["metadata"] = {"api_key": "must-not-enter-graph"}
    with pytest.raises(FormatError, match="credential metadata"):
        graph_from_mapping(hostile)
    malformed = graph.to_mapping()
    malformed["edges"][0]["target"] = "missing"
    with pytest.raises(FormatError, match="endpoint"):
        graph_from_mapping(malformed)


def test_all_search_strategies_are_bounded_and_deterministic() -> None:
    graph = planted_composition_graph()
    assert pairwise_candidates(graph)
    assert t_wise_candidates(graph, 3, limit=10)
    assert risk_guided_candidates(graph, max_path_nodes=4, limit=10)
    assert trigger_aware_candidates(graph, limit=10)
    assert trigger_aware_candidates(graph, limit=10) == trigger_aware_candidates(graph, limit=10)
    with pytest.raises(FormatError, match="at least two"):
        t_wise_candidates(graph, 1, limit=10)
    with pytest.raises(FormatError, match="positive"):
        risk_guided_candidates(graph, max_path_nodes=1, limit=10)


def test_ground_truth_composition_only_failure_is_found_minimized_and_attributed() -> None:
    graph = planted_composition_graph()
    report = CompositionSearchEngine(
        graph,
        CompositionBudget(max_attempts=50, max_candidates=50, max_path_nodes=4),
    ).search(CompositionStrategy.TRIGGER_AWARE, PlantedCompositionEvaluator())
    assert report.successful is not None
    assert report.minimized is not None
    assert report.composition_only_confirmed
    assert report.minimized.node_ids == ("memory", "agent", "tool")
    assert all(item.necessary_under_test is True for item in report.attribution)
    validate_document(report.to_mapping(), "sova.composition-report")
    fragment = composition_to_scenario_fragment(graph, report.minimized, report=report)
    assert fragment["compositionOnlyConfirmed"] is True
    assert fragment["executorMechanicsIncluded"] is False
    assert fragment["requiredFreshAuthorization"] is True


def test_node_minimization_removes_incident_edges_and_requires_fresh_evidence() -> None:
    graph = planted_composition_graph()
    candidate = trigger_aware_candidates(graph, limit=20)[0]
    seen: list[tuple[str, ...]] = []

    def evaluator(reduced: CompositionCandidate) -> CompositionObservation:
        seen.append(reduced.edge_ids)
        triggered = "observer" not in reduced.node_ids
        return CompositionObservation(
            triggered=triggered,
            evidence_complete=True,
            oracle_state="fixture",
            trace_references=(),
            individual_outcomes=(),
        )

    minimized, used = minimize_composition(candidate, graph, evaluator, budget=20)
    assert used > 0
    assert "observer" not in minimized.node_ids
    remaining_edges = {edge.edge_id for edge in graph.edges if edge.source != "observer"}
    assert set(minimized.edge_ids).issubset(remaining_edges)
    assert len(seen) == used


def test_attempt_budget_and_missing_observation_remain_inconclusive() -> None:
    graph = planted_composition_graph()

    def inconclusive(_candidate: CompositionCandidate) -> CompositionObservation:
        return CompositionObservation(
            triggered=None,
            evidence_complete=False,
            oracle_state="missing-sensor",
            trace_references=(),
            individual_outcomes=(),
        )

    report = CompositionSearchEngine(
        graph, CompositionBudget(max_attempts=1, max_candidates=10)
    ).search(CompositionStrategy.PAIRWISE, inconclusive)
    assert report.successful is None
    assert report.stop_reason == "attempt-budget"
    with pytest.raises(FormatError, match="budgets"):
        CompositionSearchEngine(graph, CompositionBudget(max_attempts=0))
