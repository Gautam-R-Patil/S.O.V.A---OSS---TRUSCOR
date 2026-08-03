# SPDX-License-Identifier: Apache-2.0
"""Budgeted pairwise, t-wise, risk-path, and trigger-aware composition search."""

from __future__ import annotations

import itertools
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from sova.composition.model import (
    CompositionAttempt,
    CompositionBudget,
    CompositionCandidate,
    CompositionGraph,
    CompositionObservation,
    CompositionReport,
    CompositionStrategy,
    DependencyEdge,
    ElementAttribution,
)
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Sequence

_MIN_COMPOSITION_SIZE = 2


CompositionEvaluator = Callable[[CompositionCandidate], CompositionObservation]


def _candidate_for_nodes(graph: CompositionGraph, node_ids: Sequence[str]) -> CompositionCandidate:
    selected = set(node_ids)
    edges = tuple(
        edge.edge_id for edge in graph.edges if edge.source in selected and edge.target in selected
    )
    ordered_edges = sorted(
        (edge for edge in graph.edges if edge.edge_id in edges),
        key=lambda edge: (edge.order is None, edge.order or 0, edge.edge_id),
    )
    return CompositionCandidate(
        tuple(sorted(selected)),
        tuple(sorted(edges)),
        tuple(edge.edge_id for edge in ordered_edges),
    )


def pairwise_candidates(graph: CompositionGraph) -> tuple[CompositionCandidate, ...]:
    """Create the explicit pairwise baseline over connected component pairs."""
    candidates = {
        _candidate_for_nodes(graph, (edge.source, edge.target)).digest: _candidate_for_nodes(
            graph, (edge.source, edge.target)
        )
        for edge in graph.edges
    }
    return tuple(candidates[key] for key in sorted(candidates))


def t_wise_candidates(
    graph: CompositionGraph,
    t: int,
    *,
    limit: int,
) -> tuple[CompositionCandidate, ...]:
    """Materialize a bounded t-wise baseline without hiding combinatorial growth."""
    if t < _MIN_COMPOSITION_SIZE:
        raise FormatError("SOVA-COMPOSE-T", "t must be at least two")
    if limit <= 0:
        raise FormatError("SOVA-COMPOSE-SEARCH-LIMIT", "candidate limit must be positive")
    candidates: list[CompositionCandidate] = []
    for node_ids in itertools.combinations(sorted(node.node_id for node in graph.nodes), t):
        candidate = _candidate_for_nodes(graph, node_ids)
        if candidate.edge_ids:
            candidates.append(candidate)
        if len(candidates) >= limit:
            break
    return tuple(candidates)


def risk_guided_candidates(
    graph: CompositionGraph,
    *,
    max_path_nodes: int,
    limit: int,
) -> tuple[CompositionCandidate, ...]:
    """Rank simple directed paths by declared edge risk and state/order metadata."""
    if max_path_nodes < _MIN_COMPOSITION_SIZE or limit <= 0:
        raise FormatError(
            "SOVA-COMPOSE-SEARCH-LIMIT", "path length and candidate limit must be positive"
        )
    outgoing: dict[str, list[DependencyEdge]] = {}
    for edge in graph.edges:
        outgoing.setdefault(edge.source, []).append(edge)
    paths: list[tuple[int, CompositionCandidate]] = []

    def visit(nodes: tuple[str, ...], edges: tuple[str, ...], risk: int) -> None:
        current = nodes[-1]
        if len(nodes) >= _MIN_COMPOSITION_SIZE:
            candidate = CompositionCandidate(nodes, edges, edges)
            paths.append((risk, candidate))
        if len(nodes) >= max_path_nodes:
            return
        for edge in sorted(
            outgoing.get(current, []),
            key=lambda item: (-item.risk_weight, item.edge_id),
        ):
            if edge.target in nodes:
                continue
            metadata_bonus = 10 if edge.state_condition is not None or edge.order is not None else 0
            visit(
                (*nodes, edge.target),
                (*edges, edge.edge_id),
                risk + edge.risk_weight + metadata_bonus,
            )

    for node in sorted(graph.nodes, key=lambda item: item.node_id):
        visit((node.node_id,), (), 0)
    paths.sort(key=lambda item: (-item[0], item[1].digest))
    unique: dict[str, CompositionCandidate] = {}
    for _risk, candidate in paths:
        unique.setdefault(candidate.digest, candidate)
        if len(unique) >= limit:
            break
    return tuple(unique.values())


def trigger_aware_candidates(
    graph: CompositionGraph,
    *,
    limit: int,
) -> tuple[CompositionCandidate, ...]:
    """Prioritize order/state-dependent paths while retaining deterministic scheduling."""
    candidates = risk_guided_candidates(
        graph,
        max_path_nodes=max(2, min(8, len(graph.nodes))),
        limit=max(limit * 2, limit),
    )
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    ranked = sorted(
        candidates,
        key=lambda candidate: (
            -sum(
                edge_by_id[edge_id].state_condition is not None
                or edge_by_id[edge_id].order is not None
                for edge_id in candidate.edge_ids
            ),
            -sum(edge_by_id[edge_id].risk_weight for edge_id in candidate.edge_ids),
            candidate.digest,
        ),
    )
    return tuple(ranked[:limit])


def _reduce_candidate(
    candidate: CompositionCandidate,
    graph: CompositionGraph,
    *,
    remove_node: str | None = None,
    remove_edge: str | None = None,
) -> CompositionCandidate:
    nodes = tuple(node for node in candidate.node_ids if node != remove_node)
    edge_by_id = {edge.edge_id: edge for edge in graph.edges}
    edges = tuple(
        edge_id
        for edge_id in candidate.edge_ids
        if edge_id != remove_edge
        and (
            remove_node is None
            or (
                edge_by_id[edge_id].source != remove_node
                and edge_by_id[edge_id].target != remove_node
            )
        )
    )
    sequence = tuple(edge for edge in candidate.sequence if edge in edges)
    return CompositionCandidate(nodes, edges, sequence, candidate.digest)


def minimize_composition(
    candidate: CompositionCandidate,
    graph: CompositionGraph,
    evaluator: CompositionEvaluator,
    *,
    budget: int,
) -> tuple[CompositionCandidate, int]:
    """Remove elements only after a fresh evidence-complete confirming execution."""
    current = candidate
    used = 0
    changed = True
    while changed and used < budget:
        changed = False
        for edge_id in current.edge_ids:
            reduced = _reduce_candidate(current, graph, remove_edge=edge_id)
            observation = evaluator(reduced)
            used += 1
            if observation.triggered is True and observation.evidence_complete:
                current = reduced
                changed = True
                break
            if used >= budget:
                break
        if changed:
            continue
        for node_id in current.node_ids:
            reduced = _reduce_candidate(current, graph, remove_node=node_id)
            observation = evaluator(reduced)
            used += 1
            if observation.triggered is True and observation.evidence_complete:
                current = reduced
                changed = True
                break
            if used >= budget:
                break
    return current, used


class CompositionSearchEngine:
    """Search composition candidates without executing provider-specific mechanics."""

    def __init__(self, graph: CompositionGraph, budget: CompositionBudget | None = None) -> None:
        self.graph = graph
        self.budget = budget or CompositionBudget()
        if (
            self.budget.max_attempts <= 0
            or self.budget.max_duration_ms <= 0
            or self.budget.max_candidates <= 0
            or self.budget.max_path_nodes < _MIN_COMPOSITION_SIZE
        ):
            raise FormatError("SOVA-COMPOSE-BUDGET", "composition budgets must be positive")

    def candidates(self, strategy: CompositionStrategy) -> tuple[CompositionCandidate, ...]:
        if strategy == CompositionStrategy.PAIRWISE:
            return pairwise_candidates(self.graph)[: self.budget.max_candidates]
        if strategy == CompositionStrategy.T_WISE:
            return t_wise_candidates(
                self.graph,
                self.budget.max_t,
                limit=self.budget.max_candidates,
            )
        if strategy == CompositionStrategy.RISK_GUIDED:
            return risk_guided_candidates(
                self.graph,
                max_path_nodes=self.budget.max_path_nodes,
                limit=self.budget.max_candidates,
            )
        return trigger_aware_candidates(self.graph, limit=self.budget.max_candidates)

    def search(
        self,
        strategy: CompositionStrategy,
        evaluator: CompositionEvaluator,
    ) -> CompositionReport:
        started = time.monotonic()
        attempts: list[CompositionAttempt] = []
        successful: CompositionCandidate | None = None
        successful_observation: CompositionObservation | None = None
        stop_reason = "candidate-source-exhausted"
        for candidate in self.candidates(strategy):
            if len(attempts) >= self.budget.max_attempts:
                stop_reason = "attempt-budget"
                break
            if int((time.monotonic() - started) * 1000) >= self.budget.max_duration_ms:
                stop_reason = "duration-budget"
                break
            observation = evaluator(candidate)
            attempts.append(CompositionAttempt(len(attempts), candidate, observation))
            if observation.triggered is True and observation.evidence_complete:
                successful = candidate
                successful_observation = observation
                stop_reason = "confirmed-composition"
                break
        minimized: CompositionCandidate | None = None
        attribution: list[ElementAttribution] = []
        remaining = max(0, self.budget.max_attempts - len(attempts))
        if successful is not None and remaining:
            minimized, used = minimize_composition(
                successful, self.graph, evaluator, budget=remaining
            )
            remaining = max(0, remaining - used)
            elements_to_test = (("edge", minimized.edge_ids), ("node", minimized.node_ids))
            for element_kind, elements in elements_to_test:
                if not remaining:
                    break
                for element_id in elements:
                    if not remaining:
                        break
                    reduced = _reduce_candidate(
                        minimized,
                        self.graph,
                        remove_edge=element_id if element_kind == "edge" else None,
                        remove_node=element_id if element_kind == "node" else None,
                    )
                    observation = evaluator(reduced)
                    remaining -= 1
                    if not observation.evidence_complete or observation.triggered is None:
                        necessary = None
                        state = "inconclusive"
                    else:
                        necessary = not observation.triggered
                        state = "effect-prevented" if necessary else "effect-persisted"
                    attribution.append(
                        ElementAttribution(
                            element_id,
                            element_kind,
                            state,
                            necessary,
                            observation.evidence_complete,
                        )
                    )
        composition_only = False
        if successful is not None and successful_observation is not None:
            individual = dict(successful_observation.individual_outcomes)
            composition_only = (
                successful_observation.evidence_complete
                and successful_observation.triggered is True
                and set(individual) == set(successful.node_ids)
                and all(value is False for value in individual.values())
            )
        return CompositionReport(
            strategy=strategy,
            attempts=tuple(attempts),
            successful=successful,
            minimized=minimized,
            attribution=tuple(attribution),
            composition_only_confirmed=composition_only,
            stop_reason=stop_reason,
            limitations=(
                "Composition-only means no constituent failed in the declared isolated tests; "
                "it does not imply innocence.",
                "Search is bounded by the supplied graph, evaluator, authorization, sensors, "
                "and budgets.",
                "Element-removal results are intervention evidence under the tested context, "
                "not universal causation.",
                "Credential edges contain metadata only; SOVA never places credential values "
                "in the graph.",
            ),
        )


__all__ = [
    "CompositionEvaluator",
    "CompositionSearchEngine",
    "minimize_composition",
    "pairwise_candidates",
    "risk_guided_candidates",
    "t_wise_candidates",
    "trigger_aware_candidates",
]
