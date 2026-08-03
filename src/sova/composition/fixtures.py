# SPDX-License-Identifier: Apache-2.0
"""Safe deterministic composition fixture used by conformance and examples."""

from __future__ import annotations

from dataclasses import dataclass

from sova.composition.model import (
    ComponentNode,
    CompositionCandidate,
    CompositionGraph,
    CompositionObservation,
    DependencyEdge,
    EdgeKind,
    NodeKind,
)


def planted_composition_graph() -> CompositionGraph:
    """Return a metadata-only graph with one three-component interaction failure."""
    return CompositionGraph(
        nodes=(
            ComponentNode("agent", NodeKind.AGENT, "Fixture agent", "1"),
            ComponentNode("memory", NodeKind.DATA_STORE, "Fixture memory", "1"),
            ComponentNode("tool", NodeKind.TOOL, "Fixture sink tool", "1"),
            ComponentNode("observer", NodeKind.AGENT, "Benign observer", "1"),
        ),
        edges=(
            DependencyEdge(
                "read-memory",
                "memory",
                "agent",
                EdgeKind.SHARED_MEMORY,
                "synthetic-ground-truth",
                observed=True,
                risk_weight=80,
                order=0,
                state_condition="fixture-marker-present",
            ),
            DependencyEdge(
                "invoke-tool",
                "agent",
                "tool",
                EdgeKind.PERMISSION,
                "synthetic-ground-truth",
                observed=True,
                risk_weight=90,
                permission="fixture.sink.write",
                order=1,
            ),
            DependencyEdge(
                "observe-agent",
                "observer",
                "agent",
                EdgeKind.CROSS_AGENT,
                "synthetic-ground-truth",
                observed=False,
                risk_weight=5,
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class PlantedCompositionEvaluator:
    """Observable oracle for the planted sequence; it executes no native code."""

    required_nodes: frozenset[str] = frozenset({"memory", "agent", "tool"})
    required_sequence: tuple[str, ...] = ("read-memory", "invoke-tool")

    def __call__(self, candidate: CompositionCandidate) -> CompositionObservation:
        triggered = self.required_nodes.issubset(candidate.node_ids) and all(
            edge in candidate.sequence for edge in self.required_sequence
        )
        ordered = (
            tuple(edge for edge in candidate.sequence if edge in self.required_sequence)
            == self.required_sequence
        )
        result = triggered and ordered
        return CompositionObservation(
            triggered=result,
            evidence_complete=True,
            oracle_state="fixture-effect-observed" if result else "fixture-effect-absent",
            trace_references=(f"fixture-trace:{candidate.digest}",),
            individual_outcomes=tuple((node_id, False) for node_id in candidate.node_ids),
            limitations=("Deterministic synthetic ground truth; no field-validity claim.",),
        )


__all__ = ["PlantedCompositionEvaluator", "planted_composition_graph"]
