# SPDX-License-Identifier: Apache-2.0
"""Composition-graph analysis and emergent-chain search."""

from sova.composition.fixtures import PlantedCompositionEvaluator, planted_composition_graph
from sova.composition.graph import graph_from_mapping
from sova.composition.model import (
    ComponentNode,
    CompositionAttempt,
    CompositionBudget,
    CompositionCandidate,
    CompositionGraph,
    CompositionObservation,
    CompositionReport,
    CompositionStrategy,
    DependencyEdge,
    EdgeKind,
    ElementAttribution,
    NodeKind,
)
from sova.composition.portable import composition_to_scenario_fragment
from sova.composition.search import (
    CompositionEvaluator,
    CompositionSearchEngine,
    minimize_composition,
    pairwise_candidates,
    risk_guided_candidates,
    t_wise_candidates,
    trigger_aware_candidates,
)

__all__ = [
    "ComponentNode",
    "CompositionAttempt",
    "CompositionBudget",
    "CompositionCandidate",
    "CompositionEvaluator",
    "CompositionGraph",
    "CompositionObservation",
    "CompositionReport",
    "CompositionSearchEngine",
    "CompositionStrategy",
    "DependencyEdge",
    "EdgeKind",
    "ElementAttribution",
    "NodeKind",
    "PlantedCompositionEvaluator",
    "composition_to_scenario_fragment",
    "graph_from_mapping",
    "minimize_composition",
    "pairwise_candidates",
    "planted_composition_graph",
    "risk_guided_candidates",
    "t_wise_candidates",
    "trigger_aware_candidates",
]
