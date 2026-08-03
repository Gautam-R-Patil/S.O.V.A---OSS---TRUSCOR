# SPDX-License-Identifier: Apache-2.0
"""Portable `.sova` fragments for composition-only behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sova.composition.model import CompositionCandidate, CompositionGraph, CompositionReport


def composition_to_scenario_fragment(
    graph: CompositionGraph,
    candidate: CompositionCandidate,
    *,
    report: CompositionReport | None = None,
) -> dict[str, Any]:
    """Encode portable component identities and ordering, not executor mechanics."""
    nodes = {node.node_id: node for node in graph.nodes}
    edges = {edge.edge_id: edge for edge in graph.edges}
    return {
        "kind": "composition-only-behavior",
        "components": [nodes[node_id].to_mapping() for node_id in candidate.node_ids],
        "interactions": [edges[edge_id].to_mapping() for edge_id in candidate.edge_ids],
        "sequence": list(candidate.sequence),
        "candidateDigest": candidate.digest,
        "compositionOnlyConfirmed": (
            report.composition_only_confirmed if report is not None else None
        ),
        "portableIntentOnly": True,
        "executorMechanicsIncluded": False,
        "requiredFreshAuthorization": True,
        "limitations": [
            "Reproduction requires compatible components and declared interaction semantics.",
            "A removed or substituted component may make the scenario incompatible "
            "or inconclusive.",
        ],
    }


__all__ = ["composition_to_scenario_fragment"]
