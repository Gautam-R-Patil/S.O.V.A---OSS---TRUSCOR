# SPDX-License-Identifier: Apache-2.0
"""Evidence-aware capability reach and risk classification."""

from __future__ import annotations

from collections import defaultdict, deque

from sova.mapping.model import (
    CapabilityGraph,
    EdgeKind,
    EvidenceClass,
    MapFinding,
    NodeKind,
)

_TRAVERSABLE = {
    EdgeKind.DECLARES,
    EdgeKind.DELEGATES,
    EdgeKind.INVOKES,
    EdgeKind.USES,
    EdgeKind.GRANTS,
    EdgeKind.READS,
    EdgeKind.WRITES,
    EdgeKind.REACHES,
    EdgeKind.EGRESS,
    EdgeKind.DEPENDS_ON,
}


def _adjacency(
    graph: CapabilityGraph,
    *,
    allowed: frozenset[EvidenceClass],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges.values():
        if edge.kind in _TRAVERSABLE and edge.evidence_class in allowed:
            result[edge.source].append(edge.id)
    for edges in result.values():
        edges.sort()
    return result


def reachable_paths(
    graph: CapabilityGraph,
    start: str,
    *,
    max_depth: int = 8,
    allowed: frozenset[EvidenceClass] = frozenset(
        {EvidenceClass.DECLARED, EvidenceClass.OBSERVED, EvidenceClass.INFERRED}
    ),
) -> dict[str, tuple[str, ...]]:
    """Return one deterministic shortest evidence path to every reachable node."""
    adjacency = _adjacency(graph, allowed=allowed)
    discovered: dict[str, tuple[str, ...]] = {start: ()}
    pending: deque[tuple[str, tuple[str, ...]]] = deque([(start, ())])
    while pending:
        node_id, path = pending.popleft()
        if len(path) >= max_depth:
            continue
        for edge_id in adjacency.get(node_id, []):
            edge = graph.edges[edge_id]
            if edge.target in discovered:
                continue
            next_path = (*path, edge_id)
            discovered[edge.target] = next_path
            pending.append((edge.target, next_path))
    discovered.pop(start, None)
    return discovered


def _path_evidence(graph: CapabilityGraph, path: tuple[str, ...]) -> EvidenceClass:
    classes = {graph.edges[edge_id].evidence_class for edge_id in path}
    if EvidenceClass.INFERRED in classes:
        return EvidenceClass.INFERRED
    if EvidenceClass.OBSERVED in classes:
        return EvidenceClass.OBSERVED
    return EvidenceClass.DECLARED


def capability_closures(graph: CapabilityGraph) -> dict[str, list[dict[str, object]]]:
    """Keep static possibility, declarations, witnesses, and conflicts separate."""
    result: dict[str, list[dict[str, object]]] = {
        "declared": [],
        "witnessLinked": [],
        "possible": [],
        "conflicts": [],
    }
    roots = sorted(
        node.id
        for node in graph.nodes.values()
        if node.kind in {NodeKind.AGENT, NodeKind.SUB_AGENT}
    )
    for root in roots:
        declared = reachable_paths(
            graph,
            root,
            allowed=frozenset({EvidenceClass.DECLARED}),
        )
        witness_linked = reachable_paths(
            graph,
            root,
            allowed=frozenset({EvidenceClass.DECLARED, EvidenceClass.OBSERVED}),
        )
        possible = reachable_paths(graph, root)
        for target, path in sorted(declared.items()):
            result["declared"].append({"source": root, "target": target, "edgeIds": list(path)})
        for target, path in sorted(witness_linked.items()):
            if any(
                graph.edges[edge_id].evidence_class == EvidenceClass.OBSERVED for edge_id in path
            ):
                result["witnessLinked"].append(
                    {"source": root, "target": target, "edgeIds": list(path)}
                )
        for target, path in sorted(possible.items()):
            result["possible"].append({"source": root, "target": target, "edgeIds": list(path)})
    for edge in sorted(graph.edges.values(), key=lambda item: item.id):
        if edge.evidence_class == EvidenceClass.REFUTED:
            result["conflicts"].append(
                {"source": edge.source, "target": edge.target, "edgeIds": [edge.id]}
            )
    return result


def analyze_capability_graph(  # noqa: PLR0912
    graph: CapabilityGraph,
) -> tuple[MapFinding, ...]:
    """Analyze reach without claiming that a path was exploitably executed."""
    findings: list[MapFinding] = []
    roots = sorted(
        node.id
        for node in graph.nodes.values()
        if node.kind in {NodeKind.AGENT, NodeKind.SUB_AGENT}
    )
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for root in roots:
        for target, path in sorted(reachable_paths(graph, root).items()):
            node = graph.nodes[target]
            evidence_class = _path_evidence(graph, path)
            if len(path) > 1:
                key = ("SOVA-MAP-TRANSITIVE-REACH", target, path)
                if key not in seen:
                    findings.append(
                        MapFinding(
                            "SOVA-MAP-TRANSITIVE-REACH",
                            "info",
                            "Transitive declared or possible capability path",
                            (root, target),
                            path,
                            evidence_class,
                            "The graph exposes a multi-edge declared, witness-linked, or inferred "
                            "path. Consult the separated closures; this is not proof of actual or "
                            "exploitable runtime reach.",
                        )
                    )
                    seen.add(key)
            if node.attributes.get("sensitivity") == "credential":
                findings.append(
                    MapFinding(
                        "SOVA-MAP-CREDENTIAL-PATH",
                        "high",
                        "Credential-reference path",
                        (root, target),
                        path,
                        evidence_class,
                        "An agent-reachable declaration references credential-like state. "
                        "SOVA did not read the value.",
                    )
                )
            if node.kind == NodeKind.EXTERNAL_SYSTEM or node.attributes.get("external") is True:
                findings.append(
                    MapFinding(
                        "SOVA-MAP-EGRESS-PATH",
                        "medium",
                        "External-system reach",
                        (root, target),
                        path,
                        evidence_class,
                        "A declared or observed path reaches an external system. Authorization "
                        "and exploitability were not inferred.",
                    )
                )
            if node.attributes.get("consequence") == "high":
                path_nodes = {graph.edges[edge_id].source for edge_id in path}
                path_nodes.update(graph.edges[edge_id].target for edge_id in path)
                if not any(graph.nodes[item].kind == NodeKind.APPROVAL_GATE for item in path_nodes):
                    findings.append(
                        MapFinding(
                            "SOVA-MAP-APPROVAL-GAP",
                            "high",
                            "High-consequence path lacks a declared approval gate",
                            (root, target),
                            path,
                            EvidenceClass.INFERRED,
                            "No approval-gate node appears on this static path. Runtime policy "
                            "may still enforce one and must be checked separately.",
                        )
                    )
    declared = {
        (edge.source, edge.target, edge.kind)
        for edge in graph.edges.values()
        if edge.evidence_class == EvidenceClass.DECLARED
    }
    for edge in sorted(graph.edges.values(), key=lambda item: item.id):
        if edge.evidence_class != EvidenceClass.OBSERVED:
            continue
        if (edge.source, edge.target, edge.kind) in declared:
            continue
        findings.append(
            MapFinding(
                "SOVA-MAP-UNDECLARED-OBSERVED-REACH",
                "high",
                "Observed relationship was not declared",
                (edge.source, edge.target),
                (edge.id,),
                EvidenceClass.OBSERVED,
                "An authorized runtime inventory reported a relationship absent from the "
                "static declarations.",
            )
        )
    incoming: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges.values():
        incoming[edge.target].append(edge.id)
    for node in sorted(graph.nodes.values(), key=lambda item: item.id):
        if node.kind != NodeKind.PERMISSION:
            continue
        granted = [
            edge_id
            for edge_id in incoming.get(node.id, [])
            if graph.edges[edge_id].kind == EdgeKind.GRANTS
        ]
        observed = any(
            graph.edges[edge_id].evidence_class == EvidenceClass.OBSERVED
            for edge_id in incoming.get(node.id, [])
        )
        if granted and not observed:
            findings.append(
                MapFinding(
                    "SOVA-MAP-POSSIBLE-PERMISSION-ROT",
                    "low",
                    "Declared permission has no observed witness",
                    (node.id,),
                    tuple(sorted(granted)),
                    EvidenceClass.INFERRED,
                    "The permission is declared but the supplied runtime inventory contains no "
                    "matching witness. Absence of a witness is not proof that it is unused.",
                )
            )
    return tuple(
        sorted(
            findings,
            key=lambda item: (item.code, item.node_ids, item.edge_ids),
        )
    )


__all__ = ["analyze_capability_graph", "capability_closures", "reachable_paths"]
