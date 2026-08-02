# SPDX-License-Identifier: Apache-2.0
"""Portable, provenance-bearing capability graph primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sova.contracts import IdentifierKind, new_stable_identifier
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError


class NodeKind(StrEnum):
    """Kinds represented by the public capability graph."""

    AGENT = "agent"
    SUB_AGENT = "sub-agent"
    MCP_SERVER = "mcp-server"
    TOOL = "tool"
    SKILL = "skill"
    PLUGIN = "plugin"
    PACKAGE = "package"
    IDENTITY = "identity"
    PERMISSION = "permission"
    DATA_SOURCE = "data-source"
    DESTINATION = "destination"
    APPROVAL_GATE = "approval-gate"
    EXTERNAL_SYSTEM = "external-system"
    RUNTIME = "runtime"


class EdgeKind(StrEnum):
    """Directional relationships used for reachability analysis."""

    DECLARES = "declares"
    DELEGATES = "delegates"
    INVOKES = "invokes"
    USES = "uses"
    GRANTS = "grants"
    READS = "reads"
    WRITES = "writes"
    REACHES = "reaches"
    EGRESS = "egress"
    PROTECTED_BY = "protected-by"
    DEPENDS_ON = "depends-on"


class EvidenceClass(StrEnum):
    """How a graph assertion was obtained."""

    DECLARED = "declared"
    OBSERVED = "observed"
    INFERRED = "inferred"
    REFUTED = "refuted"


@dataclass(frozen=True, slots=True)
class Provenance:
    """One redacted source reference for a node or edge assertion."""

    source: str
    pointer: str
    evidence_class: EvidenceClass
    projection_digest: str

    def __post_init__(self) -> None:
        if not self.source or not self.pointer:
            raise FormatError(
                "SOVA-MAP-PROVENANCE",
                "mapping provenance requires a source and pointer",
            )
        if not self.projection_digest.startswith("sha256:"):
            raise FormatError(
                "SOVA-MAP-PROVENANCE",
                "mapping provenance requires a SHA-256 projection digest",
            )

    def to_mapping(self) -> dict[str, str]:
        return {
            "source": self.source,
            "pointer": self.pointer,
            "evidenceClass": self.evidence_class.value,
            "projectionDigest": self.projection_digest,
        }


def projected_provenance(
    source: str,
    pointer: str,
    evidence_class: EvidenceClass,
    projection: object,
) -> Provenance:
    """Bind provenance to a deliberately secret-free extracted projection."""
    return Provenance(
        source,
        pointer,
        evidence_class,
        sha256_digest(canonical_json_bytes(projection)),
    )


def scoped_identifier(kind: str, key: str) -> str:
    """Create a deterministic report-scoped identifier without host paths."""
    digest = sha256_digest(canonical_json_bytes({"kind": kind, "key": key}))
    return f"map:{kind}:{digest.removeprefix('sha256:')[:32]}"


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One capability-graph node with explicit evidence state."""

    id: str
    kind: NodeKind
    name: str
    attributes: dict[str, Any]
    provenance: tuple[Provenance, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "name": self.name,
            "attributes": self.attributes,
            "provenance": [item.to_mapping() for item in self.provenance],
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """One directional capability or authority relationship."""

    id: str
    source: str
    target: str
    kind: EdgeKind
    evidence_class: EvidenceClass
    attributes: dict[str, Any]
    provenance: tuple[Provenance, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "evidenceClass": self.evidence_class.value,
            "attributes": self.attributes,
            "provenance": [item.to_mapping() for item in self.provenance],
        }


@dataclass(slots=True)
class CapabilityGraph:
    """Deterministic graph builder that merges duplicate declarations."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, GraphEdge] = field(default_factory=dict)

    def add_node(
        self,
        kind: NodeKind,
        key: str,
        name: str,
        *,
        attributes: dict[str, Any] | None = None,
        provenance: Provenance,
    ) -> str:
        node_id = scoped_identifier(kind.value, key)
        current = self.nodes.get(node_id)
        if current is None:
            self.nodes[node_id] = GraphNode(
                node_id,
                kind,
                name,
                dict(attributes or {}),
                (provenance,),
            )
            return node_id
        merged_attributes = dict(current.attributes)
        merged_attributes.update(attributes or {})
        merged_provenance = tuple(
            sorted(
                {*current.provenance, provenance},
                key=lambda item: (
                    item.source,
                    item.pointer,
                    item.evidence_class.value,
                ),
            )
        )
        self.nodes[node_id] = GraphNode(
            node_id,
            current.kind,
            current.name,
            merged_attributes,
            merged_provenance,
        )
        return node_id

    def add_edge(  # noqa: PLR0913
        self,
        source: str,
        target: str,
        kind: EdgeKind,
        *,
        evidence_class: EvidenceClass,
        attributes: dict[str, Any] | None = None,
        provenance: Provenance,
    ) -> str:
        if source not in self.nodes or target not in self.nodes:
            raise FormatError(
                "SOVA-MAP-DANGLING-EDGE",
                "capability edge endpoints must exist before the edge is added",
            )
        key = f"{source}\x00{kind.value}\x00{target}\x00{evidence_class.value}"
        edge_id = scoped_identifier("edge", key)
        self.edges[edge_id] = GraphEdge(
            edge_id,
            source,
            target,
            kind,
            evidence_class,
            dict(attributes or {}),
            (provenance,),
        )
        return edge_id

    def to_mapping(self) -> dict[str, Any]:
        return {
            "nodes": [self.nodes[key].to_mapping() for key in sorted(self.nodes)],
            "edges": [self.edges[key].to_mapping() for key in sorted(self.edges)],
        }


@dataclass(frozen=True, slots=True)
class MapFinding:
    """A bounded graph observation, never an executed-vulnerability claim."""

    code: str
    severity: str
    title: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    evidence_class: EvidenceClass
    explanation: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "nodeIds": list(self.node_ids),
            "edgeIds": list(self.edge_ids),
            "evidenceClass": self.evidence_class.value,
            "explanation": self.explanation,
        }


@dataclass(frozen=True, slots=True)
class CapabilityMapReport:
    """The distinct machine-readable `*.sova-map.json` artifact."""

    graph: CapabilityGraph
    findings: tuple[MapFinding, ...]
    limitations: tuple[str, ...]
    inputs: tuple[dict[str, Any], ...]
    closures: dict[str, list[dict[str, Any]]]
    tool_drift: tuple[dict[str, Any], ...] = ()
    id: str = field(default_factory=lambda: str(new_stable_identifier(IdentifierKind.ARTIFACT)))

    def to_mapping(self) -> dict[str, Any]:
        graph = self.graph.to_mapping()
        inventory: list[dict[str, Any]] = []
        for node in graph["nodes"]:
            attributes = node["attributes"]
            if (
                attributes.get("sensitivity") == "credential"
                or attributes.get("consequence") == "high"
            ):
                risk = "high"
                rationale = "credential reference or declared high-consequence capability"
            elif node["kind"] == NodeKind.EXTERNAL_SYSTEM.value or attributes.get("external"):
                risk = "medium"
                rationale = "external-system or egress-related capability"
            elif node["kind"] in {NodeKind.IDENTITY.value, NodeKind.PERMISSION.value}:
                risk = "low"
                rationale = "identity or permission relationship requires review"
            else:
                risk = "info"
                rationale = "inventory presence only; no executed vulnerability claim"
            inventory.append(
                {
                    "nodeId": node["id"],
                    "kind": node["kind"],
                    "name": node["name"],
                    "risk": risk,
                    "rationale": rationale,
                }
            )
        body: dict[str, Any] = {
            "artifactType": "sova.map",
            "schemaVersion": "0.1.0",
            "id": self.id,
            "methodology": "sova.capability-reach/0.1.0",
            "inputs": list(self.inputs),
            "inventory": inventory,
            "graph": graph,
            "closures": self.closures,
            "findings": [item.to_mapping() for item in self.findings],
            "toolDrift": list(self.tool_drift),
            "coverage": {
                "nodeCount": len(graph["nodes"]),
                "edgeCount": len(graph["edges"]),
                "findingCount": len(self.findings),
                "partial": bool(self.limitations),
            },
            "limitations": list(self.limitations),
            "claims": {
                "executedVulnerability": False,
                "safeOrClean": False,
                "inferenceIsEvidence": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


__all__ = [
    "CapabilityGraph",
    "CapabilityMapReport",
    "EdgeKind",
    "EvidenceClass",
    "GraphEdge",
    "GraphNode",
    "MapFinding",
    "NodeKind",
    "Provenance",
    "projected_provenance",
    "scoped_identifier",
]
