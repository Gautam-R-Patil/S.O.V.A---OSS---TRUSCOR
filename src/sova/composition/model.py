# SPDX-License-Identifier: Apache-2.0
"""Typed composition graphs, candidates, observations, and search reports."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest


class NodeKind(StrEnum):
    AGENT = "agent"
    TOOL = "tool"
    IDENTITY = "identity"
    DATA_STORE = "data-store"
    MCP_SERVER = "mcp-server"
    MODEL = "model"
    EXTERNAL_SERVICE = "external-service"


class EdgeKind(StrEnum):
    DECLARED_DEPENDENCY = "declared-dependency"
    OBSERVED_DEPENDENCY = "observed-dependency"
    HANDOFF = "handoff"
    PERMISSION = "permission"
    SHARED_MEMORY = "shared-memory"
    SHARED_CREDENTIAL = "shared-credential-metadata"
    CROSS_AGENT = "cross-agent"
    CROSS_MCP = "cross-mcp"


class CompositionStrategy(StrEnum):
    PAIRWISE = "pairwise"
    T_WISE = "bounded-t-wise"
    RISK_GUIDED = "risk-guided-path"
    TRIGGER_AWARE = "trigger-aware-sequence"


@dataclass(frozen=True, slots=True)
class ComponentNode:
    node_id: str
    kind: NodeKind
    name: str
    version: str
    actor_id: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind.value,
            "name": self.name,
            "version": self.version,
            "actorId": self.actor_id,
        }


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    edge_id: str
    source: str
    target: str
    kind: EdgeKind
    provenance: str
    observed: bool
    risk_weight: int
    permission: str | None = None
    shared_resource: str | None = None
    order: int | None = None
    state_condition: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "provenance": self.provenance,
            "observed": self.observed,
            "riskWeight": self.risk_weight,
            "permission": self.permission,
            "sharedResource": self.shared_resource,
            "order": self.order,
            "stateCondition": self.state_condition,
        }


@dataclass(frozen=True, slots=True)
class CompositionGraph:
    nodes: tuple[ComponentNode, ...]
    edges: tuple[DependencyEdge, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_mapping() for node in self.nodes],
            "edges": [edge.to_mapping() for edge in self.edges],
        }


@dataclass(frozen=True, slots=True)
class CompositionCandidate:
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    sequence: tuple[str, ...]
    parent_digest: str | None = None

    @property
    def digest(self) -> str:
        return sha256_digest(
            canonical_json_bytes(
                {
                    "nodes": list(self.node_ids),
                    "edges": list(self.edge_ids),
                    "sequence": list(self.sequence),
                }
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "nodes": list(self.node_ids),
            "edges": list(self.edge_ids),
            "sequence": list(self.sequence),
            "digest": self.digest,
            "parentDigest": self.parent_digest,
        }


@dataclass(frozen=True, slots=True)
class CompositionObservation:
    triggered: bool | None
    evidence_complete: bool
    oracle_state: str
    trace_references: tuple[str, ...]
    individual_outcomes: tuple[tuple[str, bool | None], ...]
    limitations: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "triggered": self.triggered,
            "evidenceComplete": self.evidence_complete,
            "oracleState": self.oracle_state,
            "traceReferences": list(self.trace_references),
            "individualOutcomes": dict(self.individual_outcomes),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class CompositionBudget:
    max_attempts: int = 100
    max_duration_ms: int = 30_000
    max_t: int = 3
    max_path_nodes: int = 5
    max_candidates: int = 10_000


@dataclass(frozen=True, slots=True)
class CompositionAttempt:
    index: int
    candidate: CompositionCandidate
    observation: CompositionObservation

    def to_mapping(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "candidate": self.candidate.to_mapping(),
            "observation": self.observation.to_mapping(),
        }


@dataclass(frozen=True, slots=True)
class ElementAttribution:
    element_id: str
    element_kind: str
    removal_state: str
    necessary_under_test: bool | None
    evidence_complete: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "elementId": self.element_id,
            "elementKind": self.element_kind,
            "removalState": self.removal_state,
            "necessaryUnderTest": self.necessary_under_test,
            "evidenceComplete": self.evidence_complete,
        }


@dataclass(frozen=True, slots=True)
class CompositionReport:
    strategy: CompositionStrategy
    attempts: tuple[CompositionAttempt, ...]
    successful: CompositionCandidate | None
    minimized: CompositionCandidate | None
    attribution: tuple[ElementAttribution, ...]
    composition_only_confirmed: bool
    stop_reason: str
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.composition-report",
            "schemaVersion": "0.1.0",
            "strategy": self.strategy.value,
            "attempts": [attempt.to_mapping() for attempt in self.attempts],
            "successfulCandidate": (
                None if self.successful is None else self.successful.to_mapping()
            ),
            "minimizedCandidate": None if self.minimized is None else self.minimized.to_mapping(),
            "elementAttribution": [item.to_mapping() for item in self.attribution],
            "compositionOnlyConfirmed": self.composition_only_confirmed,
            "stopReason": self.stop_reason,
            "limitations": list(self.limitations),
        }


__all__ = [
    "ComponentNode",
    "CompositionAttempt",
    "CompositionBudget",
    "CompositionCandidate",
    "CompositionGraph",
    "CompositionObservation",
    "CompositionReport",
    "CompositionStrategy",
    "DependencyEdge",
    "EdgeKind",
    "ElementAttribution",
    "NodeKind",
]
