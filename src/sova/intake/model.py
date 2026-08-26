# SPDX-License-Identifier: Apache-2.0
"""Deterministic workflow, attack-surface, provenance, coverage, and drift models."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.mapping import EvidenceClass

if TYPE_CHECKING:
    from sova.intake.contracts import SourceClass, TargetProfile


class WorkflowNodeKind(StrEnum):
    """Observed or declared workflow state categories."""

    ACTOR = "actor"
    ENTRY = "entry"
    PAGE = "page"
    API_OPERATION = "api-operation"
    AUTH_STATE = "auth-state"
    USER_ACTION = "user-action"
    PROCESS_STATE = "process-state"
    AGENT_STATE = "agent-state"
    DATA_STATE = "data-state"
    EXTERNAL_STATE = "external-state"
    UNKNOWN = "unknown"


class SurfaceNodeKind(StrEnum):
    """Security-relevant target surface categories."""

    INPUT = "input"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    PRIVILEGE = "privilege"
    TRUST_BOUNDARY = "trust-boundary"
    DATA_STORE = "data-store"
    DATA_FLOW = "data-flow"
    DEPENDENCY = "dependency"
    PROTOCOL = "protocol"
    TOOL = "tool"
    SKILL = "skill"
    MEMORY = "memory"
    EXTERNAL_RESOURCE = "external-resource"
    PROCESS = "process"
    WINDOW = "window"
    CONTROL = "control"
    FILE = "file"
    CONFIGURATION = "configuration"
    SECRET_REFERENCE = "secret-reference"  # noqa: S105 - taxonomy, not a credential
    MODEL = "model"
    AGENT = "agent"


class CoverageState(StrEnum):
    """Non-interchangeable coverage states."""

    DECLARED = "declared"
    DISCOVERED = "discovered"
    EXERCISED = "exercised"
    REPRODUCED = "reproduced"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class GenerationState(StrEnum):
    """Target material fingerprint relationship."""

    MATCH = "match"
    DRIFT = "drift"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class IntakeProvenance:
    """One content-bound, non-secret evidence pointer."""

    source_id: str
    pointer: str
    source_class: SourceClass
    evidence_class: EvidenceClass
    projection_digest: str

    def __post_init__(self) -> None:
        if not self.source_id or not self.pointer:
            raise FormatError("SOVA-INTAKE-PROVENANCE", "source and pointer are required")
        if not self.projection_digest.startswith("sha256:"):
            raise FormatError("SOVA-INTAKE-PROVENANCE", "projection digest must use SHA-256")

    def to_mapping(self) -> dict[str, str]:
        return {
            "sourceId": self.source_id,
            "pointer": self.pointer,
            "sourceClass": self.source_class.value,
            "evidenceClass": self.evidence_class.value,
            "projectionDigest": self.projection_digest,
        }


def intake_provenance(
    source_id: str,
    pointer: str,
    source_class: SourceClass,
    evidence_class: EvidenceClass,
    projection: object,
) -> IntakeProvenance:
    """Create provenance over a deliberately reduced projection."""
    return IntakeProvenance(
        source_id=source_id,
        pointer=pointer,
        source_class=source_class,
        evidence_class=evidence_class,
        projection_digest=sha256_digest(canonical_json_bytes(projection)),
    )


def graph_identifier(namespace: str, key: str) -> str:
    """Return one deterministic report-scoped graph identifier."""
    digest = sha256_digest(canonical_json_bytes({"namespace": namespace, "key": key}))
    return f"intake:{namespace}:{digest.removeprefix('sha256:')[:32]}"


@dataclass(frozen=True, slots=True)
class IntakeNode:
    """One workflow or surface graph node."""

    id: str
    kind: str
    name: str
    attributes: dict[str, Any]
    evidence_class: EvidenceClass
    confidence: float
    provenance: tuple[IntakeProvenance, ...]

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise FormatError("SOVA-INTAKE-CONFIDENCE", "node confidence must be in [0, 1]")
        if not self.provenance:
            raise FormatError("SOVA-INTAKE-PROVENANCE", "graph nodes require provenance")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "attributes": self.attributes,
            "evidenceClass": self.evidence_class.value,
            "confidence": _confidence_text(self.confidence),
            "provenance": [item.to_mapping() for item in self.provenance],
        }


@dataclass(frozen=True, slots=True)
class IntakeEdge:
    """One directional workflow transition or surface relationship."""

    id: str
    source: str
    target: str
    kind: str
    preconditions: tuple[str, ...]
    effects: tuple[str, ...]
    attributes: dict[str, Any]
    evidence_class: EvidenceClass
    confidence: float
    provenance: tuple[IntakeProvenance, ...]

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise FormatError("SOVA-INTAKE-CONFIDENCE", "edge confidence must be in [0, 1]")
        if not self.provenance:
            raise FormatError("SOVA-INTAKE-PROVENANCE", "graph edges require provenance")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "preconditions": list(self.preconditions),
            "effects": list(self.effects),
            "attributes": self.attributes,
            "evidenceClass": self.evidence_class.value,
            "confidence": _confidence_text(self.confidence),
            "provenance": [item.to_mapping() for item in self.provenance],
        }


@dataclass(slots=True)
class IntakeGraph:
    """Deterministic graph builder with provenance-preserving merges."""

    namespace: str
    nodes: dict[str, IntakeNode] = field(default_factory=dict)
    edges: dict[str, IntakeEdge] = field(default_factory=dict)

    def add_node(  # noqa: PLR0913 - graph evidence inputs stay explicit
        self,
        kind: StrEnum | str,
        key: str,
        name: str,
        *,
        attributes: dict[str, Any] | None,
        evidence_class: EvidenceClass,
        confidence: float,
        provenance: IntakeProvenance,
    ) -> str:
        kind_value = kind.value if isinstance(kind, StrEnum) else kind
        node_id = graph_identifier(f"{self.namespace}-node", f"{kind_value}\x00{key}")
        current = self.nodes.get(node_id)
        if current is None:
            self.nodes[node_id] = IntakeNode(
                id=node_id,
                kind=kind_value,
                name=name,
                attributes=dict(attributes or {}),
                evidence_class=evidence_class,
                confidence=confidence,
                provenance=(provenance,),
            )
            return node_id
        merged_attributes = dict(current.attributes)
        merged_attributes.update(attributes or {})
        merged_provenance = tuple(
            sorted(
                {*current.provenance, provenance},
                key=lambda item: (
                    item.source_id,
                    item.pointer,
                    item.source_class.value,
                    item.evidence_class.value,
                ),
            )
        )
        merged_class = _stronger_evidence(current.evidence_class, evidence_class)
        self.nodes[node_id] = IntakeNode(
            id=node_id,
            kind=current.kind,
            name=current.name,
            attributes=merged_attributes,
            evidence_class=merged_class,
            confidence=max(current.confidence, confidence),
            provenance=merged_provenance,
        )
        return node_id

    def add_edge(  # noqa: PLR0913 - graph evidence inputs stay explicit
        self,
        source: str,
        target: str,
        kind: str,
        *,
        key: str = "",
        preconditions: tuple[str, ...] = (),
        effects: tuple[str, ...] = (),
        attributes: dict[str, Any] | None = None,
        evidence_class: EvidenceClass,
        confidence: float,
        provenance: IntakeProvenance,
    ) -> str:
        if source not in self.nodes or target not in self.nodes:
            raise FormatError(
                "SOVA-INTAKE-DANGLING-EDGE", "graph endpoints must exist before the edge"
            )
        edge_id = graph_identifier(
            f"{self.namespace}-edge", f"{source}\x00{kind}\x00{target}\x00{key}"
        )
        current = self.edges.get(edge_id)
        if current is not None:
            merged_attributes = dict(current.attributes)
            merged_attributes.update(attributes or {})
            merged_provenance = tuple(
                sorted(
                    {*current.provenance, provenance},
                    key=lambda item: (
                        item.source_id,
                        item.pointer,
                        item.source_class.value,
                        item.evidence_class.value,
                    ),
                )
            )
            self.edges[edge_id] = IntakeEdge(
                id=edge_id,
                source=source,
                target=target,
                kind=kind,
                preconditions=tuple(sorted(set(current.preconditions) | set(preconditions))),
                effects=tuple(sorted(set(current.effects) | set(effects))),
                attributes=merged_attributes,
                evidence_class=_stronger_evidence(current.evidence_class, evidence_class),
                confidence=max(current.confidence, confidence),
                provenance=merged_provenance,
            )
            return edge_id
        self.edges[edge_id] = IntakeEdge(
            id=edge_id,
            source=source,
            target=target,
            kind=kind,
            preconditions=preconditions,
            effects=effects,
            attributes=dict(attributes or {}),
            evidence_class=evidence_class,
            confidence=confidence,
            provenance=(provenance,),
        )
        return edge_id

    def to_mapping(self) -> dict[str, Any]:
        return {
            "nodes": [self.nodes[key].to_mapping() for key in sorted(self.nodes)],
            "edges": [self.edges[key].to_mapping() for key in sorted(self.edges)],
        }


def _stronger_evidence(left: EvidenceClass, right: EvidenceClass) -> EvidenceClass:
    order = {
        EvidenceClass.INFERRED: 0,
        EvidenceClass.DECLARED: 1,
        EvidenceClass.OBSERVED: 2,
        EvidenceClass.REFUTED: 3,
    }
    return left if order[left] >= order[right] else right


def _confidence_text(value: float) -> str:
    """Encode bounded confidence without non-portable binary JSON numbers."""
    return format(value, ".12g")


@dataclass(frozen=True, slots=True)
class CoverageItem:
    """One target-kind, workflow, surface, input, or relationship coverage statement."""

    subject: str
    dimension: str
    state: CoverageState
    reason: str
    evidence_refs: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "dimension": self.dimension,
            "state": self.state.value,
            "reason": self.reason,
            "evidenceRefs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class CoverageContract:
    """Coverage accounting that cannot translate missing evidence into pass."""

    items: tuple[CoverageItem, ...]

    def to_mapping(self) -> dict[str, Any]:
        counts = Counter(item.state.value for item in self.items)
        unknown = counts[CoverageState.UNKNOWN.value]
        blocked = counts[CoverageState.BLOCKED.value]
        unsupported = counts[CoverageState.UNSUPPORTED.value]
        return {
            "items": [
                item.to_mapping()
                for item in sorted(
                    self.items,
                    key=lambda value: (value.dimension, value.subject, value.state.value),
                )
            ],
            "counts": {state.value: counts[state.value] for state in CoverageState},
            "partial": bool(unknown or blocked or unsupported),
            "allVulnerabilitiesFound": False,
            "safeOrClean": False,
        }


@dataclass(frozen=True, slots=True)
class MaterialFingerprint:
    """Start/end material identity and drift state."""

    input_id: str
    expected_digest: str
    start_digest: str | None
    end_digest: str | None
    state: GenerationState
    reason: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "inputId": self.input_id,
            "expectedDigest": self.expected_digest,
            "startDigest": self.start_digest,
            "endDigest": self.end_digest,
            "state": self.state.value,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class UniversalIntakeReport:
    """One deterministic, provenance-separated universal intake result."""

    profile: TargetProfile
    status: str
    workflow_graph: IntakeGraph
    attack_surface_graph: IntakeGraph
    coverage: CoverageContract
    fingerprints: tuple[MaterialFingerprint, ...]
    inputs: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    errors: tuple[dict[str, str], ...]

    def to_mapping(self) -> dict[str, Any]:
        workflow = self.workflow_graph.to_mapping()
        attack_surface = self.attack_surface_graph.to_mapping()
        body: dict[str, Any] = {
            "artifactType": "sova.intake-report",
            "schemaVersion": "0.1.0",
            "id": graph_identifier("report", self.profile.digest),
            "profileDigest": self.profile.digest,
            "targetManifestDigest": (
                None
                if self.profile.legacy_target_manifest is None
                else self.profile.legacy_target_manifest.digest
            ),
            "status": self.status,
            "inputs": list(self.inputs),
            "generation": {
                "state": _aggregate_generation_state(self.fingerprints).value,
                "fingerprints": [item.to_mapping() for item in self.fingerprints],
            },
            "workflowGraph": workflow,
            "attackSurfaceGraph": attack_surface,
            "coverage": self.coverage.to_mapping(),
            "limitations": sorted(set(self.limitations)),
            "errors": list(self.errors),
            "claims": {
                "targetCodeExecuted": False,
                "activeObservationsIndependentlyAttested": False,
                "inferenceIsExecutionEvidence": False,
                "allWorkflowsUnderstood": False,
                "allAttackSurfacesEnumerated": False,
                "allVulnerabilitiesFound": False,
                "safeOrClean": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


def _aggregate_generation_state(
    fingerprints: tuple[MaterialFingerprint, ...],
) -> GenerationState:
    if any(item.state == GenerationState.DRIFT for item in fingerprints):
        return GenerationState.DRIFT
    if any(item.state == GenerationState.INCOMPLETE for item in fingerprints):
        return GenerationState.INCOMPLETE
    return GenerationState.MATCH


__all__ = [
    "CoverageContract",
    "CoverageItem",
    "CoverageState",
    "GenerationState",
    "IntakeEdge",
    "IntakeGraph",
    "IntakeNode",
    "IntakeProvenance",
    "MaterialFingerprint",
    "SurfaceNodeKind",
    "UniversalIntakeReport",
    "WorkflowNodeKind",
    "graph_identifier",
    "intake_provenance",
]
