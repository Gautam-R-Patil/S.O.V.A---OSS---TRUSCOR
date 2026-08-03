# SPDX-License-Identifier: Apache-2.0
"""Typed, evidence-linked forensic reconstruction and attribution results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class CausalLayer(StrEnum):
    """Candidate intervention layers without assigning organizational blame."""

    BASE_MODEL = "base-model"
    SYSTEM_POLICY = "system-prompt-or-policy"
    ORCHESTRATION = "orchestration"
    TOOL = "tool-description-or-implementation"
    AUTHORIZATION = "permission-or-approval"
    MEMORY = "memory-or-retrieval"
    HANDOFF = "downstream-handoff-or-subagent"
    ENVIRONMENT = "environment-or-external-service"
    MULTIPLE = "multiple-contributing-layers"
    UNKNOWN = "unknown"


class AttributionState(StrEnum):
    """Evidence-bounded state of one counterfactual hypothesis."""

    SUPPORTED = "supported-under-declared-interventions"
    CONTRADICTED = "contradicted-under-declared-interventions"
    INCONCLUSIVE = "inconclusive"
    CONFOUNDED = "confounded"
    IMPOSSIBLE = "intervention-impossible"


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """One reconstruction entry with its evidence and ordering limits."""

    event_id: str
    sequence: int
    kind: str
    phase: str
    actor: str
    target: str
    wall_time: str | None
    clock_domain: str
    order_basis: str
    decision_point: bool
    missing_or_redacted: bool
    parents: tuple[str, ...]
    evidence_digest: str | None
    statement: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "sequence": self.sequence,
            "kind": self.kind,
            "phase": self.phase,
            "actor": self.actor,
            "target": self.target,
            "wallTime": self.wall_time,
            "clockDomain": self.clock_domain,
            "orderBasis": self.order_basis,
            "decisionPoint": self.decision_point,
            "missingOrRedacted": self.missing_or_redacted,
            "parents": list(self.parents),
            "evidenceDigest": self.evidence_digest,
            "statement": self.statement,
        }


@dataclass(frozen=True, slots=True)
class ReconstructionReport:
    """A deterministic partial-order reconstruction, never a causal verdict."""

    source_type: str
    source_id: str
    source_digest: str | None
    integrity_state: str
    entries: tuple[TimelineEntry, ...]
    causal_edges: tuple[tuple[str, str], ...]
    uncertain_order_pairs: tuple[tuple[str, str], ...]
    missing_sensor_markers: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.forensic-reconstruction",
            "schemaVersion": "0.1.0",
            "source": {
                "type": self.source_type,
                "id": self.source_id,
                "digest": self.source_digest,
                "integrityState": self.integrity_state,
            },
            "entries": [entry.to_mapping() for entry in self.entries],
            "causalEdges": [
                {"parent": parent, "child": child} for parent, child in self.causal_edges
            ],
            "uncertainOrderPairs": [
                {"left": left, "right": right} for left, right in self.uncertain_order_pairs
            ],
            "missingSensorMarkers": list(self.missing_sensor_markers),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class CounterfactualTrial:
    """One paired intervention trial over observable outcomes."""

    trial_id: str
    layer: CausalLayer
    changed_layers: tuple[CausalLayer, ...]
    baseline_outcome: bool | None
    intervention_outcome: bool | None
    context_equivalent: bool
    evidence_complete: bool
    original_trace: str | None
    counterfactual_trace: str | None
    execution_status: str = "completed"
    limitation: str | None = None


@dataclass(frozen=True, slots=True)
class HypothesisAssessment:
    """Aggregate paired-intervention evidence for one candidate layer."""

    layer: CausalLayer
    state: AttributionState
    eligible_trials: int
    prevented: int
    persisted: int
    confounded: int
    inconclusive: int
    prevention_rate: str | None
    interval_low: str | None
    interval_high: str | None
    evidence_links: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "layer": self.layer.value,
            "state": self.state.value,
            "eligibleTrials": self.eligible_trials,
            "prevented": self.prevented,
            "persisted": self.persisted,
            "confounded": self.confounded,
            "inconclusive": self.inconclusive,
            "preventionRate": self.prevention_rate,
            "interval": (
                None
                if self.interval_low is None
                else {"method": "wilson-95", "low": self.interval_low, "high": self.interval_high}
            ),
            "evidenceLinks": list(self.evidence_links),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class AttributionReport:
    """Ranked candidate causes under declared interventions and assumptions."""

    original_trace: str
    assessments: tuple[HypothesisAssessment, ...]
    trial_count: int
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.counterfactual-attribution",
            "schemaVersion": "0.1.0",
            "originalTrace": self.original_trace,
            "trialCount": self.trial_count,
            "assessments": [item.to_mapping() for item in self.assessments],
            "authoritativeBlame": False,
            "limitations": list(self.limitations),
        }


__all__ = [
    "AttributionReport",
    "AttributionState",
    "CausalLayer",
    "CounterfactualTrial",
    "HypothesisAssessment",
    "ReconstructionReport",
    "TimelineEntry",
]
