# SPDX-License-Identifier: Apache-2.0
"""Universal typed primitives shared by capsule domain profiles."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sova.contracts.versions import ContentDigest


@dataclass(frozen=True, slots=True)
class Actor:
    """A human, agent, model, service, tool, recorder, or policy actor."""

    id: str
    kind: str
    name: str
    version: str | None = None
    provenance_ref: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Artifact:
    """A bounded content-addressed payload."""

    id: str
    media_type: str
    digest: ContentDigest
    size: int
    role: str
    sensitivity: str = "unknown"

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        value["digest"] = self.digest.value
        return value


@dataclass(frozen=True, slots=True)
class Event:
    """One observable, ordered event reference without inferred hidden thought."""

    id: str
    run_id: str
    sequence: int
    kind: str
    actor_id: str
    target_id: str
    payload: dict[str, Any]
    parent_ids: tuple[str, ...] = ()
    event_hash: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Environment:
    """A reproducibility context without embedded credentials."""

    id: str
    platform: str
    runtime: str
    dependencies: tuple[dict[str, str], ...] = ()
    model: dict[str, str] | None = None
    tools: tuple[dict[str, str], ...] = ()
    limitations: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Procedure:
    """Portable intent independent from one executor's mechanism."""

    id: str
    steps: tuple[dict[str, Any], ...]
    parameters: dict[str, Any] = field(default_factory=dict)
    preconditions: tuple[dict[str, Any], ...] = ()
    safety: dict[str, Any] = field(default_factory=dict)
    cleanup: tuple[dict[str, Any], ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Evaluation:
    """A versioned bounded interpretation of observations."""

    id: str
    evaluator: str
    evaluator_version: str
    subject_refs: tuple[str, ...]
    outcome: str
    confidence: str | None
    limitations: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Provenance:
    """Origin, authorship, transformation, and custody information."""

    id: str
    creators: tuple[str, ...]
    sources: tuple[str, ...]
    transformations: tuple[str, ...]
    custody: tuple[dict[str, str], ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


__all__ = [
    "Actor",
    "Artifact",
    "Environment",
    "Evaluation",
    "Event",
    "Procedure",
    "Provenance",
]
