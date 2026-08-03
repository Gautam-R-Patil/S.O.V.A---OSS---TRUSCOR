# SPDX-License-Identifier: Apache-2.0
"""Typed trigger-space, candidate, observation, budget, and result contracts."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError


def _decimal(value: float) -> str:
    return format(value, ".12g")


class TriggerDimension(StrEnum):
    """Portable dimensions that may condition observable AI behavior."""

    CONTENT = "content-and-phrasing"
    HISTORY = "conversation-history"
    ENVIRONMENT = "environment-and-configuration"
    FILESYSTEM = "filesystem-and-file-history"
    TOOL = "tool-availability-and-order"
    PERMISSION = "permission-and-identity"
    INVOCATION = "invocation-and-session-count"
    TIME = "time-delay-date-and-position"
    MEMORY = "memory-and-retrieval"
    INTER_AGENT = "inter-agent-and-delegation"
    BROWSER = "browser-and-ui-state"
    COMPOSITION = "cross-component-composition"
    CUSTOM = "user-defined"


class SearchStrategy(StrEnum):
    SIGNATURE = "known-signature"
    RANDOM = "seeded-random"
    GRID = "bounded-grid"
    COVERAGE = "coverage-guided"
    HUMAN = "human-heuristic"
    ADAPTIVE = "adaptive-evolutionary"


@dataclass(frozen=True, slots=True)
class TriggerCandidate:
    """One typed condition assignment and optional ordered interaction sequence."""

    values: dict[str, Any]
    sequence: tuple[dict[str, Any], ...] = ()
    parent_digests: tuple[str, ...] = ()
    generation: int = 0
    mutations: int = 0

    def __post_init__(self) -> None:
        if self.generation < 0 or self.mutations < 0:
            raise FormatError("SOVA-SEARCH-CANDIDATE", "candidate counters cannot be negative")
        encoded = canonical_json_bytes(self.portable_mapping())
        if len(encoded) > 1024 * 1024:
            raise FormatError("SOVA-SEARCH-CANDIDATE", "candidate exceeds the 1 MiB budget")

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.portable_mapping()))

    def portable_mapping(self) -> dict[str, Any]:
        return {"values": self.values, "sequence": list(self.sequence)}


@dataclass(frozen=True, slots=True)
class SearchSpace:
    """Finite declared domains plus explicit dimension semantics."""

    domains: dict[str, tuple[Any, ...]]
    dimensions: dict[str, TriggerDimension]
    defaults: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.domains or set(self.domains) != set(self.dimensions):
            raise FormatError(
                "SOVA-SEARCH-SPACE",
                "every non-empty domain requires one declared trigger dimension",
            )
        if any(not values for values in self.domains.values()):
            raise FormatError("SOVA-SEARCH-SPACE", "search domains cannot be empty")
        missing_defaults = set(self.defaults) - set(self.domains)
        if missing_defaults:
            raise FormatError("SOVA-SEARCH-SPACE", "defaults reference unknown domains")

    @property
    def cardinality(self) -> int:
        return math.prod(len(values) for values in self.domains.values())


@dataclass(frozen=True, slots=True)
class SearchBudget:
    """Hard attempt, mutation, generation, population, and duration ceilings."""

    max_attempts: int = 100
    max_mutations: int = 1000
    max_generations: int = 20
    population_size: int = 12
    max_duration_ms: int = 60_000
    stagnation_generations: int = 5
    exploration_fraction: float = 0.35

    def __post_init__(self) -> None:
        values = (
            self.max_attempts,
            self.max_mutations,
            self.max_generations,
            self.population_size,
            self.max_duration_ms,
            self.stagnation_generations,
        )
        if any(value <= 0 for value in values):
            raise FormatError("SOVA-SEARCH-BUDGET", "search budget values must be positive")
        if self.population_size > self.max_attempts:
            raise FormatError("SOVA-SEARCH-BUDGET", "population cannot exceed total attempt budget")
        if not 0 <= self.exploration_fraction <= 1:
            raise FormatError(
                "SOVA-SEARCH-BUDGET",
                "exploration fraction must be between zero and one",
            )


@dataclass(frozen=True, slots=True)
class SearchObservation:
    """Deterministic evaluator result; near-miss score is bounded and inspectable."""

    triggered: bool
    score: float
    coverage: frozenset[str]
    effects: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()
    turns: int = 1
    tokens: int = 0
    duration_ms: int = 0
    status: str = "confirmed"
    false_positive: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 1 or min(self.turns, self.tokens, self.duration_ms) < 0:
            raise FormatError("SOVA-SEARCH-OBSERVATION", "invalid search observation metrics")
        if self.status not in {"confirmed", "not-confirmed", "inconclusive", "failed"}:
            raise FormatError("SOVA-SEARCH-OBSERVATION", "invalid search observation status")


@dataclass(frozen=True, slots=True)
class SearchAttempt:
    index: int
    candidate: TriggerCandidate
    observation: SearchObservation
    new_coverage: frozenset[str]


@dataclass(frozen=True, slots=True)
class TriggerFamilyMetric:
    """Search effort and best observable score for one declared trigger family."""

    dimension: TriggerDimension
    changed_attempts: int
    confirmed: int
    best_score: float | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension.value,
            "changedAttempts": self.changed_attempts,
            "confirmed": self.confirmed,
            "bestScore": None if self.best_score is None else _decimal(self.best_score),
        }


@dataclass(frozen=True, slots=True)
class SearchReport:
    """Measurable result for one named baseline or adaptive search."""

    strategy: SearchStrategy
    attempts: tuple[SearchAttempt, ...]
    success: TriggerCandidate | None
    minimized: TriggerCandidate | None
    stop_reason: str
    coverage: frozenset[str]
    duration_ms: int
    reproduction_rate: float | None
    family_performance: tuple[TriggerFamilyMetric, ...]
    limitations: tuple[str, ...]
    declared_space_cardinality: int | None = None

    def to_mapping(self) -> dict[str, Any]:
        confirmed = sum(item.observation.triggered for item in self.attempts)
        inconclusive = sum(item.observation.status == "inconclusive" for item in self.attempts)
        false_positives = sum(item.observation.false_positive for item in self.attempts)
        eligible = len(self.attempts) - inconclusive
        return {
            "artifactType": "sova.trigger-search-report",
            "schemaVersion": "0.1.0",
            "strategy": self.strategy.value,
            "attempts": len(self.attempts),
            "confirmed": confirmed,
            "inconclusive": inconclusive,
            "success": None if self.success is None else self.success.portable_mapping(),
            "successDigest": None if self.success is None else self.success.digest,
            "minimized": None if self.minimized is None else self.minimized.portable_mapping(),
            "minimizedDigest": None if self.minimized is None else self.minimized.digest,
            "stopReason": self.stop_reason,
            "coverage": sorted(self.coverage),
            "durationMs": self.duration_ms,
            "turns": sum(item.observation.turns for item in self.attempts),
            "tokens": sum(item.observation.tokens for item in self.attempts),
            "mutations": sum(item.candidate.mutations for item in self.attempts),
            "falsePositiveRate": (None if eligible == 0 else _decimal(false_positives / eligible)),
            "searchSpaceCardinality": self.declared_space_cardinality,
            "attemptCoverageFraction": (
                None
                if self.declared_space_cardinality in {None, 0}
                else _decimal(min(1.0, len(self.attempts) / self.declared_space_cardinality))
            ),
            "reproductionRate": (
                None if self.reproduction_rate is None else _decimal(self.reproduction_rate)
            ),
            "familyPerformance": [item.to_mapping() for item in self.family_performance],
            "limitations": list(self.limitations),
        }


__all__ = [
    "SearchAttempt",
    "SearchBudget",
    "SearchObservation",
    "SearchReport",
    "SearchSpace",
    "SearchStrategy",
    "TriggerCandidate",
    "TriggerDimension",
    "TriggerFamilyMetric",
]
