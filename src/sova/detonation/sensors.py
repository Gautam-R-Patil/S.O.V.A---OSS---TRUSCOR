# SPDX-License-Identifier: Apache-2.0
"""Unified sensor mesh with claim-conditioned evidence-closure reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace.redaction import Redactor


class SensorKind(StrEnum):
    TOOL = "tool"
    MCP = "mcp"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    NETWORK = "network"
    DNS = "dns"
    BROWSER = "browser"
    COMPUTER = "computer"
    MEMORY = "memory"
    RETRIEVAL = "retrieval"
    INTER_AGENT = "inter-agent"
    DATABASE = "database"
    API = "api"


class SensorHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class SensorObservation:
    sequence: int
    sensor: SensorKind
    kind: str
    actor: str
    target: str
    payload: dict[str, Any]
    source: str
    confidence: str = "deterministic"

    @property
    def digest(self) -> str:
        value = asdict(self)
        value["sensor"] = self.sensor.value
        return sha256_digest(canonical_json_bytes(value))


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    """One claim requires all primary sensors or one declared alternative set."""

    id: str
    claim: str
    required: frozenset[SensorKind]
    alternatives: tuple[frozenset[SensorKind], ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.claim or (not self.required and not self.alternatives):
            raise FormatError(
                "SOVA-SENSOR-REQUIREMENT",
                "evidence requirement needs identity, claim, and sensor coverage",
            )


@dataclass(frozen=True, slots=True)
class EvidenceClosureReport:
    status: str
    requirement_id: str
    observed: tuple[str, ...]
    missing: tuple[str, ...]
    degraded: tuple[str, ...]
    contradictory_observations: tuple[str, ...]
    coverage_ratio: float

    @property
    def sufficient(self) -> bool:
        return self.status == "sufficient"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "requirementId": self.requirement_id,
            "observed": list(self.observed),
            "missing": list(self.missing),
            "degraded": list(self.degraded),
            "contradictoryObservations": list(self.contradictory_observations),
            # Canonical SOVA JSON forbids binary floating-point values.
            "coverageRatio": format(self.coverage_ratio, ".6f").rstrip("0").rstrip("."),
            "method": "sova.claim-conditioned-evidence-closure/0.1",
            "limitations": [
                "Coverage describes configured and reporting sensors, not complete reality.",
                (
                    "A compromised or dishonest sensor can emit internally consistent "
                    "false observations."
                ),
            ],
        }


class SensorMesh:
    """Normalize observations and refuse strong claims under missing coverage."""

    def __init__(
        self,
        health: dict[SensorKind, SensorHealth] | None = None,
    ) -> None:
        self._health = dict.fromkeys(SensorKind, SensorHealth.MISSING)
        self._health.update(health or {})
        self._observations: list[SensorObservation] = []
        self._redactor = Redactor()

    def set_health(self, sensor: SensorKind, health: SensorHealth) -> None:
        self._health[sensor] = health

    def observe(  # noqa: PLR0913 - normalized observations need explicit provenance fields
        self,
        sensor: SensorKind,
        kind: str,
        *,
        actor: str,
        target: str,
        payload: dict[str, Any],
        source: str = "synthetic-world",
        confidence: str = "deterministic",
    ) -> SensorObservation:
        if self._health[sensor] == SensorHealth.MISSING:
            raise FormatError(
                "SOVA-SENSOR-MISSING",
                "a missing sensor cannot report observations",
                details={"sensor": sensor.value},
            )
        redacted, _records = self._redactor.redact(payload)
        observation = SensorObservation(
            len(self._observations),
            sensor,
            kind,
            actor,
            target,
            redacted,
            source,
            confidence,
        )
        self._observations.append(observation)
        return observation

    @property
    def observations(self) -> tuple[SensorObservation, ...]:
        return tuple(self._observations)

    def reset_observations(self) -> None:
        self._observations.clear()

    def health_report(self) -> dict[str, str]:
        return {kind.value: self._health[kind].value for kind in SensorKind}

    def evidence_closure(self, requirement: EvidenceRequirement) -> EvidenceClosureReport:
        observed_sensors = {observation.sensor for observation in self._observations}
        healthy_observed = {
            sensor for sensor in observed_sensors if self._health[sensor] == SensorHealth.HEALTHY
        }
        candidate_sets = (requirement.required, *requirement.alternatives)
        selected = min(
            candidate_sets,
            key=lambda group: len(group - healthy_observed),
        )
        missing = selected - observed_sensors
        degraded = {
            sensor
            for sensor in selected & observed_sensors
            if self._health[sensor] != SensorHealth.HEALTHY
        }
        contradictions = self._contradictions()
        if contradictions:
            status = "conflict"
        elif missing or degraded:
            status = "insufficient"
        else:
            status = "sufficient"
        ratio = 1.0 if not selected else len(selected & healthy_observed) / len(selected)
        return EvidenceClosureReport(
            status,
            requirement.id,
            tuple(sorted(sensor.value for sensor in observed_sensors)),
            tuple(sorted(sensor.value for sensor in missing)),
            tuple(sorted(sensor.value for sensor in degraded)),
            contradictions,
            ratio,
        )

    def _contradictions(self) -> tuple[str, ...]:
        by_claim: dict[str, set[str]] = {}
        for observation in self._observations:
            claim = observation.payload.get("claimId")
            verdict = observation.payload.get("verdict")
            if isinstance(claim, str) and verdict in {"pass", "fail"}:
                by_claim.setdefault(claim, set()).add(verdict)
        return tuple(sorted(claim for claim, values in by_claim.items() if len(values) > 1))


__all__ = [
    "EvidenceClosureReport",
    "EvidenceRequirement",
    "SensorHealth",
    "SensorKind",
    "SensorMesh",
    "SensorObservation",
]
