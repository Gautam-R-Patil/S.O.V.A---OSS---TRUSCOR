# SPDX-License-Identifier: Apache-2.0
"""Explicit sensor-coverage accounting without total-observability claims."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sova.detonation.sensors import SensorKind


class SensorSurface(StrEnum):
    SOVA = "sova-runtime"
    HOST = "host"
    BROWSER = "browser"
    MODEL = "model-or-agent"
    EXTERNAL = "external-service"


class CaptureMode(StrEnum):
    DIRECT = "direct"
    PROVIDER = "provider-reported"
    DERIVED = "derived"
    UNAVAILABLE = "unavailable"


class OrderingGuarantee(StrEnum):
    LOCAL_TOTAL = "local-total-order"
    PARTIAL = "causal-partial-order"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SensorDeclaration:
    id: str
    kind: SensorKind
    surface: SensorSurface
    health: str
    source: str
    capture_mode: CaptureMode
    clock_domain: str
    ordering: OrderingGuarantee
    emitted_events: int = 0
    dropped_events: int = 0
    blind_spots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.source or not self.clock_domain:
            raise FormatError(
                "SOVA-COVERAGE-DECLARATION",
                "sensor identity and provenance are required",
            )
        if self.health not in {"healthy", "degraded", "missing"}:
            raise FormatError("SOVA-COVERAGE-DECLARATION", "sensor health is unsupported")
        if self.emitted_events < 0 or self.dropped_events < 0:
            raise FormatError("SOVA-COVERAGE-COUNT", "sensor event counts cannot be negative")
        if self.capture_mode == CaptureMode.UNAVAILABLE and self.health != "missing":
            raise FormatError(
                "SOVA-COVERAGE-DECLARATION",
                "an unavailable capture mode must be marked missing",
            )
        if self.dropped_events and self.health == "healthy":
            raise FormatError(
                "SOVA-COVERAGE-DROP",
                "a sensor with known dropped events cannot be declared healthy",
            )

    @property
    def digest(self) -> str:
        value = asdict(self)
        value["kind"] = self.kind.value
        value["surface"] = self.surface.value
        value["capture_mode"] = self.capture_mode.value
        value["ordering"] = self.ordering.value
        return sha256_digest(canonical_json_bytes(value))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "surface": self.surface.value,
            "health": self.health,
            "source": self.source,
            "captureMode": self.capture_mode.value,
            "clockDomain": self.clock_domain,
            "ordering": self.ordering.value,
            "emittedEvents": self.emitted_events,
            "droppedEvents": self.dropped_events,
            "blindSpots": list(self.blind_spots),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class CoverageRequirement:
    surface: SensorSurface
    kind: SensorKind
    activity_required: bool = True

    @property
    def key(self) -> str:
        return f"{self.surface.value}/{self.kind.value}"


@dataclass(frozen=True, slots=True)
class SensorCoveragePolicy:
    id: str
    claim: str
    requirements: tuple[CoverageRequirement, ...]

    def __post_init__(self) -> None:
        if not self.id or not self.claim or not self.requirements:
            raise FormatError(
                "SOVA-COVERAGE-POLICY",
                "coverage policy needs identity, claim, and requirements",
            )
        keys = [requirement.key for requirement in self.requirements]
        if len(keys) != len(set(keys)):
            raise FormatError("SOVA-COVERAGE-POLICY", "coverage requirements must be unique")


@dataclass(frozen=True, slots=True)
class SensorCoverageReport:
    status: str
    policy_id: str
    sufficient: tuple[str, ...]
    degraded: tuple[str, ...]
    missing: tuple[str, ...]
    coverage_ratio: str
    declared_sensors: tuple[SensorDeclaration, ...]
    blind_spots: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return self.status == "sufficient"

    def to_mapping(self) -> dict[str, Any]:
        material = {
            "artifactType": "sova.sensor-coverage-report",
            "schemaVersion": "0.1.0",
            "status": self.status,
            "accepted": self.accepted,
            "policyId": self.policy_id,
            "sufficient": list(self.sufficient),
            "degraded": list(self.degraded),
            "missing": list(self.missing),
            "coverageRatio": self.coverage_ratio,
            "declaredSensors": [item.to_mapping() for item in self.declared_sensors],
            "blindSpots": list(self.blind_spots),
            "claims": {
                "totalSensorCoverage": False,
                "hiddenModelThoughtsObserved": False,
                "absenceOfEvidenceMeansAbsenceOfBehavior": False,
            },
            "method": "sova.declared-sensor-coverage/0.1",
            "limitations": [
                "Coverage is relative to the declared policy and admitted sensor sources.",
                "Provider-reported observations are not independent host observations.",
                "A compromised recorder, host, provider, or clock can emit plausible false data.",
                "Unobservable external state and hidden model thoughts remain outside scope.",
            ],
        }
        material["digest"] = sha256_digest(canonical_json_bytes(material))
        return material


class SensorCoverageLedger:
    """Evaluate claim-conditioned coverage from explicit sensor declarations."""

    def __init__(self, declarations: Iterable[SensorDeclaration] = ()) -> None:
        self._declarations: dict[str, SensorDeclaration] = {}
        for declaration in declarations:
            self.register(declaration)

    def register(self, declaration: SensorDeclaration) -> None:
        if declaration.id in self._declarations:
            raise FormatError("SOVA-COVERAGE-DUPLICATE", "sensor declaration id is duplicated")
        self._declarations[declaration.id] = declaration

    @property
    def declarations(self) -> tuple[SensorDeclaration, ...]:
        return tuple(self._declarations[key] for key in sorted(self._declarations))

    def evaluate(self, policy: SensorCoveragePolicy) -> SensorCoverageReport:
        by_key: dict[str, list[SensorDeclaration]] = {}
        for declaration in self.declarations:
            key = f"{declaration.surface.value}/{declaration.kind.value}"
            by_key.setdefault(key, []).append(declaration)
        sufficient: list[str] = []
        degraded: list[str] = []
        missing: list[str] = []
        blind_spots: set[str] = set()
        for requirement in policy.requirements:
            rows = by_key.get(requirement.key, [])
            blind_spots.update(item for row in rows for item in row.blind_spots)
            healthy = [
                row
                for row in rows
                if row.health == "healthy"
                and row.dropped_events == 0
                and (not requirement.activity_required or row.emitted_events > 0)
            ]
            if healthy:
                sufficient.append(requirement.key)
            elif rows:
                degraded.append(requirement.key)
            else:
                missing.append(requirement.key)
        total = len(policy.requirements)
        ratio = f"{len(sufficient) / total:.6f}".rstrip("0").rstrip(".")
        status = "sufficient" if not degraded and not missing else "insufficient"
        return SensorCoverageReport(
            status,
            policy.id,
            tuple(sorted(sufficient)),
            tuple(sorted(degraded)),
            tuple(sorted(missing)),
            ratio,
            self.declarations,
            tuple(sorted(blind_spots)),
        )


__all__ = [
    "CaptureMode",
    "CoverageRequirement",
    "OrderingGuarantee",
    "SensorCoverageLedger",
    "SensorCoveragePolicy",
    "SensorCoverageReport",
    "SensorDeclaration",
    "SensorSurface",
]
