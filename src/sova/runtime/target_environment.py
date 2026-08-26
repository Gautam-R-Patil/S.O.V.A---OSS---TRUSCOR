# SPDX-License-Identifier: Apache-2.0
"""Immutable target-instance and execution-session affinity contracts.

These contracts describe an already admitted target environment.  They do not
launch a browser, desktop, process, or VM and deliberately contain no secret or
raw profile material.  Executor integration remains the responsibility of a
trusted coordinator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


def _require_digest(value: str, role: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FormatError(
            "SOVA-UNIFIED-DIGEST",
            f"{role} must be a canonical lowercase SHA-256 digest",
        )


def _require_identifier(value: str, role: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise FormatError("SOVA-UNIFIED-IDENTIFIER", f"{role} is invalid")


def _canonical_identifiers(values: tuple[str, ...], role: str) -> tuple[str, ...]:
    for value in values:
        _require_identifier(value, role)
    normalized = tuple(sorted(set(values)))
    if len(normalized) != len(values):
        raise FormatError("SOVA-UNIFIED-DUPLICATE", f"{role} contains a duplicate")
    return normalized


class TargetLifecycle(StrEnum):
    """Immutable lifecycle observation for one target generation."""

    STARTING = "starting"
    READY = "ready"
    STOPPING = "stopping"
    CLOSED = "closed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class TargetInstance:
    """One exact target generation and its secret-free attachment evidence."""

    instance_id: str
    target_manifest_digest: str
    environment_digest: str
    containment_digest: str
    generation: int
    clock_domain: str
    lifecycle: TargetLifecycle = TargetLifecycle.READY
    process_id: int | None = None
    process_start_digest: str | None = None
    browser_context_digest: str | None = None
    window_handle_digest: str | None = None
    endpoint_digest: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.instance_id, "target instance id")
        _require_identifier(self.clock_domain, "target clock domain")
        for value, role in (
            (self.target_manifest_digest, "target manifest digest"),
            (self.environment_digest, "target environment digest"),
            (self.containment_digest, "target containment digest"),
        ):
            _require_digest(value, role)
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise FormatError(
                "SOVA-UNIFIED-TARGET-GENERATION",
                "target generation must be a positive integer",
            )
        if (self.process_id is None) != (self.process_start_digest is None):
            raise FormatError(
                "SOVA-UNIFIED-PROCESS-BINDING",
                "process id and process-start digest must be supplied together",
            )
        if self.process_id is not None and (
            isinstance(self.process_id, bool)
            or not isinstance(self.process_id, int)
            or self.process_id <= 0
        ):
            raise FormatError(
                "SOVA-UNIFIED-PROCESS-BINDING",
                "target process id must be a positive integer",
            )
        for optional_value, role in (
            (self.process_start_digest, "process-start digest"),
            (self.browser_context_digest, "browser-context digest"),
            (self.window_handle_digest, "window-handle digest"),
            (self.endpoint_digest, "target endpoint digest"),
        ):
            if optional_value is not None:
                _require_digest(optional_value, role)
        if self.window_handle_digest is not None and self.process_id is None:
            raise FormatError(
                "SOVA-UNIFIED-WINDOW-BINDING",
                "a target window requires a process-generation binding",
            )
        if not isinstance(self.lifecycle, TargetLifecycle):
            raise FormatError(
                "SOVA-UNIFIED-TARGET-LIFECYCLE",
                "target lifecycle must use the declared lifecycle contract",
            )

    @property
    def ready(self) -> bool:
        return self.lifecycle == TargetLifecycle.READY

    def to_mapping(self) -> dict[str, Any]:
        return {
            "instanceId": self.instance_id,
            "targetManifestDigest": self.target_manifest_digest,
            "environmentDigest": self.environment_digest,
            "containmentDigest": self.containment_digest,
            "generation": self.generation,
            "clockDomain": self.clock_domain,
            "lifecycle": self.lifecycle.value,
            "process": (
                None
                if self.process_id is None
                else {
                    "id": self.process_id,
                    "startDigest": self.process_start_digest,
                }
            ),
            "browserContextDigest": self.browser_context_digest,
            "windowHandleDigest": self.window_handle_digest,
            "endpointDigest": self.endpoint_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class CapabilityGeneration:
    """One capability contract in one backend inventory generation."""

    identifier: str
    generation: int
    contract_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.identifier, "capability identifier")
        if self.identifier.count("/") != 1 or any(
            not item for item in self.identifier.split("/", 1)
        ):
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY",
                "capability identifier must include an exact version",
            )
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY-GENERATION",
                "capability generation must be a positive integer",
            )
        _require_digest(self.contract_digest, "capability contract digest")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "generation": self.generation,
            "contractDigest": self.contract_digest,
        }


@dataclass(frozen=True, slots=True)
class BackendGeneration:
    """An attested executor generation attached to one target environment."""

    backend_id: str
    generation: int
    target_instance_digest: str
    environment_digest: str
    capabilities: tuple[CapabilityGeneration, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.backend_id, "backend id")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise FormatError(
                "SOVA-UNIFIED-BACKEND-GENERATION",
                "backend generation must be a positive integer",
            )
        _require_digest(self.target_instance_digest, "backend target-instance digest")
        _require_digest(self.environment_digest, "backend environment digest")
        if not self.capabilities:
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY",
                "backend generation must declare at least one capability",
            )
        ordered = tuple(sorted(self.capabilities, key=lambda item: item.identifier))
        if len({item.identifier for item in ordered}) != len(ordered):
            raise FormatError(
                "SOVA-UNIFIED-DUPLICATE",
                "backend capability identifier is duplicated",
            )
        object.__setattr__(self, "capabilities", ordered)

    def capability(self, identifier: str) -> CapabilityGeneration:
        match = next((item for item in self.capabilities if item.identifier == identifier), None)
        if match is None:
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY",
                "backend generation does not contain the exact capability",
                details={"backendId": self.backend_id, "capability": identifier},
            )
        return match

    def to_mapping(self) -> dict[str, Any]:
        return {
            "backendId": self.backend_id,
            "generation": self.generation,
            "targetInstanceDigest": self.target_instance_digest,
            "environmentDigest": self.environment_digest,
            "capabilities": [item.to_mapping() for item in self.capabilities],
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class SessionEnvelope:
    """One logical run session bound to exact target and backend generations."""

    session_id: str
    run_id: str
    generation: int
    target_instance_digest: str
    environment_digest: str
    containment_digest: str
    identity_digest: str
    clock_domain: str
    backend_generations: tuple[BackendGeneration, ...]
    affinity_resources: tuple[str, ...]
    profile_lease_digest: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.session_id, "session id")
        _require_identifier(self.run_id, "run id")
        _require_identifier(self.clock_domain, "session clock domain")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise FormatError(
                "SOVA-UNIFIED-SESSION-GENERATION",
                "session generation must be a positive integer",
            )
        for value, role in (
            (self.target_instance_digest, "session target-instance digest"),
            (self.environment_digest, "session environment digest"),
            (self.containment_digest, "session containment digest"),
            (self.identity_digest, "session identity digest"),
        ):
            _require_digest(value, role)
        if self.profile_lease_digest is not None:
            _require_digest(self.profile_lease_digest, "browser profile lease digest")
        if not self.backend_generations:
            raise FormatError(
                "SOVA-UNIFIED-BACKEND-GENERATION",
                "session requires at least one backend generation",
            )
        ordered_backends = tuple(sorted(self.backend_generations, key=lambda item: item.backend_id))
        if len({item.backend_id for item in ordered_backends}) != len(ordered_backends):
            raise FormatError(
                "SOVA-UNIFIED-DUPLICATE",
                "session backend id is duplicated",
            )
        for backend in ordered_backends:
            if backend.target_instance_digest != self.target_instance_digest:
                raise FormatError(
                    "SOVA-UNIFIED-TARGET-AFFINITY",
                    "backend generation is attached to a different target instance",
                )
            if backend.environment_digest != self.environment_digest:
                raise FormatError(
                    "SOVA-UNIFIED-ENVIRONMENT-AFFINITY",
                    "backend generation is attached to a different environment",
                )
        resources = _canonical_identifiers(self.affinity_resources, "affinity resource")
        if not resources:
            raise FormatError(
                "SOVA-UNIFIED-AFFINITY",
                "session requires at least one affinity resource",
            )
        object.__setattr__(self, "backend_generations", ordered_backends)
        object.__setattr__(self, "affinity_resources", resources)

    def backend(self, backend_id: str) -> BackendGeneration:
        match = next(
            (item for item in self.backend_generations if item.backend_id == backend_id),
            None,
        )
        if match is None:
            raise FormatError(
                "SOVA-UNIFIED-BACKEND-GENERATION",
                "backend is not attached to this session",
                details={"backendId": backend_id},
            )
        return match

    def assert_target(self, target: TargetInstance) -> None:
        if target.digest != self.target_instance_digest:
            raise FormatError(
                "SOVA-UNIFIED-TARGET-AFFINITY",
                "session target instance was substituted",
            )
        if target.environment_digest != self.environment_digest:
            raise FormatError(
                "SOVA-UNIFIED-ENVIRONMENT-AFFINITY",
                "session and target environment digests differ",
            )
        if target.containment_digest != self.containment_digest:
            raise FormatError(
                "SOVA-UNIFIED-CONTAINMENT-AFFINITY",
                "session and target containment digests differ",
            )
        if target.clock_domain != self.clock_domain:
            raise FormatError(
                "SOVA-UNIFIED-CLOCK-AFFINITY",
                "session and target clock domains differ",
            )
        if not target.ready:
            raise FormatError(
                "SOVA-UNIFIED-TARGET-NOT-READY",
                "target generation is not ready for execution",
            )

    def assert_affinity(self, resources: tuple[str, ...]) -> None:
        requested = set(_canonical_identifiers(resources, "affinity resource"))
        absent = sorted(requested - set(self.affinity_resources))
        if absent:
            raise FormatError(
                "SOVA-UNIFIED-AFFINITY",
                "action references resources outside the session affinity",
                details={"missing": absent},
            )

    @property
    def affinity_digest(self) -> str:
        return sha256_digest(
            canonical_json_bytes(
                {
                    "sessionId": self.session_id,
                    "generation": self.generation,
                    "targetInstanceDigest": self.target_instance_digest,
                    "environmentDigest": self.environment_digest,
                    "identityDigest": self.identity_digest,
                    "profileLeaseDigest": self.profile_lease_digest,
                    "resources": list(self.affinity_resources),
                }
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "sessionId": self.session_id,
            "runId": self.run_id,
            "generation": self.generation,
            "targetInstanceDigest": self.target_instance_digest,
            "environmentDigest": self.environment_digest,
            "containmentDigest": self.containment_digest,
            "identityDigest": self.identity_digest,
            "clockDomain": self.clock_domain,
            "backendGenerations": [item.to_mapping() for item in self.backend_generations],
            "affinityResources": list(self.affinity_resources),
            "profileLeaseDigest": self.profile_lease_digest,
            "affinityDigest": self.affinity_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


__all__ = [
    "BackendGeneration",
    "CapabilityGeneration",
    "SessionEnvelope",
    "TargetInstance",
    "TargetLifecycle",
]
