# SPDX-License-Identifier: Apache-2.0
"""Capability-aware containment admission without sandbox overclaims."""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass
from enum import IntEnum, StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest


class IsolationKind(IntEnum):
    """Ordered isolation classes; only the named properties are claimed."""

    NONE = 0
    PROCESS = 1
    CONTAINER = 2
    USER_KERNEL = 3
    MICROVM = 4


class NetworkMode(IntEnum):
    """Increasingly permissive network exposure."""

    NONE = 0
    SINK_ONLY = 1
    ALLOWLISTED = 2
    LIVE = 3


class ReadinessState(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class BackendDescriptor:
    id: str
    name: str
    isolation: IsolationKind
    executes_native_code: bool
    network_mode: NetworkMode
    disposable: bool
    deterministic_reset: bool
    synthetic_credentials: bool
    post_cleanup_verification: bool
    readiness: ReadinessState
    protections: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def digest(self) -> str:
        value = asdict(self)
        value["isolation"] = self.isolation.name.lower()
        value["network_mode"] = self.network_mode.name.lower()
        value["readiness"] = self.readiness.value
        return sha256_digest(canonical_json_bytes(value))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "isolation": self.isolation.name.lower(),
            "executesNativeCode": self.executes_native_code,
            "networkMode": self.network_mode.name.lower(),
            "disposable": self.disposable,
            "deterministicReset": self.deterministic_reset,
            "syntheticCredentials": self.synthetic_credentials,
            "postCleanupVerification": self.post_cleanup_verification,
            "readiness": self.readiness.value,
            "protections": list(self.protections),
            "limitations": list(self.limitations),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class ContainmentRequirements:
    minimum_isolation: IsolationKind
    maximum_network_mode: NetworkMode = NetworkMode.SINK_ONLY
    disposable: bool = True
    deterministic_reset: bool = True
    synthetic_credentials: bool = True
    post_cleanup_verification: bool = True
    allow_developer_mode: bool = False
    allow_no_native_code_simulation: bool = True


@dataclass(frozen=True, slots=True)
class ContainmentDecision:
    status: str
    backend_id: str
    backend_digest: str
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "backendId": self.backend_id,
            "backendDigest": self.backend_digest,
            "reasons": list(self.reasons),
            "limitations": list(self.limitations),
            "method": "sova.containment-admission/0.1",
        }


class ContainmentGate:
    """Refuse or explicitly downgrade when required protections are absent."""

    def assess(
        self,
        backend: BackendDescriptor,
        requirements: ContainmentRequirements,
    ) -> ContainmentDecision:
        reasons: list[str] = []
        if backend.readiness == ReadinessState.UNAVAILABLE:
            reasons.append("backend-unavailable")
        simulation_exempt = (
            requirements.allow_no_native_code_simulation and not backend.executes_native_code
        )
        if not simulation_exempt and backend.isolation < requirements.minimum_isolation:
            reasons.append("isolation-below-requirement")
        if backend.network_mode > requirements.maximum_network_mode:
            reasons.append("network-more-permissive-than-requirement")
        for required, actual, label in (
            (requirements.disposable, backend.disposable, "not-disposable"),
            (
                requirements.deterministic_reset,
                backend.deterministic_reset,
                "reset-not-deterministic",
            ),
            (
                requirements.synthetic_credentials,
                backend.synthetic_credentials,
                "real-credentials-possible",
            ),
            (
                requirements.post_cleanup_verification,
                backend.post_cleanup_verification,
                "cleanup-not-verified",
            ),
        ):
            if required and not actual:
                reasons.append(label)
        if (
            reasons
            and requirements.allow_developer_mode
            and backend.isolation >= IsolationKind.PROCESS
        ):
            status = "developer-only"
        else:
            status = "denied" if reasons else "allowed"
        return ContainmentDecision(
            status,
            backend.id,
            backend.digest,
            tuple(reasons),
            backend.limitations,
        )


def known_backend_descriptors() -> tuple[BackendDescriptor, ...]:
    """Return a capability inventory; no backend is started by this probe."""
    docker_present = shutil.which("docker") is not None
    runsc_present = shutil.which("runsc") is not None
    firecracker_present = shutil.which("firecracker") is not None
    kata_present = shutil.which("kata-runtime") is not None
    return (
        BackendDescriptor(
            id="sova:backend:synthetic",
            name="SOVA in-memory synthetic world",
            isolation=IsolationKind.NONE,
            executes_native_code=False,
            network_mode=NetworkMode.SINK_ONLY,
            disposable=True,
            deterministic_reset=True,
            synthetic_credentials=True,
            post_cleanup_verification=True,
            readiness=ReadinessState.READY,
            protections=("no native target code", "in-memory effects", "sink-only egress"),
            limitations=(
                "This is a simulator, not an operating-system sandbox.",
                "It cannot expose behavior that depends on real kernel or application details.",
            ),
        ),
        BackendDescriptor(
            id="sova:backend:restricted-local",
            name="Restricted local process developer mode",
            isolation=IsolationKind.PROCESS,
            executes_native_code=True,
            network_mode=NetworkMode.LIVE,
            disposable=False,
            deterministic_reset=False,
            synthetic_credentials=False,
            post_cleanup_verification=False,
            readiness=ReadinessState.READY,
            protections=("allowlisted executable", "bounded cwd", "no shell"),
            limitations=("Ordinary host-process restrictions are not a security sandbox.",),
        ),
        BackendDescriptor(
            id="sova:backend:docker",
            name="OCI container backend",
            isolation=IsolationKind.CONTAINER,
            executes_native_code=True,
            network_mode=NetworkMode.NONE,
            disposable=True,
            deterministic_reset=True,
            synthetic_credentials=True,
            post_cleanup_verification=True,
            readiness=ReadinessState.DEGRADED if docker_present else ReadinessState.UNAVAILABLE,
            protections=(
                "namespaces",
                "cgroups",
                "seccomp-profile-required",
                "read-only-rootfs-required",
            ),
            limitations=(
                "Client presence does not prove a running or hardened daemon.",
                "Containers share the host kernel unless a stronger runtime is selected.",
            ),
        ),
        BackendDescriptor(
            id="sova:backend:gvisor",
            name="gVisor user-kernel container backend",
            isolation=IsolationKind.USER_KERNEL,
            executes_native_code=True,
            network_mode=NetworkMode.NONE,
            disposable=True,
            deterministic_reset=True,
            synthetic_credentials=True,
            post_cleanup_verification=True,
            readiness=ReadinessState.READY if runsc_present else ReadinessState.UNAVAILABLE,
            protections=("user-space kernel", "OCI integration"),
            limitations=("Runtime configuration and host protections still require validation.",),
        ),
        BackendDescriptor(
            id="sova:backend:firecracker",
            name="Firecracker microVM backend",
            isolation=IsolationKind.MICROVM,
            executes_native_code=True,
            network_mode=NetworkMode.NONE,
            disposable=True,
            deterministic_reset=True,
            synthetic_credentials=True,
            post_cleanup_verification=True,
            readiness=ReadinessState.READY if firecracker_present else ReadinessState.UNAVAILABLE,
            protections=("KVM microVM boundary", "minimal device model"),
            limitations=("Requires a supported Linux/KVM host and hardened orchestration.",),
        ),
        BackendDescriptor(
            id="sova:backend:kata",
            name="Kata Containers VM-backed OCI backend",
            isolation=IsolationKind.MICROVM,
            executes_native_code=True,
            network_mode=NetworkMode.NONE,
            disposable=True,
            deterministic_reset=True,
            synthetic_credentials=True,
            post_cleanup_verification=True,
            readiness=ReadinessState.READY if kata_present else ReadinessState.UNAVAILABLE,
            protections=("VM-backed container boundary", "OCI integration"),
            limitations=("Runtime and hypervisor configuration require independent validation.",),
        ),
    )


__all__ = [
    "BackendDescriptor",
    "ContainmentDecision",
    "ContainmentGate",
    "ContainmentRequirements",
    "IsolationKind",
    "NetworkMode",
    "ReadinessState",
    "known_backend_descriptors",
]
