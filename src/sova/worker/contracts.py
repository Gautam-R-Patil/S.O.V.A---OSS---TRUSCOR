# SPDX-License-Identifier: Apache-2.0
"""Immutable controller/worker, microVM, broker, and receipt contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

SCHEMA_VERSION = "0.1.0"
PROTOCOL_VERSION = "0.1.0"
FIRECRACKER_VERSION = "1.16.1"
MAX_JOB_AUTHORITY_SECONDS = 86_400
MAX_SECRET_USES = 16
MAX_TCP_UDP_PORT = 65_535
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,190}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _digest(value: str, role: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise FormatError("SOVA-WORKER-DIGEST", f"{role} must be canonical lowercase SHA-256")


def _identifier(value: str, role: str) -> None:
    if _IDENTIFIER.fullmatch(value) is None:
        raise FormatError("SOVA-WORKER-ID", f"{role} identifier is invalid")


def _time(value: str, role: str) -> datetime:
    if _RFC3339.fullmatch(value) is None:
        raise FormatError("SOVA-WORKER-TIME", f"{role} must be second-precision UTC")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _unique(values: tuple[str, ...], role: str) -> None:
    if len(values) != len(set(values)):
        raise FormatError("SOVA-WORKER-UNIQUE", f"{role} values must be unique")


class WorkerBackend(StrEnum):
    FIRECRACKER = "firecracker"
    KATA = "kata"
    GVISOR = "gvisor"


class WorkerReadiness(StrEnum):
    PRODUCTION_READY = "production-ready"
    IMPLEMENTATION_READY = "implementation-ready"
    DEVELOPER_ONLY = "developer-only"
    UNAVAILABLE = "unavailable"


class WorkerJobState(StrEnum):
    ACCEPTED = "accepted"
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    CANCELLED = "cancelled"
    CLEANUP_FAILED = "cleanup-failed"


class SecretKind(StrEnum):
    """Only scalar, broker-delivered secret classes are guest-accessible."""

    TARGET_CREDENTIAL = "target-credential"
    PROVIDER_TOKEN = "provider-token"  # noqa: S105 - capability class, not a credential
    CANARY = "canary"


@dataclass(frozen=True, slots=True)
class ContentReference:
    """Content-addressed input or output with no ambient filesystem authority."""

    name: str
    digest: str
    size: int
    media_type: str

    def __post_init__(self) -> None:
        _identifier(self.name, "content")
        _digest(self.digest, "content")
        if self.size < 0 or self.size > 8 * 1024 * 1024 * 1024:
            raise FormatError("SOVA-WORKER-SIZE", "content size is outside the worker bound")
        if _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise FormatError("SOVA-WORKER-MEDIA", "content media type is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "digest": self.digest,
            "size": self.size,
            "mediaType": self.media_type,
        }


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    vcpu_count: int = 1
    memory_mib: int = 512
    timeout_seconds: int = 900
    output_bytes: int = 32 * 1024 * 1024
    writable_disk_bytes: int = 2 * 1024 * 1024 * 1024
    process_limit: int = 256
    open_file_limit: int = 256
    network_connection_limit: int = 128
    network_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        ranges = (
            ("vCPU", self.vcpu_count, 1, 8),
            ("memory", self.memory_mib, 128, 32 * 1024),
            ("timeout", self.timeout_seconds, 1, 86_400),
            ("output", self.output_bytes, 1, 1024 * 1024 * 1024),
            ("writable disk", self.writable_disk_bytes, 1, 64 * 1024 * 1024 * 1024),
            ("process", self.process_limit, 1, 4096),
            ("open file", self.open_file_limit, 32, 4096),
            ("network connection", self.network_connection_limit, 0, 65_536),
            ("network byte", self.network_bytes, 0, 8 * 1024 * 1024 * 1024),
        )
        for role, value, minimum, maximum in ranges:
            if not minimum <= value <= maximum:
                raise FormatError("SOVA-WORKER-LIMIT", f"{role} limit is outside policy")

    def to_mapping(self) -> dict[str, int]:
        return {
            "vcpuCount": self.vcpu_count,
            "memoryMiB": self.memory_mib,
            "timeoutSeconds": self.timeout_seconds,
            "outputBytes": self.output_bytes,
            "writableDiskBytes": self.writable_disk_bytes,
            "processLimit": self.process_limit,
            "openFileLimit": self.open_file_limit,
            "networkConnectionLimit": self.network_connection_limit,
            "networkBytes": self.network_bytes,
        }


@dataclass(frozen=True, slots=True)
class NetworkRule:
    hostname: str
    port: int
    protocol: str
    initial_addresses: tuple[str, ...]
    allow_private: bool = False

    def __post_init__(self) -> None:
        if _HOSTNAME.fullmatch(self.hostname) is None:
            raise FormatError("SOVA-WORKER-NETWORK", "network hostname is invalid")
        if not 1 <= self.port <= MAX_TCP_UDP_PORT or self.protocol not in {"tcp", "udp"}:
            raise FormatError("SOVA-WORKER-NETWORK", "network endpoint is invalid")
        if not self.initial_addresses:
            raise FormatError("SOVA-WORKER-NETWORK", "DNS pin set cannot be empty")
        _unique(self.initial_addresses, "network address")
        for value in self.initial_addresses:
            try:
                ip_address(value)
            except ValueError as error:
                raise FormatError(
                    "SOVA-WORKER-NETWORK", "DNS pin set contains an invalid IP address"
                ) from error

    def to_mapping(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "protocol": self.protocol,
            "initialAddresses": list(self.initial_addresses),
            "allowPrivate": self.allow_private,
        }


@dataclass(frozen=True, slots=True)
class SecretGrant:
    name: str
    audience: str
    expires_at: str
    kind: SecretKind = SecretKind.TARGET_CREDENTIAL
    maximum_uses: int = 1

    def __post_init__(self) -> None:
        _identifier(self.name, "secret grant")
        _identifier(self.audience, "secret audience")
        _time(self.expires_at, "secret expiry")
        if not 1 <= self.maximum_uses <= MAX_SECRET_USES:
            raise FormatError("SOVA-WORKER-SECRET", "secret maximum uses is outside policy")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "audience": self.audience,
            "expiresAt": self.expires_at,
            "kind": self.kind.value,
            "maximumUses": self.maximum_uses,
            "secretValuePresent": False,
        }


@dataclass(frozen=True, slots=True)
class WorkerJobManifest:
    job_id: str
    issued_at: str
    expires_at: str
    target_profile_digest: str
    authorization_decision_digest: str
    methodology_plan_digest: str
    guest_output_key_digest: str
    guest_kernel: ContentReference
    root_filesystem: ContentReference
    writable_layer_seed: ContentReference
    inputs: tuple[ContentReference, ...]
    network_rules: tuple[NetworkRule, ...]
    secret_grants: tuple[SecretGrant, ...]
    output_schema_ids: tuple[str, ...]
    limits: ResourceLimits = ResourceLimits()
    backend: WorkerBackend = WorkerBackend.FIRECRACKER

    def __post_init__(self) -> None:
        _identifier(self.job_id, "worker job")
        issued = _time(self.issued_at, "job issue time")
        expires = _time(self.expires_at, "job expiry time")
        if expires <= issued:
            raise FormatError("SOVA-WORKER-TIME", "job expiry must follow issue time")
        if (expires - issued).total_seconds() > MAX_JOB_AUTHORITY_SECONDS:
            raise FormatError("SOVA-WORKER-TIME", "job authority cannot exceed 24 hours")
        for role, value in (
            ("target profile", self.target_profile_digest),
            ("authorization decision", self.authorization_decision_digest),
            ("methodology plan", self.methodology_plan_digest),
            ("guest output key", self.guest_output_key_digest),
        ):
            _digest(value, role)
        names = [
            self.guest_kernel.name,
            self.root_filesystem.name,
            self.writable_layer_seed.name,
            *(item.name for item in self.inputs),
        ]
        if len(names) != len(set(names)):
            raise FormatError("SOVA-WORKER-UNIQUE", "job content names must be unique")
        endpoint_keys = [(item.hostname, item.port, item.protocol) for item in self.network_rules]
        if len(endpoint_keys) != len(set(endpoint_keys)):
            raise FormatError("SOVA-WORKER-UNIQUE", "job network endpoints must be unique")
        grants = [(item.name, item.audience) for item in self.secret_grants]
        if len(grants) != len(set(grants)):
            raise FormatError("SOVA-WORKER-UNIQUE", "job secret grants must be unique")
        if not self.output_schema_ids:
            raise FormatError("SOVA-WORKER-OUTPUT", "at least one output schema is required")
        _unique(self.output_schema_ids, "output schema")
        for value in self.output_schema_ids:
            _identifier(value, "output schema")
        if self.backend != WorkerBackend.FIRECRACKER:
            raise FormatError(
                "SOVA-WORKER-BACKEND",
                "hostile jobs require the Firecracker backend in protocol version 0.1.0",
            )

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-job-manifest",
            "schemaVersion": SCHEMA_VERSION,
            "protocolVersion": PROTOCOL_VERSION,
            "jobId": self.job_id,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "bindings": {
                "targetProfileDigest": self.target_profile_digest,
                "authorizationDecisionDigest": self.authorization_decision_digest,
                "methodologyPlanDigest": self.methodology_plan_digest,
                "guestOutputKeyDigest": self.guest_output_key_digest,
            },
            "backend": self.backend.value,
            "boot": {
                "guestKernel": self.guest_kernel.to_mapping(),
                "rootFilesystem": self.root_filesystem.to_mapping(),
                "writableLayerSeed": self.writable_layer_seed.to_mapping(),
            },
            "inputs": [item.to_mapping() for item in self.inputs],
            "networkRules": [item.to_mapping() for item in self.network_rules],
            "secretGrants": [item.to_mapping() for item in self.secret_grants],
            "outputSchemaIds": list(self.output_schema_ids),
            "limits": self.limits.to_mapping(),
            "claims": {
                "executionAuthorizedByManifestAlone": False,
                "hostMountsAllowed": False,
                "hostCredentialsEmbedded": False,
                "guestVerdictsTrusted": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class WorkerAttestation:
    worker_id: str
    measured_at: str
    backend: WorkerBackend
    dedicated_linux_host: bool
    wsl_environment: bool
    kvm_available: bool
    cgroup_v2: bool
    swap_disabled: bool
    default_seccomp: bool
    unique_uid_gid_per_job: bool
    host_paths_root_owned: bool
    firecracker_version: str
    firecracker_digest: str
    jailer_digest: str
    host_kernel_digest: str
    microcode_digest: str
    guest_kernel_digest: str
    root_filesystem_digest: str
    policy_digest: str
    advisory_snapshot_digest: str
    independent_review_receipt: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.worker_id, "worker")
        _time(self.measured_at, "worker measurement time")
        for role, value in (
            ("Firecracker", self.firecracker_digest),
            ("jailer", self.jailer_digest),
            ("host kernel", self.host_kernel_digest),
            ("microcode", self.microcode_digest),
            ("guest kernel", self.guest_kernel_digest),
            ("root filesystem", self.root_filesystem_digest),
            ("worker policy", self.policy_digest),
            ("advisory snapshot", self.advisory_snapshot_digest),
        ):
            _digest(value, role)
        if self.independent_review_receipt is not None:
            _digest(self.independent_review_receipt, "independent review receipt")

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-attestation",
            "schemaVersion": SCHEMA_VERSION,
            "workerId": self.worker_id,
            "measuredAt": self.measured_at,
            "backend": self.backend.value,
            "host": {
                "dedicatedLinuxHost": self.dedicated_linux_host,
                "wslEnvironment": self.wsl_environment,
                "kvmAvailable": self.kvm_available,
                "cgroupV2": self.cgroup_v2,
                "swapDisabled": self.swap_disabled,
                "hostPathsRootOwned": self.host_paths_root_owned,
            },
            "isolation": {
                "defaultSeccomp": self.default_seccomp,
                "uniqueUidGidPerJob": self.unique_uid_gid_per_job,
                "hostMountsAllowed": False,
                "pciEnabled": False,
            },
            "pins": {
                "firecrackerVersion": self.firecracker_version,
                "firecrackerDigest": self.firecracker_digest,
                "jailerDigest": self.jailer_digest,
                "hostKernelDigest": self.host_kernel_digest,
                "microcodeDigest": self.microcode_digest,
                "guestKernelDigest": self.guest_kernel_digest,
                "rootFilesystemDigest": self.root_filesystem_digest,
                "policyDigest": self.policy_digest,
                "advisorySnapshotDigest": self.advisory_snapshot_digest,
            },
            "independentReviewReceipt": self.independent_review_receipt,
            "claims": {
                "selfMeasured": True,
                "independentlyReviewed": self.independent_review_receipt is not None,
                "escapeImpossible": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class WorkerAdmission:
    readiness: WorkerReadiness
    reasons: tuple[str, ...]
    attestation_digest: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "readiness": self.readiness.value,
            "reasons": list(self.reasons),
            "attestationDigest": self.attestation_digest,
            "productionIsolationClaimAllowed": self.readiness == WorkerReadiness.PRODUCTION_READY,
        }


def assess_worker_attestation(
    attestation: WorkerAttestation,
    *,
    expected_policy_digest: str,
    expected_guest_kernel_digest: str,
    expected_root_filesystem_digest: str,
) -> WorkerAdmission:
    """Admit exact pins while keeping development and production claims separate."""
    reasons: list[str] = []
    _digest(expected_policy_digest, "expected worker policy")
    if attestation.backend != WorkerBackend.FIRECRACKER:
        reasons.append("firecracker-backend-required")
    if attestation.firecracker_version != FIRECRACKER_VERSION:
        reasons.append("firecracker-version-not-approved")
    for condition, reason in (
        (attestation.kvm_available, "kvm-unavailable"),
        (attestation.cgroup_v2, "cgroup-v2-unavailable"),
        (attestation.swap_disabled, "swap-enabled"),
        (attestation.default_seccomp, "default-seccomp-not-enforced"),
        (attestation.unique_uid_gid_per_job, "unique-job-identity-not-enforced"),
        (attestation.host_paths_root_owned, "trusted-host-path-ownership-unverified"),
        (attestation.policy_digest == expected_policy_digest, "worker-policy-pin-mismatch"),
        (
            attestation.guest_kernel_digest == expected_guest_kernel_digest,
            "guest-kernel-pin-mismatch",
        ),
        (
            attestation.root_filesystem_digest == expected_root_filesystem_digest,
            "root-filesystem-pin-mismatch",
        ),
    ):
        if not condition:
            reasons.append(reason)
    if reasons:
        readiness = WorkerReadiness.UNAVAILABLE
    elif attestation.wsl_environment or not attestation.dedicated_linux_host:
        readiness = WorkerReadiness.DEVELOPER_ONLY
        reasons.append("dedicated-linux-host-required")
    elif attestation.independent_review_receipt is None:
        readiness = WorkerReadiness.IMPLEMENTATION_READY
        reasons.append("independent-isolation-review-required")
    else:
        readiness = WorkerReadiness.PRODUCTION_READY
    return WorkerAdmission(readiness, tuple(reasons), attestation.digest)


__all__ = [
    "FIRECRACKER_VERSION",
    "PROTOCOL_VERSION",
    "SCHEMA_VERSION",
    "ContentReference",
    "NetworkRule",
    "ResourceLimits",
    "SecretGrant",
    "SecretKind",
    "WorkerAdmission",
    "WorkerAttestation",
    "WorkerBackend",
    "WorkerJobManifest",
    "WorkerJobState",
    "WorkerReadiness",
    "assess_worker_attestation",
]
