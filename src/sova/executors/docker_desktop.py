# SPDX-License-Identifier: Apache-2.0
"""Fail-closed execution inside a VM-hosted, hardened OCI container."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast

from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.safety.containment import (
    BackendDescriptor,
    IsolationKind,
    NetworkMode,
    ReadinessState,
)

if TYPE_CHECKING:
    from pathlib import Path

_DIGEST_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_SANDBOX_NAME = re.compile(r"^sova-[a-z0-9]{20}$")
_MAX_ARGS = 256
_MAX_ARG_BYTES = 64 * 1024
_MIN_OUTPUT = 1024
_MAX_OUTPUT = 64 * 1024 * 1024
_MIN_PIDS = 8
_MAX_PIDS = 4096
_MAX_RUNTIME_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class DockerCommandResult:
    """Bounded result from one shell-free Docker CLI invocation."""

    state: str
    returncode: int | None
    stdout: bytes
    stderr: bytes


class DockerCommandRunner(Protocol):
    """Injectable command boundary used by deterministic conformance tests."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
        max_output_bytes: int,
    ) -> DockerCommandResult: ...


class BoundedDockerCommandRunner:
    """Run argv without a shell and terminate it on cancellation or hard bounds."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
        max_output_bytes: int,
    ) -> DockerCommandResult:
        if _cancelled(cancellation):
            return DockerCommandResult("cancelled", None, b"", b"")
        creationflags = (
            int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) if os.name == "nt" else 0
        )
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    start_new_session=os.name != "nt",
                    creationflags=creationflags,
                )
            except OSError:
                return DockerCommandResult("start-failed", None, b"", b"")
            deadline = time.monotonic() + timeout_seconds
            state = "completed"
            while process.poll() is None:
                if _cancelled(cancellation):
                    state = "cancelled"
                    _terminate(process)
                    break
                if time.monotonic() >= deadline:
                    state = "timeout"
                    _terminate(process)
                    break
                if (
                    os.fstat(stdout.fileno()).st_size > max_output_bytes
                    or os.fstat(stderr.fileno()).st_size > max_output_bytes
                ):
                    state = "output-limit"
                    _terminate(process)
                    break
                time.sleep(0.02)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            stdout.seek(0)
            stderr.seek(0)
            return DockerCommandResult(
                state,
                process.returncode,
                stdout.read(max_output_bytes),
                stderr.read(max_output_bytes),
            )


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        with suppress(OSError):
            process.kill()


def _cancelled(token: CancellationToken) -> bool:
    """Avoid static narrowing across a concurrently mutable cancellation token."""
    return token.cancelled


@dataclass(frozen=True, slots=True)
class DockerDesktopAttestation:
    """Safe capability projection; raw daemon configuration is never retained."""

    readiness: str
    client_version: str | None
    server_version: str | None
    operating_system: str | None
    kernel_version: str | None
    cgroup_version: str | None
    image: str
    image_cached: bool
    docker_desktop_vm: bool
    seccomp: bool
    memory_limit: bool
    cpu_limit: bool
    pids_limit: bool
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return self.readiness == "ready"

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(asdict(self)))

    def to_mapping(self) -> dict[str, Any]:
        return {**asdict(self), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class DockerDesktopIsolationPolicy:
    """Fixed maximum authority for one container invocation."""

    memory_bytes: int = 256 * 1024 * 1024
    cpus: str = "0.5"
    pids_limit: int = 32
    tmpfs_bytes: int = 16 * 1024 * 1024
    max_output_bytes: int = 1024 * 1024
    max_runtime_seconds: float = 300

    def __post_init__(self) -> None:
        if not 64 * 1024 * 1024 <= self.memory_bytes <= 16 * 1024 * 1024 * 1024:
            raise FormatError("SOVA-OCI-MEMORY", "memory limit must be between 64 MiB and 16 GiB")
        if not re.fullmatch(r"(?:0\.[1-9]|[1-9][0-9]?(?:\.0)?)", self.cpus):
            raise FormatError("SOVA-OCI-CPU", "CPU limit must be a positive bounded decimal")
        if not _MIN_PIDS <= self.pids_limit <= _MAX_PIDS:
            raise FormatError("SOVA-OCI-PIDS", "PID limit must be between 8 and 4096")
        if not 1024 * 1024 <= self.tmpfs_bytes <= self.memory_bytes:
            raise FormatError("SOVA-OCI-TMPFS", "tmpfs must be between 1 MiB and memory limit")
        if not _MIN_OUTPUT <= self.max_output_bytes <= _MAX_OUTPUT:
            raise FormatError("SOVA-OCI-OUTPUT", "output limit must be between 1 KiB and 64 MiB")
        if not 1 <= self.max_runtime_seconds <= _MAX_RUNTIME_SECONDS:
            raise FormatError("SOVA-OCI-RUNTIME", "runtime must be between one second and one hour")


def _load_json_object(data: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FormatError(code, "Docker returned malformed JSON") from error
    if not isinstance(value, dict):
        raise FormatError(code, "Docker JSON root must be an object")
    return value


def attest_docker_desktop(
    docker_executable: Path,
    image: str,
    *,
    runner: DockerCommandRunner | None = None,
) -> DockerDesktopAttestation:
    """Attest a cached digest-pinned image and enforceable Docker capabilities."""
    executable = docker_executable.resolve()
    if not executable.is_file():
        raise FormatError("SOVA-OCI-DOCKER", "Docker executable must be an existing file")
    if not _DIGEST_IMAGE.fullmatch(image):
        raise FormatError(
            "SOVA-OCI-IMAGE",
            "container image must be an exact repository@sha256 digest",
        )
    command_runner = runner or BoundedDockerCommandRunner()
    token = CancellationToken()

    version_result = command_runner.run(
        (str(executable), "version", "--format", "{{json .}}"),
        timeout_seconds=20,
        cancellation=token,
        max_output_bytes=4 * 1024 * 1024,
    )
    info_result = command_runner.run(
        (str(executable), "info", "--format", "{{json .}}"),
        timeout_seconds=20,
        cancellation=token,
        max_output_bytes=4 * 1024 * 1024,
    )
    image_result = command_runner.run(
        (
            str(executable),
            "image",
            "inspect",
            image,
            "--format",
            "{{json .RepoDigests}}",
        ),
        timeout_seconds=20,
        cancellation=token,
        max_output_bytes=1024 * 1024,
    )
    reasons: list[str] = []
    if version_result.state != "completed" or version_result.returncode != 0:
        reasons.append("docker-daemon-unavailable")
    if info_result.state != "completed" or info_result.returncode != 0:
        reasons.append("docker-info-unavailable")
    if image_result.state != "completed" or image_result.returncode != 0:
        reasons.append("digest-pinned-image-not-cached")
    if reasons:
        return DockerDesktopAttestation(
            readiness="unavailable",
            client_version=None,
            server_version=None,
            operating_system=None,
            kernel_version=None,
            cgroup_version=None,
            image=image,
            image_cached=False,
            docker_desktop_vm=False,
            seccomp=False,
            memory_limit=False,
            cpu_limit=False,
            pids_limit=False,
            reasons=tuple(reasons),
            limitations=(
                "No image pull is attempted; admission requires a previously cached exact digest.",
                "Client presence alone never establishes a running or hardened backend.",
            ),
        )

    version = _load_json_object(version_result.stdout, "SOVA-OCI-VERSION-JSON")
    info = _load_json_object(info_result.stdout, "SOVA-OCI-INFO-JSON")
    try:
        repo_digests = json.loads(image_result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FormatError("SOVA-OCI-IMAGE-JSON", "Docker returned malformed image JSON") from error
    raw_client = version.get("Client")
    raw_server = version.get("Server")
    client: dict[str, Any] = (
        cast("dict[str, Any]", raw_client) if isinstance(raw_client, dict) else {}
    )
    server: dict[str, Any] = (
        cast("dict[str, Any]", raw_server) if isinstance(raw_server, dict) else {}
    )
    raw_platform = server.get("Platform")
    platform: dict[str, Any] = (
        cast("dict[str, Any]", raw_platform) if isinstance(raw_platform, dict) else {}
    )
    raw_security = info.get("SecurityOptions")
    security: list[Any] = raw_security if isinstance(raw_security, list) else []
    client_version = client.get("Version") if isinstance(client.get("Version"), str) else None
    server_version = server.get("Version") if isinstance(server.get("Version"), str) else None
    operating_system = (
        info.get("OperatingSystem") if isinstance(info.get("OperatingSystem"), str) else None
    )
    kernel_version = (
        info.get("KernelVersion") if isinstance(info.get("KernelVersion"), str) else None
    )
    cgroup_version = (
        str(info.get("CgroupVersion")) if info.get("CgroupVersion") is not None else None
    )
    image_cached = isinstance(repo_digests, list) and image in repo_digests
    raw_platform_name = platform.get("Name")
    platform_name = raw_platform_name if isinstance(raw_platform_name, str) else ""
    docker_desktop_vm = (
        "docker desktop" in (operating_system or "").casefold()
        or "docker desktop" in platform_name.casefold()
    ) and server.get("Os") == "linux"
    seccomp = any(isinstance(value, str) and "seccomp" in value for value in security)
    memory_limit = info.get("MemoryLimit") is True
    cpu_limit = info.get("CpuCfsQuota") is True
    pids_limit = info.get("PidsLimit") is True
    checks = (
        (image_cached, "exact-image-digest-not-confirmed"),
        (docker_desktop_vm, "docker-desktop-linux-vm-not-attested"),
        (seccomp, "seccomp-unavailable"),
        (memory_limit, "memory-limit-unavailable"),
        (cpu_limit, "cpu-limit-unavailable"),
        (pids_limit, "pid-limit-unavailable"),
    )
    reasons.extend(label for passed, label in checks if not passed)
    return DockerDesktopAttestation(
        readiness="ready" if not reasons else "degraded",
        client_version=client_version,
        server_version=server_version,
        operating_system=operating_system,
        kernel_version=kernel_version,
        cgroup_version=cgroup_version,
        image=image,
        image_cached=image_cached,
        docker_desktop_vm=docker_desktop_vm,
        seccomp=seccomp,
        memory_limit=memory_limit,
        cpu_limit=cpu_limit,
        pids_limit=pids_limit,
        reasons=tuple(reasons),
        limitations=(
            "The workload is an OCI container sharing the Docker Desktop VM kernel.",
            "The outer Docker Desktop Linux VM is a host boundary, not a per-workload microVM.",
            "Docker Desktop, its hypervisor/backend, and the container runtime remain trusted.",
            "No claim is made against a compromised host, hypervisor, or Docker daemon.",
        ),
    )


def docker_desktop_backend_descriptor(
    attestation: DockerDesktopAttestation,
) -> BackendDescriptor:
    """Project a live attestation into the ordinary containment admission gate."""
    readiness = {
        "ready": ReadinessState.READY,
        "degraded": ReadinessState.DEGRADED,
        "unavailable": ReadinessState.UNAVAILABLE,
    }[attestation.readiness]
    return BackendDescriptor(
        id="sova:backend:docker-desktop-oci",
        name="SOVA VM-hosted hardened OCI executor",
        isolation=IsolationKind.CONTAINER,
        executes_native_code=True,
        network_mode=NetworkMode.NONE,
        disposable=True,
        deterministic_reset=True,
        synthetic_credentials=True,
        post_cleanup_verification=True,
        readiness=readiness,
        protections=(
            "docker-desktop-linux-vm-host-boundary",
            "digest-pinned-cached-image",
            "no-host-mounts-or-daemon-socket",
            "network-none",
            "read-only-rootfs",
            "non-root-zero-capabilities-no-new-privileges",
            "cpu-memory-pid-bounds",
            f"attestation:{attestation.digest}",
        ),
        limitations=attestation.limitations,
    )


class DockerDesktopOciExecutor:
    """Run container-local argv with no network, host mount, daemon socket, or image pull."""

    name = "sova-docker-desktop-oci"

    def __init__(
        self,
        docker_executable: Path,
        image: str,
        *,
        policy: DockerDesktopIsolationPolicy | None = None,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        self._docker = docker_executable.resolve()
        self._image = image
        self._policy = policy or DockerDesktopIsolationPolicy()
        self._runner = runner or BoundedDockerCommandRunner()
        self._attestation = attest_docker_desktop(
            self._docker,
            image,
            runner=self._runner,
        )

    @property
    def attestation(self) -> DockerDesktopAttestation:
        return self._attestation

    def capabilities(self) -> tuple[Capability, ...]:
        if not self._attestation.ready:
            return ()
        return (
            Capability(
                name="process.exec",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("stdout", "stderr", "returncode", "containment-attestation"),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context  # no host workspace or capsule bytes cross into the container
        if request.action != "process.exec":
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-OCI-UNSUPPORTED",
            )
        if not self._attestation.ready:
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {"attestationDigest": self._attestation.digest},
                error_code="SOVA-OCI-NOT-ATTESTED",
                limitations=self._attestation.limitations,
            )
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-EXECUTOR-CANCELLED",
            )
        argv = _container_argv(request.inputs)
        container_name = f"sova-{uuid.uuid4().hex[:20]}"
        result = self._runner.run(
            self._run_argv(container_name, argv),
            timeout_seconds=min(request.timeout_seconds, self._policy.max_runtime_seconds),
            cancellation=cancellation,
            max_output_bytes=self._policy.max_output_bytes,
        )
        cleanup_verified = self._cleanup(container_name)
        status = {
            "completed": (
                OutcomeStatus.SUCCEEDED if result.returncode == 0 else OutcomeStatus.FAILED
            ),
            "timeout": OutcomeStatus.TIMEOUT,
            "cancelled": OutcomeStatus.CANCELLED,
            "output-limit": OutcomeStatus.PARTIAL,
            "start-failed": OutcomeStatus.FAILED,
        }.get(result.state, OutcomeStatus.FAILED)
        if not cleanup_verified:
            status = OutcomeStatus.PARTIAL
        stdout = result.stdout[: self._policy.max_output_bytes]
        stderr = result.stderr[: self._policy.max_output_bytes]
        evidence = (
            EvidenceReference("stdout", "text/plain", sha256_digest(stdout), len(stdout)),
            EvidenceReference("stderr", "text/plain", sha256_digest(stderr), len(stderr)),
            EvidenceReference(
                "containment-attestation",
                "application/json",
                self._attestation.digest,
                len(canonical_json_bytes(self._attestation.to_mapping())),
            ),
        )
        error_code = None
        if status != OutcomeStatus.SUCCEEDED:
            error_code = (
                "SOVA-OCI-CLEANUP-UNVERIFIED"
                if not cleanup_verified
                else f"SOVA-OCI-{status.value.upper()}"
            )
        return ActionOutcome(
            request.id,
            status,
            SideEffect.MUTATE,
            {
                "returncode": result.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "attestationDigest": self._attestation.digest,
                "cleanupVerified": cleanup_verified,
                "networkMode": "none",
                "hostWorkspaceMounted": False,
            },
            evidence=evidence,
            verification="vm-hosted-oci-policy-attested-and-cleanup-checked",
            retryable=False,
            error_code=error_code,
            limitations=self._attestation.limitations,
            failure_cause=(
                FailureCause.NONE
                if status == OutcomeStatus.SUCCEEDED
                else FailureCause.EVIDENCE
                if not cleanup_verified
                else FailureCause.UNKNOWN
            ),
        )

    def _run_argv(self, container_name: str, argv: tuple[str, ...]) -> tuple[str, ...]:
        if not _SANDBOX_NAME.fullmatch(container_name):  # pragma: no cover - generated locally
            raise FormatError("SOVA-OCI-NAME", "invalid generated container name")
        return (
            str(self._docker),
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self._policy.pids_limit),
            "--memory",
            f"{self._policy.memory_bytes}b",
            "--cpus",
            self._policy.cpus,
            "--user",
            "65534:65534",
            "--ipc",
            "private",
            "--log-driver",
            "none",
            "--tmpfs",
            (
                "/tmp:rw,noexec,nosuid,nodev,"  # noqa: S108 - in-container tmpfs mount
                f"size={self._policy.tmpfs_bytes},mode=1777"
            ),
            "--entrypoint",
            argv[0],
            self._image,
            *argv[1:],
        )

    def _cleanup(self, container_name: str) -> bool:
        token = CancellationToken()
        self._runner.run(
            (str(self._docker), "rm", "--force", container_name),
            timeout_seconds=15,
            cancellation=token,
            max_output_bytes=1024 * 1024,
        )
        inspection = self._runner.run(
            (str(self._docker), "inspect", container_name),
            timeout_seconds=10,
            cancellation=token,
            max_output_bytes=1024 * 1024,
        )
        return inspection.state == "completed" and inspection.returncode != 0


def _container_argv(inputs: dict[str, Any]) -> tuple[str, ...]:
    unknown = sorted(set(inputs) - {"argv"})
    if unknown:
        raise FormatError(
            "SOVA-OCI-INPUT",
            "OCI process inputs contain unsupported fields",
            details={"fields": unknown},
        )
    argv = inputs.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > _MAX_ARGS
        or not all(isinstance(value, str) and value and "\x00" not in value for value in argv)
    ):
        raise FormatError("SOVA-OCI-ARGV", "argv must be a bounded non-empty string array")
    if not argv[0].startswith("/") or "\\" in argv[0]:
        raise FormatError(
            "SOVA-OCI-EXECUTABLE",
            "container executable must be an absolute POSIX path",
        )
    if sum(len(value.encode("utf-8")) for value in argv) > _MAX_ARG_BYTES:
        raise FormatError("SOVA-OCI-ARGV", "argv exceeds the 64 KiB encoded budget")
    return tuple(argv)


__all__ = [
    "BoundedDockerCommandRunner",
    "DockerCommandResult",
    "DockerDesktopAttestation",
    "DockerDesktopIsolationPolicy",
    "DockerDesktopOciExecutor",
    "attest_docker_desktop",
    "docker_desktop_backend_descriptor",
]
