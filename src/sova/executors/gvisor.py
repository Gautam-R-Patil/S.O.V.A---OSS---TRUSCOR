# SPDX-License-Identifier: Apache-2.0
"""Fail-closed OCI execution through the gVisor runsc user-space kernel."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

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
from sova.executors.docker_desktop import (
    BoundedDockerCommandRunner,
    DockerCommandRunner,
    DockerDesktopIsolationPolicy,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.safety import BackendDescriptor, IsolationKind, NetworkMode
from sova.safety.containment import ReadinessState

if TYPE_CHECKING:
    from pathlib import Path

_DIGEST_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_CONTAINER_NAME = re.compile(r"^sova-runsc-[a-z0-9]{20}$")
_MAX_ARGS = 256
_MAX_ARG_BYTES = 64 * 1024
_MAX_STDIN_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class GVisorAttestation:
    readiness: str
    runtime: str
    image: str
    runtime_registered: bool
    image_cached: bool
    engine_server_version: str | None
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


def _json(data: bytes, *, code: str) -> Any:
    try:
        return json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FormatError(code, "container engine returned malformed JSON") from error


def attest_gvisor(
    docker_executable: Path,
    image: str,
    *,
    runtime: str = "runsc",
    runner: DockerCommandRunner | None = None,
) -> GVisorAttestation:
    """Attest a registered runsc runtime and exact cached image without pulling."""
    executable = docker_executable.resolve()
    if not executable.is_file():
        raise FormatError("SOVA-GVISOR-DOCKER", "container engine executable must exist")
    if _DIGEST_IMAGE.fullmatch(image) is None:
        raise FormatError("SOVA-GVISOR-IMAGE", "image must be an exact repository@sha256 digest")
    if runtime != "runsc":
        raise FormatError(
            "SOVA-GVISOR-RUNTIME",
            "gVisor isolation requires the Docker runtime name to be exactly runsc",
        )
    command_runner = runner or BoundedDockerCommandRunner()
    cancellation = CancellationToken()
    info = command_runner.run(
        (
            str(executable),
            "info",
            "--format",
            "{{json .Runtimes}}",
        ),
        timeout_seconds=20,
        cancellation=cancellation,
        max_output_bytes=1024 * 1024,
    )
    version = command_runner.run(
        (str(executable), "version", "--format", "{{json .Server.Version}}"),
        timeout_seconds=20,
        cancellation=cancellation,
        max_output_bytes=1024 * 1024,
    )
    image_result = command_runner.run(
        (str(executable), "image", "inspect", image, "--format", "{{json .RepoDigests}}"),
        timeout_seconds=20,
        cancellation=cancellation,
        max_output_bytes=1024 * 1024,
    )
    reasons: list[str] = []
    if info.state != "completed" or info.returncode != 0:
        reasons.append("container-engine-info-unavailable")
    if version.state != "completed" or version.returncode != 0:
        reasons.append("container-engine-version-unavailable")
    if image_result.state != "completed" or image_result.returncode != 0:
        reasons.append("digest-pinned-image-not-cached")
    if reasons:
        return GVisorAttestation(
            readiness="unavailable",
            runtime=runtime,
            image=image,
            runtime_registered=False,
            image_cached=False,
            engine_server_version=None,
            reasons=tuple(reasons),
            limitations=(
                "No runtime installation, daemon reconfiguration, or image pull is attempted.",
                "Static client presence does not establish a live user-kernel boundary.",
            ),
        )
    runtimes = _json(info.stdout, code="SOVA-GVISOR-INFO-JSON")
    server_version = _json(version.stdout, code="SOVA-GVISOR-VERSION-JSON")
    repo_digests = _json(image_result.stdout, code="SOVA-GVISOR-IMAGE-JSON")
    runtime_registered = isinstance(runtimes, dict) and runtime in runtimes
    image_cached = isinstance(repo_digests, list) and image in repo_digests
    if not runtime_registered:
        reasons.append("runsc-runtime-not-registered")
    if not image_cached:
        reasons.append("exact-image-digest-not-confirmed")
    return GVisorAttestation(
        readiness="ready" if not reasons else "degraded",
        runtime=runtime,
        image=image,
        runtime_registered=runtime_registered,
        image_cached=image_cached,
        engine_server_version=server_version if isinstance(server_version, str) else None,
        reasons=tuple(reasons),
        limitations=(
            "gVisor interposes a user-space application kernel; it is not a separate VM kernel.",
            (
                "The host kernel, container engine, runsc binary, and their configuration "
                "remain trusted."
            ),
            (
                "This attestation proves registration and exact image caching, not escape "
                "impossibility."
            ),
            (
                "No host mount, engine socket, network, ambient capability, or real credential "
                "is admitted."
            ),
        ),
    )


def gvisor_backend_descriptor(attestation: GVisorAttestation) -> BackendDescriptor:
    readiness = {
        "ready": ReadinessState.READY,
        "degraded": ReadinessState.DEGRADED,
        "unavailable": ReadinessState.UNAVAILABLE,
    }[attestation.readiness]
    return BackendDescriptor(
        id="sova:backend:gvisor-runsc",
        name="SOVA hardened OCI executor through gVisor runsc",
        isolation=IsolationKind.USER_KERNEL,
        executes_native_code=True,
        network_mode=NetworkMode.NONE,
        disposable=True,
        deterministic_reset=True,
        synthetic_credentials=True,
        post_cleanup_verification=True,
        readiness=readiness,
        protections=(
            "runsc-user-space-kernel",
            "digest-pinned-cached-image",
            "network-none",
            "no-host-mounts-or-engine-socket",
            "read-only-rootfs",
            "non-root-zero-capabilities-no-new-privileges",
            "cpu-memory-pid-bounds",
            f"attestation:{attestation.digest}",
        ),
        limitations=attestation.limitations,
    )


def _container_argv(inputs: dict[str, Any]) -> tuple[str, ...]:
    if not {"argv"} <= set(inputs) <= {"argv", "stdin"}:
        raise FormatError(
            "SOVA-GVISOR-INPUT", "gVisor execution accepts only argv and optional stdin"
        )
    argv = inputs.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > _MAX_ARGS
        or not all(isinstance(item, str) and item and "\x00" not in item for item in argv)
    ):
        raise FormatError("SOVA-GVISOR-ARGV", "argv must be a bounded non-empty string array")
    if not argv[0].startswith("/") or "\\" in argv[0]:
        raise FormatError("SOVA-GVISOR-EXECUTABLE", "executable must be an absolute POSIX path")
    if sum(len(item.encode()) for item in argv) > _MAX_ARG_BYTES:
        raise FormatError("SOVA-GVISOR-ARGV", "argv exceeds 64 KiB")
    return tuple(argv)


def _container_stdin(inputs: dict[str, Any]) -> bytes | None:
    value = inputs.get("stdin")
    if value is None:
        return None
    if not isinstance(value, str):
        raise FormatError("SOVA-GVISOR-STDIN", "stdin must be a UTF-8 string")
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_STDIN_BYTES:
        raise FormatError("SOVA-GVISOR-STDIN", "stdin exceeds the 64 KiB encoded budget")
    return encoded


class GVisorOciExecutor:
    """Run exact container-local argv and optional bounded stdin through runsc."""

    name = "sova-gvisor-runsc"

    def __init__(
        self,
        docker_executable: Path,
        image: str,
        *,
        runtime: str = "runsc",
        policy: DockerDesktopIsolationPolicy | None = None,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        self._docker = docker_executable.resolve()
        self._image = image
        self._runtime = runtime
        self._policy = policy or DockerDesktopIsolationPolicy()
        self._runner = runner or BoundedDockerCommandRunner()
        self._attestation = attest_gvisor(
            self._docker,
            image,
            runtime=runtime,
            runner=self._runner,
        )

    @property
    def attestation(self) -> GVisorAttestation:
        return self._attestation

    def reattest(self) -> GVisorOciExecutor:
        """Return a fresh executor after rechecking the same engine, image, and runtime."""
        return GVisorOciExecutor(
            self._docker,
            self._image,
            runtime=self._runtime,
            policy=self._policy,
            runner=self._runner,
        )

    def capabilities(self) -> tuple[Capability, ...]:
        if not self._attestation.ready:
            return ()
        return (
            Capability(
                name="process.exec",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("stdout", "stderr", "returncode", "gvisor-attestation"),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        if request.action != "process.exec":
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-GVISOR-UNSUPPORTED",
            )
        if not self._attestation.ready:
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {"attestationDigest": self._attestation.digest},
                error_code="SOVA-GVISOR-NOT-ATTESTED",
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
        stdin_data = _container_stdin(request.inputs)
        name = f"sova-runsc-{uuid.uuid4().hex[:20]}"
        result = self._runner.run(
            self._run_argv(name, argv, stdin_enabled=stdin_data is not None),
            timeout_seconds=min(request.timeout_seconds, self._policy.max_runtime_seconds),
            cancellation=cancellation,
            max_output_bytes=self._policy.max_output_bytes,
            stdin_data=stdin_data,
        )
        cleanup = self._cleanup(name)
        status = {
            "completed": OutcomeStatus.SUCCEEDED
            if result.returncode == 0
            else OutcomeStatus.FAILED,
            "timeout": OutcomeStatus.TIMEOUT,
            "cancelled": OutcomeStatus.CANCELLED,
            "output-limit": OutcomeStatus.PARTIAL,
            "start-failed": OutcomeStatus.FAILED,
        }.get(result.state, OutcomeStatus.FAILED)
        if not cleanup:
            status = OutcomeStatus.PARTIAL
        stdout = result.stdout[: self._policy.max_output_bytes]
        stderr = result.stderr[: self._policy.max_output_bytes]
        return ActionOutcome(
            request_id=request.id,
            status=status,
            side_effect=SideEffect.MUTATE,
            output={
                "returncode": result.returncode,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "runtime": self._runtime,
                "attestationDigest": self._attestation.digest,
                "cleanupVerified": cleanup,
                "networkMode": "none",
                "hostWorkspaceMounted": False,
            },
            evidence=(
                EvidenceReference("stdout", "text/plain", sha256_digest(stdout), len(stdout)),
                EvidenceReference("stderr", "text/plain", sha256_digest(stderr), len(stderr)),
                EvidenceReference(
                    "gvisor-attestation",
                    "application/json",
                    self._attestation.digest,
                    len(canonical_json_bytes(self._attestation.to_mapping())),
                ),
            ),
            verification="runsc-user-kernel-policy-attested-and-cleanup-checked",
            retryable=False,
            error_code=(None if status == OutcomeStatus.SUCCEEDED else "SOVA-GVISOR-EXECUTION"),
            limitations=self._attestation.limitations,
            failure_cause=(
                FailureCause.NONE if status == OutcomeStatus.SUCCEEDED else FailureCause.EXECUTOR
            ),
        )

    def _run_argv(
        self,
        name: str,
        argv: tuple[str, ...],
        *,
        stdin_enabled: bool,
    ) -> tuple[str, ...]:
        if _CONTAINER_NAME.fullmatch(name) is None:  # pragma: no cover - generated locally
            raise FormatError("SOVA-GVISOR-NAME", "generated container name is invalid")
        return (
            str(self._docker),
            "run",
            *(("--interactive",) if stdin_enabled else ()),
            "--rm",
            "--pull",
            "never",
            "--runtime",
            self._runtime,
            "--name",
            name,
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
                f"/tmp:rw,noexec,nosuid,nodev,size={self._policy.tmpfs_bytes},mode=1777"  # noqa: S108 - isolated in-container tmpfs
            ),
            "--entrypoint",
            argv[0],
            self._image,
            *argv[1:],
        )

    def _cleanup(self, name: str) -> bool:
        token = CancellationToken()
        self._runner.run(
            (str(self._docker), "rm", "--force", name),
            timeout_seconds=15,
            cancellation=token,
            max_output_bytes=1024 * 1024,
        )
        absence = self._runner.run(
            (
                str(self._docker),
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.Names}}",
            ),
            timeout_seconds=10,
            cancellation=token,
            max_output_bytes=1024 * 1024,
        )
        # A failed ``inspect`` cannot distinguish an absent container from an
        # unavailable daemon.  A successful filtered listing proves both that
        # the daemon answered and that the exact generated name is absent.
        return (
            absence.state == "completed" and absence.returncode == 0 and not absence.stdout.strip()
        )


__all__ = [
    "GVisorAttestation",
    "GVisorOciExecutor",
    "attest_gvisor",
    "gvisor_backend_descriptor",
]
