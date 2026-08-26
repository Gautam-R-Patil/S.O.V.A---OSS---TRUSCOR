# SPDX-License-Identifier: Apache-2.0
"""Authorization-gated, phase-owned local software executor-engine runtime."""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import signal
import subprocess
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sova.community.executor_engine import (
    CodecFactory,
    EnginePhaseGeneration,
    EngineSurfaceGeneration,
    ExecutorEngineRuntime,
    SurfaceFactory,
    capture_workspace_seed_digest,
)
from sova.community.executor_surfaces import (
    ExactProcessSurfaceSpec,
    computer_codec_factory,
    melra_computer_surface_generation,
    process_codec_factory,
    process_surface_generation,
    workspace_codec_factory,
    workspace_surface_generation,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.environment_builder import TargetEnvironmentAdmission
from sova.runtime.software_target import (
    SoftwareTargetAttestation,
    attest_software_target,
    wait_for_owned_window,
)
from sova.safety import ControlProof, ControlProofMethod
from sova.targets import TargetKind, TargetManifest, validate_target_manifest

if TYPE_CHECKING:
    from pathlib import Path

    from sova.runtime.window_recording import SoftwareWindowRecordingCoordinator

_MAX_LAUNCH_ARGS = 64
_MAX_LAUNCH_ARG_BYTES = 4096
_MAX_STARTUP_TIMEOUT_SECONDS = 120.0
_SAFE_ENV_KEYS = (
    "COMSPEC",
    "LANG",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
)
_COMPUTER_CODEC_ID = "sova.action-codec.computer/0.1.0"
_WORKSPACE_CODEC_ID = "sova.action-codec.workspace/0.1.0"
_PROCESS_CODEC_ID = "sova.action-codec.process/0.1.0"
_SHA256_DIGEST_LENGTH = 71

SoftwareComputerSurfaceFactory = Callable[[SoftwareTargetAttestation, str], EngineSurfaceGeneration]


def _additional_surfaces(
    factory: SurfaceFactory,
    phase: str,
    expected_digest: str,
) -> tuple[EngineSurfaceGeneration, ...]:
    value = factory(phase)
    valid_shape = (
        isinstance(value, tuple)
        and bool(value)
        and all(type(item) is EngineSurfaceGeneration for item in value)
    )
    actual_digest = (
        sha256_digest(
            canonical_json_bytes(
                [
                    item.contract_mapping()
                    for item in sorted(value, key=lambda item: item.sensor_name)
                ]
            )
        )
        if valid_shape
        else None
    )
    if not valid_shape or actual_digest != expected_digest:
        if isinstance(value, tuple):
            for surface in reversed(value):
                if type(surface) is EngineSurfaceGeneration:
                    with suppress(Exception):
                        surface.close()
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-SURFACE-SUBSTITUTION",
            "additional software runtime surfaces differ from their admitted contract",
        )
    return value


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def local_software_authority_target(target: TargetManifest) -> str:
    """Return the narrow authorization subject for one local software manifest."""
    if (
        type(target) is not TargetManifest
        or target.kind is not TargetKind.LOCAL_PROCESS
        or not validate_target_manifest(target)["accepted"]
    ):
        raise FormatError(
            "SOVA-SOFTWARE-CONTROL-PROOF",
            "local software authority requires one conformant local-process target",
        )
    return f"sova:local-software:{target.digest[7:31]}"


def create_local_software_control_proof(
    target: TargetManifest,
    executable: Path,
    *,
    workspace_seed: Path | None = None,
) -> ControlProof:
    """Capture a short-lived proof bound to the exact local software inputs."""
    subject = local_software_authority_target(target)
    try:
        resolved = executable.resolve(strict=True)
    except OSError as error:
        raise FormatError(
            "SOVA-SOFTWARE-CONTROL-PROOF",
            "software proof executable is unavailable",
        ) from error
    if resolved.is_symlink() or not resolved.is_file():
        raise FormatError(
            "SOVA-SOFTWARE-CONTROL-PROOF",
            "software proof executable must be one real regular file",
        )
    now = datetime.now(UTC)
    challenge = "sova-local-control:" + secrets.token_urlsafe(18)
    return ControlProof(
        ControlProofMethod.LOCAL_POSSESSION,
        subject,
        challenge,
        {
            "challenge": challenge,
            "operatorAssertion": True,
            "executableDigest": _digest_file(resolved),
            "workspaceFingerprint": capture_workspace_seed_digest(workspace_seed),
            "targetDigest": target.digest,
            "legalAuthorityIndependentlyVerified": False,
        },
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.local-software-control/0.1",
    )


@dataclass(frozen=True, slots=True)
class SoftwareLaunchSpec:
    """Exact non-shell launch contract for one authorized local application."""

    executable: Path
    argv: tuple[str, ...] = ()
    window_required: bool = False
    window_title_contains: str | None = None
    startup_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        try:
            executable = self.executable.resolve(strict=True)
        except OSError as error:
            raise FormatError(
                "SOVA-SOFTWARE-ENGINE-LAUNCH",
                "software launch executable is unavailable",
            ) from error
        if executable.is_symlink() or not executable.is_file():
            raise FormatError(
                "SOVA-SOFTWARE-ENGINE-LAUNCH",
                "software launch executable must be one real regular file",
            )
        if (
            not isinstance(self.argv, tuple)
            or len(self.argv) > _MAX_LAUNCH_ARGS
            or any(
                not isinstance(item, str)
                or not item
                or "\x00" in item
                or len(item.encode("utf-8")) > _MAX_LAUNCH_ARG_BYTES
                for item in self.argv
            )
            or not isinstance(self.window_required, bool)
            or (self.window_title_contains is not None and not self.window_required)
            or isinstance(self.startup_timeout_seconds, bool)
            or not isinstance(self.startup_timeout_seconds, (int, float))
            or not 0 < self.startup_timeout_seconds <= _MAX_STARTUP_TIMEOUT_SECONDS
        ):
            raise FormatError(
                "SOVA-SOFTWARE-ENGINE-LAUNCH",
                "software launch argv, window selector, or startup budget is malformed",
            )


@dataclass(slots=True)
class _OwnedSoftwareProcess:
    process: subprocess.Popen[bytes]

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.kill(-self.process.pid, signal.SIGTERM)
            else:
                self.process.terminate()
            self.process.wait(timeout=3)
        except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=3)


@dataclass(slots=True)
class _SoftwarePhaseCloser:
    target: _OwnedSoftwareProcess
    recording: Any | None = None

    def close(self) -> None:
        failures = 0
        if self.recording is not None:
            try:
                self.recording.close()
            except Exception:  # noqa: BLE001 - aggregate cleanup without leaking target data
                failures += 1
        try:
            self.target.close()
        except Exception:  # noqa: BLE001 - aggregate cleanup without leaking target data
            failures += 1
        if failures:
            raise FormatError(
                "SOVA-SOFTWARE-ENGINE-CLEANUP",
                "software target or its exact-window recorder could not be closed",
            )


def _launch_environment() -> dict[str, str]:
    return {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}


def _launch(spec: SoftwareLaunchSpec, workspace: Path) -> _OwnedSoftwareProcess:
    creation_flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    try:
        process = subprocess.Popen(  # noqa: S603 - exact executable/argv; shell is false
            [str(spec.executable.resolve()), *spec.argv],
            cwd=workspace,
            env=_launch_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creation_flags if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
    except OSError as error:
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-LAUNCH",
            "the admitted software target could not be launched",
        ) from error
    owned = _OwnedSoftwareProcess(process)
    if process.poll() is not None:
        owned.close()
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-LAUNCH",
            "the admitted software target exited before identity measurement",
        )
    return owned


def melra_software_computer_surface_factory(
    *,
    node_executable: Path,
    cli_entrypoint: Path,
    policy_factory: Callable[[Path], Path],
    mutations: tuple[str, ...] = ("computer.click", "computer.type"),
) -> SoftwareComputerSurfaceFactory:
    """Bind a fresh MELRA surface only to the newly measured phase window."""

    def factory(
        attestation: SoftwareTargetAttestation,
        identity_digest: str,
    ) -> EngineSurfaceGeneration:
        if attestation.window_id is None or attestation.window_handle_digest is None:
            raise FormatError(
                "SOVA-SOFTWARE-ENGINE-COMPUTER",
                "computer surface requires one measured target-owned window",
            )
        attestation.assert_still_live()
        return melra_computer_surface_generation(
            node_executable=node_executable,
            cli_entrypoint=cli_entrypoint,
            policy_factory=policy_factory,
            identity_digest=identity_digest,
            pid=attestation.pid,
            window_id=attestation.window_id,
            mutations=mutations,
        )

    return factory


def build_authorized_software_runtime(  # noqa: PLR0913, PLR0915
    target: TargetManifest,
    launch: SoftwareLaunchSpec,
    *,
    workspace_parent: Path,
    workspace_seed: Path | None = None,
    process_templates: Sequence[ExactProcessSurfaceSpec] = (),
    computer_surface_factory: SoftwareComputerSurfaceFactory | None = None,
    window_recording: SoftwareWindowRecordingCoordinator | None = None,
    additional_surface_factory: SurfaceFactory | None = None,
    additional_codec_factories: dict[str, CodecFactory] | None = None,
    additional_surface_contract_digest: str | None = None,
) -> ExecutorEngineRuntime:
    """Build a two-phase runtime that launches and measures the target itself.

    Authorization remains the responsibility of `run_executor_engine_document`;
    constructing this runtime alone performs no launch. Every environment call
    gets a clean workspace, a new process, an optional unambiguous owned window,
    fresh executor surfaces, and deterministic cleanup.
    """
    if (
        type(target) is not TargetManifest
        or target.kind is not TargetKind.LOCAL_PROCESS
        or not validate_target_manifest(target)["accepted"]
        or type(launch) is not SoftwareLaunchSpec
        or not isinstance(process_templates, Sequence)
        or len(process_templates) > 1
        or any(type(item) is not ExactProcessSurfaceSpec for item in process_templates)
        or (
            launch.window_required
            != (computer_surface_factory is not None or window_recording is not None)
        )
        or ((additional_surface_factory is None) != (additional_codec_factories is None))
        or ((additional_surface_factory is None) != (additional_surface_contract_digest is None))
        or (
            additional_surface_factory is not None
            and (
                not callable(additional_surface_factory)
                or not additional_codec_factories
                or not isinstance(additional_surface_contract_digest, str)
                or len(additional_surface_contract_digest) != _SHA256_DIGEST_LENGTH
                or not additional_surface_contract_digest.startswith("sha256:")
            )
        )
    ):
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-CONTRACT",
            "software runtime requires a conformant local target and matching UI surface",
        )
    templates = tuple(process_templates)
    template_ids = [item.identifier for item in templates]
    if len(template_ids) != len(set(template_ids)):
        raise FormatError(
            "SOVA-SOFTWARE-ENGINE-CONTRACT",
            "software process template identifiers must be unique",
        )
    executable = launch.executable.resolve(strict=True)
    executable_digest = _digest_file(executable)
    workspace_seed_digest = capture_workspace_seed_digest(workspace_seed)
    authority_target = local_software_authority_target(target)

    def validate_runtime_control_proof(proof: ControlProof) -> None:
        if proof.method is ControlProofMethod.SANDBOX:
            if not proof.subject.startswith("sova:sandbox:"):
                raise FormatError(
                    "SOVA-SOFTWARE-CONTROL-PROOF",
                    "sandbox software proof subject is not sandbox-scoped",
                )
            return
        evidence = proof.evidence
        if (
            proof.method is not ControlProofMethod.LOCAL_POSSESSION
            or proof.subject != authority_target
            or evidence.get("executableDigest") != executable_digest
            or evidence.get("workspaceFingerprint") != workspace_seed_digest
            or evidence.get("targetDigest") != target.digest
        ):
            raise FormatError(
                "SOVA-SOFTWARE-CONTROL-PROOF",
                "software proof is not bound to this exact target, executable, and workspace",
            )

    containment = {
        "backend": "phase-owned-host-process",
        "workspace": "credential-stripped-disposable-copy",
        "originalWorkspaceMutationAllowed": False,
        "networkIsolation": False,
        "filesystemIsolation": False,
        "securitySandbox": False,
    }
    containment_digest = sha256_digest(canonical_json_bytes(containment))
    identity_digest = sha256_digest(
        canonical_json_bytes(
            {
                "targetDigest": target.digest,
                "executableDigest": executable_digest,
                "argv": list(launch.argv),
                "windowRequired": launch.window_required,
                "windowTitleSelectorDigest": (
                    None
                    if launch.window_title_contains is None
                    else sha256_digest(launch.window_title_contains.encode("utf-8"))
                ),
            }
        )
    )
    stable_target_contract_digest = sha256_digest(
        canonical_json_bytes(
            {
                "targetDigest": target.digest,
                "executableDigest": executable_digest,
                "identityDigest": identity_digest,
                "containmentDigest": containment_digest,
                "additionalSurfaceContractDigest": additional_surface_contract_digest,
            }
        )
    )
    codec_factories: dict[str, CodecFactory] = {_WORKSPACE_CODEC_ID: workspace_codec_factory()}
    if computer_surface_factory is not None:
        codec_factories[_COMPUTER_CODEC_ID] = computer_codec_factory()
    for template in templates:
        codec_factories[_PROCESS_CODEC_ID] = process_codec_factory(template)
    for identifier, factory in (additional_codec_factories or {}).items():
        if identifier in codec_factories or not identifier or not callable(factory):
            raise FormatError(
                "SOVA-SOFTWARE-ENGINE-CODEC",
                "additional runtime attempted to replace or malformed a built-in codec",
            )
        codec_factories[identifier] = factory

    def phase_factory(phase: str, workspace: Path) -> EnginePhaseGeneration:
        owned = _launch(launch, workspace)
        recording_session: Any | None = None
        surfaces: list[EngineSurfaceGeneration] = []
        try:
            window_id = (
                wait_for_owned_window(
                    owned.process.pid,
                    title_contains=launch.window_title_contains,
                    timeout_seconds=launch.startup_timeout_seconds,
                )
                if launch.window_required
                else None
            )
            attestation = attest_software_target(
                executable,
                pid=owned.process.pid,
                window_id=window_id,
            )
            if window_recording is not None:
                recording_session = window_recording.start(phase, attestation)
            environment_digest = sha256_digest(
                canonical_json_bytes(
                    {
                        "platform": platform.platform(),
                        "python": platform.python_version(),
                        "executableDigest": executable_digest,
                    }
                )
            )
            admission = TargetEnvironmentAdmission(
                instance_id=f"software:{phase}:{attestation.generation_digest[7:31]}",
                target_manifest_digest=target.digest,
                environment_digest=environment_digest,
                containment_digest=containment_digest,
                identity_digest=identity_digest,
                clock_domain="clock:software-engine",
                process_id=attestation.pid,
                process_start_digest=attestation.process_start_digest,
                window_handle_digest=attestation.window_handle_digest,
            )
            surfaces.append(workspace_surface_generation())
            surfaces.extend(process_surface_generation(item) for item in templates)
            if computer_surface_factory is not None:
                surfaces.append(computer_surface_factory(attestation, identity_digest))
            if (
                additional_surface_factory is not None
                and additional_surface_contract_digest is not None
            ):
                surfaces.extend(
                    _additional_surfaces(
                        additional_surface_factory,
                        phase,
                        additional_surface_contract_digest,
                    )
                )
            return EnginePhaseGeneration(
                admission,
                tuple(surfaces),
                stable_target_contract_digest,
                _SoftwarePhaseCloser(owned, recording_session).close,
            )
        except BaseException as error:
            for surface in reversed(surfaces):
                with suppress(Exception):
                    surface.close()
            try:
                _SoftwarePhaseCloser(owned, recording_session).close()
            except Exception as cleanup_error:
                raise cleanup_error from error
            raise

    runtime = ExecutorEngineRuntime(
        codec_factories=codec_factories,
        phase_surface_factory=phase_factory,
        workspace_parent=workspace_parent,
        workspace_seed=workspace_seed,
        control_proof_validator=validate_runtime_control_proof,
    )
    if runtime.seed_digest != workspace_seed_digest:
        raise FormatError(
            "SOVA-SOFTWARE-CONTROL-PROOF",
            "workspace seed changed while the authorized runtime was constructed",
        )
    return runtime


__all__ = [
    "SoftwareComputerSurfaceFactory",
    "SoftwareLaunchSpec",
    "build_authorized_software_runtime",
    "create_local_software_control_proof",
    "local_software_authority_target",
    "melra_software_computer_surface_factory",
]
