# SPDX-License-Identifier: Apache-2.0
"""Full-capability authorized run: browser + workspace + authorized computer
and one reviewed host-process (terminal) surface, composed over the live web
engine.

This module adds no new execution machinery.  It assembles the additional
computer and/or process surfaces `run_live_web_executor_engine` already
accepts through `additional_surface_factory`/`additional_codec_factories`/
`additional_surface_contract_digest`, and pins their contract digest so the
engine's reproduction phase can detect substitution exactly as it does for
browser/workspace.  Planners still only ever see redacted observations and
declarative grants for whichever surfaces the operator's chamber document
actually grants -- adding a computer or process spec here does not by itself
expose it to any participant.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from sova.community.executor_surfaces import (
    ExactProcessSurfaceSpec,
    computer_codec_factory,
    melra_computer_surface_generation,
    process_codec_factory,
    process_surface_generation,
)
from sova.community.live_executor_engine import run_live_web_executor_engine
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import ReviewedComputerTarget
from sova.runtime.native_windows_computer import (
    native_windows_computer_surface_factory,
    native_windows_discovery_surface_factory,
)
from sova.runtime.software_target import SoftwareTargetAttestation
from sova.runtime.window_recording import SoftwareWindowRecordingCoordinator
from sova.safety import ControlProof, ControlProofMethod, validate_control_proof
from sova.targets import TargetKind, TargetManifest, validate_target_manifest

from .executor_engine import capture_workspace_seed_digest
from .software_executor_engine import local_software_authority_target

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.community.executor_chamber import (
        ActionAdmissionHook,
        ApprovalPrompt,
        CoordinationContextProvider,
        ExecutorChamberArtifacts,
    )
    from sova.community.executor_engine import CodecFactory, EngineSurfaceGeneration
    from sova.live.semantic_workflow import SemanticBrowserMission
    from sova.runtime import RoleModel

_COMPUTER_CODEC_ID = "sova.action-codec.computer/0.1.0"
_PROCESS_CODEC_ID = "sova.action-codec.process/0.1.0"
_DEFAULT_COMPUTER_MUTATIONS: tuple[str, ...] = ("computer.click", "computer.type")
#: Full-capability composition never accepts a browser profile lease, so the
#: underlying engine's own identity-digest formula always resolves to this mode.
_EPHEMERAL_BROWSER_MODE = "ephemeral-browser"


@dataclass(frozen=True, slots=True)
class LocalComputerAuthorization:
    """Independent authorization for one externally attached software window.

    The website proof cannot authorize an unrelated desktop process.  A full
    composition therefore requires a second local-process manifest and a fresh
    local-possession proof bound to the exact executable, target manifest, and
    disposable workspace seed.  The measured process/window generation is
    carried beside that proof and checked again before every surface build.
    """

    software_target: TargetManifest
    control_proof: ControlProof
    target_attestation: SoftwareTargetAttestation

    def __post_init__(self) -> None:
        if (
            type(self.software_target) is not TargetManifest
            or self.software_target.kind is not TargetKind.LOCAL_PROCESS
            or not validate_target_manifest(self.software_target)["accepted"]
            or type(self.control_proof) is not ControlProof
            or type(self.target_attestation) is not SoftwareTargetAttestation
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER-AUTH",
                "computer use requires an exact local-process manifest, control proof, "
                "and measured software target attestation",
            )
        if (
            self.target_attestation.window_id is None
            or self.target_attestation.window_handle_digest is None
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER-AUTH",
                "computer use requires an OS-verified live window owned by the target process",
            )

    def validate(self, workspace_seed: Path | None) -> _ValidatedComputerAuthorization:
        """Validate the current proof and return its inert signed-observation binding."""
        authority_target = local_software_authority_target(self.software_target)
        proof_ok, proof_reasons = validate_control_proof(
            self.control_proof,
            target=authority_target,
        )
        evidence = self.control_proof.evidence
        workspace_fingerprint = capture_workspace_seed_digest(workspace_seed)
        binding_ok = (
            self.control_proof.method is ControlProofMethod.LOCAL_POSSESSION
            and evidence.get("targetDigest") == self.software_target.digest
            and evidence.get("executableDigest") == self.target_attestation.executable_digest
            and evidence.get("workspaceFingerprint") == workspace_fingerprint
        )
        if not proof_ok or not binding_ok:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER-AUTH",
                "computer control proof is not current and bound to the exact software "
                "target, executable, and workspace seed",
                details={"proofReasons": list(proof_reasons)},
            )
        self.target_attestation.assert_still_live()
        document = {
            "artifactType": "sova.composed-computer-authorization",
            "schemaVersion": "0.1.0",
            "status": "verified-local-possession",
            "softwareTargetManifestDigest": self.software_target.digest,
            "controlProofDigest": self.control_proof.digest,
            "controlProofMethod": self.control_proof.method.value,
            "softwareTargetAttestationDigest": self.target_attestation.digest,
            "workspaceFingerprint": workspace_fingerprint,
        }
        return _ValidatedComputerAuthorization(
            document,
            sha256_digest(canonical_json_bytes(document)),
        )


@dataclass(frozen=True, slots=True)
class _ValidatedComputerAuthorization:
    document: dict[str, Any]
    digest: str


@dataclass(frozen=True, slots=True)
class MelraComputerBackendSpec:
    """Everything needed to launch one reviewed MELRA computer window.

    There is deliberately no `identity_digest` field here: in a composed run
    the computer surface binds to the *session's* shared identity, which only
    `run_full_capability_web_engine` can compute (it mirrors
    `run_live_web_executor_engine`'s own formula) -- an operator-supplied value
    would just be one more way to get the binding wrong.
    """

    node_executable: Path
    cli_entrypoint: Path
    policy_factory: Callable[[Path], Path]
    authorization: LocalComputerAuthorization
    mutations: tuple[str, ...] = _DEFAULT_COMPUTER_MUTATIONS

    def __post_init__(self) -> None:
        if not callable(self.policy_factory):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER",
                "MELRA computer backend spec requires a callable policy factory",
            )
        if type(self.authorization) is not LocalComputerAuthorization:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER",
                "MELRA computer use requires independent local software authorization",
            )

    @property
    def target_attestation(self) -> SoftwareTargetAttestation:
        return self.authorization.target_attestation


@dataclass(frozen=True, slots=True)
class NativeWindowsComputerBackendSpec:
    """Exact-HWND native Windows backend with reviewed or dynamic controls."""

    authorization: LocalComputerAuthorization
    reviewed_targets: tuple[ReviewedComputerTarget, ...] | None = None
    discover_controls: bool = False

    def __post_init__(self) -> None:
        reviewed = self.reviewed_targets
        if (
            type(self.authorization) is not LocalComputerAuthorization
            or not isinstance(self.discover_controls, bool)
            or (reviewed is None) != self.discover_controls
            or (
                reviewed is not None
                and (
                    not isinstance(reviewed, tuple)
                    or not reviewed
                    or any(type(item) is not ReviewedComputerTarget for item in reviewed)
                )
            )
        ):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-NATIVE-COMPUTER",
                "native Windows computer use requires independent authorization and exactly "
                "one reviewed target map or dynamic owned-control discovery",
            )

    @property
    def target_attestation(self) -> SoftwareTargetAttestation:
        return self.authorization.target_attestation


ComputerBackendSpec = MelraComputerBackendSpec | NativeWindowsComputerBackendSpec


def _session_identity_digest(target_digest: str) -> str:
    """Mirror `run_live_web_executor_engine`'s identity-digest formula exactly.

    That engine computes `identity_digest` internally from the target digest,
    profile evidence, and browser mode, then binds every surface's session to
    it.  Full-capability composition never supplies a profile lease, so
    `profile` is always `None` and `mode` is always `"ephemeral-browser"`;
    reproducing the formula here lets the composed computer surface bind to
    the exact same session identity without either module needing to expose
    or duplicate the other's internals beyond this one pinned contract.
    """
    return sha256_digest(
        canonical_json_bytes(
            {"targetDigest": target_digest, "profile": None, "mode": _EPHEMERAL_BROWSER_MODE}
        )
    )


def _build_additional(
    computer: ComputerBackendSpec | None,
    process_template: ExactProcessSurfaceSpec | None,
    *,
    identity_digest: str | None,
    computer_authorization: _ValidatedComputerAuthorization | None,
) -> tuple[EngineSurfaceGeneration, ...]:
    surfaces: list[EngineSurfaceGeneration] = []
    if computer is not None:
        if identity_digest is None or computer_authorization is None:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER",
                "a computer surface requires its session identity digest and authorization binding",
            )
        computer.target_attestation.assert_still_live()
        window_id = computer.target_attestation.window_id
        if window_id is None:  # guarded by the exact spec constructor
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-COMPUTER",
                "the measured software target no longer has an admitted window",
            )
        if isinstance(computer, MelraComputerBackendSpec):
            generation = melra_computer_surface_generation(
                node_executable=computer.node_executable,
                cli_entrypoint=computer.cli_entrypoint,
                policy_factory=computer.policy_factory,
                identity_digest=identity_digest,
                pid=computer.target_attestation.pid,
                window_id=window_id,
                mutations=computer.mutations,
            )
        else:
            factory = (
                native_windows_discovery_surface_factory()
                if computer.discover_controls
                else native_windows_computer_surface_factory(computer.reviewed_targets or ())
            )
            generation = factory(computer.target_attestation, identity_digest)
        original_observe = generation.observe
        authorization_document = computer_authorization.document

        def observe() -> dict[str, Any]:
            observed = original_observe()
            if not isinstance(observed, dict):
                observed = dict(observed)
            return {
                **observed,
                "targetAuthorization": authorization_document,
            }

        authorization_resource = f"computer-authorization:{computer_authorization.digest}"
        generation = replace(
            generation,
            backend=replace(
                generation.backend,
                affinity_resources=tuple(
                    sorted((*generation.backend.affinity_resources, authorization_resource))
                ),
            ),
            observe=observe,
        )
        surfaces.append(generation)
    if process_template is not None:
        surfaces.append(process_surface_generation(process_template))
    return tuple(surfaces)


def _close_all(surfaces: tuple[EngineSurfaceGeneration, ...]) -> None:
    failures = 0
    for surface in reversed(surfaces):
        try:
            surface.close()
        except Exception:  # noqa: BLE001 - private adapter details remain hidden
            failures += 1
    if failures:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-FULL-CLEANUP",
            "one or more full-capability probe surfaces could not be closed",
        )


def _contract_digest(
    computer: ComputerBackendSpec | None,
    process_template: ExactProcessSurfaceSpec | None,
    *,
    identity_digest: str | None,
    computer_authorization: _ValidatedComputerAuthorization | None,
) -> str:
    """Build the additional-surface contract digest from a throwaway generation.

    Every input to `_build_additional` is fixed data (paths, digests, ints, an
    immutable spec) so a never-launched probe build produces the exact same
    contract every subsequent phase produces; the probe is closed immediately
    without ever starting a process.
    """
    representative = _build_additional(
        computer,
        process_template,
        identity_digest=identity_digest,
        computer_authorization=computer_authorization,
    )
    try:
        return sha256_digest(
            canonical_json_bytes(
                [
                    surface.contract_mapping()
                    for surface in sorted(representative, key=lambda item: item.sensor_name)
                ]
            )
        )
    finally:
        _close_all(representative)


def run_full_capability_web_engine(  # noqa: PLR0913, PLR0915 - explicit trust/lifecycle inputs
    target: TargetManifest,
    mission: SemanticBrowserMission,
    chamber_document: dict[str, Any],
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    control_proof: ControlProof | None = None,
    external_models: Mapping[str, RoleModel] | None = None,
    computer: ComputerBackendSpec | None = None,
    process_template: ExactProcessSurfaceSpec | None = None,
    offensive: bool = False,
    headless: bool = True,
    record_video: bool = False,
    record_computer_screen: bool = False,
    computer_recording_interval_seconds: float = 0.5,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    workspace_parent: Path | None = None,
    workspace_seed: Path | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
    coordination_context_provider: CoordinationContextProvider | None = None,
    action_admission_hook: ActionAdmissionHook | None = None,
) -> ExecutorChamberArtifacts:
    """Run the live web engine with browser + workspace plus computer and/or
    process surfaces added, under the exact same proof-of-control gate.

    At least one of `computer` or `process_template` is required; a run with
    neither is just `run_live_web_executor_engine` and should call that
    directly.  Authorization, offensive declaration, and proof-of-control are
    unchanged from the underlying engine -- full capability changes what an
    already-authorized agent may do, never whether authorization is required.
    """
    if computer is None and process_template is None:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-FULL",
            "full-capability run requires at least one of a computer or process "
            "surface; use run_live_web_executor_engine for browser+workspace only",
        )
    if type(computer) not in (
        type(None),
        MelraComputerBackendSpec,
        NativeWindowsComputerBackendSpec,
    ) or type(process_template) not in (type(None), ExactProcessSurfaceSpec):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-FULL",
            "full-capability computer/process inputs must use their exact declared types",
        )
    if type(record_computer_screen) is not bool:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-FULL-RECORDING",
            "computer recording control must be an exact boolean",
        )
    if record_computer_screen and computer is None:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-FULL-RECORDING",
            "computer recording requires one independently authorized computer surface",
        )

    codec_factories: dict[str, CodecFactory] = {}
    if computer is not None:
        codec_factories[_COMPUTER_CODEC_ID] = computer_codec_factory(sensor_name="computer")
    if process_template is not None:
        codec_factories[_PROCESS_CODEC_ID] = process_codec_factory(process_template)

    identity_digest = _session_identity_digest(target.digest) if computer is not None else None
    computer_authorization = (
        None if computer is None else computer.authorization.validate(workspace_seed)
    )
    process_id = computer.target_attestation.pid if computer is not None else None
    process_start_digest = (
        computer.target_attestation.process_start_digest if computer is not None else None
    )
    window_handle_digest = (
        computer.target_attestation.window_handle_digest if computer is not None else None
    )
    contract_digest = _contract_digest(
        computer,
        process_template,
        identity_digest=identity_digest,
        computer_authorization=computer_authorization,
    )
    computer_recordings = (
        SoftwareWindowRecordingCoordinator(
            destination,
            interval_seconds=computer_recording_interval_seconds,
        )
        if record_computer_screen
        else None
    )

    def additional_surface_factory(phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        recording = (
            None
            if computer_recordings is None or computer is None
            else computer_recordings.start(phase, computer.target_attestation)
        )
        try:
            generated = _build_additional(
                computer,
                process_template,
                identity_digest=identity_digest,
                computer_authorization=computer_authorization,
            )
        except Exception:
            if recording is not None:
                recording.close()
            raise
        if recording is None:
            return generated
        computer_indexes = [
            index for index, surface in enumerate(generated) if surface.sensor_name == "computer"
        ]
        if len(computer_indexes) != 1:  # pragma: no cover - exact composition invariant
            _close_all(generated)
            recording.close()
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-RECORDING",
                "computer recording could not bind exactly one computer surface",
            )
        index = computer_indexes[0]
        original = generated[index]

        def close_recorded_surface() -> None:
            surface_error: Exception | None = None
            try:
                original.close()
            except Exception as error:  # noqa: BLE001 - preserve adapter cleanup failure
                surface_error = error
            try:
                recording.close()
            except Exception as error:
                if surface_error is None:
                    raise
                raise surface_error from error
            if surface_error is not None:
                raise surface_error

        return (
            *generated[:index],
            replace(original, close=close_recorded_surface),
            *generated[index + 1 :],
        )

    def observed(channel: str, event: dict[str, Any]) -> None:
        if computer_recordings is not None:
            computer_recordings.observe(channel, event)
        if event_observer is not None:
            event_observer(channel, event)

    def computer_recording_attachments() -> Mapping[str, bytes]:
        if computer_recordings is None:
            return {}
        original = computer_recordings.attachments()
        names = {
            "visual-replay-01.sovaframes": "computer-visual-replay-01.sovaframes",
            "replay-cues.json": "computer-replay-cues.json",
            "reproduction-visual-replay-01.sovaframes": (
                "reproduction-computer-visual-replay-01.sovaframes"
            ),
            "reproduction-replay-cues.json": "reproduction-computer-replay-cues.json",
        }
        if set(original) != set(names):  # pragma: no cover - coordinator contract invariant
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-FULL-RECORDING",
                "computer recording coordinator returned an unexpected evidence set",
            )
        return {names[name]: data for name, data in original.items()}

    artifacts = run_live_web_executor_engine(
        target,
        mission,
        chamber_document,
        destination,
        package_runner=package_runner,
        browser_executable=browser_executable,
        approval_prompt=approval_prompt,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        target_observation_disclosure_authorized=target_observation_disclosure_authorized,
        control_proof=control_proof,
        external_models=external_models,
        offensive=offensive,
        headless=headless,
        record_video=record_video,
        package_cache=package_cache,
        browser_cache=browser_cache,
        workspace_parent=workspace_parent,
        workspace_seed=workspace_seed,
        additional_surface_factory=additional_surface_factory,
        additional_codec_factories=codec_factories,
        additional_surface_contract_digest=contract_digest,
        additional_target_process_id=process_id,
        additional_target_process_start_digest=process_start_digest,
        additional_target_window_handle_digest=window_handle_digest,
        additional_capsule_attachment_provider=(
            computer_recording_attachments if computer_recordings is not None else None
        ),
        event_observer=observed
        if computer_recordings is not None or event_observer is not None
        else None,
        coordination_context_provider=coordination_context_provider,
        action_admission_hook=action_admission_hook,
    )
    if computer_recordings is None or artifacts.status != "pass":
        return artifacts
    computer_media, computer_cues = computer_recordings.artifact_paths()
    return replace(
        artifacts,
        visual_replays=(*artifacts.visual_replays, *computer_media),
        replay_cues=(*artifacts.replay_cues, *computer_cues),
    )


__all__ = [
    "ComputerBackendSpec",
    "LocalComputerAuthorization",
    "MelraComputerBackendSpec",
    "NativeWindowsComputerBackendSpec",
    "run_full_capability_web_engine",
]
