# SPDX-License-Identifier: Apache-2.0
"""Authorized live-web composition for the heterogeneous SOVA Executor Engine."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from sova.community.executor_chamber import (
    ChamberDeterministicOracle,
    CompositeProjectionOracle,
    ProjectionFieldOracle,
)
from sova.community.executor_chamber_config import validate_executor_chamber_document
from sova.community.executor_engine import (
    CodecFactory,
    EngineSurfaceGeneration,
    ExecutorEngineRuntime,
    SurfaceFactory,
    run_executor_engine_document,
)
from sova.community.executor_surfaces import (
    browser_codec_factory,
    browser_surface_generation,
    workspace_codec_factory,
    workspace_surface_generation,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.live.browser import verified_browser_control
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime.browser_surface import ManagedPlaywrightBrowserSurface
from sova.runtime.environment_builder import TargetEnvironmentAdmission
from sova.runtime.sessions import BrowserProfileLease
from sova.targets import TargetKind, TargetManifest

if TYPE_CHECKING:
    from pathlib import Path

    from sova.community.executor_chamber import (
        ActionAdmissionHook,
        ApprovalPrompt,
        CoordinationContextProvider,
        ExecutorChamberArtifacts,
    )
    from sova.runtime import RoleModel
    from sova.safety import ControlProof

EngineEventObserver = Callable[[str, dict[str, Any]], None]
CapsuleAttachmentProvider = Callable[[], Mapping[str, bytes]]
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _destination_admissible(destination: Path) -> None:
    unresolved = destination.absolute()
    for candidate in (unresolved, *unresolved.parents):
        junction = getattr(candidate, "is_junction", lambda: False)
        if candidate.exists() and (candidate.is_symlink() or junction()):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-EXISTS",
                "live engine destination cannot traverse a link or junction",
            )
    resolved = destination.resolve()
    if resolved.exists() and (not resolved.is_dir() or any(resolved.iterdir())):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-EXISTS",
            "live engine destination must be an empty real directory",
        )


def _merged_codec_factories(
    mission: SemanticBrowserMission,
    additional: Mapping[str, CodecFactory] | None,
) -> dict[str, CodecFactory]:
    factories: dict[str, CodecFactory] = {
        "sova.action-codec.browser/0.1.0": browser_codec_factory(mission),
        "sova.action-codec.workspace/0.1.0": workspace_codec_factory(),
    }
    if additional is None:
        return factories
    if not isinstance(additional, Mapping):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-CODEC",
            "additional codec registry is malformed",
        )
    for identifier, factory in additional.items():
        if identifier in factories:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CODEC",
                "additional runtime attempted to replace a built-in codec",
                details={"codecId": identifier},
            )
        if not isinstance(identifier, str) or not identifier or not callable(factory):
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-CODEC",
                "additional codec registry is malformed",
            )
        factories[identifier] = factory
    return factories


def _surface_contract_digest(surfaces: tuple[EngineSurfaceGeneration, ...]) -> str:
    return sha256_digest(
        canonical_json_bytes(
            [
                surface.contract_mapping()
                for surface in sorted(surfaces, key=lambda item: item.sensor_name)
            ]
        )
    )


def _close_surfaces(surfaces: tuple[EngineSurfaceGeneration, ...]) -> None:
    failures = 0
    for surface in reversed(surfaces):
        try:
            surface.close()
        except Exception:  # noqa: BLE001 - private adapter details remain hidden
            failures += 1
    if failures:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-CLEANUP",
            "one or more live engine surfaces could not be closed",
        )


def _profile_evidence(
    profile_lease: BrowserProfileLease | None,
    target_digest: str,
) -> dict[str, object] | None:
    if profile_lease is None:
        return None
    if type(profile_lease) is not BrowserProfileLease:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-PROFILE",
            "live engine profile binding requires one exact browser profile lease",
        )
    profile_lease.require_target(target_digest)
    now_ms = time.time_ns() // 1_000_000
    if not profile_lease.acquired_unix_ms <= now_ms < profile_lease.expires_unix_ms:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-PROFILE",
            "browser profile lease is not within its admitted lifetime",
        )
    profile_lease.path_for_executor()
    return profile_lease.trace_mapping()


def _validate_controls(  # noqa: PLR0913 - each control is an independent trust input
    mission: SemanticBrowserMission,
    *,
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    offensive: bool,
    headless: bool,
    record_video: bool,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    event_observer: EngineEventObserver | None,
) -> None:
    if any(
        type(value) is not bool
        for value in (
            provider_calls_authorized,
            target_observation_disclosure_authorized,
            offensive,
            headless,
            record_video,
        )
    ):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-CONTROL",
            "live engine control flags must be exact booleans",
        )
    if (
        not callable(approval_prompt)
        or not callable(secret_resolver)
        or (event_observer is not None and not callable(event_observer))
    ):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-CALLBACK",
            "live engine callbacks are malformed",
        )
    if target_observation_disclosure_authorized is not True:
        raise FormatError(
            "SOVA-TARGET-OBSERVATION-DISCLOSURE-NOT-ALLOWED",
            "live engine planning requires explicit redacted target observation disclosure",
        )
    if mission.offensive != offensive:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-OFFENSIVE",
            "mission offensive declaration must exactly match runtime authorization",
        )


def _validate_additional_configuration(
    factory: SurfaceFactory | None,
    codecs: Mapping[str, CodecFactory] | None,
    contract_digest: str | None,
) -> None:
    if factory is None:
        if codecs is not None or contract_digest is not None:
            raise FormatError(
                "SOVA-EXECUTOR-ENGINE-SURFACE",
                "additional codec/contract metadata requires an additional surface factory",
            )
        return
    if (
        not callable(factory)
        or not isinstance(codecs, Mapping)
        or not codecs
        or not isinstance(contract_digest, str)
        or _DIGEST.fullmatch(contract_digest) is None
    ):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SURFACE",
            "additional surfaces require exact codec and contract bindings",
        )


def _validate_mission_oracle_binding(
    mission: SemanticBrowserMission,
    *,
    field_path: tuple[str, ...],
    contains: str,
) -> None:
    """Require the chamber finding oracle to describe the browser mission.

    The semantic mission and executor chamber are independently signed inputs.
    Without this cross-binding a caller can run one adversarial mission while
    declaring success against an unrelated chamber field or substring.  The
    managed browser projection exposes the redacted page text at
    ``browser.snapshot``; that is the only live-web field that can establish
    the mission's declared finding condition.
    """
    if field_path != ("browser", "snapshot") or contains != mission.oracle_contains:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-ORACLE-BINDING",
            "chamber oracle must exactly match the browser mission finding oracle",
            details={
                "requiredFieldPath": ["browser", "snapshot"],
                "missionOracleDigest": sha256_digest(
                    canonical_json_bytes({"contains": mission.oracle_contains})
                ),
            },
        )


def _validate_chamber_oracle_binding(
    mission: SemanticBrowserMission,
    oracle: ChamberDeterministicOracle,
) -> None:
    """Require every success branch to include the mission's exact browser marker."""
    if isinstance(oracle, ProjectionFieldOracle):
        _validate_mission_oracle_binding(
            mission,
            field_path=oracle.field_path,
            contains=oracle.contains,
        )
        return
    if isinstance(oracle, CompositeProjectionOracle):
        matching = [
            child
            for child in oracle.children
            if isinstance(child, ProjectionFieldOracle)
            and child.field_path == ("browser", "snapshot")
            and child.contains == mission.oracle_contains
        ]
        safe = bool(matching) if oracle.mode == "all" else len(matching) == len(oracle.children)
        if safe:
            return
    raise FormatError(
        "SOVA-EXECUTOR-ENGINE-ORACLE-BINDING",
        "chamber oracle must exactly match the browser mission finding oracle",
        details={
            "requiredFieldPath": ["browser", "snapshot"],
            "missionOracleDigest": sha256_digest(
                canonical_json_bytes({"contains": mission.oracle_contains})
            ),
        },
    )


def _validated_additional_surfaces(
    value: object,
    expected_digest: str | None,
) -> tuple[EngineSurfaceGeneration, ...]:
    if (
        not isinstance(value, tuple)
        or not value
        or any(type(item) is not EngineSurfaceGeneration for item in value)
    ):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SURFACE",
            "additional surface factory returned a malformed generation tuple",
        )
    surfaces = tuple(value)
    if _surface_contract_digest(surfaces) != expected_digest:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SURFACE-SUBSTITUTION",
            "additional surface generation differs from its admitted contract digest",
        )
    return surfaces


def run_live_web_executor_engine(  # noqa: PLR0913, PLR0915
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
    profile_lease: BrowserProfileLease | None = None,
    external_models: Mapping[str, RoleModel] | None = None,
    offensive: bool = False,
    headless: bool = True,
    record_video: bool = False,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    workspace_parent: Path | None = None,
    workspace_seed: Path | None = None,
    additional_surface_factory: SurfaceFactory | None = None,
    additional_codec_factories: Mapping[str, CodecFactory] | None = None,
    additional_surface_contract_digest: str | None = None,
    additional_target_process_id: int | None = None,
    additional_target_process_start_digest: str | None = None,
    additional_target_window_handle_digest: str | None = None,
    additional_capsule_attachment_provider: CapsuleAttachmentProvider | None = None,
    event_observer: EngineEventObserver | None = None,
    coordination_context_provider: CoordinationContextProvider | None = None,
    action_admission_hook: ActionAdmissionHook | None = None,
) -> ExecutorChamberArtifacts:
    """Run 2-8 planners over trusted browser/workspace surfaces on an owned URL.

    Extra process/computer surfaces may be supplied only through exact trusted
    factories and codecs.  Planners still receive observations and grants, never
    those surface objects or their credentials.

    `additional_target_process_id`/`_process_start_digest`/`_window_handle_digest`
    are opaque identity evidence for one additional window-kind surface (e.g. a
    composed MELRA computer surface) that needs `TargetInstance.process_id`/
    `window_handle_digest` populated to bind; every other caller leaves them
    `None`, which reproduces this function's exact prior admission shape.
    """
    if type(target) is not TargetManifest or target.kind != TargetKind.BROWSER_AGENT:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-TARGET",
            "live web engine requires one exact browser-agent target manifest",
        )
    if type(mission) is not SemanticBrowserMission:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-MISSION",
            "live web engine requires one exact semantic browser mission",
        )
    _validate_controls(
        mission,
        provider_calls_authorized=provider_calls_authorized,
        target_observation_disclosure_authorized=target_observation_disclosure_authorized,
        offensive=offensive,
        headless=headless,
        record_video=record_video,
        approval_prompt=approval_prompt,
        secret_resolver=secret_resolver,
        event_observer=event_observer,
    )
    if additional_capsule_attachment_provider is not None and not callable(
        additional_capsule_attachment_provider
    ):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-CALLBACK",
            "additional capsule attachment provider is malformed",
        )
    target_digest = target.digest
    mission_digest = mission.digest
    _destination_admissible(destination)
    validated = validate_executor_chamber_document(
        chamber_document,
        provider_calls_authorized=provider_calls_authorized,
        offensive=offensive,
    )
    _validate_chamber_oracle_binding(mission, validated.oracle)
    origins, host, proof, proof_status = verified_browser_control(target, control_proof)
    if target.digest != target_digest or mission.digest != mission_digest:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-SUBSTITUTION",
            "target or mission changed during live engine admission",
        )
    if mission.entry_origin not in origins:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-ORIGIN",
            "browser mission entry origin is outside the authorized target origins",
        )
    if validated.authority.authority_target != host:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-AUTHORITY",
            "chamber authority target must equal the verified website host",
        )
    profile_evidence = _profile_evidence(profile_lease, target_digest)
    _validate_additional_configuration(
        additional_surface_factory,
        additional_codec_factories,
        additional_surface_contract_digest,
    )
    if (additional_target_process_id is None) != (additional_target_process_start_digest is None):
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-ADDITIONAL-IDENTITY",
            "additional target process id and process-start digest must be supplied together",
        )
    if additional_target_window_handle_digest is not None and additional_target_process_id is None:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-ADDITIONAL-IDENTITY",
            "an additional target window requires an additional process-generation binding",
        )

    identity_document = {
        "targetDigest": target_digest,
        "profile": profile_evidence,
        "mode": "ephemeral-browser" if profile_lease is None else "opaque-profile-lease",
    }
    identity_digest = sha256_digest(canonical_json_bytes(identity_document))
    containment_document = {
        "targetDigest": target_digest,
        "missionDigest": mission_digest,
        "browser": {
            "allowedOriginRequestFiltering": True,
            "postActionOriginDriftDetection": True,
            "serviceWorkersBlocked": True,
            "profilePathExposedToModels": False,
            "networkEgressSandbox": False,
            "signedDecisiveVideoRequested": record_video,
        },
        "workspace": {
            "disposable": True,
            "pathExposedToModels": False,
            "linkEscapeRejected": True,
        },
        "additionalSurfaceContractDigest": additional_surface_contract_digest,
        "sharedVmOrMicroVmAttested": False,
    }
    containment_digest = sha256_digest(canonical_json_bytes(containment_document))
    environment_document = {
        "targetDigest": target_digest,
        "missionDigest": mission_digest,
        "proofDigest": proof.digest,
        "proofStatus": proof_status,
        "origins": list(origins),
        "headless": headless,
        "recordVideo": record_video,
        "profileEvidence": profile_evidence,
        "additionalSurfaceContractDigest": additional_surface_contract_digest,
    }
    environment_digest = sha256_digest(canonical_json_bytes(environment_document))
    admission = TargetEnvironmentAdmission(
        instance_id=f"web:{target.identifier}",
        target_manifest_digest=target_digest,
        environment_digest=environment_digest,
        containment_digest=containment_digest,
        identity_digest=identity_digest,
        clock_domain="host-monotonic",
        browser_context_digest=sha256_digest(
            canonical_json_bytes(
                {
                    "missionDigest": mission_digest,
                    "profileEvidence": profile_evidence,
                }
            )
        ),
        endpoint_digest=sha256_digest(canonical_json_bytes(list(origins))),
        profile_lease_digest=(
            None
            if profile_evidence is None
            else sha256_digest(canonical_json_bytes(profile_evidence))
        ),
        process_id=additional_target_process_id,
        process_start_digest=additional_target_process_start_digest,
        window_handle_digest=additional_target_window_handle_digest,
    )

    phase_browsers: dict[str, ManagedPlaywrightBrowserSurface] = {}

    def surfaces(phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        browser = ManagedPlaywrightBrowserSurface(
            mission=mission,
            target_digest=target_digest,
            package_runner=package_runner,
            browser_executable=browser_executable,
            package_cache=package_cache,
            browser_cache=browser_cache,
            profile_lease=profile_lease,
            headless=headless,
            record_video=record_video,
            recording_destination=destination if record_video else None,
            recording_label=phase,
        )
        phase_browsers[phase] = browser
        try:
            browser_generation = browser_surface_generation(browser)
        except Exception:
            try:
                browser.close()
            except Exception as cleanup_error:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-CLEANUP",
                    "live browser surface could not be closed after admission failure",
                ) from cleanup_error
            raise
        built: tuple[EngineSurfaceGeneration, ...] = (browser_generation,)
        try:
            built = (*built, workspace_surface_generation())
        except Exception as error:
            try:
                _close_surfaces(built)
            except Exception as cleanup_error:
                raise cleanup_error from error
            raise
        if additional_surface_factory is None:
            return built
        owned: tuple[EngineSurfaceGeneration, ...] = built
        try:
            additional_value = additional_surface_factory(phase)
            recognized = (
                tuple(item for item in additional_value if type(item) is EngineSurfaceGeneration)
                if isinstance(additional_value, tuple)
                else ()
            )
            owned = (*built, *recognized)
            additional = _validated_additional_surfaces(
                additional_value,
                additional_surface_contract_digest,
            )
            owned = (*built, *additional)
            combined = owned
        except Exception as error:
            try:
                _close_surfaces(owned)
            except Exception as cleanup_error:
                raise cleanup_error from error
            raise
        return combined

    runtime = ExecutorEngineRuntime(
        target_admission=admission,
        surface_factory=surfaces,
        codec_factories=_merged_codec_factories(mission, additional_codec_factories),
        workspace_parent=workspace_parent,
        workspace_seed=workspace_seed,
    )

    def observed(channel: str, event: dict[str, Any]) -> None:
        browser = phase_browsers.get(channel)
        if browser is not None:
            browser.observe_recording_event(channel, event)
        if event_observer is not None:
            event_observer(channel, event)

    def recording_attachments() -> Mapping[str, bytes]:
        attachments: dict[str, bytes] = {}
        if record_video:
            missing = sorted(
                phase
                for phase in ("primary", "reproduction")
                if phase not in phase_browsers
                or not phase_browsers[phase].visual_replays
                or phase_browsers[phase].replay_cues is None
            )
            if missing:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-VIDEO-MISSING",
                    "passing engine finding lacks signed decisive recording evidence",
                    details={"phases": missing},
                )
            for phase in ("primary", "reproduction"):
                browser = phase_browsers[phase]
                for index, media in enumerate(browser.visual_replays, 1):
                    logical_name = (
                        f"visual-replay-{index:02d}.webm"
                        if phase == "primary"
                        else f"reproduction-visual-replay-{index:02d}.webm"
                    )
                    attachments[logical_name] = media.read_bytes()
                cues = browser.replay_cues
                if cues is None:  # pragma: no cover - guarded above
                    raise TypeError
                attachments[
                    "replay-cues.json" if phase == "primary" else "reproduction-replay-cues.json"
                ] = cues.read_bytes()
        if additional_capsule_attachment_provider is not None:
            additional = dict(additional_capsule_attachment_provider())
            collisions = sorted(set(attachments) & set(additional))
            if collisions:
                raise FormatError(
                    "SOVA-EXECUTOR-ENGINE-ATTACHMENT-COLLISION",
                    "additional evidence attempted to replace browser recording evidence",
                    details={"names": collisions},
                )
            attachments.update(additional)
        return attachments

    artifacts = run_executor_engine_document(
        chamber_document,
        destination,
        runtime=runtime,
        proof=proof,
        approval_prompt=approval_prompt,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        offensive=offensive,
        external_models=external_models,
        allowed_domains=(host,),
        allowed_identities=(),
        event_observer=observed,
        capsule_attachment_provider=(
            recording_attachments
            if record_video or additional_capsule_attachment_provider is not None
            else None
        ),
        coordination_context_provider=coordination_context_provider,
        action_admission_hook=action_admission_hook,
    )
    visual_replays = tuple(
        media
        for phase in ("primary", "reproduction")
        if phase in phase_browsers
        for media in phase_browsers[phase].visual_replays
    )
    replay_cues = tuple(
        cues
        for phase in ("primary", "reproduction")
        if phase in phase_browsers
        for cues in (phase_browsers[phase].replay_cues,)
        if cues is not None
    )
    return replace(artifacts, visual_replays=visual_replays, replay_cues=replay_cues)


__all__ = [
    "CapsuleAttachmentProvider",
    "EngineEventObserver",
    "run_live_web_executor_engine",
]
