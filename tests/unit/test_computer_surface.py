# SPDX-License-Identifier: Apache-2.0
"""Managed computer surface and SOVA Engine adapter contracts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import pytest

from sova.community import executor_surfaces as executor_surfaces_module
from sova.community.executor_chamber import ChamberObservation
from sova.community.executor_engine import EngineSurfaceGeneration
from sova.community.executor_surfaces import (
    computer_codec_factory,
    computer_surface_generation,
)
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime import computer_surface as computer_surface_module
from sova.runtime.action_codecs import ComputerActionCodec, ReviewedComputerTarget
from sova.runtime.computer_surface import (
    ComputerSurfaceSnapshot,
    ManagedComputerSurface,
)
from sova.runtime.environment_builder import capability_contract_digest
from sova.runtime.managed_surfaces import PolicyEvidenceVerifier
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
)
from sova.runtime.unified_execution import CapabilityBinding

if TYPE_CHECKING:
    from collections.abc import Mapping


def _digest(label: str) -> str:
    return sha256_digest(label.encode())


class _FixtureComputerExecutor:
    name = "fixture-computer"

    def __init__(self, kind: Literal["application", "window"]) -> None:
        self.kind = kind
        self.clicks = 0
        self.text = ""
        self.closed = 0
        self.substitute_inventory = False

    def capabilities(self) -> tuple[Capability, ...]:
        read_action = "computer.snapshot" if self.kind == "application" else "computer.inspect"
        capabilities = (
            Capability(
                read_action,
                "0.1",
                SideEffect.READ,
                idempotent=True,
                evidence=("ui-state",),
            ),
            Capability(
                "computer.click",
                "0.1",
                SideEffect.MUTATE,
                idempotent=False,
                evidence=("ui-state-before", "ui-state-after"),
            ),
            Capability(
                "computer.type",
                "0.1",
                SideEffect.MUTATE,
                idempotent=False,
                evidence=("ui-state-before", "ui-state-after"),
            ),
        )
        if self.substitute_inventory:
            return (*capabilities[:-1], replace(capabilities[-1], version="9.9"))
        return capabilities

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        capability = next(
            (item for item in self.capabilities() if item.name == request.action),
            None,
        )
        if capability is None:
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
            )
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                capability.side_effect,
                {},
            )
        if request.action == "computer.click":
            self.clicks += 1
        elif request.action == "computer.type":
            self.text = str(request.inputs["text"])
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            capability.side_effect,
            {
                "postObservationCaptured": True,
                "clicks": self.clicks,
                "textLength": len(self.text),
            },
            verification="fixture-post-action-snapshot",
        )

    def close(self) -> None:
        self.closed += 1


def _targets(
    kind: Literal["application", "window"],
) -> tuple[ReviewedComputerTarget, ...]:
    if kind == "application":
        return (
            ReviewedComputerTarget(
                "arm-button",
                ("computer.click",),
                {"role": "push button", "name": "Arm"},
            ),
            ReviewedComputerTarget(
                "editor",
                ("computer.type",),
                {"role": "text", "name": "Editor"},
            ),
        )
    return (
        ReviewedComputerTarget(
            "arm-button",
            ("computer.click",),
            {"x": 24, "y": 48},
        ),
        ReviewedComputerTarget(
            "editor",
            ("computer.type",),
            {"elementToken": "node-7"},
        ),
    )


def _managed_surface(
    kind: Literal["application", "window"] = "application",
    *,
    projection_extra: Mapping[str, Any] | None = None,
    reviewed_targets: tuple[ReviewedComputerTarget, ...] | None = None,
    cleanup: Any = None,
) -> tuple[ManagedComputerSurface, _FixtureComputerExecutor]:
    executor = _FixtureComputerExecutor(kind)
    identity = _digest(f"{kind}-identity")

    def snapshot() -> ComputerSurfaceSnapshot:
        projection: dict[str, Any] = {
            "clicks": executor.clicks,
            "text": executor.text,
            **dict(projection_extra or {}),
        }
        return ComputerSurfaceSnapshot(
            projection,
            _targets(kind) if reviewed_targets is None else reviewed_targets,
        )

    surface = ManagedComputerSurface(
        executor=executor,
        kind=kind,
        identity_digest=identity,
        snapshot=snapshot,
        pid=412 if kind == "window" else None,
        window_id=73 if kind == "window" else None,
        cleanup=cleanup,
    )
    return surface, executor


def _target_and_session(
    surface: ManagedComputerSurface,
    *,
    kind: Literal["application", "window"] = "application",
    process_id: int | None = None,
    include_window_handle: bool = True,
) -> tuple[TargetInstance, SessionEnvelope]:
    process = 412 if kind == "window" and process_id is None else process_id
    target = TargetInstance(
        instance_id="target:computer-surface",
        target_manifest_digest=_digest("computer-manifest"),
        environment_digest=_digest("computer-environment"),
        containment_digest=_digest("computer-containment"),
        generation=1,
        clock_domain="clock:computer",
        process_id=process,
        process_start_digest=_digest("process-start") if process is not None else None,
        window_handle_digest=(
            _digest("window-handle") if kind == "window" and include_window_handle else None
        ),
    )
    capabilities = surface.capabilities()
    backend = BackendGeneration(
        "computer",
        1,
        target.digest,
        target.environment_digest,
        tuple(
            CapabilityGeneration(item.identifier, 1, capability_contract_digest(item))
            for item in capabilities
        ),
    )
    session = SessionEnvelope(
        session_id="session:computer-surface",
        run_id="run:computer-surface",
        generation=1,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        identity_digest=surface.identity_digest,
        clock_domain=target.clock_domain,
        backend_generations=(backend,),
        affinity_resources=(
            f"computer-identity:{surface.identity_digest}",
            "computer:session",
            "target:computer-surface",
        ),
    )
    return target, session


def _binding(
    generation: EngineSurfaceGeneration,
    target: TargetInstance,
    session: SessionEnvelope,
    action: str,
) -> CapabilityBinding:
    capability = next(
        item for item in generation.backend.executor.capabilities() if item.name == action
    )
    backend = session.backend(generation.backend.backend_id)
    capability_generation = backend.capability(capability.identifier)
    return CapabilityBinding(
        binding_id=f"binding:computer:{action.replace('.', '-')}",
        backend_id=generation.backend.backend_id,
        backend_generation=backend.generation,
        backend_generation_digest=backend.digest,
        capability_name=capability.name,
        capability_version=capability.version,
        capability_generation=capability_generation.generation,
        capability_contract_digest=capability_generation.contract_digest,
        session_digest=session.digest,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        side_effect=capability.side_effect,
        idempotent=capability.idempotent,
        expected_evidence=tuple(sorted(capability.evidence)),
        verifier_id=generation.backend.verifier_id,
        affinity_resources=tuple(
            sorted({"target:computer-surface", *generation.backend.affinity_resources})
        ),
        effect_resources=tuple(
            sorted(generation.backend.effect_resources.get(capability.name, ()))
        ),
    )


def _observation(
    generation: EngineSurfaceGeneration,
    target: TargetInstance,
    session: SessionEnvelope,
    sequence: int,
) -> ChamberObservation:
    return ChamberObservation.capture(
        session,
        target,
        sequence,
        {generation.sensor_name: dict(generation.observe())},
    )


def _model_document(codec: Any, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": action,
        "arguments": arguments,
        "binding": codec.binding.to_mapping(),
        "observationDigest": codec.observation_digest,
    }


def test_application_surface_binds_redacts_detaches_and_dispatches_reviewed_action(
    tmp_path: Path,
) -> None:
    credential_material = "sk-" + "fixture-computer-secret-123456"
    surface, executor = _managed_surface(projection_extra={"credential": credential_material})
    target, session = _target_and_session(surface)
    with pytest.raises(FormatError, match="closed or unbound"):
        surface.observe()
    surface.bind(session, target, tmp_path)

    observed = surface.observe()
    encoded = canonical_json_bytes(dict(observed))
    assert credential_material.encode() not in encoded
    assert b"$redacted" in encoded
    assert observed["binding"] == {
        "kind": "application",
        "sessionDigest": session.digest,
        "identityDigest": surface.identity_digest,
    }
    observed["reviewedTargets"][0]["locator"]["name"] = "tampered"
    assert surface.observe()["reviewedTargets"][0]["locator"]["name"] == "Arm"

    generation = computer_surface_generation(surface)
    before = _observation(generation, target, session, 0)
    codec = computer_codec_factory()(before)
    request = codec.decode(
        _model_document(codec, "computer.click", {"targetRef": "arm-button"}),
        request_id="click",
        timeout_seconds=5,
    )
    outcome = generation.backend.executor.execute(
        request,
        ExecutionContext(
            tmp_path,
            {"decision": "allowed"},
            environment={"sessionDigest": session.digest},
        ),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert request.inputs == {"role": "push button", "name": "Arm"}
    assert executor.clicks == 1


def test_computer_surface_rejects_workspace_session_and_inventory_substitution(
    tmp_path: Path,
) -> None:
    surface, executor = _managed_surface()
    target, session = _target_and_session(surface)
    substituted_session = replace(session, identity_digest=_digest("other-identity"))
    with pytest.raises(FormatError, match="identity differs"):
        surface.bind(substituted_session, target, tmp_path)
    surface.bind(session, target, tmp_path)

    request = ActionRequest("click", "computer.click", {"role": "button", "name": "Arm"}, 5)
    with pytest.raises(FormatError, match="session/workspace grant"):
        surface.executor.execute(
            request,
            ExecutionContext(
                tmp_path,
                {"decision": "allowed"},
                environment={"sessionDigest": _digest("other-session")},
            ),
            CancellationToken(),
        )
    executor.substitute_inventory = True
    with pytest.raises(FormatError, match="generation changed"):
        surface.observe()


def test_computer_surface_rejects_links_and_revalidates_bound_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    surface, _executor = _managed_surface()
    target, session = _target_and_session(surface)
    original_is_junction = getattr(Path, "is_junction", None)

    def is_junction(path: Path) -> bool:
        return path == tmp_path or bool(original_is_junction and original_is_junction(path))

    monkeypatch.setattr(Path, "is_junction", is_junction, raising=False)
    with pytest.raises(FormatError, match="link or junction"):
        surface.bind(session, target, tmp_path)
    monkeypatch.undo()

    surface, _executor = _managed_surface()
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    monkeypatch.setattr(Path, "is_junction", is_junction, raising=False)
    with pytest.raises(FormatError, match="identity is no longer valid"):
        surface.observe()


def test_window_surface_requires_exact_attested_process_and_window_generation(
    tmp_path: Path,
) -> None:
    surface, _executor = _managed_surface("window")
    target, session = _target_and_session(surface, kind="window", process_id=999)
    with pytest.raises(FormatError, match="target process/window generation"):
        surface.bind(session, target, tmp_path)

    surface, _executor = _managed_surface("window")
    target, session = _target_and_session(
        surface,
        kind="window",
        include_window_handle=False,
    )
    with pytest.raises(FormatError, match="target process/window generation"):
        surface.bind(session, target, tmp_path)

    surface, _executor = _managed_surface("window")
    target, session = _target_and_session(surface, kind="window")
    surface.bind(session, target, tmp_path)
    observed = surface.observe()
    assert observed["binding"] == {
        "kind": "window",
        "sessionDigest": session.digest,
        "identityDigest": surface.identity_digest,
        "pid": 412,
        "windowId": 73,
    }


def test_surface_rejects_wrong_locator_family_and_projection_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cua_target = ReviewedComputerTarget(
        "wrong-family",
        ("computer.click",),
        {"x": 1, "y": 2},
    )
    surface, _executor = _managed_surface(reviewed_targets=(cua_target,))
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    with pytest.raises(FormatError, match="do not match"):
        surface.observe()

    surface, _executor = _managed_surface(projection_extra={"large": "x" * 512})
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    monkeypatch.setattr(computer_surface_module, "_MAX_PROJECTION_BYTES", 128)
    with pytest.raises(FormatError, match="exceeds 256 KiB"):
        surface.observe()
    monkeypatch.setattr(computer_surface_module, "_MAX_PROJECTION_BYTES", 256 * 1024)

    surface, _executor = _managed_surface()
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    monkeypatch.setattr(executor_surfaces_module, "_MAX_REVIEWED_COMPUTER_TARGETS", 1)
    generation = computer_surface_generation(surface)
    observation = _observation(generation, target, session, 0)
    with pytest.raises(FormatError, match="too many reviewed targets"):
        computer_codec_factory()(observation)


def test_computer_generation_policies_verify_read_and_mutation_from_fresh_state(
    tmp_path: Path,
) -> None:
    surface, _executor = _managed_surface()
    generation = computer_surface_generation(surface)
    assert type(generation) is EngineSurfaceGeneration
    assert generation.backend.effect_resources == {
        "computer.click": (f"computer-identity:{surface.identity_digest}",),
        "computer.type": (f"computer-identity:{surface.identity_digest}",),
    }
    target, session = _target_and_session(surface)
    generation.bind(session, target, tmp_path)
    verifier = PolicyEvidenceVerifier(generation.evidence_policies)

    before = _observation(generation, target, session, 0)
    codec = computer_codec_factory()(before)
    snapshot_request = codec.decode(
        _model_document(codec, "computer.snapshot", {}),
        request_id="snapshot",
        timeout_seconds=5,
    )
    context = ExecutionContext(
        tmp_path,
        {"decision": "allowed"},
        environment={"sessionDigest": session.digest},
    )
    snapshot_outcome = generation.backend.executor.execute(
        snapshot_request,
        context,
        CancellationToken(),
    )
    after_snapshot = _observation(generation, target, session, 1)
    assert verifier(
        snapshot_request,
        snapshot_outcome,
        _binding(generation, target, session, "computer.snapshot"),
        before,
        after_snapshot,
    ).verified

    codec = computer_codec_factory()(after_snapshot)
    type_request = codec.decode(
        _model_document(
            codec,
            "computer.type",
            {"targetRef": "editor", "text": "blue owl"},
        ),
        request_id="type",
        timeout_seconds=5,
    )
    type_outcome = generation.backend.executor.execute(
        type_request,
        context,
        CancellationToken(),
    )
    after_type = _observation(generation, target, session, 2)
    verification = verifier(
        type_request,
        type_outcome,
        _binding(generation, target, session, "computer.type"),
        after_snapshot,
        after_type,
    )
    assert verification.verified
    assert verification.satisfied_evidence == (
        "ui-state-after",
        "ui-state-before",
    )


def test_computer_codec_factory_rejects_stale_malformed_and_unreviewed_targets(
    tmp_path: Path,
) -> None:
    surface, _executor = _managed_surface()
    generation = computer_surface_generation(surface)
    target, session = _target_and_session(surface)
    generation.bind(session, target, tmp_path)
    observation = _observation(generation, target, session, 0)
    codec = cast("ComputerActionCodec", computer_codec_factory()(observation))
    assert codec.codec_id == "sova.action-codec.computer/0.1.0"
    assert codec.binding.session_digest == session.digest

    with pytest.raises(FormatError, match="absent from the current"):
        codec.decode(
            _model_document(codec, "computer.click", {"targetRef": "unknown"}),
            request_id="unknown",
            timeout_seconds=5,
        )
    tampered_projection = dict(observation.projection)
    tampered_projection["extra"] = True
    tampered = replace(observation, projection=tampered_projection)
    with pytest.raises(FormatError, match="version binding is malformed"):
        computer_codec_factory()(tampered)
    malformed_projection = {
        "computer": {
            **observation.projection["computer"],
            "binding": {"kind": "application"},
        }
    }
    malformed = observation.advance(malformed_projection)
    with pytest.raises(FormatError, match="identity binding is malformed"):
        computer_codec_factory()(malformed)


def test_computer_surface_cleanup_is_idempotent_and_fail_closed(tmp_path: Path) -> None:
    cleanup_calls: list[str] = []
    surface, executor = _managed_surface(cleanup=lambda: cleanup_calls.append("cleanup"))
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    surface.close()
    surface.close()
    assert executor.closed == 1
    assert cleanup_calls == ["cleanup"]
    assert surface.closed
    assert surface.cleanup_complete
    with pytest.raises(FormatError, match="closed or unbound"):
        surface.observe()

    def fail_cleanup() -> None:
        raise RuntimeError

    failed, failed_executor = _managed_surface(cleanup=fail_cleanup)
    target, session = _target_and_session(failed)
    failed.bind(session, target, tmp_path)
    with pytest.raises(FormatError, match="could not be verified"):
        failed.close()
    assert failed_executor.closed == 1
    assert not failed.cleanup_complete
    with pytest.raises(FormatError, match="cleanup was not verified"):
        failed.close()


def test_computer_generation_requires_exact_managed_surface() -> None:
    with pytest.raises(FormatError, match="exact managed computer generation"):
        computer_surface_generation(cast("ManagedComputerSurface", object()))
    with pytest.raises(FormatError, match="valid sensor name"):
        computer_codec_factory(sensor_name="not valid")
