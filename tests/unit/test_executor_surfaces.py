# SPDX-License-Identifier: Apache-2.0
"""Concrete workspace and exact-process SOVA Engine surface contracts."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sova.community import executor_surfaces as surfaces_module
from sova.community.executor_chamber import ChamberObservation
from sova.community.executor_engine import EngineSurfaceGeneration, ExecutorEngineRuntime
from sova.community.executor_surfaces import (
    ExactOciProcessSurfaceSpec,
    ExactProcessSurfaceSpec,
    browser_codec_factory,
    browser_surface_generation,
    computer_codec_factory,
    melra_computer_surface_generation,
    process_codec_factory,
    process_surface_generation,
    workspace_codec_factory,
    workspace_surface_generation,
)
from sova.executors import CancellationToken, ExecutionContext, OutcomeStatus
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime.environment_builder import (
    TargetEnvironmentAdmission,
    capability_contract_digest,
)
from sova.runtime.managed_surfaces import PolicyEvidenceVerifier
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
)
from sova.runtime.unified_execution import CapabilityBinding, ObservationVersion


def _digest(label: str) -> str:
    return sha256_digest(label.encode())


def _codec_observation() -> ChamberObservation:
    projection: dict[str, Any] = {}
    return ChamberObservation(
        ObservationVersion(
            _digest("codec-session"),
            _digest("codec-target"),
            0,
            sha256_digest(canonical_json_bytes(projection)),
        ),
        projection,
    )


def _browser_mission() -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="executor-surface-browser-fixture",
        title="Executor surface browser fixture",
        entry_url="http://127.0.0.1:8080/",
        objective="Exercise one reviewed browser control.",
        allowed_actions=("browser.click",),
        seed_inputs=(),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="FIXTURE-OBSERVED",
        max_planner_turns=1,
        max_actions=1,
        max_actions_per_plan=1,
        max_duration_seconds=30,
        max_pages=1,
        max_mutations=1,
        max_consecutive_failures=1,
        max_generated_text_characters=128,
        max_total_tokens=None,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def _target_and_session(
    surface: EngineSurfaceGeneration,
) -> tuple[TargetInstance, SessionEnvelope]:
    target = TargetInstance(
        instance_id="target:executor-surfaces",
        target_manifest_digest=_digest("manifest"),
        environment_digest=_digest("environment"),
        containment_digest=_digest("containment"),
        generation=1,
        clock_domain="clock:test",
    )
    backend = BackendGeneration(
        backend_id=surface.backend.backend_id,
        generation=surface.backend.generation,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        capabilities=tuple(
            CapabilityGeneration(
                capability.identifier,
                surface.backend.capability_generation,
                capability_contract_digest(capability),
            )
            for capability in surface.backend.executor.capabilities()
        ),
    )
    session = SessionEnvelope(
        session_id="session:executor-surfaces",
        run_id="run:executor-surfaces",
        generation=1,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        identity_digest=_digest("identity"),
        clock_domain=target.clock_domain,
        backend_generations=(backend,),
        affinity_resources=tuple(
            sorted({"target:executor-surfaces", *surface.backend.affinity_resources})
        ),
    )
    return target, session


def _binding(
    surface: EngineSurfaceGeneration,
    session: SessionEnvelope,
    target: TargetInstance,
    action: str,
) -> CapabilityBinding:
    capability = next(
        item for item in surface.backend.executor.capabilities() if item.name == action
    )
    backend = session.backend(surface.backend.backend_id)
    generation = backend.capability(capability.identifier)
    return CapabilityBinding(
        binding_id=f"binding:{surface.backend.backend_id}:{action.replace('.', '-')}",
        backend_id=surface.backend.backend_id,
        backend_generation=backend.generation,
        backend_generation_digest=backend.digest,
        capability_name=capability.name,
        capability_version=capability.version,
        capability_generation=generation.generation,
        capability_contract_digest=generation.contract_digest,
        session_digest=session.digest,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        side_effect=capability.side_effect,
        idempotent=capability.idempotent,
        expected_evidence=tuple(sorted(capability.evidence)),
        verifier_id=surface.backend.verifier_id,
        affinity_resources=tuple(
            sorted({"target:executor-surfaces", *surface.backend.affinity_resources})
        ),
        effect_resources=tuple(sorted(surface.backend.effect_resources.get(capability.name, ()))),
    )


def _observation(
    surface: EngineSurfaceGeneration,
    session: SessionEnvelope,
    target: TargetInstance,
    sequence: int,
) -> ChamberObservation:
    return ChamberObservation.capture(
        session,
        target,
        sequence,
        {surface.sensor_name: dict(surface.observe())},
    )


def _workspace_request(
    action: str,
    arguments: dict[str, object],
    *,
    request_id: str,
) -> Any:
    return workspace_codec_factory()(_codec_observation()).decode(
        {"action": action, "arguments": arguments},
        request_id=request_id,
        timeout_seconds=5,
    )


def test_browser_codec_factory_requires_exact_current_mission_locator_and_version() -> None:
    mission = _browser_mission()
    with pytest.raises(FormatError, match="exact mission"):
        browser_codec_factory(cast("Any", SimpleNamespace()))
    with pytest.raises(FormatError, match="sensor name"):
        browser_codec_factory(mission, sensor_name="")
    factory = browser_codec_factory(mission)
    with pytest.raises(FormatError, match="observation is absent"):
        factory(cast("Any", SimpleNamespace(projection=None, version=None)))

    malformed_surface = {
        "missionDigest": "sha256:" + "0" * 64,
        "locatorRefs": ["e1", "e1"],
    }
    with pytest.raises(FormatError, match="locator reference set"):
        factory(
            cast(
                "Any",
                SimpleNamespace(
                    projection={"browser": malformed_surface},
                    version=SimpleNamespace(content_digest=_digest("observation")),
                ),
            )
        )
    valid_surface = {"missionDigest": mission.digest, "locatorRefs": ["e1"]}
    with pytest.raises(FormatError, match="version digest"):
        factory(
            cast(
                "Any",
                SimpleNamespace(
                    projection={"browser": valid_surface},
                    version=SimpleNamespace(content_digest=None),
                ),
            )
        )
    codec: Any = factory(
        cast(
            "Any",
            SimpleNamespace(
                projection={"browser": valid_surface},
                version=SimpleNamespace(content_digest=_digest("observation")),
            ),
        )
    )
    assert codec.observation_digest == _digest("observation")
    with pytest.raises(FormatError, match="exact managed Playwright"):
        browser_surface_generation(cast("Any", SimpleNamespace()))


def test_computer_codec_factory_rejects_absent_binding_kind_session_and_target() -> None:
    with pytest.raises(FormatError, match="valid sensor name"):
        computer_codec_factory(sensor_name="bad sensor")
    factory = computer_codec_factory()
    session_digest = _digest("computer-session")

    def observation(
        surface: dict[str, Any], *, session: str = session_digest
    ) -> ChamberObservation:
        projection = {"computer": surface}
        return cast(
            "ChamberObservation",
            SimpleNamespace(
                projection=projection,
                version=SimpleNamespace(
                    content_digest=sha256_digest(canonical_json_bytes(projection)),
                    session_digest=session,
                ),
            ),
        )

    with pytest.raises(FormatError, match="reviewed target list is absent"):
        factory(observation({}))
    with pytest.raises(FormatError, match="identity binding is malformed"):
        factory(observation({"binding": {"kind": "other"}, "reviewedTargets": []}))
    binding = {
        "kind": "application",
        "sessionDigest": session_digest,
        "identityDigest": _digest("computer-identity"),
    }
    with pytest.raises(FormatError, match="substituted its session"):
        factory(observation({"binding": binding, "reviewedTargets": []}, session=_digest("other")))
    with pytest.raises(FormatError, match="reviewed target is malformed"):
        factory(observation({"binding": binding, "reviewedTargets": [1]}))
    codec: Any = factory(
        observation(
            {
                "binding": binding,
                "reviewedTargets": [
                    {
                        "reference": "control:submit",
                        "actions": ["computer.click"],
                        "locator": {"role": "button", "name": "Submit"},
                    }
                ],
            }
        )
    )
    assert codec.binding.session_digest == session_digest


def test_workspace_observer_detects_root_link_file_root_and_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = surfaces_module._WorkspaceObservation()
    surface = workspace_surface_generation()
    target, session = _target_and_session(surface)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == workspace or original_is_symlink(path),
    )
    with pytest.raises(FormatError, match="real disposable workspace"):
        observation.bind(session, target, workspace)
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    file_root = tmp_path / "file-root"
    file_root.write_text("not a directory", encoding="utf-8")
    with pytest.raises(FormatError, match="real disposable workspace"):
        surfaces_module._WorkspaceObservation().bind(session, target, file_root)

    observation.bind(session, target, workspace)
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == workspace or original_is_symlink(path),
    )
    with pytest.raises(FormatError, match="no longer valid"):
        observation()
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    unavailable = surfaces_module._WorkspaceObservation()
    unavailable.bind(session, target, workspace)
    original_stat = Path.stat
    monkeypatch.setattr(Path, "is_symlink", lambda _path: False)
    monkeypatch.setattr(Path, "is_junction", lambda _path: False, raising=False)

    def failed_stat(path: Path, *args: object, **kwargs: Any) -> Any:
        if path == workspace:
            raise OSError
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", failed_stat)
    with pytest.raises(FormatError, match="no longer valid"):
        unavailable()
    monkeypatch.setattr(Path, "stat", original_stat)

    drifted = surfaces_module._WorkspaceObservation()
    drifted.bind(session, target, workspace)
    current = workspace.stat()
    values = list(current)
    values[1] += 1
    changed_identity = type(current)(values)
    monkeypatch.setattr(
        Path,
        "stat",
        lambda path, *args, **kwargs: (
            changed_identity if path == workspace else original_stat(path, *args, **kwargs)
        ),
    )
    with pytest.raises(FormatError, match="no longer valid"):
        drifted()


def test_exact_oci_template_and_gvisor_adapters_require_exact_contract_types() -> None:
    with pytest.raises(FormatError, match="valid identifier"):
        ExactOciProcessSurfaceSpec("bad identifier", "/bin/echo")
    with pytest.raises(FormatError, match="exact OCI template"):
        surfaces_module.gvisor_process_surface_generation(
            cast("Any", SimpleNamespace()), cast("Any", SimpleNamespace())
        )
    with pytest.raises(FormatError, match="exact template"):
        surfaces_module.oci_process_codec_factory(
            cast("Any", SimpleNamespace()), cast("Any", SimpleNamespace())
        )


def test_workspace_observation_is_session_bound_detached_and_utf8_bounded(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "visible.txt").write_text("visible", encoding="utf-8")
    (workspace / "binary.bin").write_bytes(b"\xff\x00")
    (workspace / ".sova").mkdir()
    (workspace / ".sova" / "private.txt").write_text("excluded", encoding="utf-8")
    surface = workspace_surface_generation()
    target, session = _target_and_session(surface)

    with pytest.raises(FormatError, match="not session-bound"):
        surface.observe()
    surface.bind(session, target, workspace)
    first = surface.observe()
    assert first["sessionDigest"] == session.digest
    assert set(first["documents"]) == {"binary.bin", "visible.txt"}
    assert first["documents"]["visible.txt"]["text"] == "visible"
    assert first["documents"]["binary.bin"]["textIncluded"] is False

    first["documents"]["visible.txt"]["text"] = "tampered"
    second = surface.observe()
    assert second["documents"]["visible.txt"]["text"] == "visible"
    assert second["generationDigest"] == sha256_digest(canonical_json_bytes(second["documents"]))
    with pytest.raises(FormatError, match="cannot be rebound"):
        surface.bind(session, target, workspace)


def test_workspace_binding_rejects_target_substitution_missing_roots_and_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    surface = workspace_surface_generation()
    target, session = _target_and_session(surface)
    substituted = TargetInstance(
        instance_id="target:substituted",
        target_manifest_digest=target.target_manifest_digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        generation=1,
        clock_domain=target.clock_domain,
    )
    with pytest.raises(FormatError, match="substituted"):
        surface.bind(session, substituted, workspace)
    with pytest.raises(FormatError, match="real disposable workspace"):
        surface.bind(session, target, tmp_path / "missing")

    linked = workspace / "linked"
    linked.mkdir()
    original_is_symlink = Path.is_symlink

    def selective_is_symlink(path: Path) -> bool:
        return path == linked or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", selective_is_symlink)
    surface.bind(session, target, workspace)
    with pytest.raises(FormatError, match="links or junctions"):
        surface.observe()


def test_workspace_observation_enforces_file_and_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_workspace = tmp_path / "files"
    file_workspace.mkdir()
    (file_workspace / "one.txt").write_text("1", encoding="utf-8")
    (file_workspace / "two.txt").write_text("2", encoding="utf-8")
    file_surface = workspace_surface_generation()
    target, session = _target_and_session(file_surface)
    file_surface.bind(session, target, file_workspace)
    monkeypatch.setattr(surfaces_module, "_MAX_OBSERVED_FILES", 1)
    with pytest.raises(FormatError, match="exceeds 256 files or 8 MiB"):
        file_surface.observe()

    byte_workspace = tmp_path / "bytes"
    byte_workspace.mkdir()
    (byte_workspace / "large.txt").write_text("12345", encoding="utf-8")
    byte_surface = workspace_surface_generation()
    target, session = _target_and_session(byte_surface)
    byte_surface.bind(session, target, byte_workspace)
    monkeypatch.setattr(surfaces_module, "_MAX_OBSERVED_FILES", 256)
    monkeypatch.setattr(surfaces_module, "_MAX_OBSERVED_BYTES", 4)
    with pytest.raises(FormatError, match="exceeds 256 files or 8 MiB"):
        byte_surface.observe()


def test_workspace_write_move_delete_are_visible_and_policy_verified(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "out").mkdir()
    surface = workspace_surface_generation(max_read_bytes=64, max_write_bytes=64)
    target, session = _target_and_session(surface)
    surface.bind(session, target, workspace)
    context = ExecutionContext(workspace, {"decision": "allowed"})
    verifier = PolicyEvidenceVerifier(surface.evidence_policies)
    sequence = 0

    before = _observation(surface, session, target, sequence)
    write = surface.backend.executor.execute(
        _workspace_request(
            "filesystem.write",
            {"path": "result.txt", "content": "verified", "overwrite": False},
            request_id="write",
        ),
        context,
        CancellationToken(),
    )
    sequence += 1
    after_write = _observation(surface, session, target, sequence)
    assert write.status == OutcomeStatus.SUCCEEDED
    assert after_write.projection["workspace"]["documents"]["result.txt"]["text"] == "verified"
    write_verification = verifier(
        _workspace_request(
            "filesystem.write",
            {"path": "result.txt", "content": "verified", "overwrite": False},
            request_id="write",
        ),
        write,
        _binding(surface, session, target, "filesystem.write"),
        before,
        after_write,
    )
    assert write_verification.verified
    assert write_verification.satisfied_evidence == (
        "content-digest",
        "path",
        "size",
    )

    move_request = _workspace_request(
        "filesystem.move",
        {"source": "result.txt", "destination": "out/result.txt", "overwrite": False},
        request_id="move",
    )
    moved = surface.backend.executor.execute(
        move_request,
        context,
        CancellationToken(),
    )
    sequence += 1
    after_move = _observation(surface, session, target, sequence)
    assert moved.status == OutcomeStatus.SUCCEEDED
    assert "result.txt" not in after_move.projection["workspace"]["documents"]
    assert after_move.projection["workspace"]["documents"]["out/result.txt"]["text"] == "verified"
    assert verifier(
        move_request,
        moved,
        _binding(surface, session, target, "filesystem.move"),
        after_write,
        after_move,
    ).verified

    delete_request = _workspace_request(
        "filesystem.delete",
        {"path": "out/result.txt"},
        request_id="delete",
    )
    deleted = surface.backend.executor.execute(
        delete_request,
        context,
        CancellationToken(),
    )
    sequence += 1
    after_delete = _observation(surface, session, target, sequence)
    assert deleted.status == OutcomeStatus.SUCCEEDED
    assert after_delete.projection["workspace"]["documents"] == {}
    assert verifier(
        delete_request,
        deleted,
        _binding(surface, session, target, "filesystem.delete"),
        after_move,
        after_delete,
    ).verified


def test_surface_contracts_and_workspace_codec_are_exact() -> None:
    surface = workspace_surface_generation()
    assert type(surface) is EngineSurfaceGeneration
    assert surface.sensor_name == "workspace"
    capabilities = surface.backend.executor.capabilities()
    assert [item.identifier for item in capabilities] == [
        "filesystem.read/0.1",
        "filesystem.write/0.1",
        "filesystem.delete/0.1",
        "filesystem.move/0.1",
    ]
    assert {item.capability for item in surface.evidence_policies} == {
        item.identifier for item in capabilities
    }
    assert surface.backend.effect_resources == {
        "filesystem.write": ("workspace:files",),
        "filesystem.delete": ("workspace:files",),
        "filesystem.move": ("workspace:files",),
    }

    first = workspace_codec_factory(max_content_bytes=16)(_codec_observation())
    second = workspace_codec_factory(max_content_bytes=16)(_codec_observation())
    assert first is not second
    assert first.codec_id == "sova.action-codec.workspace/0.1.0"
    with pytest.raises(FormatError, match="fields are invalid"):
        first.decode(
            {"action": "filesystem.read", "arguments": {"path": "ok.txt"}, "extra": True},
            request_id="invalid",
            timeout_seconds=1,
        )
    with pytest.raises(FormatError, match="cannot escape"):
        first.decode(
            {"action": "filesystem.read", "arguments": {"path": "../escape.txt"}},
            request_id="escape",
            timeout_seconds=1,
        )


def test_process_surface_requires_explicit_host_acknowledgement_and_exact_codec() -> None:
    executable = Path(sys.executable).resolve()
    with pytest.raises(FormatError, match="explicit trusted-host acknowledgement"):
        ExactProcessSurfaceSpec("python", executable)

    spec = ExactProcessSurfaceSpec(
        "python",
        executable,
        trusted_host_process_acknowledged=True,
    )
    codec = process_codec_factory(spec)(_codec_observation())
    request = codec.decode(
        {
            "action": "process.exec",
            "arguments": {"args": ["-c", "print('surface-ok')"], "cwd": "."},
        },
        request_id="process",
        timeout_seconds=10,
    )
    assert request.inputs["argv"] == [
        str(executable),
        "-c",
        "print('surface-ok')",
    ]
    with pytest.raises(FormatError, match="args must be an array"):
        codec.decode(
            {
                "action": "process.exec",
                "arguments": {"args": "-c print('unsafe')", "cwd": "."},
            },
            request_id="shell-string",
            timeout_seconds=10,
        )


def test_process_surface_records_only_detached_normalized_output_and_closes_fresh(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve()
    spec = ExactProcessSurfaceSpec(
        "python",
        executable,
        trusted_host_process_acknowledged=True,
    )
    first = process_surface_generation(spec)
    second = process_surface_generation(spec)
    assert first.backend.executor is not second.backend.executor
    assert first.observe() == {"templateId": "python", "executed": False}
    request = process_codec_factory(spec)(_codec_observation()).decode(
        {
            "action": "process.exec",
            "arguments": {"args": ["-c", "print('surface-ok')"], "cwd": "."},
        },
        request_id="process",
        timeout_seconds=10,
    )
    outcome = first.backend.executor.execute(
        request,
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    observed = first.observe()
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert observed["status"] == "succeeded"
    assert observed["output"]["returncode"] == 0
    assert observed["output"]["stdout"].splitlines() == ["surface-ok"]
    assert observed["output"]["stderr"] == ""
    assert "argv" not in observed
    observed["output"]["stdout"] = "tampered"
    assert first.observe()["output"]["stdout"].splitlines() == ["surface-ok"]

    first.close()
    first.close()
    second_outcome = second.backend.executor.execute(
        request,
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert second_outcome.status == OutcomeStatus.SUCCEEDED
    second.close()


def test_process_policy_verifies_normalized_output_and_fresh_observation(
    tmp_path: Path,
) -> None:
    spec = ExactProcessSurfaceSpec(
        "python",
        Path(sys.executable).resolve(),
        trusted_host_process_acknowledged=True,
    )
    surface = process_surface_generation(spec)
    target, session = _target_and_session(surface)
    before = _observation(surface, session, target, 0)
    request = process_codec_factory(spec)(_codec_observation()).decode(
        {
            "action": "process.exec",
            "arguments": {"args": ["-c", "print('verified')"], "cwd": "."},
        },
        request_id="process",
        timeout_seconds=10,
    )
    outcome = surface.backend.executor.execute(
        request,
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    after = _observation(surface, session, target, 1)
    verification = PolicyEvidenceVerifier(surface.evidence_policies)(
        request,
        outcome,
        _binding(surface, session, target, "process.exec"),
        before,
        after,
    )
    assert verification.verified
    assert verification.satisfied_evidence == (
        "exact-argv-prefix",
        "returncode",
        "stderr",
        "stdout",
    )
    surface.close()


def test_workspace_surface_composes_with_engine_and_redacts_secret_observations(
    tmp_path: Path,
) -> None:
    admission = TargetEnvironmentAdmission(
        instance_id="target:engine-surfaces",
        target_manifest_digest=_digest("engine-manifest"),
        environment_digest=_digest("engine-environment"),
        containment_digest=_digest("engine-containment"),
        identity_digest=_digest("engine-identity"),
        clock_domain="clock:engine",
    )
    generations: list[EngineSurfaceGeneration] = []

    def surface_factory(_phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        generation = workspace_surface_generation()
        generations.append(generation)
        return (generation,)

    runtime = ExecutorEngineRuntime(
        target_admission=admission,
        surface_factory=surface_factory,
        codec_factories={
            "sova.action-codec.workspace/0.1.0": workspace_codec_factory(),
        },
        workspace_parent=tmp_path,
    )
    primary = runtime.environment_factory("primary")
    credential_material = "sk-" + "this-is-a-fake-secret-value-123456"
    (primary.workspace / "secret.txt").write_text(credential_material, encoding="utf-8")
    observed = primary.observe()
    encoded = canonical_json_bytes(dict(observed))
    assert credential_material.encode() not in encoded
    assert b"$redacted" in encoded
    observed["workspace"]["documents"] = {}
    assert primary.observe()["workspace"]["documents"]
    primary_session_digest = primary.session.digest
    primary_workspace = primary.workspace
    primary.close()
    assert not primary_workspace.exists()

    reproduction = runtime.environment_factory("reproduction")
    assert generations[0].backend.executor is not generations[1].backend.executor
    assert reproduction.session.digest != primary_session_digest
    reproduction_workspace = reproduction.workspace
    reproduction.close()
    assert not reproduction_workspace.exists()


def test_melra_computer_surface_generation_threads_the_mutation_ceiling(tmp_path: Path) -> None:
    ceiling = ("computer.click", "computer.scroll")
    generation = melra_computer_surface_generation(
        node_executable=tmp_path / "node",
        cli_entrypoint=tmp_path / "melra-cli.js",
        policy_factory=lambda workspace: workspace / "policy.json",
        identity_digest=_digest("melra-identity"),
        pid=1234,
        window_id=5678,
        mutations=ceiling,
    )
    advertised = {item.name for item in generation.backend.executor.capabilities()}
    assert advertised == {"computer.inspect", "computer.click", "computer.scroll"}


def test_melra_computer_surface_generation_defaults_to_click_and_type(tmp_path: Path) -> None:
    generation = melra_computer_surface_generation(
        node_executable=tmp_path / "node",
        cli_entrypoint=tmp_path / "melra-cli.js",
        policy_factory=lambda workspace: workspace / "policy.json",
        identity_digest=_digest("melra-identity-default"),
        pid=1,
        window_id=1,
    )
    advertised = {item.name for item in generation.backend.executor.capabilities()}
    assert advertised == {"computer.inspect", "computer.click", "computer.type"}
