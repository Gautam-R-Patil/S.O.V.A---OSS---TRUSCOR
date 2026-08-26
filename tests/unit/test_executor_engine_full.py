# SPDX-License-Identifier: Apache-2.0
"""Full-capability engine composition: browser+workspace+computer+process."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sova.community import executor_engine_full as full_module
from sova.community.executor_chamber import ExecutorChamberArtifacts
from sova.community.executor_engine import capture_workspace_seed_digest
from sova.community.executor_engine_full import (
    LocalComputerAuthorization,
    MelraComputerBackendSpec,
    NativeWindowsComputerBackendSpec,
    _build_additional,
    _close_all,
    _contract_digest,
    _session_identity_digest,
    run_full_capability_web_engine,
)
from sova.community.executor_surfaces import ExactProcessSurfaceSpec
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import ReviewedComputerTarget
from sova.runtime.software_target import SoftwareTargetAttestation
from sova.safety import ControlProof, ControlProofMethod
from sova.targets import TargetKind, TargetManifest

_COMPUTER_CODEC_ID = "sova.action-codec.computer/0.1.0"
_PROCESS_CODEC_ID = "sova.action-codec.process/0.1.0"


class _FakeTarget:
    digest = "sha256:" + "2" * 64


def _software_target() -> TargetManifest:
    return TargetManifest(
        "sova:target:owned-full-unit-window",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "computer.observe", "computer.click"),
        "self-owned full-engine unit fixture",
        {"authorityBasis": "self", "interface": "native-window"},
    )


def _authorization(attestation: SoftwareTargetAttestation) -> LocalComputerAuthorization:
    target = _software_target()
    now = datetime.now(UTC)
    challenge = "sova-local-control:full-engine-unit"
    proof = ControlProof(
        ControlProofMethod.LOCAL_POSSESSION,
        f"sova:local-software:{target.digest[7:31]}",
        challenge,
        {
            "challenge": challenge,
            "operatorAssertion": True,
            "executableDigest": attestation.executable_digest,
            "workspaceFingerprint": capture_workspace_seed_digest(None),
            "targetDigest": target.digest,
            "legalAuthorityIndependentlyVerified": False,
        },
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.full-engine-unit-control/0.1",
    )
    return LocalComputerAuthorization(target, proof, attestation)


def _attestation() -> SoftwareTargetAttestation:
    return SoftwareTargetAttestation(
        pid=1234,
        executable_name="owned-target.exe",
        executable_digest="sha256:" + "3" * 64,
        executable_size=1024,
        process_start_digest="sha256:" + "4" * 64,
        window_id=5678,
        window_handle_digest="sha256:" + "5" * 64,
        window_title_digest="sha256:" + "6" * 64,
        method="unit-fixture/0.1",
        code_signature_measured=False,
        _executable_path=Path("owned-target.exe"),
    )


def _computer_spec(**overrides: Any) -> MelraComputerBackendSpec:
    attestation = overrides.pop("target_attestation", _attestation())
    defaults: dict[str, Any] = {
        "node_executable": Path("node"),
        "cli_entrypoint": Path("melra-cli.js"),
        "policy_factory": lambda workspace: workspace / "policy.json",
        "authorization": _authorization(attestation),
    }
    defaults.update(overrides)
    return MelraComputerBackendSpec(**defaults)


def _binding(computer: MelraComputerBackendSpec | NativeWindowsComputerBackendSpec) -> Any:
    return computer.authorization.validate(None)


def _process_spec() -> ExactProcessSurfaceSpec:
    return ExactProcessSurfaceSpec(
        "python",
        Path(sys.executable).resolve(),
        trusted_host_process_acknowledged=True,
    )


def test_requires_at_least_one_extra_surface() -> None:
    with pytest.raises(FormatError, match="requires at least one"):
        run_full_capability_web_engine(
            "target",  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            {},
            Path("dest"),
            package_runner=Path("pr"),
            browser_executable=Path("be"),
            approval_prompt=lambda _c, _i: "x",
            secret_resolver=lambda _n: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
        )


def test_session_identity_digest_is_deterministic() -> None:
    first = _session_identity_digest("sha256:" + "1" * 64)
    second = _session_identity_digest("sha256:" + "1" * 64)
    assert first == second
    assert first != _session_identity_digest("sha256:" + "2" * 64)


@pytest.fixture(autouse=True)
def _admitted_unit_target_stays_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SoftwareTargetAttestation, "assert_still_live", lambda _self: None)


def test_computer_spec_rejects_process_only_attestation() -> None:
    process_only = SoftwareTargetAttestation(
        pid=1234,
        executable_name="owned-target.exe",
        executable_digest="sha256:" + "3" * 64,
        executable_size=1024,
        process_start_digest="sha256:" + "4" * 64,
        window_id=None,
        window_handle_digest=None,
        window_title_digest=None,
        method="unit-fixture/0.1",
        code_signature_measured=False,
        _executable_path=Path("owned-target.exe"),
    )
    with pytest.raises(FormatError, match="OS-verified live window"):
        _computer_spec(target_attestation=process_only)


def test_computer_authorization_and_melra_spec_require_exact_contract_types() -> None:
    with pytest.raises(FormatError, match="exact local-process manifest"):
        LocalComputerAuthorization(
            cast("Any", "not-a-target"),
            _authorization(_attestation()).control_proof,
            _attestation(),
        )
    authorization = _authorization(_attestation())
    with pytest.raises(FormatError, match="callable policy factory"):
        MelraComputerBackendSpec(
            Path("node"),
            Path("melra"),
            cast("Any", "not-callable"),
            authorization,
        )
    with pytest.raises(FormatError, match="independent local software authorization"):
        MelraComputerBackendSpec(
            Path("node"),
            Path("melra"),
            lambda workspace: workspace / "policy.json",
            cast("Any", object()),
        )


def test_full_surface_probe_cleanup_aggregates_backend_failures() -> None:
    def fail() -> None:
        raise RuntimeError

    surface = cast("Any", SimpleNamespace(close=fail))
    with pytest.raises(FormatError, match="could not be closed"):
        _close_all((surface,))


@pytest.mark.parametrize("mismatch", ["target", "executable", "workspace", "expired"])
def test_computer_authorization_rejects_unbound_or_stale_proof(mismatch: str) -> None:
    attestation = _attestation()
    authorization = _authorization(attestation)
    proof = authorization.control_proof
    evidence = dict(proof.evidence)
    if mismatch == "target":
        evidence["targetDigest"] = "sha256:" + "9" * 64
    elif mismatch == "executable":
        evidence["executableDigest"] = "sha256:" + "9" * 64
    elif mismatch == "workspace":
        evidence["workspaceFingerprint"] = "sha256:" + "9" * 64
    else:
        proof = replace(
            proof,
            observed_at=datetime.now(UTC) - timedelta(minutes=2),
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    if mismatch != "expired":
        proof = replace(proof, evidence=evidence)
    invalid = LocalComputerAuthorization(
        authorization.software_target,
        proof,
        attestation,
    )
    with pytest.raises(FormatError, match="not current and bound"):
        invalid.validate(None)


def test_native_backend_requires_exactly_one_control_selection_mode() -> None:
    authorization = _authorization(_attestation())
    with pytest.raises(FormatError, match="exactly one"):
        NativeWindowsComputerBackendSpec(authorization)
    with pytest.raises(FormatError, match="exactly one"):
        NativeWindowsComputerBackendSpec(
            authorization,
            reviewed_targets=(
                ReviewedComputerTarget(
                    "owned-button",
                    ("computer.click",),
                    {"x": 1, "y": 2},
                ),
            ),
            discover_controls=True,
        )


def test_contract_digest_is_stable_across_rebuilds() -> None:
    computer = _computer_spec()
    process_template = _process_spec()
    identity_digest = _session_identity_digest(_FakeTarget.digest)
    authorization = _binding(computer)
    first = _contract_digest(
        computer,
        process_template,
        identity_digest=identity_digest,
        computer_authorization=authorization,
    )
    second = _contract_digest(
        computer,
        process_template,
        identity_digest=identity_digest,
        computer_authorization=authorization,
    )
    assert first == second


def test_contract_digest_changes_with_mutations() -> None:
    identity_digest = _session_identity_digest(_FakeTarget.digest)
    baseline_computer = _computer_spec()
    baseline = _contract_digest(
        baseline_computer,
        None,
        identity_digest=identity_digest,
        computer_authorization=_binding(baseline_computer),
    )
    widened_computer = _computer_spec(
        mutations=("computer.click", "computer.type", "computer.scroll")
    )
    widened = _contract_digest(
        widened_computer,
        None,
        identity_digest=identity_digest,
        computer_authorization=_binding(widened_computer),
    )
    assert baseline != widened


def test_contract_digest_computer_without_identity_digest_raises() -> None:
    computer = _computer_spec()
    with pytest.raises(FormatError, match="session identity digest"):
        _contract_digest(
            computer,
            None,
            identity_digest=None,
            computer_authorization=_binding(computer),
        )


def test_build_additional_returns_one_surface_per_configured_backend() -> None:
    identity_digest = _session_identity_digest(_FakeTarget.digest)
    computer = _computer_spec()
    computer_only = _build_additional(
        computer,
        None,
        identity_digest=identity_digest,
        computer_authorization=_binding(computer),
    )
    assert len(computer_only) == 1
    assert computer_only[0].sensor_name == "computer"
    for surface in computer_only:
        surface.close()

    process_only = _build_additional(
        None,
        _process_spec(),
        identity_digest=None,
        computer_authorization=None,
    )
    assert len(process_only) == 1
    for surface in process_only:
        surface.close()

    computer = _computer_spec()
    both = _build_additional(
        computer,
        _process_spec(),
        identity_digest=identity_digest,
        computer_authorization=_binding(computer),
    )
    assert len(both) == 2
    for surface in both:
        surface.close()


def test_native_backend_binds_authorization_into_observation_and_contract() -> None:
    authorization = _authorization(_attestation())
    computer = NativeWindowsComputerBackendSpec(
        authorization,
        reviewed_targets=(
            ReviewedComputerTarget(
                "owned-button",
                ("computer.click",),
                {"x": 10, "y": 20},
            ),
        ),
    )
    binding = _binding(computer)
    generation = _build_additional(
        computer,
        None,
        identity_digest=_session_identity_digest(_FakeTarget.digest),
        computer_authorization=binding,
    )[0]
    try:
        assert any(binding.digest in item for item in generation.backend.affinity_resources)
        assert generation.backend.backend_id == "computer"
    finally:
        generation.close()


def test_codec_registry_has_expected_ids_for_both_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run_live(*_args: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return "artifacts"

    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    result: Any = run_full_capability_web_engine(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        {},
        Path("dest"),
        package_runner=Path("pr"),
        browser_executable=Path("be"),
        approval_prompt=lambda _c, _i: "x",
        secret_resolver=lambda _n: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        computer=_computer_spec(),
        process_template=_process_spec(),
    )
    assert result == "artifacts"
    codecs = captured["additional_codec_factories"]
    assert set(codecs) == {_COMPUTER_CODEC_ID, _PROCESS_CODEC_ID}
    assert callable(captured["additional_surface_factory"])
    assert isinstance(captured["additional_surface_contract_digest"], str)
    assert captured["additional_target_process_id"] == 1234
    assert captured["additional_target_process_start_digest"] is not None
    assert captured["additional_target_window_handle_digest"] is not None
    generated = captured["additional_surface_factory"]("primary")
    assert len(generated) == 2
    _close_all(generated)


def test_computer_only_registers_only_the_computer_codec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run_live(*_args: Any, **kwargs: Any) -> str:
        captured.update(kwargs)
        return "artifacts"

    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    run_full_capability_web_engine(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        {},
        Path("dest"),
        package_runner=Path("pr"),
        browser_executable=Path("be"),
        approval_prompt=lambda _c, _i: "x",
        secret_resolver=lambda _n: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        computer=_computer_spec(),
    )
    assert set(captured["additional_codec_factories"]) == {_COMPUTER_CODEC_ID}


def test_process_only_registers_only_the_process_codec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run_live(*_args: Any, **kwargs: Any) -> str:
        captured.update(kwargs)
        return "artifacts"

    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    run_full_capability_web_engine(
        "target",  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        {},
        Path("dest"),
        package_runner=Path("pr"),
        browser_executable=Path("be"),
        approval_prompt=lambda _c, _i: "x",
        secret_resolver=lambda _n: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        process_template=_process_spec(),
    )
    assert set(captured["additional_codec_factories"]) == {_PROCESS_CODEC_ID}
    assert captured["additional_target_process_id"] is None
    assert captured["additional_target_process_start_digest"] is None
    assert captured["additional_target_window_handle_digest"] is None


def test_forwards_core_engine_arguments_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run_live(*args: Any, **kwargs: Any) -> str:
        captured["args"] = args
        captured.update(kwargs)
        return "artifacts"

    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    run_full_capability_web_engine(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        {"grants": []},
        Path("dest"),
        package_runner=Path("pr"),
        browser_executable=Path("be"),
        approval_prompt=lambda _c, _i: "x",
        secret_resolver=lambda _n: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        offensive=True,
        headless=False,
        computer=_computer_spec(),
    )
    assert isinstance(captured["args"][0], _FakeTarget)
    assert captured["args"][1] == "mission"
    assert captured["args"][2] == {"grants": []}
    assert captured["args"][3] == Path("dest")
    assert captured["offensive"] is True
    assert captured["headless"] is False


def test_rejects_wrong_spec_types() -> None:
    with pytest.raises(FormatError, match="exact declared types"):
        run_full_capability_web_engine(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            {},
            Path("dest"),
            package_runner=Path("pr"),
            browser_executable=Path("be"),
            approval_prompt=lambda _c, _i: "x",
            secret_resolver=lambda _n: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
            computer="not-a-spec",  # type: ignore[arg-type]
        )


def test_computer_recording_is_wired_into_events_capsule_and_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, dict[str, Any]]] = []
    forwarded: list[tuple[str, dict[str, Any]]] = []
    closed: list[str] = []
    supplied: dict[str, Any] = {}

    class Recording:
        def __init__(self, phase: str) -> None:
            self.phase = phase

        def close(self) -> None:
            closed.append(self.phase)

    class Coordinator:
        def __init__(self, destination: Path, *, interval_seconds: float) -> None:
            assert destination == tmp_path / "result"
            assert interval_seconds == 0.25

        def start(self, phase: str, _attestation: SoftwareTargetAttestation) -> Recording:
            return Recording(phase)

        def observe(self, channel: str, event: dict[str, Any]) -> None:
            observed.append((channel, event))

        def attachments(self) -> dict[str, bytes]:
            assert closed == ["primary", "reproduction"]
            return {
                "visual-replay-01.sovaframes": b"primary-media",
                "replay-cues.json": b"primary-cues",
                "reproduction-visual-replay-01.sovaframes": b"reproduction-media",
                "reproduction-replay-cues.json": b"reproduction-cues",
            }

        def artifact_paths(self) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
            return (
                (tmp_path / "primary.sovaframes", tmp_path / "reproduction.sovaframes"),
                (tmp_path / "primary-cues.json", tmp_path / "reproduction-cues.json"),
            )

    def fake_run_live(*_args: Any, **kwargs: Any) -> ExecutorChamberArtifacts:
        supplied.update(kwargs)
        for phase in ("primary", "reproduction"):
            surfaces = kwargs["additional_surface_factory"](phase)
            kwargs["event_observer"](
                phase, {"kind": "oracle.completed", "payload": {"status": "pass"}}
            )
            _close_all(surfaces)
        attachments = dict(kwargs["additional_capsule_attachment_provider"]())
        assert set(attachments) == {
            "computer-visual-replay-01.sovaframes",
            "computer-replay-cues.json",
            "reproduction-computer-visual-replay-01.sovaframes",
            "reproduction-computer-replay-cues.json",
        }
        return ExecutorChamberArtifacts(
            "pass",
            tmp_path / "report.json",
            tmp_path / "primary.sova-trace",
            tmp_path / "reproduction.sova-trace",
            tmp_path / "finding.sova",
            tmp_path / "live.jsonl",
            (tmp_path / "browser.webm",),
            (tmp_path / "browser-cues.json",),
        )

    monkeypatch.setattr(full_module, "SoftwareWindowRecordingCoordinator", Coordinator)
    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    artifacts = run_full_capability_web_engine(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        {},
        tmp_path / "result",
        package_runner=Path("pr"),
        browser_executable=Path("be"),
        approval_prompt=lambda _c, _i: "x",
        secret_resolver=lambda _n: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        computer=_computer_spec(),
        record_computer_screen=True,
        computer_recording_interval_seconds=0.25,
        event_observer=lambda channel, event: forwarded.append((channel, event)),
    )
    assert closed == ["primary", "reproduction"]
    assert [item[0] for item in observed] == ["primary", "reproduction"]
    assert forwarded == observed
    assert supplied["additional_capsule_attachment_provider"] is not None
    assert [path.suffix for path in artifacts.visual_replays] == [
        ".webm",
        ".sovaframes",
        ".sovaframes",
    ]
    assert len(artifacts.replay_cues) == 3


def test_computer_recording_requires_an_authorized_computer_surface() -> None:
    with pytest.raises(FormatError, match="requires one independently authorized computer"):
        run_full_capability_web_engine(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            {},
            Path("dest"),
            package_runner=Path("pr"),
            browser_executable=Path("be"),
            approval_prompt=lambda _c, _i: "x",
            secret_resolver=lambda _n: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
            process_template=_process_spec(),
            record_computer_screen=True,
        )
    with pytest.raises(FormatError, match="exact boolean"):
        run_full_capability_web_engine(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            {},
            Path("dest"),
            package_runner=Path("pr"),
            browser_executable=Path("be"),
            approval_prompt=lambda _c, _i: "x",
            secret_resolver=lambda _n: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
            process_template=_process_spec(),
            record_computer_screen=cast("Any", 1),
        )


def test_computer_recording_closes_when_surface_construction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    class Recording:
        def close(self) -> None:
            closed.append("closed")

    class Coordinator:
        def __init__(self, _destination: Path, *, interval_seconds: float) -> None:
            assert interval_seconds == 0.5

        def start(self, _phase: str, _attestation: SoftwareTargetAttestation) -> Recording:
            return Recording()

        def observe(self, _channel: str, _event: dict[str, Any]) -> None:
            return None

        def attachments(self) -> dict[str, bytes]:
            raise AssertionError

        def artifact_paths(self) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
            raise AssertionError

    def fake_run_live(*_args: Any, **kwargs: Any) -> Any:
        return kwargs["additional_surface_factory"]("primary")

    monkeypatch.setattr(full_module, "SoftwareWindowRecordingCoordinator", Coordinator)
    monkeypatch.setattr(
        full_module, "_contract_digest", lambda *_args, **_kwargs: "sha256:" + "1" * 64
    )
    monkeypatch.setattr(
        full_module,
        "_build_additional",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("surface failed")),
    )
    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    with pytest.raises(RuntimeError, match="surface failed"):
        run_full_capability_web_engine(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            {},
            tmp_path,
            package_runner=Path("pr"),
            browser_executable=Path("be"),
            approval_prompt=lambda _c, _i: "x",
            secret_resolver=lambda _n: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
            computer=_computer_spec(),
            record_computer_screen=True,
        )
    assert closed == ["closed"]


@pytest.mark.parametrize(
    ("surface_fails", "recording_fails", "message"),
    [
        (True, False, "surface"),
        (False, True, "recording"),
        (True, True, "surface"),
    ],
)
def test_computer_recording_preserves_surface_and_evidence_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    surface_fails: bool,
    recording_fails: bool,
    message: str,
) -> None:
    computer = _computer_spec()
    base = _build_additional(
        computer,
        None,
        identity_digest=_session_identity_digest(_FakeTarget.digest),
        computer_authorization=_binding(computer),
    )[0]

    def surface_close() -> None:
        if surface_fails:
            raise RuntimeError("surface")

    class Recording:
        def close(self) -> None:
            if recording_fails:
                raise RuntimeError("recording")

    class Coordinator:
        def __init__(self, _destination: Path, *, interval_seconds: float) -> None:
            assert interval_seconds == 0.5

        def start(self, _phase: str, _attestation: SoftwareTargetAttestation) -> Recording:
            return Recording()

        def observe(self, _channel: str, _event: dict[str, Any]) -> None:
            return None

        def attachments(self) -> dict[str, bytes]:
            raise AssertionError

        def artifact_paths(self) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
            raise AssertionError

    def fake_run_live(*_args: Any, **kwargs: Any) -> Any:
        generated = kwargs["additional_surface_factory"]("primary")
        generated[0].close()
        raise AssertionError

    monkeypatch.setattr(full_module, "SoftwareWindowRecordingCoordinator", Coordinator)
    monkeypatch.setattr(
        full_module, "_contract_digest", lambda *_args, **_kwargs: "sha256:" + "1" * 64
    )
    monkeypatch.setattr(
        full_module,
        "_build_additional",
        lambda *_args, **_kwargs: (replace(base, close=surface_close),),
    )
    monkeypatch.setattr(full_module, "run_live_web_executor_engine", fake_run_live)
    with pytest.raises(RuntimeError, match=message):
        run_full_capability_web_engine(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            {},
            tmp_path,
            package_runner=Path("pr"),
            browser_executable=Path("be"),
            approval_prompt=lambda _c, _i: "x",
            secret_resolver=lambda _n: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
            computer=computer,
            record_computer_screen=True,
        )
