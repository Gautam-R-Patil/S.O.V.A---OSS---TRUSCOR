# SPDX-License-Identifier: Apache-2.0
"""No-network tests for public live-workflow CLI delegation and approval routes."""

from __future__ import annotations

import argparse
import builtins
import json
import shutil
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from sova import cli
from sova.formats.errors import FormatError
from sova.live import owned_web_target
from sova.runtime import ModelRouter

if TYPE_CHECKING:
    from pathlib import Path


def _intent() -> SimpleNamespace:
    return SimpleNamespace(
        id="intent-1",
        target="owned-fixture",
        action="browser.observe",
        effect=SimpleNamespace(name="READ"),
        domain="browser",
        offensive=False,
        irreversible=False,
        required_evidence=frozenset({"browser.snapshot"}),
    )


def _campaign_artifacts(root: Path, *, status: str = "pass", complete: bool = True) -> Any:
    return SimpleNamespace(
        status=status,
        traces=(root / "attempt.sova-trace",),
        reproduction_trace=root / "reproduction.sova-trace" if complete else None,
        discovery_capsule=root / "discovery.sova" if complete else None,
        report=root / "report.json",
    )


def _tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "APPROVE")


def test_detected_path_covers_explicit_path_search_and_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    assert cli._detected_path(executable, (), "runner") == executable.resolve()
    with pytest.raises(FormatError, match="does not exist"):
        cli._detected_path(tmp_path / "missing.exe", (), "runner")

    monkeypatch.setattr(shutil, "which", lambda name: str(executable) if name == "found" else None)
    assert cli._detected_path(None, ("found",), "runner") == executable.resolve()
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert cli._detected_path(None, (str(executable),), "runner") == executable.resolve()
    with pytest.raises(FormatError, match="was not detected"):
        cli._detected_path(None, ("absent-command",), "runner")


def test_docker_attestation_cli_delegates_and_reports_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"fixture")
    observed: list[tuple[Path, str]] = []

    class _Attestation:
        ready = True

        @staticmethod
        def to_mapping() -> dict[str, object]:
            return {"readiness": "ready", "rawDaemonConfigurationIncluded": False}

    def attest(path: Path, image: str) -> _Attestation:
        observed.append((path, image))
        return _Attestation()

    monkeypatch.setattr(cli, "attest_docker_desktop", attest)
    image = "example.invalid/sova/fixture@sha256:" + "a" * 64
    assert cli.main(["safety", "attest-docker", "--docker", str(docker), "--image", image]) == 0
    assert observed == [(docker.resolve(), image)]
    assert json.loads(capfd.readouterr().out)["rawDaemonConfigurationIncluded"] is False


def test_gvisor_attestation_cli_delegates_and_reports_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"fixture")
    observed: list[tuple[Path, str, str]] = []

    class _Attestation:
        ready = True

        @staticmethod
        def to_mapping() -> dict[str, object]:
            return {"readiness": "ready", "runtimeRegistered": True}

    def attest(path: Path, image: str, *, runtime: str) -> _Attestation:
        observed.append((path, image, runtime))
        return _Attestation()

    monkeypatch.setattr(cli, "attest_gvisor", attest)
    image = "example.invalid/sova/fixture@sha256:" + "b" * 64
    assert (
        cli.main(
            [
                "safety",
                "attest-gvisor",
                "--docker",
                str(docker),
                "--image",
                image,
                "--runtime",
                "runsc",
            ]
        )
        == 0
    )
    assert observed == [(docker.resolve(), image, "runsc")]
    assert json.loads(capfd.readouterr().out)["runtimeRegistered"] is True


def test_oci_agent_conformance_cli_routes_digest_bound_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"fixture")
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text("{}", encoding="utf-8")
    runtime = SimpleNamespace(identifier="fixture-agent")
    monkeypatch.setattr(cli, "oci_agent_runtime_from_mapping", lambda _value: runtime)

    def conform(
        received_runtime: object,
        received_docker: Path,
        destination: Path,
        *,
        approval_prompt: Any,
    ) -> Any:
        assert received_runtime is runtime
        assert received_docker == docker.resolve()
        assert (
            approval_prompt(SimpleNamespace(summary={"network": "none"}, exact_phrase="APPROVE"))
            == "APPROVE"
        )
        return SimpleNamespace(
            status="pass",
            runtime=destination / "runtime.json",
            report=destination / "report.json",
            trace=destination / "conformance.sova-trace",
        )

    monkeypatch.setattr(cli, "run_oci_agent_conformance", conform)
    destination = tmp_path / "result"
    assert (
        cli.main(
            [
                "agent",
                "conform-oci",
                str(runtime_path),
                str(destination),
                "--docker",
                str(docker),
            ]
        )
        == 0
    )
    output = json.loads(capfd.readouterr().out)
    assert output["status"] == "pass"
    assert output["trace"].endswith("conformance.sova-trace")

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="human-operated"):
        cli._agent_conform_oci(
            argparse.Namespace(
                runtime=runtime_path,
                destination=destination,
                docker=docker,
            )
        )


def test_browser_profile_cli_provisions_inspects_pairs_and_target_binds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    target = owned_web_target("http://127.0.0.1:9187")
    digest = target.digest
    vault = tmp_path / "profiles"
    create = argparse.Namespace(vault=vault, identity="operator", target_digest=digest)
    assert cli._session_browser_create(create) == 0
    provisioned = json.loads(capfd.readouterr().out)
    handle = provisioned["handle"]
    assert provisioned["profilePathIncluded"] is False

    assert cli._session_browser_inspect(argparse.Namespace(vault=vault, handle=handle)) == 0
    inspected = json.loads(capfd.readouterr().out)
    assert inspected["target"] == digest
    assert inspected["profilePathPresent"] is False

    args = argparse.Namespace(browser_profile_vault=vault, browser_profile_handle=handle)
    with cli._browser_profile_lease(args, target) as lease:
        assert lease is not None
        assert lease.target == digest
    with (
        pytest.raises(FormatError, match="supplied together"),
        cli._browser_profile_lease(
            argparse.Namespace(browser_profile_vault=vault, browser_profile_handle=None),
            target,
        ),
    ):
        pass
    with (
        pytest.raises(FormatError, match="different target"),
        cli._browser_profile_lease(
            args,
            owned_web_target("http://127.0.0.1:9188"),
        ),
    ):
        pass
    with pytest.raises(FormatError, match="exact sha256"):
        cli._session_browser_create(
            argparse.Namespace(vault=vault, identity="operator", target_digest="not-a-digest")
        )

    _tty(monkeypatch)
    executable = tmp_path / "executable"
    executable.write_bytes(b"fixture")
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))

    def handoff(*received: object, **options: Any) -> Any:
        assert received[:2] == (target, "http://127.0.0.1:9187/login")
        assert options["profile_lease"].target == target.digest
        assert options["handoff_prompt"]("APPROVE", "manual") == "APPROVE"
        return SimpleNamespace(
            status="pass",
            to_mapping=lambda: {"status": "pass", "profileMaterialIncluded": False},
        )

    monkeypatch.setattr(cli, "run_browser_profile_handoff", handoff)
    handoff_args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        entry_url="http://127.0.0.1:9187/login",
        browser_profile_vault=vault,
        browser_profile_handle=handle,
        destination=tmp_path / "handoff",
        control_proof=None,
        package_runner=None,
        browser_executable=None,
    )
    assert cli._session_browser_handoff(handoff_args) == 0
    assert json.loads(capfd.readouterr().out)["profileMaterialIncluded"] is False


def test_owned_fixture_detonation_routes_approval_and_outputs_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    executable.write_bytes(b"fixture")

    def run(destination: Path, **options: Any) -> Any:
        assert options["package_runner"] == executable
        assert options["browser_executable"] == executable
        assert options["headless"] is False
        assert options["record_video"] is True
        assert options["browser_cache"] == tmp_path / "browser-cache"
        prompt = options["approval_prompt"]
        assert prompt(SimpleNamespace(exact_phrase="APPROVE"), (_intent(),)) == "APPROVE"
        return SimpleNamespace(
            status="pass",
            trace=destination / "run.sova-trace",
            reproduction_trace=destination / "fresh.sova-trace",
            evidence_capsule=destination / "evidence.sova",
            report=destination / "report.json",
            visual_replays=(destination / "visual-replay-01.webm",),
        )

    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: executable)
    monkeypatch.setattr(cli, "run_owned_web_vertical_slice", run)
    args = argparse.Namespace(
        destination=tmp_path / "result",
        package_runner=None,
        browser_executable=None,
        headed=True,
        record_video=True,
        playwright_browser_cache=tmp_path / "browser-cache",
    )
    assert cli._detonate_owned_web_fixture(args) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "pass"

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="interactive terminal"):
        cli._detonate_owned_web_fixture(args)


def test_action_lab_detonation_routes_approval_and_registry_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    executable.write_bytes(b"fixture")

    def run(destination: Path, **options: Any) -> Any:
        assert options["package_runner"] == executable
        assert options["browser_executable"] == executable
        assert options["headless"] is False
        assert options["record_video"] is True
        assert options["browser_cache"] == tmp_path / "browser-cache"
        prompt = options["approval_prompt"]
        assert prompt(SimpleNamespace(exact_phrase="APPROVE"), (_intent(),)) == "APPROVE"
        return SimpleNamespace(
            status="pass",
            to_mapping=lambda: {
                "status": "pass",
                "evidenceCapsule": str(destination / "action-evidence.sova"),
                "replay": str(destination / "action-replay.html"),
                "registryEntry": str(destination / "registry-entry.json"),
            },
        )

    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: executable)
    monkeypatch.setattr(cli, "run_owned_action_lab_vertical_slice", run)
    args = argparse.Namespace(
        destination=tmp_path / "action-result",
        package_runner=None,
        browser_executable=None,
        headed=True,
        record_video=True,
        playwright_browser_cache=tmp_path / "browser-cache",
    )
    assert cli._detonate_action_lab(args) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["status"] == "pass"
    assert output["evidenceCapsule"].endswith("action-evidence.sova")

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="human-operated interactive terminal"):
        cli._detonate_action_lab(args)


def test_external_browser_detonation_parses_optional_proof_and_failure_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    executable.write_bytes(b"fixture")
    target, proof = object(), object()
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "control_proof_from_mapping", lambda _value: proof)
    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: executable)

    def run(received_target: object, _capsule: Path, destination: Path, **options: Any) -> Any:
        assert received_target is target and options["control_proof"] is proof
        assert options["headless"] is False
        assert options["record_video"] is True
        assert options["browser_cache"] == tmp_path / "browser-cache"
        assert (
            options["approval_prompt"](SimpleNamespace(exact_phrase="APPROVE"), (_intent(),))
            == "APPROVE"
        )
        return SimpleNamespace(
            status="not-confirmed",
            trace=destination / "run.sova-trace",
            reproduction_trace=destination / "fresh.sova-trace",
            evidence_capsule=destination / "evidence.sova",
            report=destination / "report.json",
            visual_replays=(destination / "visual-replay-01.webm",),
        )

    monkeypatch.setattr(cli, "run_live_browser_assessment", run)
    args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        control_proof=tmp_path / "proof.json",
        capsule=tmp_path / "input.sova",
        destination=tmp_path / "result",
        package_runner=None,
        browser_executable=None,
        headed=True,
        record_video=True,
        playwright_browser_cache=tmp_path / "browser-cache",
    )
    assert cli._detonate_browser(args) == 1
    assert json.loads(capfd.readouterr().out)["status"] == "not-confirmed"
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="interactive terminal"):
        cli._detonate_browser(args)


def test_owned_and_external_software_detonation_routes_exact_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    artifacts = SimpleNamespace(
        status="pass",
        to_mapping=lambda: {"status": "pass", "liveTargetExecuted": True},
    )

    def owned(destination: Path, **options: Any) -> Any:
        assert destination == tmp_path / "owned-output"
        prompt = options["approval_prompt"]
        assert prompt(SimpleNamespace(exact_phrase="APPROVE"), (_intent(),)) == "APPROVE"
        return artifacts

    monkeypatch.setattr(cli, "run_owned_software_vertical_slice", owned)
    assert (
        cli._detonate_owned_software_fixture(
            argparse.Namespace(destination=tmp_path / "owned-output")
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["liveTargetExecuted"] is True

    target = object()
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    external_artifacts = SimpleNamespace(
        status="inconclusive",
        to_mapping=lambda: {"status": "inconclusive", "liveTargetExecuted": True},
    )

    def external(received: object, *args: object, **options: Any) -> Any:
        assert received is target
        assert args == (
            tmp_path / "source.sova",
            tmp_path / "workspace",
            tmp_path / "external-output",
        )
        assert options["executable"] == tmp_path / "runner.exe"
        return external_artifacts

    monkeypatch.setattr(cli, "run_live_software_assessment", external)
    args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        capsule=tmp_path / "source.sova",
        workspace=tmp_path / "workspace",
        destination=tmp_path / "external-output",
        executable=tmp_path / "runner.exe",
    )
    assert cli._detonate_software(args) == 3
    assert json.loads(capfd.readouterr().out)["status"] == "inconclusive"

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="human-operated"):
        cli._detonate_owned_software_fixture(argparse.Namespace(destination=tmp_path / "blocked"))


def test_campaign_helpers_render_complete_and_partial_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: executable)
    args = argparse.Namespace(package_runner=None, browser_executable=None)
    assert cli._campaign_executables(args) == (executable, executable)
    challenge = SimpleNamespace(exact_phrase="APPROVE")
    assert cli._live_campaign_prompt(challenge, (_intent(),)) == "APPROVE"

    complete = cli._campaign_output(_campaign_artifacts(tmp_path))
    assert complete["reproductionTrace"] is not None
    assert complete["discoveryCapsule"] is not None
    partial = cli._campaign_output(_campaign_artifacts(tmp_path, complete=False))
    assert partial["reproductionTrace"] is None
    assert partial["discoveryCapsule"] is None


def test_all_campaign_cli_routes_delegate_with_no_target_tools_in_test(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    target, campaign, proof = object(), object(), object()
    runtime = SimpleNamespace(max_model_turns=5, max_total_tokens=100)
    router = object()
    browser = _campaign_artifacts(tmp_path)
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "browser_campaign_from_mapping", lambda _value: campaign)
    monkeypatch.setattr(cli, "control_proof_from_mapping", lambda _value: proof)
    monkeypatch.setattr(cli, "provider_runtime_from_mapping", lambda _value: runtime)
    monkeypatch.setattr(cli, "provider_model_router", lambda *_args, **_kwargs: router)
    monkeypatch.setattr(cli, "run_owned_web_campaign", lambda *_args, **_kwargs: browser)

    base = {
        "destination": tmp_path / "result",
        "package_runner": None,
        "browser_executable": None,
    }
    assert cli._hunt_owned_web_fixture(argparse.Namespace(**base)) == 0
    capfd.readouterr()

    def run_browser(*args: object, **options: Any) -> Any:
        assert args[:2] == (target, campaign)
        assert options["control_proof"] is proof
        return browser

    monkeypatch.setattr(cli, "run_browser_campaign", run_browser)
    external = argparse.Namespace(
        **base,
        manifest=tmp_path / "target.json",
        campaign=tmp_path / "campaign.json",
        control_proof=tmp_path / "proof.json",
    )
    assert cli._hunt_browser(external) == 0
    capfd.readouterr()

    agent = SimpleNamespace(
        status="pass",
        browser=browser,
        report=tmp_path / "agent-report.json",
        orchestration_trace=tmp_path / "orchestration.sova-trace",
    )

    def run_agent(*args: object, **options: Any) -> Any:
        assert args[:2] == (target, campaign)
        assert options["router"] is router
        assert options["control_proof"] is proof
        observer = options.get("event_observer")
        if observer is not None:
            observer("orchestration", {"kind": "run.started", "seq": 1})
        return agent

    monkeypatch.setattr(cli, "run_agent_browser_campaign", run_agent)
    agent_args = argparse.Namespace(
        **base,
        manifest=tmp_path / "target.json",
        campaign=tmp_path / "campaign.json",
        provider_runtime=tmp_path / "provider.json",
        control_proof=tmp_path / "proof.json",
        allow_provider_calls=True,
    )
    assert cli._hunt_agent_browser(agent_args) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["agentOrchestrationTrace"].endswith("orchestration.sova-trace")

    arena_args = argparse.Namespace(**vars(agent_args), stream_jsonl=True)
    assert cli._arena_web(arena_args) == 0
    streamed = [json.loads(line) for line in capfd.readouterr().out.splitlines()]
    assert streamed[0] == {
        "artifactType": "sova.arena-live-event",
        "channel": "orchestration",
        "event": {"kind": "run.started", "seq": 1},
        "schemaVersion": "0.1.0",
    }
    assert streamed[-1]["artifactType"] == "sova.arena-web-cli-result"
    assert streamed[-1]["agentOrchestrationTrace"].endswith("orchestration.sova-trace")

    denied_arena = vars(arena_args) | {"allow_provider_calls": False}
    with pytest.raises(FormatError, match="explicit --allow-provider-calls"):
        cli._arena_web(argparse.Namespace(**denied_arena))

    browser.status = "not-confirmed"
    assert cli._hunt_browser(external) == 2
    capfd.readouterr()


def test_semantic_arena_cli_requires_disclosure_binds_budgets_and_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    target, proof, router = object(), object(), object()
    runtime = SimpleNamespace(max_model_turns=5, max_total_tokens=100)
    mission = SimpleNamespace(max_planner_turns=4, max_total_tokens=80)
    semantic = _campaign_artifacts(tmp_path)
    semantic.mission = tmp_path / "mission.json"
    semantic.target = tmp_path / "target.json"
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))
    monkeypatch.setattr(
        cli,
        "_load_object",
        lambda path: (
            {"artifactType": "sova.provider-runtime"} if path == tmp_path / "provider.json" else {}
        ),
    )
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "semantic_browser_mission_from_mapping", lambda _value: mission)
    monkeypatch.setattr(cli, "control_proof_from_mapping", lambda _value: proof)
    monkeypatch.setattr(cli, "provider_runtime_from_mapping", lambda _value: runtime)
    monkeypatch.setattr(cli, "provider_model_router", lambda *_args, **_kwargs: router)

    def run_semantic(*args: object, **options: Any) -> Any:
        assert args[:2] == (target, mission)
        assert options["router"] is router
        assert options["control_proof"] is proof
        options["event_observer"]("semantic-browser", {"kind": "run.started", "seq": 2})
        return semantic

    monkeypatch.setattr(cli, "run_live_semantic_browser_workflow", run_semantic)
    semantic_args = argparse.Namespace(
        destination=tmp_path / "result",
        package_runner=None,
        browser_executable=None,
        manifest=tmp_path / "target.json",
        mission=tmp_path / "mission.json",
        provider_runtime=tmp_path / "provider.json",
        control_proof=tmp_path / "proof.json",
        allow_provider_calls=True,
        allow_target_observation_disclosure=True,
        stream_jsonl=True,
    )
    assert cli._arena_explore_web(semantic_args) == 0
    semantic_output = [json.loads(line) for line in capfd.readouterr().out.splitlines()]
    assert semantic_output[0]["artifactType"] == "sova.arena-semantic-browser-live-event"
    assert semantic_output[-1]["artifactType"] == "sova.arena-semantic-browser-cli-result"
    assert semantic_output[-1]["mission"].endswith("mission.json")

    denied_disclosure = vars(semantic_args) | {"allow_target_observation_disclosure": False}
    with pytest.raises(FormatError, match="explicit disclosure authorization"):
        cli._arena_explore_web(argparse.Namespace(**denied_disclosure))

    mission.max_planner_turns = 6
    with pytest.raises(FormatError, match="planner-turn budget"):
        cli._arena_explore_web(semantic_args)

    mission.max_planner_turns = 4
    with pytest.raises(FormatError, match="provider-backed semantic"):
        cli._arena_explore_web(
            argparse.Namespace(**(vars(semantic_args) | {"allow_provider_calls": False}))
        )

    mission.max_total_tokens = None
    with pytest.raises(FormatError, match="token budget must be present"):
        cli._arena_explore_web(semantic_args)
    mission.max_total_tokens = 101
    with pytest.raises(FormatError, match="no larger"):
        cli._arena_explore_web(semantic_args)

    mission.max_total_tokens = 80
    monkeypatch.setattr(cli, "_load_object", lambda _path: {"artifactType": "unknown"})
    with pytest.raises(FormatError, match="provider or OCI"):
        cli._arena_explore_web(semantic_args)


def test_semantic_arena_accepts_only_approved_attested_oci_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    executable.write_bytes(b"fixture")
    target = SimpleNamespace(digest="sha256:" + "1" * 64)
    mission = SimpleNamespace(digest="sha256:" + "2" * 64)
    oci_runtime = SimpleNamespace(image="image@sha256:" + "3" * 64, runtime="runsc")
    executor = object()

    class _Adapter:
        model_id = "oci-agent:fixture"

        @staticmethod
        def conform() -> dict[str, str]:
            return {"status": "pass"}

    adapter = _Adapter()
    semantic = _campaign_artifacts(tmp_path)
    semantic.mission = tmp_path / "result" / "mission.json"
    semantic.target = tmp_path / "result" / "target.json"
    monkeypatch.setattr(cli, "_require_live_campaign_terminal", lambda: None)
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))
    monkeypatch.setattr(
        cli,
        "_load_object",
        lambda path: (
            {"artifactType": "sova.oci-agent-runtime"}
            if path == tmp_path / "oci-agent.json"
            else {}
        ),
    )
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "semantic_browser_mission_from_mapping", lambda _value: mission)
    monkeypatch.setattr(cli, "oci_agent_runtime_from_mapping", lambda _value: oci_runtime)
    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: executable)
    monkeypatch.setattr(cli, "GVisorOciExecutor", lambda *_args, **_kwargs: executor)

    def authorize(
        received_runtime: object,
        received_executor: object,
        workspace: Path,
        *,
        use_scope: dict[str, object],
        approval_prompt: Any,
    ) -> _Adapter:
        assert received_runtime is oci_runtime
        assert received_executor is executor
        assert workspace == (tmp_path / "result")
        assert use_scope["targetDigest"] == target.digest
        assert use_scope["browserAuthorityInherited"] is False
        assert (
            approval_prompt(SimpleNamespace(summary={"network": "none"}, exact_phrase="APPROVE"))
            == "APPROVE"
        )
        return adapter

    monkeypatch.setattr(cli, "authorize_oci_agent_adapter", authorize)

    def run_semantic(*_args: object, **options: Any) -> Any:
        assert isinstance(options["router"], ModelRouter)
        return semantic

    monkeypatch.setattr(cli, "run_live_semantic_browser_workflow", run_semantic)
    args = argparse.Namespace(
        destination=tmp_path / "result",
        package_runner=None,
        browser_executable=None,
        manifest=tmp_path / "target.json",
        mission=tmp_path / "mission.json",
        provider_runtime=tmp_path / "oci-agent.json",
        control_proof=None,
        allow_provider_calls=False,
        allow_sandboxed_agent_code=True,
        allow_target_observation_disclosure=True,
        stream_jsonl=False,
        docker=None,
    )
    assert cli._arena_explore_web(args) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "pass"
    with pytest.raises(FormatError, match="allow-sandboxed-agent-code"):
        cli._arena_explore_web(
            argparse.Namespace(**(vars(args) | {"allow_sandboxed_agent_code": False}))
        )


def _agent_arena_args(tmp_path: Path, **changes: Any) -> argparse.Namespace:
    values = {
        "specification": tmp_path / "agent-arena.json",
        "destination": tmp_path / "agent-arena-output",
        "allow_provider_calls": False,
        "allow_sandboxed_agent_code": False,
        "docker": None,
    }
    values.update(changes)
    return argparse.Namespace(**values)


def test_agent_arena_oci_authority_and_document_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(FormatError, match="execution authorization"):
        cli._arena_agent_run(_agent_arena_args(tmp_path))

    monkeypatch.setattr(cli, "_load_object", lambda _path: {"participants": {}})
    with pytest.raises(FormatError, match="must be arrays"):
        cli._arena_agent_run(_agent_arena_args(tmp_path, allow_provider_calls=True))

    monkeypatch.setattr(cli, "_load_object", lambda _path: {"participants": [{}]})
    with pytest.raises(FormatError, match="provider-backed"):
        cli._arena_agent_run(_agent_arena_args(tmp_path, allow_sandboxed_agent_code=True))

    document = {"participants": [], "ociParticipants": [{"id": "agent", "runtime": {}}]}
    monkeypatch.setattr(cli, "_load_object", lambda _path: document)
    with pytest.raises(FormatError, match="require --allow-sandboxed-agent-code"):
        cli._arena_agent_run(_agent_arena_args(tmp_path, allow_provider_calls=True))

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="human-operated"):
        cli._arena_agent_run(_agent_arena_args(tmp_path, allow_sandboxed_agent_code=True))


@pytest.mark.parametrize(
    ("participant", "message"),
    [
        ([], "fields are invalid"),
        ({"id": 1, "runtime": {}}, "values are invalid"),
    ],
)
def test_agent_arena_oci_participant_shape_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    participant: object,
    message: str,
) -> None:
    _tty(monkeypatch)
    monkeypatch.setattr(
        cli,
        "validate_agent_arena_document",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        cli,
        "_load_object",
        lambda _path: {"participants": [], "ociParticipants": [participant]},
    )
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"fixture")
    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: docker)
    with pytest.raises(FormatError, match=message):
        cli._arena_agent_run(_agent_arena_args(tmp_path, allow_sandboxed_agent_code=True))


def test_agent_arena_oci_rejects_destination_and_id_drift_then_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    monkeypatch.setattr(
        cli,
        "validate_agent_arena_document",
        lambda *_args, **_kwargs: None,
    )
    runtime_document = {"artifactType": "sova.oci-agent-runtime"}
    document = {
        "participants": [],
        "ociParticipants": [{"id": "agent", "runtime": runtime_document}],
    }
    monkeypatch.setattr(cli, "_load_object", lambda _path: document)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "file").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="empty real directory"):
        cli._arena_agent_run(
            _agent_arena_args(
                tmp_path,
                destination=occupied,
                allow_sandboxed_agent_code=True,
            )
        )

    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"fixture")
    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: docker)
    runtime = SimpleNamespace(identifier="different", image="image", runtime="runsc")
    monkeypatch.setattr(cli, "oci_agent_runtime_from_mapping", lambda _value: runtime)
    with pytest.raises(FormatError, match="id must match"):
        cli._arena_agent_run(_agent_arena_args(tmp_path, allow_sandboxed_agent_code=True))

    runtime.identifier = "agent"
    executor = object()
    adapter = SimpleNamespace(conform=lambda: {"status": "pass"})
    monkeypatch.setattr(cli, "GVisorOciExecutor", lambda *_args, **_kwargs: executor)

    def authorize(
        received_runtime: object,
        received_executor: object,
        workspace: Path,
        *,
        use_scope: dict[str, object],
        approval_prompt: Any,
    ) -> object:
        assert received_runtime is runtime and received_executor is executor
        assert workspace == (tmp_path / "agent-arena-output")
        assert use_scope["participant"] == "agent"
        assert (
            approval_prompt(SimpleNamespace(summary={"network": "none"}, exact_phrase="APPROVE"))
            == "APPROVE"
        )
        return adapter

    monkeypatch.setattr(cli, "authorize_oci_agent_adapter", authorize)
    artifacts = SimpleNamespace(
        status="pass",
        report=tmp_path / "report.json",
        traces=(tmp_path / "trace.sova-trace",),
        capsules=(tmp_path / "arena.sova",),
    )

    def run(
        received_document: object,
        destination: Path,
        **options: Any,
    ) -> object:
        assert received_document is document
        assert destination == tmp_path / "agent-arena-output"
        assert options["external_models"] == {"agent": adapter}
        assert options["provider_calls_authorized"] is False
        return artifacts

    monkeypatch.setattr(cli, "run_agent_arena_document", run)
    assert cli._arena_agent_run(_agent_arena_args(tmp_path, allow_sandboxed_agent_code=True)) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "pass"


def test_agent_arena_validates_complete_document_before_oci_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tty(monkeypatch)
    document = {
        "participants": [],
        "ociParticipants": [{"id": "agent", "runtime": {}}],
    }
    monkeypatch.setattr(cli, "_load_object", lambda _path: document)
    monkeypatch.setattr(
        cli,
        "_detected_path",
        lambda *_args, **_kwargs: pytest.fail("OCI setup ran before document validation"),
    )
    destination = tmp_path / "must-not-exist"
    with pytest.raises(FormatError, match="missing: budget, matches, profile"):
        cli._arena_agent_run(
            argparse.Namespace(
                specification=tmp_path / "arena.json",
                destination=destination,
                allow_provider_calls=False,
                allow_sandboxed_agent_code=True,
                docker=None,
            )
        )
    assert not destination.exists()


def test_arena_chamber_cli_requires_fixture_authority_and_streams_canonical_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    artifacts = SimpleNamespace(
        status="pass",
        report=tmp_path / "report.json",
        trace=tmp_path / "arena.sova-trace",
        capsule=tmp_path / "arena.sova",
        live_events=tmp_path / "live-events.jsonl",
    )
    monkeypatch.setattr(cli, "_load_object", lambda _path: {"case": "fixture"})

    def run(document: object, destination: Path, **options: Any) -> Any:
        assert document == {"case": "fixture"}
        assert destination == tmp_path / "arena"
        assert options["contained_fixture_authorized"] is True
        assert options["provider_calls_authorized"] is False
        options["event_observer"]({"kind": "run.started", "sequence": 0})
        return artifacts

    monkeypatch.setattr(cli, "run_arena_chamber_document", run)
    args = argparse.Namespace(
        specification=tmp_path / "chamber.json",
        destination=tmp_path / "arena",
        authorize_contained_fixture=True,
        allow_provider_calls=False,
        stream_jsonl=True,
    )
    assert cli._arena_chamber(args) == 0
    output = [json.loads(line) for line in capfd.readouterr().out.splitlines()]
    assert output[0] == {"kind": "run.started", "sequence": 0}
    assert output[-1]["artifactType"] == "sova.arena-chamber-cli-result"


def test_browser_swarm_cli_requires_profile_and_streams_channels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    executable = tmp_path / "executable.exe"
    executable.write_bytes(b"fixture")
    target, campaign, proof, lease = object(), object(), object(), object()
    artifacts = SimpleNamespace(
        status="pass",
        report=tmp_path / "report.json",
        trace=tmp_path / "swarm.sova-trace",
        capsule=tmp_path / "swarm.sova",
        live_events=tmp_path / "live-events.jsonl",
        participant_runs=(tmp_path / "participant",),
    )
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "browser_campaign_from_mapping", lambda _value: campaign)
    monkeypatch.setattr(cli, "control_proof_from_mapping", lambda _value: proof)
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))
    monkeypatch.setattr(cli, "_browser_profile_lease", lambda _args, _target: nullcontext(lease))

    def run(*args: object, **options: Any) -> Any:
        assert args[1:3] == (target, campaign)
        assert options["profile_lease"] is lease
        assert options["control_proof"] is proof
        assert options["provider_calls_authorized"] is False
        options["event_observer"]("coordinator", {"kind": "run.started", "sequence": 0})
        return artifacts

    monkeypatch.setattr(cli, "run_browser_swarm_document", run)
    args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        campaign=tmp_path / "campaign.json",
        specification=tmp_path / "swarm.json",
        destination=tmp_path / "output",
        control_proof=tmp_path / "proof.json",
        package_runner=None,
        browser_executable=None,
        browser_profile_vault=tmp_path / "profiles",
        browser_profile_handle="profile:" + "a" * 32,
        allow_provider_calls=False,
        stream_jsonl=True,
    )
    assert cli._arena_swarm_web(args) == 0
    output = [json.loads(line) for line in capfd.readouterr().out.splitlines()]
    assert output[0]["artifactType"] == "sova.browser-swarm-live-event"
    assert output[0]["channel"] == "coordinator"
    assert output[-1]["artifactType"] == "sova.browser-swarm-cli-result"
    assert output[-1]["participantRuns"] == [str(tmp_path / "participant")]

    missing = argparse.Namespace(**(vars(args) | {"browser_profile_handle": None}))
    with pytest.raises(FormatError, match="requires an explicit target-bound profile"):
        cli._arena_swarm_web(missing)

    denied = vars(args) | {"authorize_contained_fixture": False}
    with pytest.raises(FormatError, match="explicit --authorize-contained-fixture"):
        cli._arena_chamber(argparse.Namespace(**denied))


def test_provider_rehearsal_cli_requires_permission_tty_and_delegates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    request = object()
    runtime = SimpleNamespace(max_model_turns=5, max_total_tokens=100)
    router = object()
    artifacts = SimpleNamespace(
        status="pass",
        to_mapping=lambda: {
            "status": "pass",
            "planningTrace": str(tmp_path / "planning.sova-trace"),
        },
    )
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "provider_rehearsal_request_from_mapping", lambda _value: request)
    monkeypatch.setattr(cli, "provider_runtime_from_mapping", lambda _value: runtime)
    monkeypatch.setattr(cli, "provider_model_router", lambda *_args, **_kwargs: router)

    def run(*args: object, **options: Any) -> Any:
        assert args == (request, tmp_path / "workspace", tmp_path / "artifacts")
        assert options["router"] is router
        assert options["provider_calls_authorized"] is True
        challenge = SimpleNamespace(
            phase="provider-disclosure",
            scope_digest="sha256:fixture",
            exact_phrase="APPROVE",
            summary={"providerToolsAvailable": False},
        )
        assert options["approval_prompt"](challenge) == "APPROVE"
        return artifacts

    monkeypatch.setattr(cli, "run_provider_rehearsal", run)
    args = argparse.Namespace(
        request=tmp_path / "request.json",
        provider_runtime=tmp_path / "provider.json",
        workspace=tmp_path / "workspace",
        destination=tmp_path / "artifacts",
        allow_provider_calls=True,
    )
    assert cli._rehearse_agent_run(args) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "pass"

    args.allow_provider_calls = False
    with pytest.raises(FormatError) as permission:
        cli._rehearse_agent_run(args)
    assert permission.value.issue.code == "SOVA-PROVIDER-CALLS-NOT-ALLOWED"
    args.allow_provider_calls = True
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError) as interactive:
        cli._rehearse_agent_run(args)
    assert interactive.value.issue.code == "SOVA-REHEARSE-PROVIDER-INTERACTIVE"


def _check_args(tmp_path: Path, **changes: Any) -> argparse.Namespace:
    values = {
        "check_self": False,
        "target": "fixture",
        "destination": tmp_path / "check",
        "custom_profile": None,
        "browser_campaign": None,
        "control_proof": None,
        "package_runner": None,
        "browser_executable": None,
    }
    values.update(changes)
    return argparse.Namespace(**values)


def test_check_cli_covers_self_local_and_browser_decisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "manifest_self_check", lambda: {"accepted": False})
    assert cli._check(_check_args(tmp_path, check_self=True, target=None, destination=None)) == 2
    capfd.readouterr()
    with pytest.raises(FormatError, match="does not accept"):
        cli._check(_check_args(tmp_path, check_self=True))
    with pytest.raises(FormatError, match="requires target"):
        cli._check(_check_args(tmp_path, target=None))
    with pytest.raises(FormatError, match="require --browser-campaign"):
        cli._check(_check_args(tmp_path, package_runner=tmp_path / "runner"))

    custom = tmp_path / "custom.json"
    custom.write_text('{"name":"fixture"}', encoding="utf-8")
    local_result = SimpleNamespace(exit_code=3, to_mapping=lambda: {"status": "inconclusive"})
    monkeypatch.setattr(cli, "run_check", lambda *_args, **_kwargs: local_result)
    assert cli._check(_check_args(tmp_path, custom_profile=custom)) == 3
    capfd.readouterr()

    with pytest.raises(FormatError, match="pinned standard"):
        cli._check(
            _check_args(
                tmp_path, browser_campaign=tmp_path / "campaign.json", custom_profile=custom
            )
        )

    _tty(monkeypatch)
    target, campaign, proof = object(), object(), object()
    executable = tmp_path / "executable.exe"
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "browser_campaign_from_mapping", lambda _value: campaign)
    monkeypatch.setattr(cli, "control_proof_from_mapping", lambda _value: proof)
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))
    browser_result = SimpleNamespace(
        exit_code=1,
        to_mapping=lambda: {"status": "confirmed-behavior"},
    )

    def run_browser(*args: object, **options: Any) -> Any:
        assert args[:2] == (target, campaign)
        assert options["control_proof"] is proof
        return browser_result

    monkeypatch.setattr(cli, "run_browser_check", run_browser)
    assert (
        cli._check(
            _check_args(
                tmp_path,
                browser_campaign=tmp_path / "campaign.json",
                control_proof=tmp_path / "proof.json",
            )
        )
        == 1
    )
    assert json.loads(capfd.readouterr().out)["status"] == "confirmed-behavior"


def test_target_proof_and_reference_fixture_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "fixture-report.json"
    report.write_text('{"status":"pass"}', encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "run_reference_assessment",
        lambda *_args: SimpleNamespace(report=report),
    )
    assert (
        cli._target_fixture(argparse.Namespace(kind="website", destination=tmp_path / "fixture"))
        == 0
    )
    capfd.readouterr()

    origin = "https://owned.example"
    target = SimpleNamespace(configuration={"allowedOrigins": [origin]})
    challenge = SimpleNamespace(origin=origin)
    proof = SimpleNamespace(to_mapping=lambda: {"method": "well-known"})
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "challenge_from_mapping", lambda _value: challenge)
    monkeypatch.setattr(cli, "collect_website_control_proof", lambda _challenge: proof)
    args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        challenge=tmp_path / "challenge.json",
        destination=tmp_path / "proof.json",
    )
    assert cli._target_prove(args) == 0
    assert args.destination.is_file()
    capfd.readouterr()
    target.configuration["allowedOrigins"] = ["https://different.example"]
    with pytest.raises(FormatError, match="does not match"):
        cli._target_prove(args)


def test_counterfactual_cli_and_local_mcp_human_approval_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    _tty(monkeypatch)
    target, study, proof = object(), object(), object()
    executable = tmp_path / "executable.exe"
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "browser_counterfactual_from_mapping", lambda _value: study)
    monkeypatch.setattr(cli, "control_proof_from_mapping", lambda _value: proof)
    monkeypatch.setattr(cli, "_campaign_executables", lambda _args: (executable, executable))
    artifacts = SimpleNamespace(
        status="supported-under-declared-interventions",
        report=tmp_path / "report.json",
        capsule=tmp_path / "cohort.sova",
        traces=(tmp_path / "one.sova-trace", tmp_path / "two.sova-trace"),
    )
    monkeypatch.setattr(
        cli,
        "run_browser_counterfactual_study",
        lambda *_args, **_kwargs: artifacts,
    )
    args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        study=tmp_path / "study.json",
        destination=tmp_path / "counterfactual",
        control_proof=tmp_path / "proof.json",
        package_runner=None,
        browser_executable=None,
    )
    assert cli._forensics_browser_counterfactual(args) == 0
    assert len(json.loads(capfd.readouterr().out)["traces"]) == 2

    class Store:
        malformed = False

        def challenge_record(self, challenge_id: str) -> dict[str, Any]:
            assert challenge_id == "challenge"
            return {"invocation": "invalid" if self.malformed else {"tool": "map"}}

        def approve(self, challenge_id: str, **review: Any) -> dict[str, Any]:
            assert challenge_id == "challenge"
            assert review["human_confirmed"] is True
            return {"token": "opaque-test-token", "reviewed": review["reviewed_effects"]}

    store = Store()
    monkeypatch.setattr(cli, "_mcp_store", lambda _args: store)
    responses = iter(("EXACT", "YES"))
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    approval_args = argparse.Namespace(challenge_id="challenge")
    assert cli._mcp_approve(approval_args) == 0
    assert json.loads(capfd.readouterr().out)["reviewed"] is True
    store.malformed = True
    with pytest.raises(FormatError, match="malformed"):
        cli._mcp_approve(approval_args)


def test_remaining_artifact_cli_routes_cover_unsupported_and_human_views(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    target = object()
    challenge = SimpleNamespace(to_mapping=lambda: {"id": "challenge"})
    monkeypatch.setattr(cli, "_load_object", lambda _path: {})
    monkeypatch.setattr(cli, "target_manifest_from_mapping", lambda _value: target)
    monkeypatch.setattr(cli, "create_website_control_challenge", lambda _target: challenge)
    challenge_path = tmp_path / "challenge.json"
    assert (
        cli._target_challenge(
            argparse.Namespace(manifest=tmp_path / "target.json", destination=challenge_path)
        )
        == 0
    )
    assert challenge_path.is_file()
    capfd.readouterr()

    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"unknown")
    assert (
        cli._verify(
            argparse.Namespace(
                path=unknown,
                require_signature=False,
                key_id=None,
            )
        )
        == 4
    )
    capfd.readouterr()

    reader = SimpleNamespace(events=lambda: [{"kind": "run.started", "sequence": 0}])
    monkeypatch.setattr(cli, "TraceReader", lambda _path: reader)
    assert (
        cli._export(
            argparse.Namespace(
                path=tmp_path / "run.sova-trace",
                format="native-jsonl",
                sequence=None,
                include_payload=False,
            )
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["kind"] == "run.started"

    bundle = object()
    monkeypatch.setattr(cli, "build_evidence_bundle", lambda _value: bundle)
    monkeypatch.setattr(cli, "render_evidence_report", lambda _bundle, audience: audience)
    assert (
        cli._evidence(
            argparse.Namespace(specification=tmp_path / "evidence.json", format="technical")
        )
        == 0
    )
    assert capfd.readouterr().out == "technical"


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (cli._object_member, []),
        (cli._array_member, {}),
        (cli._string_member, ""),
        (cli._boolean_member, 1),
    ],
)
def test_cli_member_guards_reject_wrong_types(function: Any, value: Any) -> None:
    with pytest.raises(FormatError):
        function({"field": value}, "field")


def test_forensic_and_adjudication_cli_input_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    report = SimpleNamespace(
        to_mapping=lambda: {
            "artifactType": "sova.forensic-reconstruction",
            "schemaVersion": "0.1.0",
        }
    )
    monkeypatch.setattr(cli, "reconstruct_trace", lambda _path: report)
    monkeypatch.setattr(cli, "validate_document", lambda *_args: None)
    assert (
        cli._forensics_reconstruct(argparse.Namespace(source=tmp_path / "recorded.sova-trace")) == 0
    )
    capfd.readouterr()

    monkeypatch.setattr(cli, "_load_object", lambda _path: {"events": [1]})
    with pytest.raises(FormatError, match="contain objects"):
        cli._forensics_reconstruct(argparse.Namespace(source=tmp_path / "events.json"))
    with pytest.raises(FormatError, match="counterfactual trial"):
        cli._counterfactual_trial([])
    with pytest.raises(FormatError, match="unsupported causal layer"):
        cli._counterfactual_trial(
            {
                "trialId": "trial",
                "layer": "not-a-layer",
                "changedLayers": [],
                "baselineOutcome": True,
                "interventionOutcome": False,
                "contextEquivalent": True,
                "evidenceComplete": True,
            }
        )
    with pytest.raises(FormatError, match="scanner finding"):
        cli._scanner_finding([])
    with pytest.raises(FormatError, match="execution observation"):
        cli._execution_observation([])
    with pytest.raises(FormatError, match="unsupported observation state"):
        cli._execution_observation(
            {
                "state": "invalid",
                "claimKey": "claim",
                "oracleMethod": "fixture",
                "evidenceComplete": True,
                "safeAndAuthorized": True,
            }
        )
    with pytest.raises(FormatError, match="string array"):
        cli._execution_observation(
            {
                "state": "confirmed",
                "claimKey": "claim",
                "oracleMethod": "fixture",
                "evidenceComplete": True,
                "safeAndAuthorized": True,
                "limitations": [1],
            }
        )

    monkeypatch.setattr(
        cli,
        "_load_object",
        lambda _path: {"findings": [], "allowedActionFamilies": [1]},
    )
    with pytest.raises(FormatError, match="contain strings"):
        cli._adjudicate_plan(argparse.Namespace(study=tmp_path / "study.json"))


def _disclosure_specification() -> dict[str, Any]:
    return {
        "evidence": {},
        "request": {
            "targetKind": "synthetic",
            "vulnerabilityState": "public",
            "containsWorkingPayload": False,
            "authorizationRedacted": True,
            "secretsScanClean": True,
            "humanReviewed": True,
            "limitationsPresent": True,
        },
        "contacts": [{"kind": "security", "value": "local-only"}],
        "vendorResponses": [],
        "reportedAt": "2026-08-07T00:00:00Z",
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value["request"].update(vulnerabilityState="invalid"), "state"),
        (lambda value: value.update(contacts="invalid"), "must be an array"),
        (lambda value: value.update(contacts=[1]), "contain objects"),
        (lambda value: value.update(contactRoot=7), "path string"),
        (lambda value: value.update(contacts=[]), "at least one"),
        (lambda value: value.update(vendorResponses=[1]), "vendorResponses"),
    ],
)
def test_disclosure_cli_rejects_unreviewable_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: Any,
    message: str,
) -> None:
    specification = _disclosure_specification()
    change(specification)
    monkeypatch.setattr(cli, "_load_object", lambda _path: specification)
    monkeypatch.setattr(cli, "build_evidence_bundle", lambda _value: object())
    with pytest.raises(FormatError, match=message):
        cli._disclose(argparse.Namespace(specification=tmp_path / "disclosure.json"))


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"traceReferences": [1], "individualOutcomes": {}, "limitations": []},
        {"traceReferences": [], "individualOutcomes": [], "limitations": []},
        {"traceReferences": [], "individualOutcomes": {}, "limitations": [1]},
        {
            "traceReferences": [],
            "individualOutcomes": {},
            "limitations": [],
            "triggered": "yes",
        },
    ],
)
def test_composition_observation_rejects_malformed_shapes(value: Any) -> None:
    with pytest.raises(FormatError):
        cli._composition_observation(value)


def test_compose_duplicate_and_snapshot_ci_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    row = {
        "candidateDigest": "sha256:" + "0" * 64,
        "triggered": False,
        "evidenceComplete": True,
        "oracleState": "not-observed",
        "traceReferences": [],
        "individualOutcomes": {},
        "limitations": [],
    }
    study = {"graph": {}, "observations": [row, row]}
    monkeypatch.setattr(cli, "_load_object", lambda _path: study)
    monkeypatch.setattr(cli, "graph_from_mapping", lambda _value: object())
    with pytest.raises(FormatError, match="duplicated"):
        cli._compose_evaluate(
            argparse.Namespace(study=tmp_path / "composition.json", strategy="pairwise")
        )
    malformed_study: dict[str, Any] = {"graph": {}, "observations": [1]}
    monkeypatch.setattr(cli, "_load_object", lambda _path: malformed_study)
    with pytest.raises(FormatError, match="must be an object"):
        cli._compose_evaluate(
            argparse.Namespace(study=tmp_path / "composition.json", strategy="pairwise")
        )

    snapshot_document = {"snapshotDigest": "sha256:" + "1" * 64}
    snapshot = SimpleNamespace(to_mapping=lambda: snapshot_document)
    monkeypatch.setattr(cli, "_load_object", lambda _path: {"id": "fixture"})
    monkeypatch.setattr(cli, "build_behavior_snapshot", lambda _value: snapshot)
    assert (
        cli._trace_snapshot(
            argparse.Namespace(specification=tmp_path / "snapshot.json", output=None)
        )
        == 0
    )
    capfd.readouterr()

    invalid_snapshot = {
        "artifactType": "sova.behavior-snapshot",
        "id": "snapshot",
        "traceReference": 7,
        "axes": {},
    }
    monkeypatch.setattr(cli, "_load_object", lambda _path: invalid_snapshot)
    with pytest.raises(FormatError, match="string or null"):
        cli._snapshot_from_file(tmp_path / "invalid.json")
    invalid_snapshot["traceReference"] = "run.sova-trace"
    assert cli._snapshot_from_file(tmp_path / "valid.json") is snapshot

    monkeypatch.setattr(cli, "_snapshot_from_file", lambda _path: snapshot)
    monkeypatch.setattr(cli, "compare_behavior_snapshots", lambda *_args: object())
    monkeypatch.setattr(
        cli,
        "evaluate_ci",
        lambda *_args: {"exitCode": 1, "sarif": {"version": "2.1.0"}},
    )
    monkeypatch.setattr(cli, "_monitor_policy", lambda _path: {})
    sarif = tmp_path / "result.sarif"
    assert (
        cli._ci(
            argparse.Namespace(
                baseline=tmp_path / "left.json",
                current=tmp_path / "right.json",
                policy=None,
                sarif=sarif,
            )
        )
        == 1
    )
    assert sarif.is_file()
    capfd.readouterr()
