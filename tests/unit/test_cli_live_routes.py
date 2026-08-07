# SPDX-License-Identifier: Apache-2.0
"""No-network tests for public live-workflow CLI delegation and approval routes."""

from __future__ import annotations

import argparse
import builtins
import json
import shutil
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from sova import cli
from sova.formats.errors import FormatError

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
        prompt = options["approval_prompt"]
        assert prompt(SimpleNamespace(exact_phrase="APPROVE"), (_intent(),)) == "APPROVE"
        return SimpleNamespace(
            status="pass",
            trace=destination / "run.sova-trace",
            reproduction_trace=destination / "fresh.sova-trace",
            evidence_capsule=destination / "evidence.sova",
            report=destination / "report.json",
        )

    monkeypatch.setattr(cli, "_detected_path", lambda *_args, **_kwargs: executable)
    monkeypatch.setattr(cli, "run_owned_web_vertical_slice", run)
    args = argparse.Namespace(
        destination=tmp_path / "result",
        package_runner=None,
        browser_executable=None,
    )
    assert cli._detonate_owned_web_fixture(args) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "pass"

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(FormatError, match="interactive terminal"):
        cli._detonate_owned_web_fixture(args)


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
        )

    monkeypatch.setattr(cli, "run_live_browser_assessment", run)
    args = argparse.Namespace(
        manifest=tmp_path / "target.json",
        control_proof=tmp_path / "proof.json",
        capsule=tmp_path / "input.sova",
        destination=tmp_path / "result",
        package_runner=None,
        browser_executable=None,
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

    browser.status = "not-confirmed"
    assert cli._hunt_browser(external) == 2
    capfd.readouterr()


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
