# SPDX-License-Identifier: Apache-2.0
"""Offline end-to-end tests for tool-isolated provider rehearsal."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.rehearsal import (
    ProviderRehearsalRequest,
    WorkspaceDisclosurePolicy,
    prepare_rehearsal_environment,
    preview_provider_rehearsal,
    provider_rehearsal_request_from_mapping,
    run_provider_rehearsal,
)
from sova.runtime import ModelRouter, RoleKind
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.rehearsal import ProviderRehearsalApproval


def _request(*, include_content: bool = False, max_actions: int = 4) -> ProviderRehearsalRequest:
    return ProviderRehearsalRequest(
        "Create a safe result file and record one inert process proposal.",
        "fixture-agent",
        max_actions,
        WorkspaceDisclosurePolicy(include_content, 16, 65_536 if include_content else 0),
    )


def _workspace(tmp_path: Path, *, content: str = "safe fixture\n") -> Path:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    (source / "input.txt").write_text(content, encoding="utf-8")
    workspace = tmp_path / "workspace"
    prepare_rehearsal_environment(source, workspace)
    return workspace


def _plan() -> dict[str, Any]:
    return {
        "actions": [
            {
                "id": "write-result",
                "kind": "file.write",
                "target": "result.txt",
                "operation": "write",
                "parameters": {"content": "provider-reviewed output\n"},
                "materialStep": False,
            },
            {
                "id": "record-process",
                "kind": "process",
                "target": "fixture-command",
                "operation": "describe",
                "parameters": {"argv": ["fixture", "--safe"]},
                "materialStep": True,
            },
        ]
    }


def _router(
    structured: dict[str, Any],
    *,
    tool_calls: tuple[dict[str, Any], ...] = (),
    token_count: int | None = 17,
) -> tuple[ScriptedModel, ModelRouter]:
    model = ScriptedModel(
        [
            ScriptedTurn(
                '"contract":"sova.provider-rehearsal-planner/0.1.0"',
                json.dumps(structured),
                structured,
                tool_calls,
                token_count=token_count,
            )
        ]
    )
    return model, ModelRouter({RoleKind.STRATEGIST: (model,)})


def _approver(phases: list[str]) -> Callable[[ProviderRehearsalApproval], str]:
    def approve(challenge: ProviderRehearsalApproval) -> str:
        phases.append(challenge.phase)
        return challenge.exact_phrase

    return approve


def test_provider_rehearsal_offline_vertical_slice(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    model, router = _router(_plan())
    phases: list[str] = []
    artifacts = run_provider_rehearsal(
        _request(),
        workspace,
        tmp_path / "artifacts",
        router=router,
        max_model_turns=1,
        max_total_tokens=100,
        provider_calls_authorized=True,
        approval_prompt=_approver(phases),
    )

    assert model.complete
    assert phases == ["provider-disclosure", "plan-execution"]
    assert artifacts.status == "pass"
    assert artifacts.to_mapping()["capsule"] == str(artifacts.capsule)
    assert (workspace / "result.txt").read_text(encoding="utf-8") == ("provider-reviewed output\n")
    assert (workspace / ".sova-rehearsal/effects/record-process.json").is_file()
    TraceReader(artifacts.planning_trace).verify()
    TraceReader(artifacts.execution_trace).verify()
    descriptors = PackageReader(artifacts.capsule).verify("sova.capsule")
    assert [item.role for item in descriptors].count("trace") == 2
    report = strict_json_loads(artifacts.report.read_bytes())
    assert report["claims"] == {
        "effectsConfinedToPreparedWorkspaceOrInertSubstitutes": True,
        "exactDisclosureApproval": True,
        "exactPlanApproval": True,
        "privateModelThoughtsCaptured": False,
        "productionEffects": False,
        "providerCallOccurred": True,
        "providerHadTargetTools": False,
        "providerOutputTreatedAsUntrusted": True,
        "securitySandbox": False,
    }
    assert report["providerInvocation"]["structuredContentCaptured"] is False


def test_provider_disclosure_redacts_bearer_content_before_model(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, content="Bearer abcdefghijklmnopqrstuvwxyz\n")
    _model, router = _router(_plan())
    phases: list[str] = []

    def approve(challenge: ProviderRehearsalApproval) -> str:
        phases.append(challenge.phase)
        if challenge.phase == "provider-disclosure":
            rendered = json.dumps(challenge.summary)
            assert "abcdefghijklmnopqrstuvwxyz" not in rendered
            assert "$redacted" in rendered
            assert challenge.summary["inventory"]["files"][0]["textIncluded"] is True
        return challenge.exact_phrase

    artifacts = run_provider_rehearsal(
        _request(include_content=True),
        workspace,
        tmp_path / "artifacts",
        router=router,
        max_model_turns=1,
        max_total_tokens=None,
        provider_calls_authorized=True,
        approval_prompt=approve,
    )
    report = strict_json_loads(artifacts.report.read_bytes())
    assert report["disclosure"]["captureTimeRedactions"] == 1
    assert report["disclosure"]["disclosedContentBytes"] > 0
    assert report["disclosure"]["fileTextStoredInReport"] is False
    assert "abcdefghijklmnopqrstuvwxyz" not in artifacts.report.read_text(encoding="utf-8")


def test_provider_rehearsal_refuses_workspace_drift_during_model_call(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    model, router = _router(_plan())

    def approve_then_drift(challenge: ProviderRehearsalApproval) -> str:
        if challenge.phase == "provider-disclosure":
            (workspace / "input.txt").write_text("changed after approval\n", encoding="utf-8")
        return challenge.exact_phrase

    with pytest.raises(FormatError) as captured:
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "artifacts",
            router=router,
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=approve_then_drift,
        )
    assert captured.value.issue.code == "SOVA-REHEARSE-PROVIDER-WORKSPACE-DRIFT"
    assert model.complete
    assert not (workspace / "result.txt").exists()


def test_provider_approval_precedes_model_call(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    model, router = _router(_plan())

    def deny(_challenge: ProviderRehearsalApproval) -> str:
        return "denied"

    with pytest.raises(FormatError, match="exact provider-disclosure approval"):
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "artifacts",
            router=router,
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=deny,
        )
    assert model.consumed == 0
    assert not (tmp_path / "artifacts").exists()


def test_provider_plan_requires_second_exact_approval(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    model, router = _router(_plan())

    def approve_once(challenge: ProviderRehearsalApproval) -> str:
        if challenge.phase == "provider-disclosure":
            return challenge.exact_phrase
        return "denied"

    with pytest.raises(FormatError, match="exact plan-execution approval"):
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "artifacts",
            router=router,
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=approve_once,
        )
    assert model.complete
    assert not (workspace / "result.txt").exists()
    TraceReader(tmp_path / "artifacts/planning.sova-trace").verify()


@pytest.mark.parametrize(
    ("structured", "code"),
    [
        ({"actions": [], "extra": True}, "SOVA-REHEARSE-PROVIDER-OUTPUT"),
        ({"actions": []}, "SOVA-REHEARSE-PROVIDER-OUTPUT"),
        ({"actions": ["not-an-object"]}, "SOVA-REHEARSE-PROVIDER-OUTPUT"),
        (
            {
                "actions": [
                    {
                        "id": "bad-parameters",
                        "kind": "file.write",
                        "target": "x.txt",
                        "operation": "write",
                        "parameters": [],
                        "materialStep": False,
                    }
                ]
            },
            "SOVA-REHEARSE-PROVIDER-OUTPUT",
        ),
        (
            {
                "actions": [
                    {
                        "id": "",
                        "kind": "file.write",
                        "target": "x.txt",
                        "operation": "write",
                        "parameters": {"content": "safe"},
                        "materialStep": False,
                    }
                ]
            },
            "SOVA-REHEARSE-PROVIDER-OUTPUT",
        ),
        (
            {
                "actions": [
                    {
                        "id": "bad",
                        "kind": "host.escape",
                        "target": "x",
                        "operation": "x",
                        "parameters": {},
                        "materialStep": False,
                    }
                ]
            },
            "SOVA-REHEARSE-PROVIDER-OUTPUT",
        ),
        (
            {
                "actions": [
                    {
                        "id": "secret",
                        "kind": "file.write",
                        "target": "x.txt",
                        "operation": "write",
                        "parameters": {"content": "Bearer abcdefghijklmnopqrstuvwxyz"},
                        "materialStep": False,
                    }
                ]
            },
            "SOVA-REHEARSE-PROVIDER-SENSITIVE-OUTPUT",
        ),
    ],
)
def test_provider_output_is_strict_and_secret_free(
    tmp_path: Path,
    structured: dict[str, Any],
    code: str,
) -> None:
    workspace = _workspace(tmp_path)
    _model, router = _router(structured)
    with pytest.raises(FormatError) as captured:
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "artifacts",
            router=router,
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=_approver([]),
        )
    assert captured.value.issue.code == code


def test_provider_tool_call_and_missing_usage_fail_closed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    _model, tool_router = _router(_plan(), tool_calls=({"name": "forbidden"},))
    with pytest.raises(FormatError) as tool_error:
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "tool-artifacts",
            router=tool_router,
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=_approver([]),
        )
    assert tool_error.value.issue.code == "SOVA-MODEL-UNAVAILABLE"

    workspace_two = _workspace(tmp_path / "second")
    _model, no_usage_router = _router(_plan(), token_count=None)
    with pytest.raises(FormatError) as usage_error:
        run_provider_rehearsal(
            _request(),
            workspace_two,
            tmp_path / "usage-artifacts",
            router=no_usage_router,
            max_model_turns=1,
            max_total_tokens=100,
            provider_calls_authorized=True,
            approval_prompt=_approver([]),
        )
    assert usage_error.value.issue.code == "SOVA-REHEARSE-PROVIDER-BUDGET"


def test_provider_request_parser_and_preview_are_strict(tmp_path: Path) -> None:
    request = _request()
    parsed = provider_rehearsal_request_from_mapping(request.to_mapping())
    assert parsed == request
    workspace = _workspace(tmp_path)
    preview = preview_provider_rehearsal(parsed, workspace)
    assert preview["providerToolsAvailable"] is False
    assert preview["productionCredentialsImported"] is False

    malformed = request.to_mapping()
    malformed["unknown"] = True
    with pytest.raises(FormatError, match="request fields are invalid"):
        provider_rehearsal_request_from_mapping(malformed)


def test_provider_rehearsal_requires_explicit_call_permission(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    model, router = _router(_plan())
    with pytest.raises(FormatError) as captured:
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "artifacts",
            router=router,
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=False,
            approval_prompt=_approver([]),
        )
    assert captured.value.issue.code == "SOVA-PROVIDER-CALLS-NOT-ALLOWED"
    assert model.consumed == 0
