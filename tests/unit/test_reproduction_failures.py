# SPDX-License-Identifier: Apache-2.0
"""Deterministic model and reproduction failure branches."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedModelError, ScriptedTurn
from sova.reproduction import compare_observable_outcomes, reproduce_with_scripted_model
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path


def _capsule(tmp_path: Path, scenario: dict[str, object]) -> Path:
    path = tmp_path / f"{len(list(tmp_path.iterdir()))}.sova"
    build_capsule(
        path,
        capsule_manifest_template(title="Fixture", summary="Fixture", author="Tester"),
        scenario=scenario,
    )
    return path


def test_scripted_model_completion_properties() -> None:
    assert ScriptedModel([]).complete
    assert not ScriptedModel([ScriptedTurn("expected", "ok")]).complete


def test_scripted_model_exhaustion_mismatch_and_failure() -> None:
    model = ScriptedModel([ScriptedTurn("expected", "ok")])
    with pytest.raises(ScriptedModelError, match="expected prompt"):
        model.respond("different")
    exhausted = ScriptedModel([])
    with pytest.raises(ScriptedModelError, match="exhausted"):
        exhausted.respond("expected")

    failing = ScriptedModel([ScriptedTurn("x", "never", failure="injected")])
    with pytest.raises(ScriptedModelError, match="injected"):
        failing.respond("x")


def test_unsupported_action_and_model_mismatch_create_failed_traces(tmp_path: Path) -> None:
    auth = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + "2" * 64,
        "decidedBy": "tester",
    }
    unsupported = scenario_template(title="Unsupported", purpose="Failure branch")
    unsupported["procedure"]["steps"][0]["action"] = "vendor.unsupported"
    result = reproduce_with_scripted_model(
        _capsule(tmp_path, unsupported),
        tmp_path / "unsupported.sova-trace",
        model=ScriptedModel([]),
        authorization=auth,
    )
    assert result.completion == "failed"

    mismatch = scenario_template(title="Mismatch", purpose="Failure branch")
    mismatch["procedure"]["steps"][0]["action"] = "model.prompt"
    mismatch["procedure"]["steps"][0]["inputs"] = {"text": "actual"}
    result = reproduce_with_scripted_model(
        _capsule(tmp_path, mismatch),
        tmp_path / "mismatch.sova-trace",
        model=ScriptedModel([ScriptedTurn("other", "no")]),
        authorization=auth,
    )
    assert result.completion == "failed"


def test_missing_scenario_and_prompt_fail_visibly(tmp_path: Path) -> None:
    empty = tmp_path / "empty.sova"
    build_capsule(
        empty,
        capsule_manifest_template(title="Empty", summary="Empty", author="Tester"),
    )
    with pytest.raises(FormatError) as no_scenario:
        reproduce_with_scripted_model(
            empty,
            tmp_path / "no.sova-trace",
            model=ScriptedModel([]),
            authorization={"decision": "allowed"},
        )
    assert no_scenario.value.issue.code == "SOVA-REPRODUCE-NO-SCENARIO"

    invalid = scenario_template(title="Invalid prompt", purpose="Failure branch")
    invalid["procedure"]["steps"][0]["action"] = "model.prompt"
    invalid["procedure"]["steps"][0]["inputs"] = {"other": "value"}
    result = reproduce_with_scripted_model(
        _capsule(tmp_path, invalid),
        tmp_path / "invalid.sova-trace",
        model=ScriptedModel([]),
        authorization={
            "decision": "allowed",
            "scopeDigest": None,
            "decidedBy": "tester",
        },
    )
    assert result.completion == "failed"


def test_comparison_detects_different_observable_outcomes(tmp_path: Path) -> None:
    scenario = scenario_template(title="Compare", purpose="Comparison")
    scenario["procedure"]["steps"][0]["action"] = "model.prompt"
    scenario["procedure"]["steps"][0]["inputs"] = {"text": "prompt"}
    capsule = _capsule(tmp_path, scenario)
    auth = {"decision": "allowed", "scopeDigest": None, "decidedBy": "tester"}
    left = reproduce_with_scripted_model(
        capsule,
        tmp_path / "left.sova-trace",
        model=ScriptedModel([ScriptedTurn("prompt", "left")]),
        authorization=auth,
    )
    right = reproduce_with_scripted_model(
        capsule,
        tmp_path / "right.sova-trace",
        model=ScriptedModel([ScriptedTurn("prompt", "right")]),
        authorization=auth,
    )
    assert not compare_observable_outcomes(left.trace_path, right.trace_path).equivalent


def test_scripted_reproduction_supports_parameter_context_tool_calls_and_approval(
    tmp_path: Path,
) -> None:
    scenario = scenario_template(title="Full fixture subset", purpose="Branch coverage")
    scenario["parameters"] = {"request": "hello", "context": "declared context"}
    scenario["procedure"]["steps"] = [
        {
            "id": "parameter",
            "action": "model.prompt",
            "inputs": {"textFromParameter": "request"},
            "onFailure": "stop",
            "requires": ["model.prompt"],
        },
        {
            "id": "context",
            "action": "model.prompt-with-context",
            "inputs": {
                "prompt": "describe",
                "contextFromParameter": "context",
            },
            "onFailure": "stop",
            "requires": ["model.prompt"],
        },
        {
            "id": "approval",
            "action": "agent.request-tool",
            "inputs": {"tool": "fixture.write", "arguments": {"value": "safe"}},
            "onFailure": "continue",
            "requires": ["agent.tool-request"],
        },
    ]
    capsule = _capsule(tmp_path, scenario)
    result = reproduce_with_scripted_model(
        capsule,
        tmp_path / "all-branches.sova-trace",
        model=ScriptedModel(
            [
                ScriptedTurn(
                    "hello",
                    "first",
                    tool_calls=({"tool": "fixture.read", "arguments": {}},),
                ),
                ScriptedTurn("declared context", "second"),
            ]
        ),
        authorization={
            "decision": "allowed",
            "scopeDigest": None,
            "decidedBy": "tester",
        },
    )
    assert result.completion == "completed"
    assert result.steps_attempted == 3
    kinds = [event["kind"] for event in TraceReader(result.trace_path).events()]
    assert kinds.count("tool.requested") == 2
    assert "blocked.approval" in kinds
