# SPDX-License-Identifier: Apache-2.0
"""Portable capsule conformance across deterministic and MCP executors."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.executors import OutcomeStatus, ScriptedAction, ScriptedExecutor, SideEffect, run_capsule
from sova.mcp import MCPExecutorAdapter, StdioMCPClient, StdioServerSpec, ToolMapping
from sova.reproduction import compare_observable_outcomes
from sova.trace import TraceReader


def _scenario() -> dict[str, Any]:
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": "sova:scenario:019fc100-0000-7000-8000-000000000013",
        "version": "0.1.0",
        "title": "MCP executor conformance fixture",
        "purpose": "Compare one portable read-only intent across independent adapters.",
        "parameters": {},
        "preconditions": [{"kind": "fixture", "owned": True}],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "echo-fixture",
                    "action": "fixture.echo",
                    "inputs": {"value": "owl"},
                    "onFailure": "stop",
                    "requires": ["fixture.echo/0.1"],
                }
            ]
        },
        "triggers": [],
        "mutations": [],
        "expectedEffects": [{"kind": "echo", "value": "owl"}],
        "oracles": [{"kind": "exact-field", "path": "$.structured.echo", "equals": "owl"}],
        "evidenceRequirements": ["tool.requested", "tool.completed", "oracle.completed"],
        "safety": {
            "budgets": {"maxSteps": 1, "maxStepSeconds": 5},
            "forbiddenEffects": ["host.write", "network.egress"],
            "stopConditions": [],
        },
        "cleanup": [],
        "limitations": ["Owned deterministic fixture only."],
        "extensions": {},
    }


@pytest.mark.integration
def test_same_capsule_has_same_declared_outcome_through_mcp(tmp_path: Path) -> None:
    scenario = _scenario()
    manifest = capsule_manifest_template(
        title=scenario["title"],
        summary="Executor conformance without an external credential or network.",
        author="SOVA deterministic test authors",
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "mcp-conformance.sova"
    build_capsule(capsule, manifest, scenario=scenario)
    authorization = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + ("1" * 64),
        "decidedBy": "synthetic-test",
    }

    scripted_trace = tmp_path / "scripted.sova-trace"
    scripted = ScriptedExecutor(
        [
            ScriptedAction(
                action="fixture.echo",
                expected_inputs={"value": "owl"},
                status=OutcomeStatus.SUCCEEDED,
                side_effect=SideEffect.READ,
                output={"text": ["owl"], "structured": {"echo": "owl"}},
                verification="direct-read-observation",
            )
        ]
    )
    run_capsule(
        capsule,
        scripted_trace,
        executor=scripted,
        workspace=tmp_path,
        authorization=authorization,
    )

    fake_server = Path(__file__).parents[1] / "support" / "fake_mcp_server.py"
    spec = StdioServerSpec(
        "sova-conformance-fixture",
        (str(Path(sys.executable).resolve()), str(fake_server)),
        tmp_path,
        {},
        "0.1.0",
        "tests/support/fake_mcp_server.py",
        "Apache-2.0",
    )
    mcp_trace = tmp_path / "mcp.sova-trace"
    with StdioMCPClient(spec) as client:
        executor = MCPExecutorAdapter(
            "fixture-mcp",
            client,
            (
                ToolMapping(
                    action="fixture.echo",
                    tool="fixture_echo",
                    version="0.1",
                    side_effect=SideEffect.READ,
                    idempotent=True,
                    evidence=("mcp-text", "mcp-structured"),
                    argument_builder=dict,
                ),
            ),
        )
        run_capsule(
            capsule,
            mcp_trace,
            executor=executor,
            workspace=tmp_path,
            authorization=authorization,
        )

    for trace in (scripted_trace, mcp_trace):
        report = TraceReader(trace).verify()
        assert report.package_integrity and report.event_chain_integrity
        oracle = next(TraceReader(trace).query(kind_prefix="oracle.completed"))
        assert oracle["payload"]["status"] == "pass"
    comparison = compare_observable_outcomes(
        scripted_trace,
        mcp_trace,
        kinds=("oracle.completed",),
    )
    assert comparison.status == "equivalent"
