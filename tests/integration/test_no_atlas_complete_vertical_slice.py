# SPDX-License-Identifier: Apache-2.0
"""Complete safe no-Atlas behavior-capsule vertical slice."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sova.capsule import (
    DomainProfile,
    build_capsule,
    capsule_manifest_template,
    render_capsule,
)
from sova.executors import (
    OutcomeStatus,
    RestrictedLocalExecutor,
    ScriptedAction,
    ScriptedExecutor,
    SideEffect,
    run_capsule,
)
from sova.reproduction import compare_observable_outcomes
from sova.trace import TraceReader
from tests.support.authorization import authorize_synthetic_steps

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "sova_independent_verify.py"
PROGRAM = "import sys; print('TRIGGERED' if sys.argv[1] == 'blue-owl' else 'BASELINE')"


def _scenario(executable: str) -> dict[str, Any]:
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": "sova:scenario:019fb400-0000-7000-8000-000000000001",
        "version": "0.1.0",
        "title": "Safe no-Atlas conditional behavior",
        "purpose": "Observe a harmless planted label after an exact synthetic trigger.",
        "parameters": {"trigger": "blue-owl"},
        "preconditions": [{"kind": "fixture", "owned": True}],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "invoke-fixture",
                    "action": "process.exec",
                    "inputs": {
                        "argv": [executable, "-c", PROGRAM, "blue-owl"],
                        "resources": {"maxOutputBytes": 4096},
                    },
                    "onFailure": "stop",
                    "requires": ["process.exec/0.1"],
                }
            ]
        },
        "triggers": [{"kind": "exact-phrase", "parameter": "trigger"}],
        "mutations": [{"parameter": "trigger", "domain": ["blue-owl", "green-owl"]}],
        "expectedEffects": [{"kind": "stdout-label", "value": "TRIGGERED"}],
        "oracles": [{"kind": "field-contains", "path": "$.stdout", "contains": "TRIGGERED"}],
        "evidenceRequirements": [
            "tool.requested",
            "tool.completed",
            "oracle.completed",
        ],
        "safety": {
            "budgets": {"maxSteps": 1, "maxStepSeconds": 5},
            "forbiddenEffects": ["network.egress", "host.read", "host.write"],
            "stopConditions": [],
        },
        "cleanup": [],
        "limitations": [
            "Owned synthetic fixture only.",
            "Restricted host execution is not a security sandbox.",
        ],
        "extensions": {},
    }


def _manifest() -> dict[str, Any]:
    manifest = capsule_manifest_template(
        title="Safe no-Atlas conditional behavior",
        summary="A complete deterministic capsule, trace, and reproduction fixture.",
        author="SOVA OSS synthetic fixture authors",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1"]
    return manifest


def _scripted(inputs: dict[str, Any]) -> ScriptedExecutor:
    return ScriptedExecutor(
        [
            ScriptedAction(
                action="process.exec",
                expected_inputs=inputs,
                status=OutcomeStatus.SUCCEEDED,
                side_effect=SideEffect.MUTATE,
                output={"returncode": 0, "stdout": "TRIGGERED\n", "stderr": ""},
                verification="process-exit-and-bounded-output-observed",
            )
        ]
    )


def _independent_verify(path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


@pytest.mark.integration
def test_complete_no_atlas_vertical_slice(tmp_path: Path) -> None:
    executable = str(Path(sys.executable).resolve())
    scenario = _scenario(executable)
    source_capsule = tmp_path / "conditional-source.sova"
    build_capsule(source_capsule, _manifest(), scenario=scenario)
    authorization = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + ("9" * 64),
        "decidedBy": "synthetic-test",
    }

    scripted_trace = tmp_path / "scripted.sova-trace"
    scripted = _scripted(scenario["procedure"]["steps"][0]["inputs"])
    scripted_result = run_capsule(
        source_capsule,
        scripted_trace,
        executor=scripted,
        workspace=tmp_path,
        authorization=authorization,
    )

    local_trace = tmp_path / "local.sova-trace"
    with RestrictedLocalExecutor(executable_allowlist=(Path(executable),)) as local:
        fresh = authorize_synthetic_steps(scenario, local.capabilities())
        local_result = run_capsule(
            source_capsule,
            local_trace,
            executor=local,
            workspace=tmp_path,
            authorization_session=fresh.session,
            approvals=fresh.approvals,
        )

    assert scripted_result.completion == local_result.completion == "completed"
    assert scripted.complete
    for trace in (scripted_trace, local_trace):
        report = TraceReader(trace).verify()
        assert report.package_integrity and report.event_chain_integrity
        oracle = next(TraceReader(trace).query(kind_prefix="oracle.completed"))
        assert oracle["payload"]["status"] == "pass"
        assert TraceReader(trace).playback()
        disclosure = TraceReader(trace).disclosure_view(
            sequences={oracle["sequence"]},
            include_payload=False,
        )
        assert disclosure["selectedEventCount"] == 1
        assert disclosure["cryptographicSelectiveDisclosure"] is False
        assert _independent_verify(trace)["artifactType"] == "sova.trace"

    comparison = compare_observable_outcomes(
        scripted_trace,
        local_trace,
        kinds=("oracle.completed",),
    )
    assert comparison.equivalent

    evidence_capsule = tmp_path / "conditional-evidence.sova"
    build_capsule(
        evidence_capsule,
        _manifest(),
        scenario=scenario,
        traces=[scripted_trace, local_trace],
    )
    assert "Objects: 3" in render_capsule(evidence_capsule)
    independently_verified = _independent_verify(evidence_capsule)
    assert independently_verified["artifactType"] == "sova.capsule"
