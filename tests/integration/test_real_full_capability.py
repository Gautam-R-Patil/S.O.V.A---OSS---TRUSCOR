# SPDX-License-Identifier: Apache-2.0
"""Opt-in live conformance: real browser + real MELRA computer + real process,
composed by `run_full_capability_web_engine` under one proof-of-control gate.

Like the other live-conformance modules in this directory, both participants
are scripted models that stop on their first turn -- this proves
the *composition* wires together (contract-digest pinning, session-identity
derivation for the computer surface, admission of a fourth codec) against real
subprocesses, not that any one surface's mutation algebra works end to end
(browser mutations are covered by the existing Playwright live lane; computer
mutations by the unit fake-transport suite; process execution by
`tests/unit/test_executor_surfaces.py`'s real-subprocess process tests).

Requires both `SOVA_RUN_REAL_BROWSER=1` and `SOVA_RUN_MELRA=1` (plus
`SOVA_MELRA_NODE`/`SOVA_MELRA_CLI`) since it launches all three backends at
once. `MelraComputerSnapshotSource` calls `computer.inspect` without a pid or
window id (see `test_real_melra_computer.py`). This composition check now also
requires an exact executable, live pid, and live owned top-level window; SOVA
measures all three before it admits the computer surface. No placeholder
identity is accepted.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from sova.community.executor_engine_full import (
    LocalComputerAuthorization,
    MelraComputerBackendSpec,
    run_full_capability_web_engine,
)
from sova.community.executor_surfaces import ExactProcessSurfaceSpec
from sova.community.software_executor_engine import create_local_software_control_proof
from sova.live import OwnedWebFixture, owned_web_target
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime.software_target import attest_software_target
from sova.targets import TargetKind, TargetManifest
from sova.trace import TraceReader

pytestmark = pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_BROWSER") != "1"
    or os.environ.get("SOVA_RUN_MELRA") != "1"
    or any(
        not os.environ.get(name)
        for name in (
            "SOVA_MELRA_NODE",
            "SOVA_MELRA_CLI",
            "SOVA_MELRA_TARGET_EXECUTABLE",
            "SOVA_MELRA_TARGET_PID",
            "SOVA_MELRA_TARGET_WINDOW_ID",
        )
    ),
    reason="set the real browser, MELRA, and measured target executable/pid/window variables",
)

_NPX = Path(r"C:\Program Files\nodejs\npx.cmd")
_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")


def _melra_policy_factory(workspace: Path) -> Path:
    """`MelraDirectories.policy` must resolve inside the admitted `workspace`
    the engine actually creates for this run (see `mcp.specs._inside`), so the
    policy file is written there, not into a separate fixture directory."""
    policy = workspace / "melra-policy.json"
    policy.write_text(
        json.dumps(
            {
                "version": "sova-live-conformance",
                "workspaceRoot": str(workspace.resolve()),
                "allowedCommands": [],
                "allowedDomains": [],
                "allowLocalhost": True,
                "mutations": "confirm",
                "approvalTtlMs": 300_000,
                "maxFileBytes": 1_000_000,
            }
        ),
        encoding="utf-8",
    )
    return policy


def _stopping_model() -> dict[str, Any]:
    return {
        "adapter": "scripted",
        "modelId": "fixture-full-capability",
        "turns": [
            {
                "expectedContains": "sova.executor-chamber-planner/0.1.0",
                "responseText": "",
                "structured": {
                    "status": "stop",
                    "message": "live full-capability composition probe; taking no action.",
                    "actions": [],
                    "coverage": [],
                    "reason": "prove real browser+computer+process composition wiring only.",
                },
                "tokenCount": 1,
            }
        ],
    }


def _document(host: str) -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": host,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "real-full-capability-probe",
            "title": "Real full-capability composition live conformance probe",
            "objective": "Prove real browser+computer+process surface composition.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 1,
            "maxDurationSeconds": 90,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 0,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 0,
            "actionTimeoutSeconds": 15,
            "stopOnSuccess": True,
            "captureProfile": "standard",
        },
        "grants": [
            {
                "id": "browser-observe",
                "bindingId": "binding:browser:browser-navigate:0.1",
                "codecId": "sova.action-codec.browser/0.1.0",
                "description": "Observe the entry page only.",
                "argumentSchema": {"type": "object"},
            },
            {
                "id": "computer-observe",
                "bindingId": "binding:computer:computer-inspect:0.1",
                "codecId": "sova.action-codec.computer/0.1.0",
                "description": "Observe the composed MELRA window only.",
                "argumentSchema": {"type": "object"},
            },
            {
                "id": "process-run",
                "bindingId": "binding:process-python:process-exec:0.1",
                "codecId": "sova.action-codec.process/0.1.0",
                "description": "Run the reviewed process template.",
                "argumentSchema": {"type": "object"},
            },
        ],
        "participants": [
            {
                "id": "worker-a",
                "objective": "Take no action; this run only proves real composition wiring.",
                "allowedGrants": ["browser-observe", "computer-observe", "process-run"],
                "model": _stopping_model(),
            },
            {
                "id": "worker-b",
                "objective": "Independently stop; this run only proves real composition wiring.",
                "allowedGrants": ["browser-observe", "computer-observe", "process-run"],
                "model": _stopping_model(),
            },
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["browser", "snapshot"],
            "contains": "SOVA-LIVE-FULL-CAPABILITY-PROBE-NEVER-MATCHES",
        },
    }


def _mission(entry_url: str) -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova-real-full-capability-probe",
        title="Real full-capability composition live conformance probe",
        entry_url=entry_url,
        objective="Load the entry page only; take no further action.",
        allowed_actions=("browser.navigate",),
        seed_inputs=("probe",),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA-LIVE-FULL-CAPABILITY-PROBE-NEVER-MATCHES",
        max_planner_turns=1,
        max_actions=1,
        max_actions_per_plan=1,
        max_duration_seconds=90,
        max_pages=1,
        max_mutations=0,
        max_consecutive_failures=1,
        max_generated_text_characters=512,
        max_total_tokens=None,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


@pytest.mark.integration
def test_optional_real_full_capability_composes_browser_computer_and_process(
    tmp_path: Path,
) -> None:
    node = Path(os.environ["SOVA_MELRA_NODE"])
    cli = Path(os.environ["SOVA_MELRA_CLI"])
    executable = Path(os.environ["SOVA_MELRA_TARGET_EXECUTABLE"])
    software_target = TargetManifest(
        "sova:target:owned-melra-full-capability",
        TargetKind.LOCAL_PROCESS,
        "0.1.0",
        ("process.invoke", "computer.observe", "computer.click", "computer.type"),
        "operator-owned measured MELRA composition target",
        {"authorityBasis": "self", "interface": "measured-window"},
    )
    computer = MelraComputerBackendSpec(
        node_executable=node,
        cli_entrypoint=cli,
        policy_factory=_melra_policy_factory,
        authorization=LocalComputerAuthorization(
            software_target,
            create_local_software_control_proof(software_target, executable),
            attest_software_target(
                executable,
                pid=int(os.environ["SOVA_MELRA_TARGET_PID"]),
                window_id=int(os.environ["SOVA_MELRA_TARGET_WINDOW_ID"]),
            ),
        ),
    )
    process_template = ExactProcessSurfaceSpec(
        "python",
        Path(sys.executable).resolve(),
        trusted_host_process_acknowledged=True,
    )

    with OwnedWebFixture() as fixture:
        target = owned_web_target(fixture.url)
        artifacts = run_full_capability_web_engine(
            target,
            _mission(fixture.url),
            _document("127.0.0.1"),
            tmp_path / "real-full-capability",
            package_runner=_NPX,
            browser_executable=_CHROME,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            target_observation_disclosure_authorized=True,
            computer=computer,
            process_template=process_template,
            headless=True,
        )
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    assert artifacts.status == "not-observed"
    assert artifacts.capsule is None
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["primary"]["actions"] == 0
    assert report["evidence"]["capsule"] is None
