# SPDX-License-Identifier: Apache-2.0
"""Opt-in live conformance: a real concurrent multi-agent swarm over a real browser.

The swarm case proves concurrent independent launch and merge without claiming
a finding. The actionful engine case then types, clicks, confirms the planted
owned behavior, repeats the same typed inputs in a fresh browser/session, and
packages the signed traces plus exact-time WebM evidence in one `.sova`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from sova.community.executor_engine_runtime_config import (
    build_executor_engine_runtime_surfaces,
    parse_executor_engine_runtime_document,
)
from sova.community.live_executor_engine import run_live_web_executor_engine
from sova.community.swarm.budget import SwarmAggregateBudget
from sova.community.swarm.runtime import run_web_swarm
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.live import OwnedWebFixture, owned_web_target
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader

pytestmark = pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_BROWSER") != "1",
    reason="set SOVA_RUN_REAL_BROWSER=1 for the optional installed-browser lane",
)

_NPX = Path(r"C:\Program Files\nodejs\npx.cmd")
_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
_PLAYWRIGHT_BROWSERS = Path(".cache/playwright-browsers").resolve()


def _stopping_model(agent_label: str) -> dict[str, Any]:
    return {
        "adapter": "scripted",
        "modelId": f"fixture-{agent_label}",
        "turns": [
            {
                "expectedContains": "sova.executor-chamber-planner/0.1.0",
                "responseText": "",
                "structured": {
                    "status": "stop",
                    "message": "live conformance probe; taking no action.",
                    "actions": [],
                    "coverage": [],
                    "reason": "prove real concurrent launch, proof-of-control, and merge only.",
                },
                "tokenCount": 1,
            }
        ],
    }


def _base_document(host: str) -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": host,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "real-browser-swarm-probe",
            "title": "Real browser swarm live conformance probe",
            "objective": "Prove real concurrent multi-agent browser launch and merge.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 1,
            "maxDurationSeconds": 60,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 0,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 0,
            "actionTimeoutSeconds": 10,
            "stopOnSuccess": True,
            "captureProfile": "standard",
        },
        "grants": [
            {
                "id": "browser-observe",
                "bindingId": "binding:browser:browser-navigate:0.1",
                "codecId": "sova.action-codec.browser/0.1.0",
                "description": "Observe the entry page only; this probe never mutates.",
                "argumentSchema": {"type": "object"},
            }
        ],
        "participants": [
            {
                "id": "worker",
                "objective": "Take no action; this run only proves real infrastructure wiring.",
                "allowedGrants": ["browser-observe"],
                "model": _stopping_model("worker"),
            }
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["browser", "snapshot"],
            "contains": "SOVA-LIVE-SWARM-PROBE-NEVER-MATCHES",
        },
    }


def _mission(entry_url: str) -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova-real-swarm-probe",
        title="Real swarm live conformance probe",
        entry_url=entry_url,
        objective="Load the entry page only; take no further action.",
        allowed_actions=("browser.navigate",),
        seed_inputs=("probe",),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA-LIVE-SWARM-PROBE-NEVER-MATCHES",
        max_planner_turns=1,
        max_actions=1,
        max_actions_per_plan=1,
        max_duration_seconds=60,
        max_pages=1,
        max_mutations=0,
        max_consecutive_failures=1,
        max_generated_text_characters=512,
        max_total_tokens=None,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def _actionful_model() -> dict[str, Any]:
    def turn(
        grant_id: str,
        action: str,
        arguments: dict[str, Any],
        coverage: str,
    ) -> dict[str, Any]:
        return {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": f"Execute the reviewed {coverage} step.",
                "actions": [
                    {
                        "grantId": grant_id,
                        "arguments": {
                            "action": action,
                            "arguments": arguments,
                            "observationDigest": "$SOVA_OBSERVATION_DIGEST",
                        },
                    }
                ],
                "coverage": [coverage],
                "reason": "Exercise the exact owned fixture workflow.",
            },
            "tokenCount": 1,
        }

    return {
        "adapter": "scripted",
        "modelId": "fixture-actionful-browser",
        "turns": [
            turn(
                "browser-type",
                "browser.type",
                {
                    "element": "Message",
                    "ref": "e5",
                    "text": "enable research mode",
                },
                "arm owned workflow",
            ),
            turn(
                "browser-click",
                "browser.click",
                {"element": "Send", "ref": "e6"},
                "submit arm state",
            ),
            turn(
                "browser-type",
                "browser.type",
                {"element": "Message", "ref": "e5", "text": "blue owl"},
                "enter trigger",
            ),
            turn(
                "browser-click",
                "browser.click",
                {"element": "Send", "ref": "e6"},
                "submit trigger",
            ),
        ],
    }


def _actionful_document(host: str) -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": host,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "real-actionful-recorded-browser",
            "title": "Real actionful recorded browser finding",
            "objective": "Exercise and reproduce the harmless planted owned behavior.",
        },
        "budget": {
            "rounds": 4,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 4,
            "maxDurationSeconds": 120,
            "maxOutputBytes": 16384,
            "maxTotalTokens": 16,
            "maxMutations": 4,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 4,
            "actionTimeoutSeconds": 20,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "browser-type",
                "bindingId": "binding:browser:browser-type:0.1",
                "codecId": "sova.action-codec.browser/0.1.0",
                "description": "Type bounded public fixture text into one current reviewed field.",
                "argumentSchema": {"type": "object"},
            },
            {
                "id": "browser-click",
                "bindingId": "binding:browser:browser-click:0.1",
                "codecId": "sova.action-codec.browser/0.1.0",
                "description": "Click one current reviewed element in the owned fixture.",
                "argumentSchema": {"type": "object"},
            },
        ],
        "participants": [
            {
                "id": "action-worker",
                "objective": "Execute only the four-step planted behavior workflow.",
                "allowedGrants": ["browser-type", "browser-click"],
                "model": _actionful_model(),
            },
            {
                "id": "independent-observer",
                "objective": "Stop immediately; deterministic sensors and reproduction judge.",
                "allowedGrants": ["browser-click"],
                "model": _stopping_model("actionful-independent-observer"),
            },
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["browser", "snapshot"],
            "contains": "SOVA_FIXTURE_TRIGGERED",
        },
    }


def _actionful_mission(entry_url: str) -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova-real-actionful-recorded-browser",
        title="Real actionful recorded browser finding",
        entry_url=entry_url,
        objective="Exercise and reproduce the harmless planted owned behavior.",
        allowed_actions=("browser.type", "browser.click"),
        seed_inputs=("enable research mode", "blue owl"),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA_FIXTURE_TRIGGERED",
        max_planner_turns=4,
        max_actions=4,
        max_actions_per_plan=1,
        max_duration_seconds=120,
        max_pages=1,
        max_mutations=4,
        max_consecutive_failures=1,
        max_generated_text_characters=128,
        max_total_tokens=16,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


@pytest.mark.integration
def test_optional_real_web_swarm_launches_concurrently_and_merges(tmp_path: Path) -> None:
    with OwnedWebFixture() as fixture:
        target = owned_web_target(fixture.url)
        document = _base_document("127.0.0.1")
        mission = _mission(fixture.url)
        artifacts = run_web_swarm(
            target,
            mission,
            document,
            tmp_path / "real-swarm",
            agent_count=3,
            package_runner=_NPX,
            browser_executable=_CHROME,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            target_observation_disclosure_authorized=True,
            headless=True,
        )
    assert artifacts.agent_count == 3
    assert artifacts.swarm_capsule.exists()
    assert artifacts.coordinator_trace.exists()
    assert TraceReader(artifacts.coordinator_trace).verify(require_signature=True).signature_valid
    assert verify_artifact(artifacts.swarm_capsule).state in {
        VerificationState.VERIFIED,
        VerificationState.PARTIAL,
    }
    report = artifacts.report
    assert report["agentCount"] == 3
    per_agent = report["perAgentSummaries"]
    assert len(per_agent) == 3
    agent_ids = {item["agentId"] for item in per_agent}
    assert agent_ids == {"agent-01", "agent-02", "agent-03"}
    for item in per_agent:
        assert item["trace"] is not None
        assert Path(item["trace"]).exists()


@pytest.mark.integration
def test_optional_real_web_engine_finalizes_recorded_nonfinding_session(tmp_path: Path) -> None:
    """Recording must be real even when no finding/cue/capsule is claimed."""
    with OwnedWebFixture() as fixture:
        target = owned_web_target(fixture.url)
        document = _base_document("127.0.0.1")
        document["participants"].append(
            {
                "id": "independent-observer",
                "objective": "Stop without action and independently confirm no finding claim.",
                "allowedGrants": ["browser-observe"],
                "model": _stopping_model("independent-observer"),
            }
        )
        artifacts = run_live_web_executor_engine(
            target,
            _mission(fixture.url),
            document,
            tmp_path / "real-recorded-engine",
            package_runner=_NPX,
            browser_executable=_CHROME,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            target_observation_disclosure_authorized=True,
            headless=True,
            record_video=True,
            browser_cache=_PLAYWRIGHT_BROWSERS,
        )
    assert artifacts.status == "not-observed"
    assert artifacts.capsule is None
    assert artifacts.replay_cues == ()
    assert len(artifacts.visual_replays) == 1
    assert artifacts.visual_replays[0].read_bytes().startswith(b"\x1a\x45\xdf\xa3")


@pytest.mark.integration
def test_optional_real_web_engine_records_reproduces_and_packages_exact_finding(
    tmp_path: Path,
) -> None:
    with OwnedWebFixture() as fixture:
        target = owned_web_target(fixture.url)
        artifacts = run_live_web_executor_engine(
            target,
            _actionful_mission(fixture.url),
            _actionful_document("127.0.0.1"),
            tmp_path / "real-actionful-recorded-engine",
            package_runner=_NPX,
            browser_executable=_CHROME,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            target_observation_disclosure_authorized=True,
            headless=True,
            record_video=True,
            browser_cache=_PLAYWRIGHT_BROWSERS,
        )
    assert artifacts.status == "pass"
    assert artifacts.reproduction_trace is not None
    assert artifacts.capsule is not None
    assert len(artifacts.visual_replays) == 2
    assert len(artifacts.replay_cues) == 2
    assert all(
        path.read_bytes().startswith(b"\x1a\x45\xdf\xa3") for path in artifacts.visual_replays
    )
    descriptors = PackageReader(artifacts.capsule).verify("sova.capsule")
    assert len([item for item in descriptors if item.role == "trace"]) == 2
    assert len([item for item in descriptors if item.role == "scenario"]) == 1
    assert len([item for item in descriptors if item.role == "visual-replay"]) == 2
    assert len([item for item in descriptors if item.role == "replay-cues"]) == 1


def _heterogeneous_model() -> dict[str, Any]:
    def turn(
        grant_id: str,
        action: str,
        arguments: dict[str, Any],
        coverage: str,
    ) -> dict[str, Any]:
        proposal: dict[str, Any] = {"action": action, "arguments": arguments}
        if action.startswith("browser."):
            proposal["observationDigest"] = "$SOVA_OBSERVATION_DIGEST"
        return {
            "expectedContains": "sova.executor-chamber-planner/0.1.0",
            "responseText": "",
            "structured": {
                "status": "continue",
                "message": f"Execute the reviewed {coverage} step.",
                "actions": [{"grantId": grant_id, "arguments": proposal}],
                "coverage": [coverage],
                "reason": "Exercise one exact authorized surface in the owned fixture.",
            },
            "tokenCount": 1,
        }

    return {
        "adapter": "scripted",
        "modelId": "fixture-heterogeneous-swarm",
        "turns": [
            turn(
                "workspace-write",
                "filesystem.write",
                {
                    "path": "swarm-proof.txt",
                    "content": "SOVA_WORKSPACE_OK",
                    "overwrite": False,
                },
                "disposable workspace write",
            ),
            turn(
                "process-run",
                "process.exec",
                {"args": ["-c", "print('SOVA_PROCESS_OK')"], "cwd": "."},
                "reviewed shell-free process execution",
            ),
            turn(
                "browser-type",
                "browser.type",
                {"element": "Message", "ref": "e5", "text": "enable research mode"},
                "browser workflow arm input",
            ),
            turn(
                "browser-click",
                "browser.click",
                {"element": "Send", "ref": "e6"},
                "browser workflow arm submission",
            ),
            turn(
                "browser-type",
                "browser.type",
                {"element": "Message", "ref": "e5", "text": "blue owl"},
                "browser workflow trigger input",
            ),
            turn(
                "browser-click",
                "browser.click",
                {"element": "Send", "ref": "e6"},
                "browser workflow trigger submission",
            ),
        ],
    }


def _heterogeneous_document(host: str) -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": host,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "real-heterogeneous-actionful-swarm",
            "title": "Real browser, file, and process swarm finding",
            "objective": "Exercise heterogeneous surfaces and reproduce the owned finding.",
        },
        "budget": {
            "rounds": 6,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 6,
            "maxDurationSeconds": 180,
            "maxOutputBytes": 16384,
            "maxTotalTokens": 16,
            "maxMutations": 6,
            "maxProcesses": 1,
            "maxFiles": 1,
            "maxNetworkRequests": 4,
            "actionTimeoutSeconds": 20,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "workspace-write",
                "bindingId": "binding:workspace:filesystem-write:0.1",
                "codecId": "sova.action-codec.workspace/0.1.0",
                "description": "Write one bounded public proof file in the disposable workspace.",
                "argumentSchema": {"type": "object"},
            },
            {
                "id": "process-run",
                "bindingId": "binding:process-python:process-exec:0.1",
                "codecId": "sova.action-codec.process.python/0.1.0",
                "description": "Run the exact reviewed Python process without a shell.",
                "argumentSchema": {"type": "object"},
            },
            {
                "id": "browser-type",
                "bindingId": "binding:browser:browser-type:0.1",
                "codecId": "sova.action-codec.browser/0.1.0",
                "description": "Type bounded public fixture text into one reviewed field.",
                "argumentSchema": {"type": "object"},
            },
            {
                "id": "browser-click",
                "bindingId": "binding:browser:browser-click:0.1",
                "codecId": "sova.action-codec.browser/0.1.0",
                "description": "Click one current reviewed element in the owned fixture.",
                "argumentSchema": {"type": "object"},
            },
        ],
        "participants": [
            {
                "id": "heterogeneous-worker",
                "objective": "Use file, process, and browser surfaces in the exact six-step plan.",
                "allowedGrants": [
                    "workspace-write",
                    "process-run",
                    "browser-type",
                    "browser-click",
                ],
                "model": _heterogeneous_model(),
            }
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["browser", "snapshot"],
            "contains": "SOVA_FIXTURE_TRIGGERED",
        },
    }


@pytest.mark.integration
def test_optional_real_actionful_swarm_uses_browser_file_process_and_embeds_proof(
    tmp_path: Path,
) -> None:
    runtime_document = {
        "artifactType": "sova.executor-engine-runtime",
        "schemaVersion": "0.1.0",
        "workspace": {"enabled": False, "maxReadBytes": 8192, "maxWriteBytes": 8192},
        "hostProcesses": [
            {
                "id": "python",
                "executable": str(Path(sys.executable).resolve()),
                "argvPrefix": [],
                "maxArgs": 16,
                "maxArgBytes": 16384,
                "maxOutputBytes": 65536,
                "trustedHostProcessAcknowledged": True,
            }
        ],
    }
    builder = build_executor_engine_runtime_surfaces(
        parse_executor_engine_runtime_document(runtime_document)
    )
    preview = builder("primary")
    try:
        contract_digest = sha256_digest(
            canonical_json_bytes(
                [
                    surface.contract_mapping()
                    for surface in sorted(preview, key=lambda item: item.sensor_name)
                ]
            )
        )
    finally:
        for surface in reversed(preview):
            surface.close()

    with OwnedWebFixture() as fixture:
        artifacts = run_web_swarm(
            owned_web_target(fixture.url),
            _actionful_mission(fixture.url),
            _heterogeneous_document("127.0.0.1"),
            tmp_path / "real-heterogeneous-swarm",
            agent_count=2,
            package_runner=_NPX,
            browser_executable=_CHROME,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            target_observation_disclosure_authorized=True,
            headless=True,
            record_video=True,
            browser_cache=_PLAYWRIGHT_BROWSERS,
            aggregate_budget=SwarmAggregateBudget(
                max_total_actions=24,
                max_duration_seconds=180,
                max_mutations=24,
                max_processes=4,
                max_files=4,
                max_network_requests=16,
            ),
            additional_surface_factory=builder,
            additional_codec_factories=builder.codec_factories,
            additional_surface_contract_digest=contract_digest,
        )

    summaries = artifacts.report["perAgentSummaries"]
    assert [item["status"] for item in summaries] == ["pass", "pass"]
    assert artifacts.report["aggregateBudget"]["consumed"] == {
        "totalActions": 24,
        "mutations": 24,
        "processes": 4,
        "files": 4,
        "networkRequests": 16,
    }
    descriptors = PackageReader(artifacts.swarm_capsule).verify("sova.capsule")
    assert len([item for item in descriptors if item.role == "capsule"]) == 2
    for summary in summaries:
        report = strict_json_loads(Path(summary["report"]).read_bytes())
        assert report["primary"]["actions"] == 6
        assert report["reproduction"]["equivalent"] is True
        assert Path(summary["capsule"]).is_file()
