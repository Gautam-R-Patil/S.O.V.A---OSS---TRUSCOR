# SPDX-License-Identifier: Apache-2.0
"""Swarm coordinator: seed differentiated workers, merge into one `.sova`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.community.executor_chamber_config import validate_executor_chamber_document
from sova.community.swarm.blackboard import SwarmBlackboard
from sova.community.swarm.coordinator import AgentRunResult, SwarmCoordinator
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.formats import PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import TraceReader, TraceWriter

if TYPE_CHECKING:
    from pathlib import Path

_AUTHORITY_TARGET = "sova:sandbox:owned-executor-fixture"


def _scripted(identifier: str, value: str) -> dict[str, Any]:
    return {
        "adapter": "scripted",
        "modelId": f"fixture-{identifier}",
        "turns": [
            {
                "expectedContains": "sova.executor-chamber-planner/0.1.0",
                "responseText": "",
                "structured": {
                    "status": "continue",
                    "message": "bounded fixture proposal",
                    "actions": [{"grantId": "set-state", "arguments": {"value": value}}],
                    "coverage": ["fixture-state"],
                    "reason": "exercise the declared state transition",
                },
                "tokenCount": 1,
            }
        ],
    }


def _base_document() -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": _AUTHORITY_TARGET,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "owned-executor-fixture",
            "title": "Owned executor fixture",
            "objective": "Find and reproduce the declared observable state.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 1,
            "maxDurationSeconds": 30,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 2,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 0,
            "actionTimeoutSeconds": 5,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "set-state",
                "bindingId": "fixture-binding",
                "codecId": "fixture-codec",
                "description": "Set one owned in-memory fixture value.",
                "argumentSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["value"],
                    "properties": {"value": {"type": "string", "maxLength": 64}},
                },
            }
        ],
        "participants": [
            {
                "id": "worker",
                "objective": "Exercise only the declared bounded state transition.",
                "allowedGrants": ["set-state"],
                "model": _scripted("worker", "scanned"),
            }
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["state"],
            "contains": "vulnerable",
        },
    }


def test_seed_builds_one_spec_per_agent_with_distinct_objectives() -> None:
    coordinator = SwarmCoordinator()
    specs = coordinator.seed(_base_document(), agent_count=3)
    assert len(specs) == 3
    assert {spec.agent_id for spec in specs} == {"agent-01", "agent-02", "agent-03"}
    objectives = {spec.chamber_document["participants"][0]["objective"] for spec in specs}
    assert len(objectives) == 3  # each got a distinct focus area
    for spec in specs:
        objective = spec.chamber_document["participants"][0]["objective"]
        assert spec.persona in objective
        assert "3 agents" in objective


def test_seed_does_not_mutate_the_template() -> None:
    template = _base_document()
    original_objective = template["participants"][0]["objective"]
    SwarmCoordinator().seed(template, agent_count=2)
    assert template["participants"][0]["objective"] == original_objective


def test_seed_uses_supplied_personas_cyclically() -> None:
    specs = SwarmCoordinator().seed(_base_document(), agent_count=4, personas=("scout", "breaker"))
    assert [spec.persona for spec in specs] == ["scout", "breaker", "scout", "breaker"]


def test_seeded_documents_remain_schema_valid() -> None:
    specs = SwarmCoordinator().seed(_base_document(), agent_count=2)
    for spec in specs:
        validated = validate_executor_chamber_document(
            spec.chamber_document,
            provider_calls_authorized=False,
            offensive=False,
        )
        assert validated.authority.authority_target == _AUTHORITY_TARGET


def test_seed_rejects_zero_agents() -> None:
    with pytest.raises(FormatError, match="at least one"):
        SwarmCoordinator().seed(_base_document(), agent_count=0)


def test_seed_rejects_a_multi_participant_template() -> None:
    document = _base_document()
    document["participants"].append(
        {
            "id": "second",
            "objective": "second",
            "allowedGrants": ["set-state"],
            "model": _scripted("second", "x"),
        }
    )
    with pytest.raises(FormatError, match="exactly one real participant"):
        SwarmCoordinator().seed(document, agent_count=2)


def _fixture_trace(path: Path) -> Path:
    writer = TraceWriter(path)
    writer.append("run.started", {"note": "fixture worker run"}, phase="fixture")
    writer.append(
        "oracle.completed",
        {"status": "pass", "oracleId": "fixture-oracle", "evidenceDigests": [], "details": {}},
        phase="fixture",
    )
    writer.append("run.completed", {"completion": "completed"}, phase="fixture")
    writer.finalize(completion="completed")
    return path


class _FakeArtifacts:
    def __init__(self, trace: Path, report: Path, capsule: Path | None) -> None:
        self.trace = trace
        self.report = report
        self.capsule = capsule


def test_merge_builds_a_verifiable_swarm_capsule_from_real_agent_traces(tmp_path: Path) -> None:
    destination = tmp_path / "swarm"
    destination.mkdir()
    board = SwarmBlackboard()
    board.post(
        SwarmMessage(
            author_agent_id="agent-01",
            seq=0,
            kind=SwarmMessageKind.OBSERVATION,
            refs=(),
            payload={"summary": "clicked login"},
            posted_unix_ms=1_700_000_000_000,
        )
    )
    board.post(
        SwarmMessage(
            author_agent_id="agent-01",
            seq=1,
            kind=SwarmMessageKind.FINDING,
            refs=(),
            payload={"summary": "status='pass'", "chamberEventId": "evt-1"},
            posted_unix_ms=1_700_000_000_001,
        )
    )
    board.post(
        SwarmMessage(
            author_agent_id="agent-02",
            seq=0,
            kind=SwarmMessageKind.FINDING,
            refs=(),
            # Same summary text as agent-01's finding -> must be deduplicated.
            payload={"summary": "status='pass'", "chamberEventId": "evt-2"},
            posted_unix_ms=1_700_000_000_002,
        )
    )

    agent_one_trace = _fixture_trace(destination / "agent-01.sova-trace")
    agent_two_trace = _fixture_trace(destination / "agent-02.sova-trace")
    agent_one_capsule = destination / "agent-01-source.sova"
    build_capsule(
        agent_one_capsule,
        capsule_manifest_template(
            title="Agent one finding",
            summary="Bounded nested fixture finding.",
            author="SOVA fixture",
        ),
    )
    results = (
        AgentRunResult(
            "agent-01",
            "scout",
            "pass",
            _FakeArtifacts(
                agent_one_trace,
                destination / "agent-01-report.json",
                agent_one_capsule,
            ),  # type: ignore[arg-type]
            None,
        ),
        AgentRunResult(
            "agent-02",
            "breaker",
            "pass",
            _FakeArtifacts(agent_two_trace, destination / "agent-02-report.json", None),  # type: ignore[arg-type]
            None,
        ),
        AgentRunResult("agent-03", "third", "failed", None, "synthetic worker failure"),
    )

    report = SwarmCoordinator().merge(
        results,
        blackboard=board,
        destination=destination,
        target_digest="sha256:" + "1" * 64,
    )

    assert report["agentCount"] == 3
    assert len(report["mergedFindings"]) == 1  # deduplicated across agent-01 and agent-02
    assert report["boardMessageCount"] == 3
    assert report["boardChainHead"] == board.chain_head_digest()

    coordinator_trace = destination / "coordinator.sova-trace"
    assert coordinator_trace.is_file()
    verification = TraceReader(coordinator_trace).verify(require_signature=True)
    assert verification.signature_valid

    capsule_path = destination / "swarm.sova"
    assert capsule_path.is_file()
    descriptors = PackageReader(capsule_path).verify("sova.capsule")
    trace_paths = {item.path for item in descriptors if item.role == "trace"}
    assert trace_paths == {
        "traces/coordinator.sova-trace",
        "traces/agent-01.sova-trace",
        "traces/agent-02.sova-trace",
    }
    nested = [item for item in descriptors if item.role == "capsule"]
    assert [item.path for item in nested] == ["capsules/agent-01-finding.sova"]
    assert report["nestedFindingCapsules"] == ["capsules/agent-01-finding.sova"]


def test_merge_builds_valid_inconclusive_capsule_when_no_worker_found_issue(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "empty-finding-swarm"
    destination.mkdir()
    trace = _fixture_trace(destination / "agent-01.sova-trace")
    results = (
        AgentRunResult(
            "agent-01",
            "scout",
            "not-observed",
            _FakeArtifacts(trace, destination / "agent-01-report.json", None),  # type: ignore[arg-type]
            None,
        ),
    )

    report = SwarmCoordinator().merge(
        results,
        blackboard=SwarmBlackboard(),
        destination=destination,
        target_digest="sha256:" + "2" * 64,
    )

    capsule = destination / "swarm.sova"
    descriptors = PackageReader(capsule).verify("sova.capsule")
    scenario_descriptor = next(item for item in descriptors if item.role == "scenario")
    scenario = strict_json_loads(PackageReader(capsule).read_object(scenario_descriptor))
    assert isinstance(scenario, dict)
    assert scenario["procedure"]["steps"] == [
        {
            "id": "inspect-no-reproduced-finding",
            "action": "sova.swarm.inspect-report",
            "inputs": {
                "reportDigest": scenario["procedure"]["steps"][0]["inputs"]["reportDigest"],
                "findingCount": 0,
            },
            "onFailure": "inconclusive",
            "requires": ["swarm.report.inspect/0.1"],
        }
    ]
    assert report["nestedFindingCapsules"] == []
