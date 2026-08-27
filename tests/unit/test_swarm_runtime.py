# SPDX-License-Identifier: Apache-2.0
"""Swarm runtime: concurrency, per-agent isolation, and merge orchestration."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any

import pytest

import sova.community.swarm.runtime as runtime_module
from sova.community.swarm.coordinator import SwarmCoordinator
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

    from sova.community.swarm.coordinator import AgentRunResult

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


class _FakeTarget:
    digest = "sha256:" + "2" * 64


def test_rejects_agent_count_outside_bounds() -> None:
    with pytest.raises(FormatError, match="admitted range"):
        runtime_module.run_web_swarm(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            _base_document(),
            "destination",  # type: ignore[arg-type]
            agent_count=0,
            package_runner="pr",  # type: ignore[arg-type]
            browser_executable="be",  # type: ignore[arg-type]
            approval_prompt=lambda _challenge, _intents: "x",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
        )
    with pytest.raises(FormatError, match="admitted range"):
        runtime_module.run_web_swarm(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            _base_document(),
            "destination",  # type: ignore[arg-type]
            agent_count=9,
            package_runner="pr",  # type: ignore[arg-type]
            browser_executable="be",  # type: ignore[arg-type]
            approval_prompt=lambda _challenge, _intents: "x",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
        )


def test_large_swarm_allowed_only_with_explicit_opt_in(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="admitted range"):
        runtime_module.run_web_swarm(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            _base_document(),
            tmp_path / "swarm",
            agent_count=9,
            package_runner="pr",  # type: ignore[arg-type]
            browser_executable="be",  # type: ignore[arg-type]
            approval_prompt=lambda _challenge, _intents: "x",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
            allow_large_swarm=False,
        )


def test_rejects_a_nonempty_destination(tmp_path: Path) -> None:
    destination = tmp_path / "swarm"
    destination.mkdir()
    (destination / "existing.txt").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="empty real directory"):
        runtime_module.run_web_swarm(
            _FakeTarget(),  # type: ignore[arg-type]
            "mission",  # type: ignore[arg-type]
            _base_document(),
            destination,
            agent_count=1,
            package_runner="pr",  # type: ignore[arg-type]
            browser_executable="be",  # type: ignore[arg-type]
            approval_prompt=lambda _challenge, _intents: "x",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=True,
            target_observation_disclosure_authorized=True,
        )


def test_concurrent_agents_actually_overlap_in_wall_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prove real concurrency: N slow fake workers finish in ~1 slot, not N slots."""
    agent_count = 4
    sleep_seconds = 0.3
    concurrently_running = 0
    max_concurrently_running = 0
    worker_starts: list[float] = []
    worker_finishes: list[float] = []
    lock = threading.Lock()

    def fake_run_swarm_worker(spec: Any, **_kwargs: Any) -> Any:
        nonlocal concurrently_running, max_concurrently_running
        with lock:
            worker_starts.append(time.monotonic())
            concurrently_running += 1
            max_concurrently_running = max(max_concurrently_running, concurrently_running)
        time.sleep(sleep_seconds)
        with lock:
            concurrently_running -= 1
            worker_finishes.append(time.monotonic())

        class _Artifacts:
            status = "pass"
            report = tmp_path / f"{spec.agent_id}-report.json"
            trace = tmp_path / f"{spec.agent_id}.sova-trace"
            capsule = None

        return _Artifacts()

    def fake_merge(_self: Any, results: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agentCount": len(results), "status": [r.status for r in results]}

    monkeypatch.setattr(runtime_module, "run_swarm_worker", fake_run_swarm_worker)
    monkeypatch.setattr(SwarmCoordinator, "merge", fake_merge, raising=True)

    artifacts = runtime_module.run_web_swarm(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        _base_document(),
        tmp_path / "swarm",
        agent_count=agent_count,
        package_runner="pr",  # type: ignore[arg-type]
        browser_executable="be",  # type: ignore[arg-type]
        approval_prompt=lambda _challenge, _intents: "x",
        secret_resolver=lambda _name: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        max_concurrency=agent_count,
    )
    worker_elapsed = max(worker_finishes) - min(worker_starts)

    assert max_concurrently_running == agent_count  # all ran at once, not one at a time
    assert worker_elapsed < sleep_seconds * agent_count  # proves overlap, not serialization
    assert artifacts.agent_count == agent_count
    assert artifacts.report["agentCount"] == agent_count


def test_a_worker_failure_is_isolated_and_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def flaky_run_swarm_worker(spec: Any, **_kwargs: Any) -> Any:
        if spec.agent_id == "agent-02":
            raise FormatError("SOVA-FIXTURE-INJECTED", "synthetic worker failure")

        class _Artifacts:
            status = "pass"
            report = tmp_path / f"{spec.agent_id}-report.json"
            trace = tmp_path / f"{spec.agent_id}.sova-trace"
            capsule = None

        return _Artifacts()

    captured_results: list[AgentRunResult] = []

    def fake_merge(_self: Any, results: Any, **_kwargs: Any) -> dict[str, Any]:
        captured_results.extend(results)
        return {"agentCount": len(results)}

    monkeypatch.setattr(runtime_module, "run_swarm_worker", flaky_run_swarm_worker)
    monkeypatch.setattr(SwarmCoordinator, "merge", fake_merge, raising=True)

    runtime_module.run_web_swarm(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        _base_document(),
        tmp_path / "swarm",
        agent_count=3,
        package_runner="pr",  # type: ignore[arg-type]
        browser_executable="be",  # type: ignore[arg-type]
        approval_prompt=lambda _challenge, _intents: "x",
        secret_resolver=lambda _name: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
    )

    by_id = {result.agent_id: result for result in captured_results}
    assert len(by_id) == 3
    assert by_id["agent-01"].status == "pass"
    assert by_id["agent-02"].status == "failed"
    assert by_id["agent-02"].error is not None
    assert by_id["agent-03"].status == "pass"


def test_agent_destinations_are_isolated_subdirectories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_destinations: list[Path] = []

    def recording_run_swarm_worker(_spec: Any, *, destination: Path, **_kwargs: Any) -> Any:
        seen_destinations.append(destination)

        class _Artifacts:
            status = "pass"
            report = destination / "report.json"
            trace = destination / "trace.sova-trace"
            capsule = None

        return _Artifacts()

    def fake_merge(_self: Any, results: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"agentCount": len(results)}

    monkeypatch.setattr(runtime_module, "run_swarm_worker", recording_run_swarm_worker)
    monkeypatch.setattr(SwarmCoordinator, "merge", fake_merge, raising=True)

    swarm_root = tmp_path / "swarm"
    runtime_module.run_web_swarm(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        _base_document(),
        swarm_root,
        agent_count=3,
        package_runner="pr",  # type: ignore[arg-type]
        browser_executable="be",  # type: ignore[arg-type]
        approval_prompt=lambda _challenge, _intents: "x",
        secret_resolver=lambda _name: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
    )

    assert len(seen_destinations) == 3
    assert len(set(seen_destinations)) == 3  # every agent got its own directory
    for destination in seen_destinations:
        assert destination.parent == swarm_root / "agents"


def test_additional_surface_contract_is_threaded_to_every_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []

    def recording_worker(spec: Any, **kwargs: Any) -> Any:
        seen.append(kwargs)

        class _Artifacts:
            status = "not-observed"
            report = tmp_path / f"{spec.agent_id}-report.json"
            trace = tmp_path / f"{spec.agent_id}.sova-trace"
            capsule = None

        return _Artifacts()

    monkeypatch.setattr(runtime_module, "run_swarm_worker", recording_worker)
    monkeypatch.setattr(
        SwarmCoordinator,
        "merge",
        lambda _self, results, **_kwargs: {"agentCount": len(results)},
        raising=True,
    )
    surface_factory = object()
    codec_factories = {"codec": object()}
    digest = "sha256:" + "3" * 64

    runtime_module.run_web_swarm(
        _FakeTarget(),  # type: ignore[arg-type]
        "mission",  # type: ignore[arg-type]
        _base_document(),
        tmp_path / "full-swarm",
        agent_count=2,
        package_runner="pr",  # type: ignore[arg-type]
        browser_executable="be",  # type: ignore[arg-type]
        approval_prompt=lambda _challenge, _intents: "x",
        secret_resolver=lambda _name: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        additional_surface_factory=surface_factory,  # type: ignore[arg-type]
        additional_codec_factories=codec_factories,  # type: ignore[arg-type]
        additional_surface_contract_digest=digest,
    )

    assert len(seen) == 2
    assert all(item["additional_surface_factory"] is surface_factory for item in seen)
    assert all(item["additional_codec_factories"] is codec_factories for item in seen)
    assert all(item["additional_surface_contract_digest"] == digest for item in seen)
