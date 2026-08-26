# SPDX-License-Identifier: Apache-2.0
"""Swarm worker: live event extraction bridge and engine wiring."""

from __future__ import annotations

from typing import Any

import pytest

import sova.community.swarm.worker as worker_module
from sova.community.swarm.blackboard import SwarmBlackboard
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.community.swarm.worker import (
    SwarmWorkerSpec,
    _bounded_summary,
    _message_kind_for,
    run_swarm_worker,
)
from sova.formats.errors import FormatError


def test_worker_spec_rejects_empty_agent_id() -> None:
    with pytest.raises(FormatError, match="agent id"):
        SwarmWorkerSpec(agent_id="", persona="p", chamber_document={})


def test_worker_spec_rejects_empty_persona() -> None:
    with pytest.raises(FormatError, match="persona"):
        SwarmWorkerSpec(agent_id="agent-01", persona="", chamber_document={})


def test_worker_spec_rejects_non_dict_document() -> None:
    with pytest.raises(FormatError, match="document must be an object"):
        SwarmWorkerSpec(agent_id="agent-01", persona="p", chamber_document="not-a-dict")  # type: ignore[arg-type]


def test_bounded_summary_includes_scalar_fields_only() -> None:
    summary = _bounded_summary({"status": "pass", "count": 3, "nested": {"skip": "me"}})
    assert "status='pass'" in summary
    assert "count=3" in summary
    assert "nested" not in summary


def test_message_kind_for_oracle_pass_is_finding() -> None:
    event = {"kind": "oracle.completed", "payload": {"status": "pass"}}
    assert _message_kind_for(event) == SwarmMessageKind.FINDING


def test_message_kind_for_oracle_non_pass_is_observation() -> None:
    event = {"kind": "oracle.result", "payload": {"status": "not-observed"}}
    assert _message_kind_for(event) == SwarmMessageKind.OBSERVATION


def test_message_kind_for_tool_completed_is_observation() -> None:
    event = {"kind": "tool.completed", "payload": {"status": "succeeded"}}
    assert _message_kind_for(event) == SwarmMessageKind.OBSERVATION


def test_bridge_posts_only_admitted_kinds_and_forwards_downstream() -> None:
    board = SwarmBlackboard()
    forwarded: list[tuple[str, dict[str, Any]]] = []
    bridge = worker_module._BlackboardBridge(
        agent_id="agent-01",
        blackboard=board,
        downstream=lambda channel, event: forwarded.append((channel, event)),
    )
    bridge("primary", {"kind": "prompt.requested", "payload": {"ignored": True}})
    bridge(
        "primary",
        {"kind": "tool.completed", "payload": {"status": "succeeded", "action": "browser.click"}},
    )
    bridge("primary", {"kind": "oracle.completed", "id": "evt-1", "payload": {"status": "pass"}})

    assert len(forwarded) == 3  # every event is still forwarded downstream
    assert len(board) == 2  # only the two admitted kinds were posted
    transcript = board.transcript()
    assert transcript[0].author_agent_id == "agent-01"
    assert transcript[0].seq == 0
    assert transcript[1].seq == 1
    assert transcript[1].kind == SwarmMessageKind.FINDING
    assert transcript[1].payload["chamberEventId"] == "evt-1"


def test_bridge_ignores_malformed_payload() -> None:
    board = SwarmBlackboard()
    bridge = worker_module._BlackboardBridge(agent_id="agent-01", blackboard=board, downstream=None)
    bridge("primary", {"kind": "tool.completed", "payload": "not-a-dict"})
    assert len(board) == 0


def test_run_swarm_worker_threads_spec_and_bridge_into_the_live_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run_live_web_executor_engine(
        target: Any, mission: Any, chamber_document: Any, destination: Any, **kwargs: Any
    ) -> str:
        captured["target"] = target
        captured["mission"] = mission
        captured["chamber_document"] = chamber_document
        captured["destination"] = destination
        captured["kwargs"] = kwargs
        return "fake-artifacts"

    monkeypatch.setattr(
        worker_module, "run_live_web_executor_engine", fake_run_live_web_executor_engine
    )
    spec = SwarmWorkerSpec(agent_id="agent-01", persona="explorer", chamber_document={"case": "x"})
    board = SwarmBlackboard()
    result: Any = run_swarm_worker(
        spec,
        target="target-sentinel",  # type: ignore[arg-type]
        mission="mission-sentinel",  # type: ignore[arg-type]
        destination="dest-sentinel",  # type: ignore[arg-type]
        package_runner="pr-sentinel",  # type: ignore[arg-type]
        browser_executable="be-sentinel",  # type: ignore[arg-type]
        approval_prompt=lambda _challenge, _intents: "phrase",
        secret_resolver=lambda _name: None,
        provider_calls_authorized=True,
        target_observation_disclosure_authorized=True,
        blackboard=board,
        additional_surface_factory="surface-factory",  # type: ignore[arg-type]
        additional_codec_factories={"codec": "factory"},  # type: ignore[dict-item]
        additional_surface_contract_digest="sha256:" + "1" * 64,
    )
    assert result == "fake-artifacts"
    assert captured["target"] == "target-sentinel"
    assert captured["mission"] == "mission-sentinel"
    assert captured["chamber_document"] == {"case": "x"}
    assert captured["destination"] == "dest-sentinel"
    assert callable(captured["kwargs"]["event_observer"])
    assert callable(captured["kwargs"]["coordination_context_provider"])
    assert captured["kwargs"]["additional_surface_factory"] == "surface-factory"
    assert captured["kwargs"]["additional_codec_factories"] == {"codec": "factory"}
    assert captured["kwargs"]["additional_surface_contract_digest"] == "sha256:" + "1" * 64

    # The threaded-in event_observer is the blackboard bridge: exercising it
    # posts to the same board instance the caller supplied.
    captured["kwargs"]["event_observer"](
        "primary", {"kind": "tool.completed", "payload": {"status": "succeeded"}}
    )
    assert len(board) == 1
    assert board.transcript()[0].author_agent_id == "agent-01"


def test_worker_peer_context_updates_between_planner_turns() -> None:
    board = SwarmBlackboard()
    first = worker_module._peer_context(board, agent_id="agent-01")
    assert first["messageCount"] == 0
    board.post(
        SwarmMessage(
            author_agent_id="agent-02",
            seq=0,
            kind=SwarmMessageKind.HYPOTHESIS,
            refs=(),
            payload={"summary": "peer observed a distinct workflow state"},
            posted_unix_ms=1_700_000_000_000,
        )
    )
    second = worker_module._peer_context(board, agent_id="agent-01")
    assert second["messageCount"] == 1
    assert second["messages"][0]["authorAgentId"] == "agent-02"
    assert second["treatAsUntrustedData"] is True
    assert second["executorAuthorityGranted"] is False
