# SPDX-License-Identifier: Apache-2.0
"""End-to-end acceptance for the real-time evidence-first Arena chamber."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sova.community import run_arena_chamber_document
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair

ROOT = Path(__file__).parents[2]


def _document() -> dict[str, Any]:
    value = strict_json_loads((ROOT / "examples" / "arena" / "chamber.json").read_bytes())
    assert isinstance(value, dict)
    return value


@pytest.mark.integration
def test_agent_vs_agent_chamber_streams_and_seals_exact_observable_evidence(
    tmp_path: Path,
) -> None:
    observed: list[dict[str, Any]] = []
    artifacts = run_arena_chamber_document(
        _document(),
        tmp_path / "arena",
        secret_resolver=lambda _name: None,
        contained_fixture_authorized=True,
        provider_calls_authorized=False,
        event_observer=observed.append,
    )

    assert artifacts.status == "pass"
    reader = TraceReader(artifacts.trace)
    verification = reader.verify(require_signature=True)
    events = reader.events()
    assert verification.signature_valid
    assert verification.completion == "completed"
    assert observed == events
    assert artifacts.live_events.read_bytes() == b"".join(
        canonical_json_bytes(event) + b"\n" for event in events
    )
    kinds = [event["kind"] for event in events]
    assert {
        "authorization.decision",
        "safety.containment",
        "prompt.requested",
        "model.response",
        "tool.requested",
        "filesystem.read",
        "network.egress-attempt",
        "inter-agent.sent",
        "inter-agent.message",
        "environment.state",
        "oracle.result",
        "judge.completed",
        "run.completed",
    } <= set(kinds)
    assert len(reader.playback()) == len(events)

    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["deterministicAssessment"] == "observed"
    assert report["evidence"]["liveStreamMatchesFinalTrace"] is True
    assert report["evidence"]["signatureValid"] is True
    assert report["claims"] == {
        "agentVsAgentSupported": True,
        "agentVsEnvironmentSupported": True,
        "completeRealityCaptured": False,
        "deterministicEvidenceControlsVerdict": True,
        "liveRedactedEventStreaming": True,
        "modelDirectToolCallsAllowed": False,
        "multiAgentSupported": True,
        "privateModelThoughtsCaptured": False,
        "providerModelsSupported": True,
        "scriptedModelsSupported": True,
        "securitySandbox": False,
    }
    assert report["environment"]["sensorHealth"]["filesystem"] == "healthy"
    assert report["environment"]["sensorHealth"]["browser"] == "missing"
    assert verify_artifact(artifacts.capsule).state == VerificationState.PARTIAL

    rendered = artifacts.live_events.read_text(encoding="utf-8")
    assert "I exercised the declared synthetic path" not in rendered
    assert "I observed the shared sensor feed" not in rendered
    assert "The result applies only" not in rendered


@pytest.mark.integration
def test_direct_model_tool_call_fails_closed_and_seals_failed_trace(tmp_path: Path) -> None:
    document = _document()
    red = document["participants"][0]["model"]["turns"][0]
    red["toolCalls"] = [{"name": "filesystem.read", "arguments": {}}]
    destination = tmp_path / "failed-arena"
    with pytest.raises(FormatError, match="direct tool calls are refused"):
        run_arena_chamber_document(
            document,
            destination,
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    trace = destination / "arena.sova-trace"
    verification = TraceReader(trace).verify(require_signature=True)
    assert verification.completion == "failed"
    assert verification.signature_valid
    events = TraceReader(trace).events()
    assert events[-1]["kind"] == "error.recorded"
    assert events[-1]["payload"]["code"] == "SOVA-CHAMBER-DIRECT-TOOL"
    assert not (destination / "arena.sova").exists()


@pytest.mark.integration
def test_trace_live_observer_gets_only_redacted_canonical_events(tmp_path: Path) -> None:
    rows: list[dict[str, Any]] = []
    trace = tmp_path / "redacted.sova-trace"
    writer = TraceWriter(
        trace,
        signing_key=generate_ed25519_keypair(),
        event_observer=rows.append,
    )
    writer.append("tool.completed", {"password": "not-for-observer", "result": "ok"})
    writer.finalize()
    assert len(rows) == 1
    assert "not-for-observer" not in canonical_json_bytes(rows[0]).decode("utf-8")
    assert rows == TraceReader(trace).events()


@pytest.mark.integration
def test_live_observer_failure_is_visible_but_partial_trace_remains_sealable(
    tmp_path: Path,
) -> None:
    def fail(_event: dict[str, Any]) -> None:
        raise RuntimeError

    trace = tmp_path / "observer-failed.sova-trace"
    writer = TraceWriter(
        trace,
        signing_key=generate_ed25519_keypair(),
        event_observer=fail,
    )
    with pytest.raises(FormatError, match="observer failed"):
        writer.append("run.started", {"fixture": True})
    writer.append("error.recorded", {"code": "SOVA-TRACE-OBSERVER"})
    writer.finalize(completion="partial")
    verification = TraceReader(trace).verify(require_signature=True)
    assert verification.completion == "partial"
    assert verification.event_count == 2
