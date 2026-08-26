# SPDX-License-Identifier: Apache-2.0
"""One swarm agent: an isolated single-agent Executor Engine run plus a thin
live event-extraction bridge onto the shared `SwarmBlackboard`.

This module deliberately does not reimplement browser/computer/terminal
execution, authorization, or evidence.  `run_swarm_worker` is a thin wrapper
around `sova.community.live_executor_engine.run_live_web_executor_engine`
(unchanged): the same engine as a single non-swarm run, invoked once per
agent, each with its own fresh browser context and disposable workspace.

Live communication is bidirectional and event-driven: as the engine emits
already-redacted trace events (`tool.completed`, `oracle.completed`,
`oracle.result`), a bounded subset is turned into `SwarmMessage`s and posted
to the shared blackboard immediately.  Before every planner turn, the trusted
coordinator snapshots recent peer messages into a bounded, redaction-checked,
data-only prompt field.  The snapshot is signed into the worker trace and
never grants tool or approval authority.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.community.live_executor_engine import run_live_web_executor_engine
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.community.executor_chamber import ApprovalPrompt, ExecutorChamberArtifacts
    from sova.community.executor_engine import CodecFactory, SurfaceFactory
    from sova.community.swarm.blackboard import SwarmBlackboard
    from sova.community.swarm.budget import SwarmBudgetLedger
    from sova.community.swarm.coverage import SwarmCoverageLedger
    from sova.live.semantic_workflow import SemanticBrowserMission
    from sova.runtime.sessions import BrowserProfileLease
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_BROADCAST_KINDS = frozenset({"tool.completed", "oracle.completed", "oracle.result"})
_MAX_AGENT_ID_CHARS = 128
_MAX_SUMMARY_CHARS = 2048
_MAX_PEER_MESSAGES_PER_TURN = 32


@dataclass(frozen=True, slots=True)
class SwarmWorkerSpec:
    """One agent's identity, persona, and fully valid single-participant document.

    `chamber_document` must already be a complete, valid `sova.executor-chamber`
    document (the same schema `sova engine run-web` consumes) declaring exactly
    the participant this worker runs.  The coordinator builds one per agent by
    cloning an operator-authored template and customizing only the
    participant's declared objective text (see
    `sova.community.swarm.coordinator.SwarmCoordinator.seed`).
    """

    agent_id: str
    persona: str
    chamber_document: dict[str, Any]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.agent_id, str)
            or not self.agent_id
            or len(self.agent_id) > _MAX_AGENT_ID_CHARS
            or "\x00" in self.agent_id
        ):
            raise FormatError(
                "SOVA-SWARM-WORKER-SPEC",
                "swarm worker agent id must be a bounded non-empty string",
            )
        if not isinstance(self.persona, str) or not self.persona:
            raise FormatError(
                "SOVA-SWARM-WORKER-SPEC",
                "swarm worker persona must be a non-empty string",
            )
        if not isinstance(self.chamber_document, dict):
            raise FormatError(
                "SOVA-SWARM-WORKER-SPEC",
                "swarm worker chamber document must be an object",
            )


def _bounded_summary(payload: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key in sorted(payload):
        value = payload[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            parts.append(f"{key}={value!r}")
        if sum(len(item) for item in parts) > _MAX_SUMMARY_CHARS:
            break
    return "; ".join(parts)[:_MAX_SUMMARY_CHARS]


def _message_kind_for(event: Mapping[str, Any]) -> SwarmMessageKind:
    kind = event.get("kind")
    payload = event.get("payload")
    status = payload.get("status") if isinstance(payload, dict) else None
    if kind in {"oracle.completed", "oracle.result"} and status == "pass":
        return SwarmMessageKind.FINDING
    return SwarmMessageKind.OBSERVATION


class _BlackboardBridge:
    """Extract a bounded subset of one worker's live engine events onto the board."""

    def __init__(
        self,
        *,
        agent_id: str,
        blackboard: SwarmBlackboard,
        downstream: Callable[[str, dict[str, Any]], None] | None,
        coverage: SwarmCoverageLedger | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._blackboard = blackboard
        self._downstream = downstream
        self._coverage = coverage
        self._seq = 0
        self._lock = threading.Lock()

    def __call__(self, channel: str, event: dict[str, Any]) -> None:
        if self._coverage is not None:
            self._coverage.observe(self._agent_id, event)
        if self._downstream is not None:
            self._downstream(channel, event)
        kind = event.get("kind")
        if kind not in _BROADCAST_KINDS or not isinstance(event.get("payload"), dict):
            return
        with self._lock:
            seq = self._seq
            self._seq += 1
        message = SwarmMessage(
            author_agent_id=self._agent_id,
            seq=seq,
            kind=_message_kind_for(event),
            refs=(),
            payload={
                "channel": channel,
                "chamberEventKind": kind,
                "chamberEventId": event.get("id"),
                "summary": _bounded_summary(event["payload"]),
            },
            posted_unix_ms=time.time_ns() // 1_000_000,
        )
        self._blackboard.post(message)


def _peer_context(
    blackboard: SwarmBlackboard,
    *,
    agent_id: str,
    coverage: SwarmCoverageLedger | None = None,
) -> dict[str, Any]:
    """Return recent peer data for one adaptive planner turn, never executor authority."""
    messages = tuple(
        message for message in blackboard.transcript() if message.author_agent_id != agent_id
    )[-_MAX_PEER_MESSAGES_PER_TURN:]
    return {
        "contract": "sova.swarm-peer-context/0.1.0",
        "messages": [message.canonical_mapping() for message in messages],
        "messageCount": len(messages),
        "blackboardChainHead": blackboard.chain_head_digest(),
        "treatAsUntrustedData": True,
        "executorAuthorityGranted": False,
        "trustedCoordinatorMeasuredCoverage": (None if coverage is None else coverage.snapshot()),
    }


BlackboardBridge = _BlackboardBridge
peer_context = _peer_context


def run_swarm_worker(  # noqa: PLR0913 - each engine trust input is independent
    spec: SwarmWorkerSpec,
    *,
    target: TargetManifest,
    mission: SemanticBrowserMission,
    destination: Path,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    blackboard: SwarmBlackboard,
    control_proof: ControlProof | None = None,
    profile_lease: BrowserProfileLease | None = None,
    offensive: bool = False,
    headless: bool = True,
    record_video: bool = False,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    workspace_seed: Path | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
    aggregate_budget_ledger: SwarmBudgetLedger | None = None,
    measured_coverage_ledger: SwarmCoverageLedger | None = None,
    additional_surface_factory: SurfaceFactory | None = None,
    additional_codec_factories: Mapping[str, CodecFactory] | None = None,
    additional_surface_contract_digest: str | None = None,
    additional_target_process_id: int | None = None,
    additional_target_process_start_digest: str | None = None,
    additional_target_window_handle_digest: str | None = None,
) -> ExecutorChamberArtifacts:
    """Run one isolated swarm agent: its own browser context, its own workspace.

    This is exactly `run_live_web_executor_engine`, unchanged, with a live
    event bridge that posts a bounded subset of this agent's events onto the
    shared blackboard as they happen.
    """
    bridge = _BlackboardBridge(
        agent_id=spec.agent_id,
        blackboard=blackboard,
        downstream=event_observer,
        coverage=measured_coverage_ledger,
    )
    return run_live_web_executor_engine(
        target,
        mission,
        spec.chamber_document,
        destination,
        package_runner=package_runner,
        browser_executable=browser_executable,
        approval_prompt=approval_prompt,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        target_observation_disclosure_authorized=target_observation_disclosure_authorized,
        control_proof=control_proof,
        profile_lease=profile_lease,
        offensive=offensive,
        headless=headless,
        record_video=record_video,
        package_cache=package_cache,
        browser_cache=browser_cache,
        workspace_seed=workspace_seed,
        event_observer=bridge,
        coordination_context_provider=lambda _participant_id: _peer_context(
            blackboard,
            agent_id=spec.agent_id,
            coverage=measured_coverage_ledger,
        ),
        action_admission_hook=(
            None
            if aggregate_budget_ledger is None
            else lambda phase, request, binding: aggregate_budget_ledger.reserve(
                agent_id=spec.agent_id,
                phase=phase,
                request=request,
                binding=binding,
            )
        ),
        additional_surface_factory=additional_surface_factory,
        additional_codec_factories=additional_codec_factories,
        additional_surface_contract_digest=additional_surface_contract_digest,
        additional_target_process_id=additional_target_process_id,
        additional_target_process_start_digest=additional_target_process_start_digest,
        additional_target_window_handle_digest=additional_target_window_handle_digest,
    )


__all__ = ["BlackboardBridge", "SwarmWorkerSpec", "peer_context", "run_swarm_worker"]
