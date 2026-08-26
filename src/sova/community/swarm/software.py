# SPDX-License-Identifier: Apache-2.0
"""Concurrent adaptive swarm over phase-owned authorized software targets."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.community.executor_engine import run_executor_engine_document
from sova.community.software_executor_engine import build_authorized_software_runtime
from sova.community.swarm.blackboard import SwarmBlackboard
from sova.community.swarm.budget import SwarmAggregateBudget, SwarmBudgetLedger
from sova.community.swarm.coordinator import AgentRunResult, SwarmCoordinator
from sova.community.swarm.coverage import SwarmCoverageLedger
from sova.community.swarm.worker import BlackboardBridge, peer_context
from sova.formats.errors import FormatError
from sova.runtime.window_recording import SoftwareWindowRecordingCoordinator
from sova.trace import Redactor

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from sova.community.executor_chamber import ApprovalPrompt
    from sova.community.executor_engine import CodecFactory, SurfaceFactory
    from sova.community.executor_surfaces import ExactProcessSurfaceSpec
    from sova.community.software_executor_engine import (
        SoftwareComputerSurfaceFactory,
        SoftwareLaunchSpec,
    )
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_DEFAULT_MAX_CONCURRENCY = 8
_HARD_AGENT_CAP = 8


@dataclass(frozen=True, slots=True)
class SoftwareSwarmArtifacts:
    destination: Path
    agent_count: int
    swarm_capsule: Path
    coordinator_trace: Path
    report: dict[str, Any]


def _empty_destination(destination: Path) -> Path:
    unresolved = destination.absolute()
    for candidate in (unresolved, *unresolved.parents):
        is_junction = getattr(candidate, "is_junction", lambda: False)
        if candidate.exists() and (candidate.is_symlink() or is_junction()):
            raise FormatError(
                "SOVA-SOFTWARE-SWARM-DESTINATION",
                "software swarm destination cannot traverse a link or junction",
            )
    root = destination.resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise FormatError(
            "SOVA-SOFTWARE-SWARM-DESTINATION",
            "software swarm destination must be an empty real directory",
        )
    root.mkdir(parents=True, exist_ok=True)
    return root


def run_software_swarm(  # noqa: PLR0913
    target: TargetManifest,
    launch: SoftwareLaunchSpec,
    base_chamber_document: dict[str, Any],
    destination: Path,
    *,
    agent_count: int,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    proof: ControlProof,
    workspace_seed: Path | None = None,
    process_templates: Sequence[ExactProcessSurfaceSpec] = (),
    computer_surface_factory: SoftwareComputerSurfaceFactory | None = None,
    personas: tuple[str, ...] | None = None,
    offensive: bool = False,
    max_concurrency: int = _DEFAULT_MAX_CONCURRENCY,
    aggregate_budget: SwarmAggregateBudget | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
    record_window: bool = False,
    recording_interval_seconds: float = 0.5,
    additional_surface_factory: SurfaceFactory | None = None,
    additional_codec_factories: dict[str, CodecFactory] | None = None,
    additional_surface_contract_digest: str | None = None,
) -> SoftwareSwarmArtifacts:
    """Run isolated software target generations concurrently under one budget.

    Every worker gets a separate primary and reproduction process/workspace.
    Only redacted signed observations cross the shared hash-chained blackboard;
    peer messages never grant executor or approval authority.
    """
    if not target_observation_disclosure_authorized:
        raise FormatError(
            "SOVA-SOFTWARE-SWARM-DISCLOSURE",
            "software swarm requires explicit redacted observation disclosure",
        )
    if agent_count < 1 or agent_count > _HARD_AGENT_CAP or max_concurrency < 1:
        raise FormatError(
            "SOVA-SOFTWARE-SWARM-COUNT",
            "software swarm agent count or concurrency is outside the admitted range",
        )
    root = _empty_destination(destination)
    agents_root = root / "agents"
    agents_root.mkdir()
    coordinator = SwarmCoordinator()
    specs = coordinator.seed(
        base_chamber_document,
        agent_count=agent_count,
        personas=personas,
    )
    blackboard = SwarmBlackboard(redactor=Redactor(context_id="sova-software-swarm"))
    ledger = SwarmBudgetLedger(
        aggregate_budget or SwarmAggregateBudget.from_chamber_document(base_chamber_document)
    )
    coverage = SwarmCoverageLedger()

    def run_one(spec: Any) -> AgentRunResult:
        agent_destination = agents_root / spec.agent_id
        workspace_parent = agent_destination / "workspaces"
        workspace_parent.mkdir(parents=True)
        bridge = BlackboardBridge(
            agent_id=spec.agent_id,
            blackboard=blackboard,
            downstream=(
                None
                if event_observer is None
                else lambda channel, event: event_observer(f"{spec.agent_id}:{channel}", event)
            ),
            coverage=coverage,
        )
        recording = (
            SoftwareWindowRecordingCoordinator(
                agent_destination / "recordings",
                interval_seconds=recording_interval_seconds,
            )
            if record_window
            else None
        )

        def observed(channel: str, event: dict[str, Any]) -> None:
            if recording is not None:
                recording.observe(channel, event)
            bridge(channel, event)

        try:
            runtime = build_authorized_software_runtime(
                target,
                launch,
                workspace_parent=workspace_parent,
                workspace_seed=workspace_seed,
                process_templates=process_templates,
                computer_surface_factory=computer_surface_factory,
                window_recording=recording,
                additional_surface_factory=additional_surface_factory,
                additional_codec_factories=additional_codec_factories,
                additional_surface_contract_digest=additional_surface_contract_digest,
            )
            artifacts = run_executor_engine_document(
                spec.chamber_document,
                agent_destination / "evidence",
                runtime=runtime,
                proof=proof,
                approval_prompt=approval_prompt,
                secret_resolver=secret_resolver,
                provider_calls_authorized=provider_calls_authorized,
                offensive=offensive,
                event_observer=observed,
                capsule_attachment_provider=(None if recording is None else recording.attachments),
                coordination_context_provider=lambda _participant_id: peer_context(
                    blackboard,
                    agent_id=spec.agent_id,
                    coverage=coverage,
                ),
                action_admission_hook=lambda phase, request, binding: ledger.reserve(
                    agent_id=spec.agent_id,
                    phase=phase,
                    request=request,
                    binding=binding,
                ),
            )
        except Exception as error:  # noqa: BLE001 - one worker cannot abort its peers
            message = error.issue.message if isinstance(error, FormatError) else "worker raised"
            return AgentRunResult(spec.agent_id, spec.persona, "failed", None, message)
        return AgentRunResult(spec.agent_id, spec.persona, artifacts.status, artifacts, None)

    with ThreadPoolExecutor(max_workers=min(agent_count, max_concurrency)) as pool:
        futures = [pool.submit(run_one, spec) for spec in specs]
        results = [future.result() for future in as_completed(futures)]
    results.sort(key=lambda item: item.agent_id)
    report = coordinator.merge(
        tuple(results),
        blackboard=blackboard,
        destination=root,
        target_digest=target.digest,
        title="SOVA concurrent software swarm run",
        aggregate_budget=ledger.snapshot(),
        measured_coverage=coverage.snapshot(),
    )
    return SoftwareSwarmArtifacts(
        root,
        agent_count,
        root / "swarm.sova",
        root / "coordinator.sova-trace",
        report,
    )


__all__ = ["SoftwareSwarmArtifacts", "run_software_swarm"]
