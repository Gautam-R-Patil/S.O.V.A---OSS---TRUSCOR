# SPDX-License-Identifier: Apache-2.0
"""Concurrent swarm runtime: thread pool, per-agent isolation, and merge."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.community.swarm.blackboard import SwarmBlackboard
from sova.community.swarm.budget import SwarmAggregateBudget, SwarmBudgetLedger
from sova.community.swarm.coordinator import AgentRunResult, SwarmCoordinator
from sova.community.swarm.coverage import SwarmCoverageLedger
from sova.community.swarm.worker import run_swarm_worker
from sova.formats.errors import FormatError
from sova.trace import Redactor

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.community.executor_chamber import ApprovalPrompt
    from sova.community.executor_engine import CodecFactory, SurfaceFactory
    from sova.live.semantic_workflow import SemanticBrowserMission
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_DEFAULT_MAX_CONCURRENCY = 8
_HARD_AGENT_CAP = 8


@dataclass(frozen=True, slots=True)
class SwarmArtifacts:
    destination: Path
    agent_count: int
    swarm_capsule: Path
    coordinator_trace: Path
    report: dict[str, Any]


def run_web_swarm(  # noqa: PLR0913 - each engine/swarm trust input is independent
    target: TargetManifest,
    mission: SemanticBrowserMission,
    base_chamber_document: dict[str, Any],
    destination: Path,
    *,
    agent_count: int,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    personas: tuple[str, ...] | None = None,
    control_proof: ControlProof | None = None,
    offensive: bool = False,
    headless: bool = True,
    record_video: bool = False,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    workspace_seed: Path | None = None,
    max_concurrency: int = _DEFAULT_MAX_CONCURRENCY,
    allow_large_swarm: bool = False,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
    aggregate_budget: SwarmAggregateBudget | None = None,
    additional_surface_factory: SurfaceFactory | None = None,
    additional_codec_factories: Mapping[str, CodecFactory] | None = None,
    additional_surface_contract_digest: str | None = None,
    additional_target_process_id: int | None = None,
    additional_target_process_start_digest: str | None = None,
    additional_target_window_handle_digest: str | None = None,
) -> SwarmArtifacts:
    """Run `agent_count` concurrent isolated agents against one authorized target.

    Each agent is its own `run_live_web_executor_engine` call (own browser
    context, own disposable workspace); agents share a redacted, hash-chained
    `SwarmBlackboard` that a coordinator merges into one `swarm.sova` capsule
    once every agent finishes or fails.  A worker failure is isolated and
    recorded; it does not abort its peers.
    """
    hard_cap = _HARD_AGENT_CAP if not allow_large_swarm else max(_HARD_AGENT_CAP, agent_count)
    if agent_count < 1 or agent_count > hard_cap:
        raise FormatError(
            "SOVA-SWARM-RUNTIME-COUNT",
            "swarm agent count is outside the admitted range",
            details={"min": 1, "max": hard_cap, "requested": agent_count},
        )
    if max_concurrency < 1:
        raise FormatError(
            "SOVA-SWARM-RUNTIME-CONCURRENCY",
            "swarm max concurrency must be positive",
        )
    budget_ledger = SwarmBudgetLedger(
        aggregate_budget or SwarmAggregateBudget.from_chamber_document(base_chamber_document)
    )
    unresolved = destination.absolute()
    for candidate in (unresolved, *unresolved.parents):
        is_junction = getattr(candidate, "is_junction", lambda: False)
        if candidate.exists() and (candidate.is_symlink() or is_junction()):
            raise FormatError(
                "SOVA-SWARM-RUNTIME-EXISTS",
                "swarm destination cannot traverse a link or junction",
            )
    root = destination.resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise FormatError(
            "SOVA-SWARM-RUNTIME-EXISTS",
            "swarm destination must be an empty real directory",
        )
    root.mkdir(parents=True, exist_ok=True)
    agents_root = root / "agents"
    agents_root.mkdir()

    coordinator = SwarmCoordinator()
    specs = coordinator.seed(base_chamber_document, agent_count=agent_count, personas=personas)
    blackboard = SwarmBlackboard(redactor=Redactor(context_id="sova-swarm-blackboard"))
    coverage = SwarmCoverageLedger()

    def _run_one(spec: Any) -> AgentRunResult:
        agent_destination = agents_root / spec.agent_id
        try:
            artifacts = run_swarm_worker(
                spec,
                target=target,
                mission=mission,
                destination=agent_destination,
                package_runner=package_runner,
                browser_executable=browser_executable,
                approval_prompt=approval_prompt,
                secret_resolver=secret_resolver,
                provider_calls_authorized=provider_calls_authorized,
                target_observation_disclosure_authorized=(target_observation_disclosure_authorized),
                blackboard=blackboard,
                control_proof=control_proof,
                offensive=offensive,
                headless=headless,
                record_video=record_video,
                package_cache=package_cache,
                browser_cache=browser_cache,
                workspace_seed=workspace_seed,
                event_observer=event_observer,
                aggregate_budget_ledger=budget_ledger,
                measured_coverage_ledger=coverage,
                additional_surface_factory=additional_surface_factory,
                additional_codec_factories=additional_codec_factories,
                additional_surface_contract_digest=additional_surface_contract_digest,
                additional_target_process_id=additional_target_process_id,
                additional_target_process_start_digest=additional_target_process_start_digest,
                additional_target_window_handle_digest=(additional_target_window_handle_digest),
            )
        except Exception as error:  # noqa: BLE001 - a worker failure must not abort the swarm
            message = error.issue.message if isinstance(error, FormatError) else "worker raised"
            return AgentRunResult(spec.agent_id, spec.persona, "failed", None, message)
        return AgentRunResult(spec.agent_id, spec.persona, artifacts.status, artifacts, None)

    with ThreadPoolExecutor(max_workers=min(agent_count, max_concurrency)) as pool:
        futures = {pool.submit(_run_one, spec): spec for spec in specs}
        results = [future.result() for future in as_completed(futures)]
    results.sort(key=lambda item: item.agent_id)

    report = coordinator.merge(
        tuple(results),
        blackboard=blackboard,
        destination=root,
        target_digest=target.digest,
        aggregate_budget=budget_ledger.snapshot(),
        measured_coverage=coverage.snapshot(),
    )
    return SwarmArtifacts(
        destination=root,
        agent_count=agent_count,
        swarm_capsule=root / "swarm.sova",
        coordinator_trace=root / "coordinator.sova-trace",
        report=report,
    )


__all__ = ["SwarmArtifacts", "run_web_swarm"]
