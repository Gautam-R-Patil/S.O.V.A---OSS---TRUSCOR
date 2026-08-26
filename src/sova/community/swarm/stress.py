# SPDX-License-Identifier: Apache-2.0
"""Bounded, authorization-gated robustness ("stress") profile over the swarm.

Stress testing here means sustained, varied adversarial input against one
proven-controlled target -- concurrency (agents) times variety (the curated
adversarial-tactic library) times bounded repetition (a wider per-mission
action budget) -- never raw request flooding. Every ceiling below is a hard
cap the operator cannot raise; this module adds no new execution surface,
network client, or authorization path. It is a composition over
`run_web_swarm` (already-audited concurrency/isolation/merge) and
`sova.live.adversarial_missions` (already-audited offensive mission library).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from sova.community.swarm.runtime import SwarmArtifacts, run_web_swarm
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.adversarial_missions import (
    adversarial_tactic,
    adversarial_tactic_ids,
    build_adversarial_mission,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.community.executor_chamber import ApprovalPrompt
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

#: Hard ceilings -- never configurable above these (anti-DoS).
_MAX_AGENTS = 8
_MAX_REPETITIONS = 25
#: Strictly below `_MAX_AGENTS * _MAX_REPETITIONS` so this is a real independent
#: ceiling, not one implied by the other two.
_MAX_TOTAL_INTERACTIONS = 128
#: `build_adversarial_mission` defaults; scaled by `repetitions` and clamped
#: to `SemanticBrowserMission`'s own engine-enforced ceilings (64/512/512).
_BASE_PLANNER_TURNS = 8
_BASE_ACTIONS = 16
_BASE_MUTATIONS = 12
_MISSION_MAX_PLANNER_TURNS = 64
_MISSION_MAX_ACTIONS = 512
_MISSION_MAX_MUTATIONS = 512


@dataclass(frozen=True, slots=True)
class StressReport:
    """One bounded robustness run's artifacts and the battery that produced it."""

    destination: Path
    swarm: SwarmArtifacts
    tactic_ids: tuple[str, ...]
    agent_count: int
    repetitions: int


def _validated_bounds(agent_count: int, repetitions: int) -> None:
    if not 1 <= agent_count <= _MAX_AGENTS:
        raise FormatError(
            "SOVA-SWARM-STRESS-BOUNDS",
            "stress profile agent count is outside the admitted range",
            details={"min": 1, "max": _MAX_AGENTS, "requested": agent_count},
        )
    if not 1 <= repetitions <= _MAX_REPETITIONS:
        raise FormatError(
            "SOVA-SWARM-STRESS-BOUNDS",
            "stress profile repetitions is outside the admitted range",
            details={"min": 1, "max": _MAX_REPETITIONS, "requested": repetitions},
        )
    if agent_count * repetitions > _MAX_TOTAL_INTERACTIONS:
        raise FormatError(
            "SOVA-SWARM-STRESS-BOUNDS",
            "stress profile agentCount * repetitions exceeds the total interaction ceiling",
            details={
                "max": _MAX_TOTAL_INTERACTIONS,
                "requested": agent_count * repetitions,
            },
        )


def _validated_tactics(tactic_ids: tuple[str, ...] | None) -> tuple[str, ...]:
    selected = tactic_ids or adversarial_tactic_ids()
    if not selected:
        raise FormatError(
            "SOVA-SWARM-STRESS-TACTICS",
            "stress profile requires at least one adversarial tactic",
        )
    for tactic_id in selected:
        adversarial_tactic(tactic_id)  # raises SOVA-ADVERSARIAL-TACTIC-UNKNOWN if unknown
    return tuple(selected)


def _battery_mission(
    tactic_ids: tuple[str, ...],
    *,
    entry_url: str,
    repetitions: int,
    extra_payloads: tuple[str, ...],
) -> Any:
    primary, *rest = tactic_ids
    rest_payloads = tuple(payload for tid in rest for payload in adversarial_tactic(tid).payloads)
    primary_payloads = set(adversarial_tactic(primary).payloads)
    # De-dupe while preserving order: the builder rejects duplicate payloads.
    combined = dict.fromkeys((*rest_payloads, *extra_payloads))
    folded_extra = tuple(payload for payload in combined if payload not in primary_payloads)
    mission = build_adversarial_mission(
        primary,
        entry_url=entry_url,
        extra_payloads=folded_extra,
        max_planner_turns=min(_BASE_PLANNER_TURNS * repetitions, _MISSION_MAX_PLANNER_TURNS),
        max_actions=min(_BASE_ACTIONS * repetitions, _MISSION_MAX_ACTIONS),
        max_mutations=min(_BASE_MUTATIONS * repetitions, _MISSION_MAX_MUTATIONS),
    )
    if repetitions == 1:
        return mission
    objective = (
        f"{mission.objective}\n\n"
        f"This is a bounded robustness ('stress') pass: after trying the battery once, if "
        f"budget remains, retry with bounded variations up to {repetitions} total passes. "
        f"Never repeat an already-confirmed-successful payload verbatim; vary phrasing across "
        f"passes to probe robustness, not to spam identical input."
    )
    return replace(mission, objective=objective)


def _mission_bound_chamber_document(
    base_chamber_document: dict[str, Any],
    *,
    oracle_contains: str,
) -> dict[str, Any]:
    """Clone the worker template and bind success to this stress mission.

    Stress missions are assembled at runtime from the selected tactic battery,
    so retaining an arbitrary oracle from the input template can report a pass
    for an unrelated page condition.  The cloned document remains the exact
    object shown at authorization time; the caller-owned input is never
    mutated.
    """
    if not isinstance(base_chamber_document, dict):
        raise FormatError(
            "SOVA-SWARM-STRESS-DOCUMENT",
            "stress profile requires one executor chamber document object",
        )
    cloned = strict_json_loads(canonical_json_bytes(base_chamber_document))
    if not isinstance(cloned, dict):  # pragma: no cover - canonical source is an object
        raise TypeError
    oracle = cloned.get("oracle")
    if not isinstance(oracle, dict):
        raise FormatError(
            "SOVA-SWARM-STRESS-DOCUMENT",
            "stress chamber document must declare a finding oracle",
        )
    cloned["oracle"] = {
        "kind": "projection-field-contains",
        "fieldPath": ["browser", "snapshot"],
        "contains": oracle_contains,
    }
    return cloned


def run_stress_profile(  # noqa: PLR0913 - each engine/swarm trust input is independent
    target: TargetManifest,
    base_chamber_document: dict[str, Any],
    destination: Path,
    *,
    entry_url: str,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    agent_count: int,
    repetitions: int = 1,
    tactic_ids: tuple[str, ...] | None = None,
    extra_payloads: tuple[str, ...] = (),
    control_proof: ControlProof | None = None,
    headless: bool = True,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> StressReport:
    """Fan the adversarial-tactic library across a concurrent swarm, bounded.

    `agent_count` and `repetitions` are hard-capped (`_MAX_AGENTS`,
    `_MAX_REPETITIONS`, `_MAX_TOTAL_INTERACTIONS`) to keep this a bounded
    authorized robustness probe, never a flood. `tactic_ids` defaults to the
    full curated library; every agent runs the same battery so the swarm's
    variety comes from concurrent exploration paths (via
    `SwarmCoordinator.seed`'s per-agent focus areas), not per-agent tactic
    partitioning. The mission is forced `offensive=True`, so the engine
    requires proof of control of `entry_url`'s origin and DESTRUCTIVE-level
    human approval before anything runs -- exactly as any other offensive
    mission would.
    """
    _validated_bounds(agent_count, repetitions)
    selected_tactics = _validated_tactics(tactic_ids)
    mission = _battery_mission(
        selected_tactics,
        entry_url=entry_url,
        repetitions=repetitions,
        extra_payloads=extra_payloads,
    )
    chamber_document = _mission_bound_chamber_document(
        base_chamber_document,
        oracle_contains=mission.oracle_contains,
    )
    swarm = run_web_swarm(
        target,
        mission,
        chamber_document,
        destination,
        agent_count=agent_count,
        package_runner=package_runner,
        browser_executable=browser_executable,
        approval_prompt=approval_prompt,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        target_observation_disclosure_authorized=target_observation_disclosure_authorized,
        control_proof=control_proof,
        offensive=True,
        headless=headless,
        package_cache=package_cache,
        browser_cache=browser_cache,
        event_observer=event_observer,
    )
    return StressReport(
        destination=swarm.destination,
        swarm=swarm,
        tactic_ids=selected_tactics,
        agent_count=agent_count,
        repetitions=repetitions,
    )


__all__ = ["StressReport", "run_stress_profile"]
