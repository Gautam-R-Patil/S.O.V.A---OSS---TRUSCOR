# SPDX-License-Identifier: Apache-2.0
"""Deterministic, authority-preserving methodology compilation and replanning."""

from __future__ import annotations

from collections import Counter
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.intake import TargetProfile, validate_intake_report
from sova.methodology.contracts import (
    PHASE_ORDER,
    PLAN_SCHEMA_VERSION,
    EffectClass,
    MethodologyObservationSet,
    MethodologyPhase,
    MethodologyPolicy,
    ObservationOutcome,
    Playbook,
    SchedulerKind,
)
from sova.methodology.library import MethodologyLibrary, load_builtin_library

COMPILER_VERSION = "0.1.0"
_PASSIVE_EFFECTS = frozenset({EffectClass.OBSERVE, EffectClass.READ_TARGET})
_PHASE_WEIGHTS = {
    MethodologyPhase.DISCOVERY: 1,
    MethodologyPhase.HYPOTHESIS: 1,
    MethodologyPhase.CONFIRMATION: 2,
    MethodologyPhase.REPRODUCTION: 2,
    MethodologyPhase.REMEDIATION_VALIDATION: 1,
    MethodologyPhase.REPORTING: 1,
}
_PLAN_CLAIMS = {
    "executionAuthorized": False,
    "authorityExpanded": False,
    "allVulnerabilitiesCovered": False,
    "allWorkflowsCovered": False,
    "oracleReliable": False,
    "safeOrClean": False,
}


def compile_methodology(
    profile: TargetProfile,
    policy: MethodologyPolicy,
    *,
    intake_report: dict[str, Any] | None = None,
    library: MethodologyLibrary | None = None,
) -> dict[str, Any]:
    """Compile one bounded plan from immutable target, policy, library, and intake inputs."""
    selected_library = library or load_builtin_library()
    _validate_inputs(profile, policy, intake_report)
    context = _intake_context(profile, intake_report)
    applicable, exclusions = _applicable_playbooks(profile, policy, selected_library)
    scheduled, budget_exclusions, assigned, phase_assigned = _schedule_playbooks(
        applicable,
        policy,
        context,
    )
    exclusions.extend(budget_exclusions)
    document = _build_plan(
        profile,
        policy,
        selected_library,
        intake_report,
        context,
        applicable,
        scheduled,
        exclusions,
        assigned,
        phase_assigned,
        parent_plan_digest=None,
        observation_set=None,
    )
    validate_methodology_plan(
        document,
        profile=profile,
        policy=policy,
        library=selected_library,
        intake_report=intake_report,
    )
    return document


def replan_methodology(  # noqa: PLR0913 - immutable compiler inputs remain explicit
    profile: TargetProfile,
    policy: MethodologyPolicy,
    previous_plan: dict[str, Any],
    observations: MethodologyObservationSet,
    *,
    intake_report: dict[str, Any] | None = None,
    library: MethodologyLibrary | None = None,
) -> dict[str, Any]:
    """Re-score an existing plan from evidence without changing its trusted contracts."""
    selected_library = library or load_builtin_library()
    _validate_inputs(profile, policy, intake_report)
    validate_methodology_plan(
        previous_plan,
        profile=profile,
        policy=policy,
        library=selected_library,
        intake_report=intake_report,
    )
    validate_document(observations.to_mapping(), "sova.methodology-observations")
    if observations.target_profile_digest != profile.digest:
        raise FormatError(
            "SOVA-METHODOLOGY-OBSERVATION-BINDING",
            "observation target profile does not match the plan target",
        )
    if observations.previous_plan_digest != previous_plan["contentDigest"]:
        raise FormatError(
            "SOVA-METHODOLOGY-OBSERVATION-BINDING",
            "observation set does not bind to the supplied previous plan",
        )
    planned_playbooks = {task["playbook"]["id"] for task in previous_plan["tasks"]}
    if any(item.playbook_id not in planned_playbooks for item in observations.observations):
        raise FormatError(
            "SOVA-METHODOLOGY-OBSERVATION-SCOPE",
            "observations cannot introduce an unplanned playbook",
        )
    if any(item.target_generation_digest != profile.digest for item in observations.observations):
        raise FormatError(
            "SOVA-METHODOLOGY-OBSERVATION-BINDING",
            "observation target generation does not match the immutable target profile",
        )
    context = _intake_context(profile, intake_report)
    library_by_id = selected_library.by_id()
    scheduled_ids = _ordered_unique(task["playbook"]["id"] for task in previous_plan["tasks"])
    scheduled = tuple(library_by_id[identifier] for identifier in scheduled_ids)
    applicable_ids = {
        item.identifier
        for item in selected_library.playbooks
        if set(item.target_predicate.any_target_kinds) & set(profile.target_kinds)
    }
    applicable = tuple(
        item for item in selected_library.playbooks if item.identifier in applicable_ids
    )
    exclusions = [dict(item) for item in previous_plan["exclusions"]]
    phase_assigned = {
        MethodologyPhase(phase): int(values["assigned"])
        for phase, values in previous_plan["budget"]["byPhase"].items()
    }
    document = _build_plan(
        profile,
        policy,
        selected_library,
        intake_report,
        context,
        applicable,
        scheduled,
        exclusions,
        int(previous_plan["budget"]["assigned"]),
        phase_assigned,
        parent_plan_digest=previous_plan["contentDigest"],
        observation_set=observations,
    )
    _assert_contracts_unchanged(previous_plan, document)
    validate_methodology_plan(
        document,
        profile=profile,
        policy=policy,
        library=selected_library,
        intake_report=intake_report,
    )
    return document


def validate_methodology_plan(  # noqa: PLR0912, PLR0915 - fail-closed checks stay visible
    document: dict[str, Any],
    *,
    profile: TargetProfile | None = None,
    policy: MethodologyPolicy | None = None,
    library: MethodologyLibrary | None = None,
    intake_report: dict[str, Any] | None = None,
) -> None:
    """Validate plan schema, digest, graph, budgets, identity, and authority invariants."""
    validate_document(document, "sova.methodology-plan")
    digest_body = dict(document)
    supplied_digest = digest_body.pop("contentDigest")
    if supplied_digest != sha256_digest(canonical_json_bytes(digest_body)):
        raise FormatError("SOVA-METHODOLOGY-PLAN-DIGEST", "plan digest does not match")
    if document["claims"] != _PLAN_CLAIMS:
        raise FormatError("SOVA-METHODOLOGY-AUTHORITY", "methodology plan claims are unsafe")
    if profile is not None and document["targetProfileDigest"] != profile.digest:
        raise FormatError("SOVA-METHODOLOGY-PLAN-BINDING", "plan target profile mismatch")
    if intake_report is not None:
        validate_intake_report(intake_report)
        if document["intakeReportDigest"] != intake_report["contentDigest"]:
            raise FormatError("SOVA-METHODOLOGY-PLAN-BINDING", "plan intake report mismatch")
    if policy is not None:
        if document["policyDigest"] != policy.digest:
            raise FormatError("SOVA-METHODOLOGY-PLAN-BINDING", "plan policy mismatch")
        if document["scheduler"] != policy.scheduler.value:
            raise FormatError("SOVA-METHODOLOGY-PLAN-BINDING", "plan scheduler mismatch")
        if document["budget"]["total"] != policy.max_budget_units or any(
            document["budget"]["byPhase"][phase.value]["total"] != policy.phase_budgets[phase]
            for phase in PHASE_ORDER
        ):
            raise FormatError("SOVA-METHODOLOGY-BUDGET", "plan policy budgets do not match")
        allowed = {item.value for item in policy.allowed_effects}
        if any(not set(task["allowedEffects"]).issubset(allowed) for task in document["tasks"]):
            raise FormatError(
                "SOVA-METHODOLOGY-AUTHORITY", "plan task effects exceed policy authority"
            )
    if library is not None:
        if document["libraryDigest"] != library.digest:
            raise FormatError("SOVA-METHODOLOGY-PLAN-BINDING", "plan library mismatch")
        known = library.by_id()
        for task in document["tasks"]:
            playbook = known.get(task["playbook"]["id"])
            if playbook is None or task["playbook"] != _playbook_reference(playbook):
                raise FormatError(
                    "SOVA-METHODOLOGY-PLAYBOOK-BINDING",
                    "plan task playbook identity is absent or changed",
                )
            if not set(task["allowedEffects"]).issubset(
                {item.value for item in playbook.allowed_effects}
            ):
                raise FormatError(
                    "SOVA-METHODOLOGY-AUTHORITY",
                    "plan task effects exceed the playbook contract",
                )
    task_ids = [task["id"] for task in document["tasks"]]
    if len(task_ids) != len(set(task_ids)):
        raise FormatError("SOVA-METHODOLOGY-TASK-IDENTITY", "plan task IDs are not unique")
    known_tasks = set(task_ids)
    if any(
        dependency not in known_tasks
        for task in document["tasks"]
        for dependency in task["dependsOn"]
    ):
        raise FormatError("SOVA-METHODOLOGY-TASK-DEPENDENCY", "plan has dangling dependencies")
    _validate_phase_matrix(document["tasks"])
    _validate_task_graph(document["tasks"])
    _validate_bound_task_contracts(document, profile, policy, library)
    assigned = sum(int(task["budgetUnits"]) for task in document["tasks"])
    if assigned != document["budget"]["assigned"]:
        raise FormatError("SOVA-METHODOLOGY-BUDGET", "assigned task budget does not match")
    total = int(document["budget"]["total"])
    if assigned > total or document["budget"]["remaining"] != total - assigned:
        raise FormatError("SOVA-METHODOLOGY-BUDGET", "total budget is inconsistent")
    for phase in PHASE_ORDER:
        phase_budget = document["budget"]["byPhase"][phase.value]
        phase_assigned = sum(
            int(task["budgetUnits"]) for task in document["tasks"] if task["phase"] == phase.value
        )
        if phase_budget["assigned"] != phase_assigned:
            raise FormatError("SOVA-METHODOLOGY-BUDGET", "phase budget is inconsistent")
        if phase_assigned > phase_budget["total"] or phase_budget["remaining"] != (
            phase_budget["total"] - phase_assigned
        ):
            raise FormatError("SOVA-METHODOLOGY-BUDGET", "phase budget was exceeded")


def _validate_inputs(
    profile: TargetProfile,
    policy: MethodologyPolicy,
    intake_report: dict[str, Any] | None,
) -> None:
    if policy.target_profile_digest != profile.digest:
        raise FormatError("SOVA-METHODOLOGY-POLICY-BINDING", "policy target digest mismatch")
    if intake_report is not None:
        validate_intake_report(intake_report)
        if intake_report["profileDigest"] != profile.digest:
            raise FormatError(
                "SOVA-METHODOLOGY-INTAKE-BINDING",
                "intake report target profile does not match",
            )


def _intake_context(
    profile: TargetProfile,
    intake_report: dict[str, Any] | None,
) -> dict[str, Any]:
    if intake_report is None:
        return {
            "inputKinds": {item.kind.value for item in profile.inputs},
            "surfaceKinds": set(),
            "workflowCount": 0,
            "dependencyCount": 0,
            "coverageGapCount": len(profile.target_kinds),
            "coverageItemCount": len(profile.target_kinds),
            "status": "not-supplied",
        }
    surface_nodes = [
        item
        for item in intake_report["attackSurfaceGraph"]["nodes"]
        if item["evidenceClass"] != "refuted"
    ]
    counts = intake_report["coverage"]["counts"]
    coverage_gap = sum(int(counts.get(name, 0)) for name in ("unknown", "blocked", "unsupported"))
    return {
        "inputKinds": {
            str(item["kind"]) for item in intake_report["inputs"] if item["status"] == "parsed"
        },
        "surfaceKinds": {str(item["kind"]) for item in surface_nodes},
        "workflowCount": len(intake_report["workflowGraph"]["nodes"]),
        "dependencyCount": sum(item["kind"] == "dependency" for item in surface_nodes),
        "coverageGapCount": coverage_gap,
        "coverageItemCount": len(intake_report["coverage"]["items"]),
        "status": str(intake_report["status"]),
    }


def _applicable_playbooks(
    profile: TargetProfile,
    policy: MethodologyPolicy,
    library: MethodologyLibrary,
) -> tuple[tuple[Playbook, ...], list[dict[str, Any]]]:
    applicable: list[Playbook] = []
    exclusions: list[dict[str, Any]] = []
    denied = set(policy.denied_playbooks)
    required = set(policy.required_playbooks)
    known = library.by_id()
    unknown_required = sorted(required - set(known))
    exclusions.extend(
        _exclusion(identifier, "required-playbook-unavailable", "absent-library")
        for identifier in unknown_required
    )
    for playbook in sorted(library.playbooks, key=lambda item: item.identifier):
        target_matches = bool(
            set(playbook.target_predicate.any_target_kinds) & set(profile.target_kinds)
        )
        if not target_matches:
            reason = (
                "required-playbook-unavailable"
                if playbook.identifier in required
                else "target-kind-mismatch"
            )
            exclusions.append(_exclusion(playbook.identifier, reason, "target-predicate"))
        elif playbook.identifier in denied:
            exclusions.append(_exclusion(playbook.identifier, "policy-denied", "policy"))
        elif not set(playbook.allowed_effects) & set(policy.allowed_effects) & _PASSIVE_EFFECTS:
            exclusions.append(
                _exclusion(playbook.identifier, "effect-not-authorized", "no-effect-intersection")
            )
        else:
            applicable.append(playbook)
    return tuple(applicable), exclusions


def _schedule_playbooks(
    applicable: tuple[Playbook, ...],
    policy: MethodologyPolicy,
    context: dict[str, Any],
) -> tuple[tuple[Playbook, ...], list[dict[str, Any]], int, dict[MethodologyPhase, int]]:
    by_id = {item.identifier: item for item in applicable}
    scores = {item.identifier: _scores(item, context, None) for item in applicable}
    candidate_order = sorted(
        applicable,
        key=lambda item: _scheduler_key(item, scores[item.identifier], policy),
    )
    scheduled: list[Playbook] = []
    scheduled_ids: set[str] = set()
    excluded_ids: set[str] = set()
    exclusions: list[dict[str, Any]] = []
    assigned = 0
    phase_assigned = dict.fromkeys(MethodologyPhase, 0)

    def add_candidate(playbook: Playbook, stack: set[str]) -> bool:
        nonlocal assigned
        if playbook.identifier in scheduled_ids:
            return True
        if playbook.identifier in excluded_ids:
            return False
        if playbook.identifier in stack:
            raise FormatError("SOVA-PLAYBOOK-DEPENDENCY-CYCLE", "playbook dependency cycle")
        next_stack = {*stack, playbook.identifier}
        for dependency_id in playbook.depends_on:
            dependency = by_id.get(dependency_id)
            if dependency is None or not add_candidate(dependency, next_stack):
                excluded_ids.add(playbook.identifier)
                exclusions.append(
                    _exclusion(playbook.identifier, "dependency-excluded", dependency_id)
                )
                return False
        costs = _phase_costs(playbook)
        fits_total = assigned + sum(costs.values()) <= policy.max_budget_units
        fits_phases = all(
            phase_assigned[phase] + cost <= policy.phase_budgets[phase]
            for phase, cost in costs.items()
        )
        if not fits_total or not fits_phases:
            excluded_ids.add(playbook.identifier)
            exclusions.append(_exclusion(playbook.identifier, "budget-exhausted", "bounded-policy"))
            return False
        scheduled.append(playbook)
        scheduled_ids.add(playbook.identifier)
        assigned += sum(costs.values())
        for phase, cost in costs.items():
            phase_assigned[phase] += cost
        return True

    for candidate in candidate_order:
        add_candidate(candidate, set())
    return tuple(scheduled), exclusions, assigned, phase_assigned


def _build_plan(  # noqa: PLR0913, PLR0917 - immutable compiler inputs remain explicit
    profile: TargetProfile,
    policy: MethodologyPolicy,
    library: MethodologyLibrary,
    intake_report: dict[str, Any] | None,
    context: dict[str, Any],
    applicable: tuple[Playbook, ...],
    scheduled: tuple[Playbook, ...],
    exclusions: list[dict[str, Any]],
    assigned: int,
    phase_assigned: dict[MethodologyPhase, int],
    *,
    parent_plan_digest: str | None,
    observation_set: MethodologyObservationSet | None,
) -> dict[str, Any]:
    observation_by_identity = (
        {}
        if observation_set is None
        else {(item.playbook_id, item.phase): item for item in observation_set.observations}
    )
    task_ids = {
        (playbook.identifier, phase): _task_identifier(
            profile.digest, policy.digest, library.digest, playbook, phase
        )
        for playbook in scheduled
        for phase in PHASE_ORDER
    }
    tasks: list[dict[str, Any]] = []
    for phase in PHASE_ORDER:
        for playbook in scheduled:
            observation = observation_by_identity.get((playbook.identifier, phase))
            scores = _scores(playbook, context, observation)
            costs = _phase_costs(playbook)
            dependencies = _task_dependencies(playbook, phase, task_ids)
            status = _task_status(playbook, phase, context, observation)
            tasks.append(
                {
                    "id": task_ids[(playbook.identifier, phase)],
                    "playbook": _playbook_reference(playbook),
                    "phase": phase.value,
                    "status": status,
                    "dependsOn": dependencies,
                    "preconditions": _task_preconditions(playbook, phase, context),
                    "allowedEffects": _phase_effects(playbook, phase, policy),
                    "toolCapabilities": sorted(
                        item.capability for item in playbook.tool_requirements
                    ),
                    "requiredEvidence": sorted(item.kind for item in playbook.required_evidence),
                    "budgetUnits": costs[phase],
                    "scores": scores,
                    "executionCondition": _execution_condition(phase, context),
                    "oracleCalibrationStatus": playbook.oracle_proposal.calibration_status,
                }
            )
    domain_counts = Counter(item.domain.value for item in scheduled)
    document: dict[str, Any] = {
        "artifactType": "sova.methodology-plan",
        "schemaVersion": PLAN_SCHEMA_VERSION,
        "compilerVersion": COMPILER_VERSION,
        "targetProfileDigest": profile.digest,
        "policyDigest": policy.digest,
        "libraryDigest": library.digest,
        "intakeReportDigest": None if intake_report is None else intake_report["contentDigest"],
        "parentPlanDigest": parent_plan_digest,
        "observationSetDigest": None if observation_set is None else observation_set.digest,
        "scheduler": policy.scheduler.value,
        "phaseOrder": [phase.value for phase in PHASE_ORDER],
        "tasks": tasks,
        "exclusions": sorted(
            exclusions,
            key=lambda item: (item["playbookId"], item["reason"], item["details"]),
        ),
        "budget": {
            "total": policy.max_budget_units,
            "assigned": assigned,
            "remaining": policy.max_budget_units - assigned,
            "byPhase": {
                phase.value: {
                    "total": policy.phase_budgets[phase],
                    "assigned": phase_assigned[phase],
                    "remaining": policy.phase_budgets[phase] - phase_assigned[phase],
                }
                for phase in PHASE_ORDER
            },
        },
        "coverage": {
            "libraryPlaybooks": len(library.playbooks),
            "applicablePlaybooks": len(applicable),
            "scheduledPlaybooks": len(scheduled),
            "excludedPlaybooks": len(exclusions),
            "domains": {
                domain.value: domain_counts[domain.value]
                for domain in sorted({item.domain for item in library.playbooks})
            },
            "partial": len(scheduled) < len(applicable) or context["status"] != "complete",
        },
        "claims": dict(_PLAN_CLAIMS),
    }
    document["contentDigest"] = sha256_digest(canonical_json_bytes(document))
    return document


def _scores(
    playbook: Playbook,
    context: dict[str, Any],
    observation: Any | None,
) -> dict[str, int]:
    risk = round((playbook.severity * playbook.likelihood) / 25 * 100)
    surface_overlap = len(
        set(playbook.target_predicate.required_surface_kinds) & context["surfaceKinds"]
    )
    surface_total = max(1, len(playbook.target_predicate.required_surface_kinds))
    input_overlap = bool({item.value for item in playbook.discovery_inputs} & context["inputKinds"])
    reachability = min(
        100, round(surface_overlap / surface_total * 70) + (30 if input_overlap else 0)
    )
    novelty = 75 if observation is None else 20
    state_coverage = min(100, 15 * int(context["workflowCount"]) + surface_overlap * 10)
    dependency_exposure = min(
        100, int(context["dependencyCount"]) * 20 + len(playbook.depends_on) * 15
    )
    item_count = max(1, int(context["coverageItemCount"]))
    evidence_gap = min(100, round(int(context["coverageGapCount"]) / item_count * 100))
    if observation is not None and observation.outcome in {
        ObservationOutcome.INCONCLUSIVE,
        ObservationOutcome.BLOCKED,
        ObservationOutcome.INFRASTRUCTURE_FAILURE,
    }:
        evidence_gap = max(evidence_gap, 90)
    priority = round(
        risk * 0.28
        + reachability * 0.18
        + novelty * 0.12
        + state_coverage * 0.12
        + dependency_exposure * 0.12
        + evidence_gap * 0.18
    )
    return {
        "risk": risk,
        "reachability": reachability,
        "novelty": novelty,
        "stateCoverage": state_coverage,
        "dependencyExposure": dependency_exposure,
        "evidenceGap": evidence_gap,
        "priority": min(100, priority),
    }


def _scheduler_key(
    playbook: Playbook,
    scores: dict[str, int],
    policy: MethodologyPolicy,
) -> tuple[int | str, ...]:
    required_rank = 0 if playbook.identifier in policy.required_playbooks else 1
    if policy.scheduler == SchedulerKind.IDENTIFIER_BASELINE:
        return (required_rank, playbook.identifier)
    if policy.scheduler == SchedulerKind.RISK_FIRST_BASELINE:
        return (required_rank, -scores["risk"], playbook.identifier)
    return (required_rank, -scores["priority"], playbook.identifier)


def _phase_costs(playbook: Playbook) -> dict[MethodologyPhase, int]:
    weight_total = sum(_PHASE_WEIGHTS.values())
    base, remainder = divmod(playbook.base_cost, weight_total)
    costs: dict[MethodologyPhase, int] = {}
    for phase in PHASE_ORDER:
        costs[phase] = base * _PHASE_WEIGHTS[phase]
    for phase in (
        MethodologyPhase.CONFIRMATION,
        MethodologyPhase.REPRODUCTION,
        MethodologyPhase.DISCOVERY,
        MethodologyPhase.HYPOTHESIS,
        MethodologyPhase.REMEDIATION_VALIDATION,
        MethodologyPhase.REPORTING,
    ):
        if remainder <= 0:
            break
        costs[phase] += 1
        remainder -= 1
    return costs


def _task_identifier(
    profile_digest: str,
    policy_digest: str,
    library_digest: str,
    playbook: Playbook,
    phase: MethodologyPhase,
) -> str:
    digest = sha256_digest(
        canonical_json_bytes(
            {
                "profile": profile_digest,
                "policy": policy_digest,
                "library": library_digest,
                "playbook": playbook.digest,
                "phase": phase.value,
            }
        )
    )
    return f"methodology:task:{digest}"


def _task_dependencies(
    playbook: Playbook,
    phase: MethodologyPhase,
    task_ids: dict[tuple[str, MethodologyPhase], str],
) -> list[str]:
    dependencies = [
        task_ids[(dependency, phase)]
        for dependency in playbook.depends_on
        if (dependency, phase) in task_ids
    ]
    phase_index = PHASE_ORDER.index(phase)
    if phase_index > 0:
        dependencies.append(task_ids[(playbook.identifier, PHASE_ORDER[phase_index - 1])])
    return sorted(set(dependencies))


def _task_preconditions(
    playbook: Playbook,
    phase: MethodologyPhase,
    context: dict[str, Any],
) -> list[str]:
    preconditions = [item.description for item in playbook.prerequisites if item.required]
    required_surfaces = set(playbook.target_predicate.required_surface_kinds)
    available_inputs = {item.value for item in playbook.discovery_inputs} & context["inputKinds"]
    if not required_surfaces.issubset(context["surfaceKinds"]):
        preconditions.append("Discover and bind every required playbook attack-surface kind.")
    if not available_inputs:
        preconditions.append("Supply or collect one supported discovery input representation.")
    if phase != MethodologyPhase.DISCOVERY:
        preconditions.append(
            "Complete the preceding methodology phase with generation-bound evidence."
        )
    return sorted(set(preconditions))


def _phase_effects(
    playbook: Playbook,
    phase: MethodologyPhase,
    policy: MethodologyPolicy,
) -> list[str]:
    allowed = set(playbook.allowed_effects) & set(policy.allowed_effects)
    if phase in {
        MethodologyPhase.DISCOVERY,
        MethodologyPhase.HYPOTHESIS,
        MethodologyPhase.REPORTING,
    }:
        allowed &= _PASSIVE_EFFECTS
    return sorted(item.value for item in allowed)


def _task_status(
    playbook: Playbook,
    phase: MethodologyPhase,
    context: dict[str, Any],
    observation: Any | None,
) -> str:
    if observation is not None:
        return {
            ObservationOutcome.OBSERVED: "completed",
            ObservationOutcome.NOT_OBSERVED: "completed",
            ObservationOutcome.INCONCLUSIVE: "inconclusive",
            ObservationOutcome.BLOCKED: "blocked",
            ObservationOutcome.INFRASTRUCTURE_FAILURE: "infrastructure-failure",
        }[observation.outcome]
    if phase == MethodologyPhase.DISCOVERY:
        return "planned"
    if context["status"] != "complete":
        return "blocked"
    surfaces = set(playbook.target_predicate.required_surface_kinds)
    inputs = {item.value for item in playbook.discovery_inputs} & context["inputKinds"]
    return "planned" if surfaces.issubset(context["surfaceKinds"]) and inputs else "blocked"


def _execution_condition(phase: MethodologyPhase, context: dict[str, Any]) -> str:
    condition = (
        "Human approval, current proof of control, unchanged target generation, admitted "
        "executor, phase budget, stop rules, cleanup capability, and evidence sink are required."
    )
    if context["status"] in {"inconclusive", "partial", "not-supplied"}:
        condition += " Resolve intake evidence gaps before any effectful execution."
    if phase in {MethodologyPhase.CONFIRMATION, MethodologyPhase.REPRODUCTION}:
        condition += " A reviewed oracle proposal and equivalent control are additionally required."
    return condition


def _exclusion(playbook_id: str, reason: str, detail: str) -> dict[str, Any]:
    return {"playbookId": playbook_id, "reason": reason, "details": [detail]}


def _playbook_reference(playbook: Playbook) -> dict[str, str]:
    return {"id": playbook.identifier, "version": playbook.version, "digest": playbook.digest}


def _validate_task_graph(tasks: list[dict[str, Any]]) -> None:
    graph = {str(task["id"]): set(task["dependsOn"]) for task in tasks}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise FormatError("SOVA-METHODOLOGY-TASK-CYCLE", "plan task graph has a cycle")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in graph[identifier]:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in graph:
        visit(identifier)


def _validate_phase_matrix(tasks: list[dict[str, Any]]) -> None:
    phases_by_playbook: dict[str, list[str]] = {}
    for task in tasks:
        phases_by_playbook.setdefault(task["playbook"]["id"], []).append(task["phase"])
    expected = [phase.value for phase in PHASE_ORDER]
    if any(sorted(phases) != sorted(expected) for phases in phases_by_playbook.values()):
        raise FormatError(
            "SOVA-METHODOLOGY-PHASES",
            "every scheduled playbook requires exactly one task in every methodology phase",
        )


def _validate_bound_task_contracts(  # noqa: PLR0912 - independent bindings stay visible
    document: dict[str, Any],
    profile: TargetProfile | None,
    policy: MethodologyPolicy | None,
    library: MethodologyLibrary | None,
) -> None:
    if library is None:
        return
    known = library.by_id()
    scheduled_ids = {task["playbook"]["id"] for task in document["tasks"]}
    exclusion_ids = [item["playbookId"] for item in document["exclusions"]]
    if len(exclusion_ids) != len(set(exclusion_ids)):
        raise FormatError(
            "SOVA-METHODOLOGY-EXCLUSION",
            "a playbook cannot have multiple plan exclusions",
        )
    if scheduled_ids & set(exclusion_ids):
        raise FormatError(
            "SOVA-METHODOLOGY-EXCLUSION",
            "a scheduled playbook cannot also be excluded",
        )
    if set(known) != scheduled_ids | (set(exclusion_ids) & set(known)):
        raise FormatError(
            "SOVA-METHODOLOGY-COVERAGE",
            "every library playbook must be scheduled or explicitly excluded",
        )
    domain_counts = Counter(known[identifier].domain.value for identifier in scheduled_ids)
    expected_domains = {
        domain.value: domain_counts[domain.value]
        for domain in sorted({item.domain for item in library.playbooks})
    }
    coverage = document["coverage"]
    if (
        coverage["libraryPlaybooks"] != len(library.playbooks)
        or coverage["scheduledPlaybooks"] != len(scheduled_ids)
        or coverage["excludedPlaybooks"] != len(exclusion_ids)
        or coverage["domains"] != expected_domains
    ):
        raise FormatError(
            "SOVA-METHODOLOGY-COVERAGE",
            "plan coverage counters do not match scheduled and excluded playbooks",
        )
    if profile is not None and policy is not None:
        applicable, _ = _applicable_playbooks(profile, policy, library)
        if coverage["applicablePlaybooks"] != len(applicable):
            raise FormatError(
                "SOVA-METHODOLOGY-COVERAGE",
                "plan applicable-playbook count does not match target and policy",
            )

    task_ids = {
        (task["playbook"]["id"], MethodologyPhase(task["phase"])): task["id"]
        for task in document["tasks"]
    }
    for task in document["tasks"]:
        playbook = known[task["playbook"]["id"]]
        phase = MethodologyPhase(task["phase"])
        if task["toolCapabilities"] != sorted(
            item.capability for item in playbook.tool_requirements
        ) or task["requiredEvidence"] != sorted(item.kind for item in playbook.required_evidence):
            raise FormatError(
                "SOVA-METHODOLOGY-PLAYBOOK-BINDING",
                "task tools or evidence requirements differ from the playbook",
            )
        if task["budgetUnits"] != _phase_costs(playbook)[phase]:
            raise FormatError(
                "SOVA-METHODOLOGY-BUDGET",
                "task cost differs from the playbook phase allocation",
            )
        if task["dependsOn"] != _task_dependencies(playbook, phase, task_ids):
            raise FormatError(
                "SOVA-METHODOLOGY-TASK-DEPENDENCY",
                "task dependencies differ from the playbook phase graph",
            )
        if policy is not None and task["allowedEffects"] != _phase_effects(playbook, phase, policy):
            raise FormatError(
                "SOVA-METHODOLOGY-AUTHORITY",
                "task effects differ from the policy and playbook intersection",
            )
        if (
            profile is not None
            and policy is not None
            and task["id"]
            != _task_identifier(
                profile.digest,
                policy.digest,
                library.digest,
                playbook,
                phase,
            )
        ):
            raise FormatError(
                "SOVA-METHODOLOGY-TASK-IDENTITY",
                "task ID does not bind the target, policy, library, playbook, and phase",
            )


def _assert_contracts_unchanged(
    previous_plan: dict[str, Any],
    next_plan: dict[str, Any],
) -> None:
    immutable_top_level = (
        "targetProfileDigest",
        "policyDigest",
        "libraryDigest",
        "intakeReportDigest",
        "scheduler",
        "phaseOrder",
        "exclusions",
        "budget",
        "claims",
    )
    if any(previous_plan[key] != next_plan[key] for key in immutable_top_level):
        raise FormatError(
            "SOVA-METHODOLOGY-REPLAN-MUTATION",
            "replanning changed an immutable plan contract",
        )
    previous_tasks = {task["id"]: task for task in previous_plan["tasks"]}
    mutable_fields = {"status", "scores"}
    for task in next_plan["tasks"]:
        previous = previous_tasks.get(task["id"])
        if previous is None:
            raise FormatError("SOVA-METHODOLOGY-REPLAN-MUTATION", "replanning introduced a task")
        left = {key: value for key, value in previous.items() if key not in mutable_fields}
        right = {key: value for key, value in task.items() if key not in mutable_fields}
        if left != right:
            raise FormatError(
                "SOVA-METHODOLOGY-REPLAN-MUTATION",
                "replanning changed a task contract",
            )


def _ordered_unique(values: Any) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values))


__all__ = [
    "COMPILER_VERSION",
    "compile_methodology",
    "replan_methodology",
    "validate_methodology_plan",
]
