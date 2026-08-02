# SPDX-License-Identifier: Apache-2.0
"""Explicitly authorized capsule scenario runner over the executor contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    Executor,
    FailureCause,
    OutcomeStatus,
    SecretProvider,
    SideEffect,
    negotiate,
)
from sova.executors.scripted import ScriptedExecutor
from sova.formats import (
    PackageReader,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.oracles import ObservableRecord, evaluate_oracles
from sova.safety.authorization import (
    ActionIntent,
    ApprovalToken,
    AuthorizationSession,
    BudgetCost,
    EffectClass,
)
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


def action_intent_for_step(
    scenario: dict[str, Any],
    step: dict[str, Any],
    *,
    side_effect: SideEffect,
    evidence: tuple[str, ...],
    target: str,
) -> ActionIntent:
    """Normalize one portable step into the authorization kernel's effect contract."""
    effect = {
        SideEffect.READ: EffectClass.READ,
        SideEffect.MUTATE: EffectClass.MUTATE,
        SideEffect.DESTRUCTIVE: EffectClass.DESTRUCTIVE,
    }[side_effect]
    if step["action"].startswith(("browser.", "computer.", "network.", "mcp.")):
        effect = max(effect, EffectClass.EXTERNAL)
    inputs = step["inputs"]
    path = inputs.get("path") if isinstance(inputs.get("path"), str) else None
    domain = inputs.get("domain") if isinstance(inputs.get("domain"), str) else None
    return ActionIntent(
        id=f"sova:intent:{scenario['id']}:{step['id']}",
        target=target,
        action=step["action"],
        effect=effect,
        required_evidence=frozenset(evidence or ("tool.completed",)),
        cost=BudgetCost(
            steps=1,
            duration_ms=int(float(scenario["safety"]["budgets"].get("maxStepSeconds", 30)) * 1000),
            mutations=int(side_effect != SideEffect.READ),
            processes=int(step["action"].startswith("process.")),
            files=int(step["action"].startswith(("filesystem.", "artifact."))),
            network_requests=int(step["action"].startswith(("browser.", "network.", "mcp."))),
        ),
        path=path,
        tool=step["action"],
        domain=domain,
        offensive=bool(inputs.get("offensive", False)),
        irreversible=bool(inputs.get("irreversible", False)),
    )


@dataclass(frozen=True, slots=True)
class ScenarioRunResult:
    """One executor-neutral scenario result."""

    completion: str
    steps_attempted: int
    steps_succeeded: int
    trace_path: Path


def _load(capsule: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    scenario_descriptor = next(
        (item for item in descriptors if item.role == "scenario"),
        None,
    )
    if scenario_descriptor is None:
        raise FormatError("SOVA-RUN-NO-SCENARIO", "capsule has no scenario")
    scenario = strict_json_loads(reader.read_object(scenario_descriptor))
    if not isinstance(scenario, dict):
        raise FormatError("SOVA-RUN-SCENARIO", "scenario root must be an object")
    validate_document(scenario, "sova.scenario")
    artifacts = {
        descriptor.digest: reader.read_object(descriptor)
        for descriptor in descriptors
        if descriptor.role in {"attachment", "fixture"}
    }
    return scenario, artifacts


def _expanded_steps(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    sequences = {item["id"]: item["steps"] for item in scenario["sequences"]}
    result: list[dict[str, Any]] = []
    active: set[str] = set()

    def expand(steps: list[dict[str, Any]]) -> None:
        for step in steps:
            if step["action"] != "sova.sequence.call":
                result.append(step)
                continue
            target = step["inputs"].get("sequence")
            if not isinstance(target, str) or target not in sequences:
                raise FormatError(
                    "SOVA-RUN-SEQUENCE",
                    "sequence call references an unknown reusable sequence",
                )
            if target in active:
                raise FormatError(
                    "SOVA-RUN-SEQUENCE-CYCLE",
                    "reusable sequence composition contains a cycle",
                )
            active.add(target)
            expand(sequences[target])
            active.remove(target)

    expand(scenario["procedure"]["steps"])
    return result


def run_capsule(  # noqa: PLR0912, PLR0913, PLR0915
    capsule: Path,
    trace_path: Path,
    *,
    executor: Executor,
    workspace: Path,
    authorization: dict[str, Any] | None = None,
    authorization_session: AuthorizationSession | None = None,
    approvals: Mapping[str, ApprovalToken] | None = None,
    cancellation: CancellationToken | None = None,
    secret_provider: SecretProvider | None = None,
) -> ScenarioRunResult:
    """Run abstract steps only after exact capability and authorization checks."""
    scenario, artifacts = _load(capsule)
    steps = _expanded_steps(scenario)
    max_steps = scenario["safety"]["budgets"].get("maxSteps")
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
        raise FormatError(
            "SOVA-RUN-STEP-BUDGET",
            "scenario safety budget requires a positive integer maxSteps",
        )
    required = sorted(
        {
            capability
            for step in steps
            for capability in step.get("requires", [f"{step['action']}/0.1"])
        }
    )
    capabilities = executor.capabilities()
    report = negotiate(capabilities, required)
    by_action = {capability.name: capability for capability in capabilities}
    effectful = not isinstance(executor, ScriptedExecutor) and any(
        by_action.get(step["action"]) is not None
        and by_action[step["action"]].side_effect != SideEffect.READ
        for step in steps
    )
    if authorization_session is None:
        if authorization is None or authorization.get("decision") != "allowed":
            raise FormatError(
                "SOVA-RUN-AUTHORIZATION",
                "scenario execution requires a fresh allowed authorization decision",
            )
        if effectful:
            raise FormatError(
                "SOVA-RUN-AUTHORIZATION-KERNEL",
                "effectful execution requires a live authorization session, not a caller assertion",
            )
        trace_authorization = authorization
    else:
        authorization_session.claim_invocation(str(trace_path.resolve()))
        trace_authorization = {
            "decision": "unknown",
            "scopeDigest": sha256_digest(
                canonical_json_bytes(authorization_session.authority.scope.to_mapping())
            ),
            "decidedBy": "sova.authorization-kernel/0.1",
        }
    writer = TraceWriter(
        trace_path,
        authorization=trace_authorization,
        executor={
            "id": f"sova:executor:{executor.name}",
            "name": executor.name,
            "version": "0.1",
            "capabilityDigest": None,
        },
    )
    writer.append(
        "run.started",
        {
            "scenarioId": scenario["id"],
            "scenarioVersion": scenario["version"],
            "executor": executor.name,
        },
    )
    if len(steps) > max_steps:
        writer.append(
            "blocked.execution-budget",
            {"declaredMaxSteps": max_steps, "expandedSteps": len(steps)},
        )
        writer.finalize(completion="failed")
        return ScenarioRunResult("failed", 0, 0, trace_path)
    if not report.compatible:
        writer.append(
            "blocked.unsupported-capability",
            {"missing": list(report.missing), "supported": list(report.supported)},
        )
        writer.finalize(completion="failed")
        return ScenarioRunResult("failed", 0, 0, trace_path)
    context = ExecutionContext(
        workspace=workspace,
        authorization=trace_authorization,
        artifacts=artifacts,
        secret_provider=secret_provider,
    )
    token = cancellation or CancellationToken()
    succeeded = 0
    attempted = 0
    completion = "completed"
    records: list[ObservableRecord] = []
    evidence_parents: list[str] = []
    for step in steps:
        attempted += 1
        authorization_parent: str | None = None
        if authorization_session is not None:
            capability = by_action[step["action"]]
            intent = action_intent_for_step(
                scenario,
                step,
                side_effect=capability.side_effect,
                evidence=capability.evidence,
                target=authorization_session.proof.subject,
            )
            decision = authorization_session.authorize(
                intent,
                approval=(approvals or {}).get(step["id"]),
            )
            authorization_parent = writer.append(
                "authorization.decision",
                decision.to_mapping(),
                phase=step["id"],
            )
            if not decision.allowed:
                writer.append(
                    "blocked.authorization",
                    {"stepId": step["id"], "reasons": list(decision.reasons)},
                    phase=step["id"],
                    parents=[authorization_parent] if authorization_parent else [],
                )
                completion = "failed"
                break
        request = ActionRequest(
            id=step["id"],
            action=step["action"],
            inputs=step["inputs"],
            timeout_seconds=float(scenario["safety"]["budgets"].get("maxStepSeconds", 30)),
        )
        requested = writer.append(
            "tool.requested",
            {
                "request": {
                    "id": request.id,
                    "action": request.action,
                    "inputs": request.inputs,
                    "timeoutSeconds": str(request.timeout_seconds),
                    "retryAttempt": request.retry_attempt,
                },
                "executor": executor.name,
            },
            phase=step["id"],
            parents=[authorization_parent] if authorization_parent else [],
        )
        records.append(
            ObservableRecord(
                "tool.requested",
                requested,
                {"action": request.action, "inputs": request.inputs},
            )
        )
        try:
            outcome = executor.execute(request, context, token)
        except Exception as error:  # noqa: BLE001 - provider boundary must fail visibly
            outcome = ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.READ,
                {"exceptionType": type(error).__name__},
                error_code="SOVA-EXECUTOR-EXCEPTION",
                limitations=(
                    "The provider raised an exception; its message was omitted "
                    "because it may contain sensitive data.",
                ),
                failure_cause=FailureCause.EXECUTOR,
            )
            completion = "crashed"
        event_kind = (
            "tool.completed" if outcome.status == OutcomeStatus.SUCCEEDED else "tool.failed"
        )
        completed = writer.append(
            event_kind,
            {"outcome": asdict(outcome)},
            phase=step["id"],
            parents=[requested] if requested else [],
        )
        records.append(
            ObservableRecord(
                event_kind,
                completed,
                {"status": outcome.status.value, **outcome.output},
            )
        )
        if completed is not None:
            evidence_parents.append(completed)
        if outcome.status == OutcomeStatus.SUCCEEDED:
            succeeded += 1
            continue
        if completion == "crashed":
            break
        completion = (
            "cancelled"
            if outcome.status == OutcomeStatus.CANCELLED
            else "timeout"
            if outcome.status == OutcomeStatus.TIMEOUT
            else "failed"
        )
        if step["onFailure"] != "continue":
            break
    oracle_report = evaluate_oracles(scenario["oracles"], records)
    writer.append(
        "oracle.completed",
        oracle_report.to_mapping(),
        parents=evidence_parents,
        producer={
            "id": "sova:actor:oracle",
            "kind": "observer",
            "name": "SOVA deterministic oracle",
        },
    )
    writer.append(
        "run.completed" if completion == "completed" else "run.failed",
        {
            "attempted": attempted,
            "succeeded": succeeded,
            "completion": completion,
            "oracleStatus": oracle_report.status.value,
        },
    )
    writer.finalize(completion=completion)
    return ScenarioRunResult(completion, attempted, succeeded, trace_path)


__all__ = ["ScenarioRunResult", "action_intent_for_step", "run_capsule"]
