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
from sova.formats import PackageReader, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.oracles import ObservableRecord, evaluate_oracles
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from pathlib import Path


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


def run_capsule(  # noqa: PLR0913, PLR0915
    capsule: Path,
    trace_path: Path,
    *,
    executor: Executor,
    workspace: Path,
    authorization: dict[str, Any],
    cancellation: CancellationToken | None = None,
    secret_provider: SecretProvider | None = None,
) -> ScenarioRunResult:
    """Run abstract steps only after exact capability and authorization checks."""
    if authorization.get("decision") != "allowed":
        raise FormatError(
            "SOVA-RUN-AUTHORIZATION",
            "scenario execution requires a fresh allowed authorization decision",
        )
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
    report = negotiate(executor.capabilities(), required)
    writer = TraceWriter(
        trace_path,
        authorization=authorization,
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
        authorization=authorization,
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


__all__ = ["ScenarioRunResult", "run_capsule"]
