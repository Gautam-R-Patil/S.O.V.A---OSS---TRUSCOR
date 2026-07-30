# SPDX-License-Identifier: Apache-2.0
"""Deterministic fixture execution and bounded outcome comparison."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedModelError
from sova.oracles import ObservableRecord, evaluate_oracles
from sova.trace import TraceReader, TraceWriter

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class ReproductionResult:
    """One controlled synthetic re-execution result."""

    completion: str
    trace_path: Path
    steps_attempted: int
    model_turns: int


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    """An integrity-checked declared-outcome comparison.

    This deliberately small public comparator is not the private experimental
    semantic-reproduction research mechanism.
    """

    equivalent: bool
    left_outcomes: tuple[tuple[str, Any], ...]
    right_outcomes: tuple[tuple[str, Any], ...]
    status: str
    limitations: tuple[str, ...]
    method: str = "sova.declared-outcome-exact/0.4"


def _scenario(capsule: Path) -> dict[str, Any]:
    reader = PackageReader(capsule)
    descriptor = next(
        (item for item in reader.verify("sova.capsule") if item.role == "scenario"),
        None,
    )
    if descriptor is None:
        raise FormatError("SOVA-REPRODUCE-NO-SCENARIO", "capsule has no scenario object")
    value = strict_json_loads(reader.read_object(descriptor))
    if not isinstance(value, dict):
        raise FormatError("SOVA-REPRODUCE-SCENARIO-TYPE", "scenario root must be an object")
    validate_document(value, "sova.scenario")
    return value


def reproduce_with_scripted_model(
    capsule: Path,
    trace_path: Path,
    *,
    model: ScriptedModel,
    authorization: dict[str, Any],
) -> ReproductionResult:
    """Execute only the synthetic model/approval action subset with fresh authority."""
    if authorization.get("decision") != "allowed":
        raise FormatError(
            "SOVA-REPRODUCE-AUTHORIZATION",
            "controlled re-execution requires a fresh allowed authorization decision",
        )
    scenario = _scenario(capsule)
    parameters = scenario["parameters"]
    writer = TraceWriter(
        trace_path,
        capture_profile="standard",
        authorization=authorization,
        environment={
            "platform": "synthetic",
            "python": "deterministic-fixture",
            "codeDigest": None,
            "model": {"id": model.model_id, "deterministic": True},
            "dependencies": [],
        },
    )
    writer.append(
        "run.started",
        {"scenarioId": scenario["id"], "scenarioVersion": scenario["version"]},
    )
    completion = "completed"
    attempted = 0
    records: list[ObservableRecord] = []
    evidence_parents: list[str] = []
    try:
        for step in scenario["procedure"]["steps"]:
            attempted += 1
            action = step["action"]
            if action in {"model.prompt", "model.prompt-with-context"}:
                inputs = step["inputs"]
                prompt = _resolve_prompt(inputs, parameters)
                prompt_id = writer.append(
                    "prompt.sent",
                    {"step": step["id"], "text": prompt},
                    phase=step["id"],
                )
                records.append(ObservableRecord("prompt.sent", prompt_id, {"text": prompt}))
                turn = model.respond(prompt)
                response_id = writer.append(
                    "model.response",
                    {
                        "step": step["id"],
                        "text": turn.response_text,
                        "structured": turn.structured,
                        "model": model.model_id,
                    },
                    phase=step["id"],
                    parents=[prompt_id] if prompt_id else [],
                )
                records.append(
                    ObservableRecord(
                        "model.response",
                        response_id,
                        {"text": turn.response_text, **(turn.structured or {})},
                    )
                )
                if response_id is not None:
                    evidence_parents.append(response_id)
                for tool_call in turn.tool_calls:
                    tool_id = writer.append(
                        "tool.requested",
                        {"step": step["id"], **tool_call},
                        phase=step["id"],
                        parents=[response_id] if response_id else [],
                    )
                    records.append(ObservableRecord("tool.requested", tool_id, tool_call))
            elif action == "agent.request-tool":
                request_id = writer.append(
                    "tool.requested",
                    {"step": step["id"], **step["inputs"]},
                    phase=step["id"],
                )
                writer.append(
                    "blocked.approval",
                    {"step": step["id"], "reason": "no runtime approval supplied"},
                    phase=step["id"],
                    parents=[request_id] if request_id else [],
                )
                records.extend(
                    (
                        ObservableRecord(
                            "tool.requested",
                            request_id,
                            step["inputs"],
                        ),
                        ObservableRecord(
                            "blocked.approval",
                            None,
                            {"reason": "no runtime approval supplied"},
                        ),
                    )
                )
            else:
                raise FormatError(  # noqa: TRY301
                    "SOVA-REPRODUCE-UNSUPPORTED-ACTION",
                    f"synthetic harness does not support action: {action}",
                )
        report = evaluate_oracles(scenario["oracles"], records)
        writer.append(
            "oracle.completed",
            report.to_mapping(),
            parents=evidence_parents,
            producer={
                "id": "sova:actor:oracle",
                "kind": "observer",
                "name": "SOVA deterministic oracle",
            },
        )
        writer.append(
            "run.completed",
            {
                "steps": attempted,
                "modelTurns": model.consumed,
                "oracleStatus": report.status.value,
            },
        )
    except (FormatError, ScriptedModelError) as error:
        completion = "failed"
        writer.append(
            "error.reproduction",
            {"type": type(error).__name__, "message": str(error)},
        )
    writer.finalize(completion=completion)
    return ReproductionResult(completion, trace_path, attempted, model.consumed)


def _resolve_prompt(inputs: dict[str, Any], parameters: dict[str, Any]) -> str:
    if isinstance(inputs.get("text"), str):
        return str(inputs["text"])
    parameter_name = inputs.get("textFromParameter")
    if isinstance(parameter_name, str) and isinstance(parameters.get(parameter_name), str):
        return str(parameters[parameter_name])
    if isinstance(inputs.get("prompt"), str):
        prompt = str(inputs["prompt"])
        context_name = inputs.get("contextFromParameter")
        if isinstance(context_name, str) and isinstance(parameters.get(context_name), str):
            prompt = f"{parameters[context_name]}\n\n{prompt}"
        return prompt
    raise FormatError(
        "SOVA-REPRODUCE-PROMPT",
        "synthetic model action does not resolve to a prompt string",
    )


def compare_observable_outcomes(
    left: Path,
    right: Path,
    *,
    kinds: Sequence[str] = ("model.response", "oracle.completed"),
) -> ComparisonResult:
    """Compare declared observable payloads after offline integrity checks.

    Any recorder-reported event loss or non-full content capture makes the
    result inconclusive. A caller must not convert missing evidence into
    equivalence.
    """
    selected = set(kinds)
    if not selected:
        raise FormatError(
            "SOVA-COMPARE-KINDS",
            "at least one observable event kind is required",
        )

    def portable_payload(kind: str, payload: Any) -> Any:
        if kind != "oracle.completed" or not isinstance(payload, dict):
            return payload
        normalized = dict(payload)
        results = normalized.get("results")
        if isinstance(results, list):
            normalized["results"] = [
                {
                    key: value
                    for key, value in result.items()
                    if key not in {"evidence_event_ids", "observed"}
                }
                if isinstance(result, dict)
                else result
                for result in results
            ]
        return normalized

    def outcomes(path: Path) -> tuple[tuple[tuple[str, Any], ...], tuple[str, ...]]:
        reader = TraceReader(path)
        reader.verify()
        manifest = reader.manifest()
        losses: list[str] = []
        dropped = manifest["capturePolicy"]["droppedEventCount"]
        if dropped:
            losses.append(f"recorder reported {dropped} dropped event(s)")
        if manifest["contentCapture"] != "full":
            losses.append(f"content capture was {manifest['contentCapture']!r}, not 'full'")
        events = reader.events()
        missing = sorted(
            kind for kind in selected if not any(event["kind"] == kind for event in events)
        )
        if missing:
            losses.append(f"selected event kinds were absent: {', '.join(missing)}")
        return tuple(
            (event["kind"], portable_payload(event["kind"], event["payload"]))
            for event in events
            if event["kind"] in selected
        ), tuple(losses)

    left_outcomes, left_losses = outcomes(left)
    right_outcomes, right_losses = outcomes(right)
    limitations = (
        *(f"left: {item}" for item in left_losses),
        *(f"right: {item}" for item in right_losses),
    )
    if limitations:
        status = "inconclusive"
        equivalent = False
    elif left_outcomes == right_outcomes:
        status = "equivalent"
        equivalent = True
    else:
        status = "divergent"
        equivalent = False
    return ComparisonResult(
        equivalent,
        left_outcomes,
        right_outcomes,
        status,
        limitations,
    )


__all__ = [
    "ComparisonResult",
    "ReproductionResult",
    "compare_observable_outcomes",
    "reproduce_with_scripted_model",
]
