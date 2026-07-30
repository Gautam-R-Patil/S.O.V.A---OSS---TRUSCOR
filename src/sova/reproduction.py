# SPDX-License-Identifier: Apache-2.0
"""Deterministic fixture execution and bounded outcome comparison."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedModelError
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
    """A deterministic comparison, not an LLM semantic judgment."""

    equivalent: bool
    left_outcomes: tuple[tuple[str, Any], ...]
    right_outcomes: tuple[tuple[str, Any], ...]
    method: str = "sova.observable-outcome-exact/0.1"


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
                for tool_call in turn.tool_calls:
                    writer.append(
                        "tool.requested",
                        {"step": step["id"], **tool_call},
                        phase=step["id"],
                        parents=[response_id] if response_id else [],
                    )
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
            else:
                raise FormatError(  # noqa: TRY301
                    "SOVA-REPRODUCE-UNSUPPORTED-ACTION",
                    f"synthetic harness does not support action: {action}",
                )
        writer.append("run.completed", {"steps": attempted, "modelTurns": model.consumed})
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
    """Compare declared observable event payloads exactly and deterministically."""
    selected = set(kinds)

    def outcomes(path: Path) -> tuple[tuple[str, Any], ...]:
        return tuple(
            (event["kind"], event["payload"])
            for event in TraceReader(path).events()
            if event["kind"] in selected
        )

    left_outcomes = outcomes(left)
    right_outcomes = outcomes(right)
    return ComparisonResult(left_outcomes == right_outcomes, left_outcomes, right_outcomes)


__all__ = [
    "ComparisonResult",
    "ReproductionResult",
    "compare_observable_outcomes",
    "reproduce_with_scripted_model",
]
