# SPDX-License-Identifier: Apache-2.0
"""Strict secret-free document parser for the real-time Arena chamber."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.community.chamber import (
    ArenaChamberAction,
    ArenaChamberArtifacts,
    ArenaChamberBudget,
    ArenaChamberCase,
    ArenaChamberMode,
    ArenaChamberParticipant,
    run_arena_chamber,
)
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.providers import ProviderRoute, provider_model_from_route

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.runtime import RoleModel


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be an object")
    return value


def _sequence(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be an array")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be a non-empty string")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be an integer")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be a boolean")
    return value


def _number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be a number")
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path} must be a number") from error


def _fields(
    value: dict[str, Any],
    path: str,
    *,
    required: tuple[str, ...],
    optional: tuple[str, ...] = (),
) -> None:
    missing = sorted(set(required) - set(value))
    unknown = sorted(set(value) - set(required) - set(optional))
    if missing or unknown:
        raise FormatError(
            "SOVA-CHAMBER-CONFIG",
            f"{path} fields are invalid",
            details={"missing": missing, "unknown": unknown},
        )


def _scripted_model(value: dict[str, Any], path: str) -> ScriptedModel:
    _fields(value, path, required=("adapter", "modelId", "turns"))
    if value["adapter"] != "scripted":
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path}.adapter must be scripted")
    turns: list[ScriptedTurn] = []
    for index, raw in enumerate(_sequence(value["turns"], f"{path}.turns")):
        turn_path = f"{path}.turns[{index}]"
        turn = _object(raw, turn_path)
        _fields(
            turn,
            turn_path,
            required=("expectedContains", "responseText", "structured"),
            optional=("toolCalls", "failure", "tokenCount"),
        )
        structured = turn["structured"]
        if structured is not None:
            structured = _object(structured, f"{turn_path}.structured")
        tool_calls = tuple(
            _object(item, f"{turn_path}.toolCalls")
            for item in _sequence(turn.get("toolCalls", []), f"{turn_path}.toolCalls")
        )
        failure = turn.get("failure")
        if failure is not None and not isinstance(failure, str):
            raise FormatError(
                "SOVA-CHAMBER-CONFIG", f"{turn_path}.failure must be a string or null"
            )
        token_count = turn.get("tokenCount")
        if token_count is not None:
            token_count = _integer(token_count, f"{turn_path}.tokenCount")
        turns.append(
            ScriptedTurn(
                _text(turn["expectedContains"], f"{turn_path}.expectedContains"),
                str(turn["responseText"]),
                structured,
                tool_calls,
                failure,
                token_count,
            )
        )
    return ScriptedModel(turns, model_id=_text(value["modelId"], f"{path}.modelId"))


def _model(
    value: dict[str, Any],
    path: str,
    *,
    role: str,
    secret_resolver: Callable[[str], str | None],
) -> RoleModel:
    adapter = value.get("adapter")
    if adapter == "scripted":
        return _scripted_model(value, path)
    if adapter != "provider":
        raise FormatError("SOVA-CHAMBER-CONFIG", f"{path}.adapter must be scripted or provider")
    _fields(
        value,
        path,
        required=(
            "adapter",
            "provider",
            "model",
            "temperature",
            "maxOutputTokens",
            "timeoutSeconds",
        ),
    )
    route = ProviderRoute(
        _text(value["provider"], f"{path}.provider"),
        _text(value["model"], f"{path}.model"),
        _number(value["temperature"], f"{path}.temperature"),
        _integer(value["maxOutputTokens"], f"{path}.maxOutputTokens"),
        _number(value["timeoutSeconds"], f"{path}.timeoutSeconds"),
    )
    return provider_model_from_route(route, role=role, secret_resolver=secret_resolver)


def run_arena_chamber_document(  # noqa: PLR0913
    document: dict[str, Any],
    destination: Path,
    *,
    secret_resolver: Callable[[str], str | None],
    contained_fixture_authorized: bool,
    provider_calls_authorized: bool,
    event_observer: Callable[[dict[str, Any]], None] | None = None,
) -> ArenaChamberArtifacts:
    """Parse and run one exact-version, local Arena chamber document."""
    _fields(
        document,
        "$",
        required=(
            "artifactType",
            "schemaVersion",
            "authorization",
            "environment",
            "case",
            "budget",
            "actions",
            "participants",
            "judge",
        ),
    )
    if document["artifactType"] != "sova.arena-chamber" or document["schemaVersion"] != "0.1.0":
        raise FormatError("SOVA-CHAMBER-VERSION", "Arena chamber document is unsupported")
    authorization = _object(document["authorization"], "$.authorization")
    _fields(authorization, "$.authorization", required=("scope", "confirmed"))
    if (
        authorization["scope"] != "self-owned-built-in-synthetic-world"
        or _boolean(authorization["confirmed"], "$.authorization.confirmed") is not True
    ):
        raise FormatError(
            "SOVA-CHAMBER-NOT-AUTHORIZED",
            "document must confirm the exact self-owned synthetic fixture scope",
        )
    environment = _object(document["environment"], "$.environment")
    _fields(environment, "$.environment", required=("kind", "version"))
    if environment != {"kind": "sova.synthetic-world", "version": "0.1.0"}:
        raise FormatError(
            "SOVA-CHAMBER-ENVIRONMENT",
            "public chamber document supports only sova.synthetic-world/0.1.0",
        )

    budget_value = _object(document["budget"], "$.budget")
    _fields(
        budget_value,
        "$.budget",
        required=(
            "rounds",
            "maxActionsPerTurn",
            "maxTotalActions",
            "maxDurationSeconds",
            "maxOutputBytes",
            "maxTotalTokens",
            "captureProfile",
            "stopOnSuccess",
        ),
    )
    max_tokens = budget_value["maxTotalTokens"]
    if max_tokens is not None:
        max_tokens = _integer(max_tokens, "$.budget.maxTotalTokens")
    budget = ArenaChamberBudget(
        _integer(budget_value["rounds"], "$.budget.rounds"),
        _integer(budget_value["maxActionsPerTurn"], "$.budget.maxActionsPerTurn"),
        _integer(budget_value["maxTotalActions"], "$.budget.maxTotalActions"),
        _integer(budget_value["maxDurationSeconds"], "$.budget.maxDurationSeconds"),
        _integer(budget_value["maxOutputBytes"], "$.budget.maxOutputBytes"),
        max_tokens,
        _text(budget_value["captureProfile"], "$.budget.captureProfile"),
        _boolean(budget_value["stopOnSuccess"], "$.budget.stopOnSuccess"),
    )

    actions: list[ArenaChamberAction] = []
    for index, raw in enumerate(_sequence(document["actions"], "$.actions")):
        path = f"$.actions[{index}]"
        action = _object(raw, path)
        _fields(action, path, required=("id", "action", "description", "inputs"))
        actions.append(
            ArenaChamberAction(
                _text(action["id"], f"{path}.id"),
                _text(action["action"], f"{path}.action"),
                _text(action["description"], f"{path}.description"),
                _object(action["inputs"], f"{path}.inputs"),
            )
        )

    participants: list[ArenaChamberParticipant] = []
    models: dict[str, RoleModel] = {}
    for index, raw in enumerate(_sequence(document["participants"], "$.participants")):
        path = f"$.participants[{index}]"
        participant = _object(raw, path)
        _fields(participant, path, required=("id", "objective", "allowedActions", "model"))
        identifier = _text(participant["id"], f"{path}.id")
        allowed = tuple(
            _text(value, f"{path}.allowedActions")
            for value in _sequence(participant["allowedActions"], f"{path}.allowedActions")
        )
        participants.append(
            ArenaChamberParticipant(
                identifier,
                _text(participant["objective"], f"{path}.objective"),
                allowed,
            )
        )
        if identifier in models:
            raise FormatError("SOVA-CHAMBER-CONFIG", "participant id is duplicated")
        models[identifier] = _model(
            _object(participant["model"], f"{path}.model"),
            f"{path}.model",
            role=f"arena-chamber:{identifier}",
            secret_resolver=secret_resolver,
        )

    judge_value = document["judge"]
    judge_id: str | None = None
    if judge_value is not None:
        judge = _object(judge_value, "$.judge")
        _fields(judge, "$.judge", required=("id", "model"))
        judge_id = _text(judge["id"], "$.judge.id")
        if judge_id in models:
            raise FormatError("SOVA-CHAMBER-CONFIG", "judge id is duplicated")
        models[judge_id] = _model(
            _object(judge["model"], "$.judge.model"),
            "$.judge.model",
            role=f"arena-chamber-judge:{judge_id}",
            secret_resolver=secret_resolver,
        )

    case_value = _object(document["case"], "$.case")
    _fields(
        case_value,
        "$.case",
        required=("id", "title", "mode", "successEventKinds", "seed"),
    )
    try:
        mode = ArenaChamberMode(_text(case_value["mode"], "$.case.mode"))
    except ValueError as error:
        raise FormatError("SOVA-CHAMBER-CONFIG", "$.case.mode is unsupported") from error
    case = ArenaChamberCase(
        _text(case_value["id"], "$.case.id"),
        _text(case_value["title"], "$.case.title"),
        mode,
        tuple(participants),
        judge_id,
        tuple(
            _text(value, "$.case.successEventKinds")
            for value in _sequence(case_value["successEventKinds"], "$.case.successEventKinds")
        ),
        _text(case_value["seed"], "$.case.seed"),
    )
    return run_arena_chamber(
        case,
        actions,
        models,
        budget,
        destination,
        contained_fixture_authorized=contained_fixture_authorized,
        provider_calls_authorized=provider_calls_authorized,
        event_observer=event_observer,
    )


__all__ = ["run_arena_chamber_document"]
