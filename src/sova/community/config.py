# SPDX-License-Identifier: Apache-2.0
"""Strict document-to-community-model adapters for the public CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.community.agent_arena import (
    AgentArenaArtifacts,
    AgentArenaBudget,
    AgentArenaCase,
    AgentArenaMatch,
    run_agent_arena,
)
from sova.community.arena import (
    STANDARD_ARENA_PROFILE,
    ArenaCase,
    ArenaMatch,
    ArenaProfile,
    run_local_arena,
)
from sova.community.ctf import CTFScenario, build_ctf_catalog
from sova.community.leaderboard import LeaderboardSubmission, build_static_leaderboard
from sova.community.media import ReplayClipSpec, ReplayFrame, render_replay_clip
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.providers import ProviderRoute, provider_model_from_route
from sova.runtime import (
    GVisorOciAgentAdapter,
    OciAgentRuntime,
    oci_agent_runtime_from_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from sova.runtime import RoleModel


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be an object")
    return value


def _sequence(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be an array")
    return value


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be a non-empty string")
    return value


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be an integer")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be a boolean")
    return value


def _fields(
    value: Mapping[str, Any],
    path: str,
    *,
    required: Sequence[str],
    optional: Sequence[str] = (),
) -> None:
    missing = sorted(set(required) - value.keys())
    unknown = sorted(value.keys() - set(required) - set(optional))
    if missing:
        raise FormatError("SOVA-COMMUNITY-FIELD", f"{path} is missing: {', '.join(missing)}")
    if unknown:
        raise FormatError(
            "SOVA-COMMUNITY-FIELD", f"{path} has unknown fields: {', '.join(unknown)}"
        )


def _resolved(base: Path, value: object, path: str) -> Path:
    root = base.resolve()
    candidate = (root / _text(value, path)).resolve()
    if candidate != root and root not in candidate.parents:
        raise FormatError("SOVA-COMMUNITY-PATH", f"{path} escapes the specification directory")
    return candidate


def run_arena_document(document: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Run a strictly described deterministic Arena document."""
    _fields(document, "$", required=("profile", "participants", "matches"))
    profile_value = _object(document["profile"], "$.profile")
    _fields(
        profile_value,
        "$.profile",
        required=("id", "version", "standard"),
        optional=("sensorPolicy",),
    )
    profile = ArenaProfile(
        identifier=_text(profile_value["id"], "$.profile.id"),
        version=_text(profile_value["version"], "$.profile.version"),
        standard=_boolean(profile_value["standard"], "$.profile.standard"),
        sensor_policy=_text(
            profile_value.get("sensorPolicy", "sova-standard-observable/0.1"),
            "$.profile.sensorPolicy",
        ),
    )
    models: dict[str, ScriptedModel] = {}
    for index, raw_participant in enumerate(_sequence(document["participants"], "$.participants")):
        path = f"$.participants[{index}]"
        participant = _object(raw_participant, path)
        _fields(participant, path, required=("id", "modelId", "turns"))
        identifier = _text(participant["id"], f"{path}.id")
        if identifier in models:
            raise FormatError("SOVA-ARENA-PARTICIPANT", "participant identifier is duplicated")
        turns: list[ScriptedTurn] = []
        for turn_index, raw_turn in enumerate(_sequence(participant["turns"], f"{path}.turns")):
            turn_path = f"{path}.turns[{turn_index}]"
            turn = _object(raw_turn, turn_path)
            _fields(
                turn,
                turn_path,
                required=("expectedContains", "responseText"),
                optional=("failure",),
            )
            failure = turn.get("failure")
            if failure is not None:
                failure = _text(failure, f"{turn_path}.failure")
            turns.append(
                ScriptedTurn(
                    expected_contains=_text(
                        turn["expectedContains"], f"{turn_path}.expectedContains"
                    ),
                    response_text=_text(turn["responseText"], f"{turn_path}.responseText"),
                    failure=failure,
                )
            )
        models[identifier] = ScriptedModel(
            turns,
            model_id=_text(participant["modelId"], f"{path}.modelId"),
        )
    matches: list[ArenaMatch] = []
    for index, raw_match in enumerate(_sequence(document["matches"], "$.matches")):
        path = f"$.matches[{index}]"
        item = _object(raw_match, path)
        _fields(item, path, required=("attacker", "defender", "case"))
        case_path = f"{path}.case"
        case_value = _object(item["case"], case_path)
        _fields(
            case_value,
            case_path,
            required=("id", "attackerPrompt", "defenderPrompt", "successMarker", "points"),
        )
        matches.append(
            ArenaMatch(
                attacker=_text(item["attacker"], f"{path}.attacker"),
                defender=_text(item["defender"], f"{path}.defender"),
                case=ArenaCase(
                    identifier=_text(case_value["id"], f"{case_path}.id"),
                    attacker_prompt=_text(
                        case_value["attackerPrompt"], f"{case_path}.attackerPrompt"
                    ),
                    defender_prompt=_text(
                        case_value["defenderPrompt"], f"{case_path}.defenderPrompt"
                    ),
                    success_marker=_text(case_value["successMarker"], f"{case_path}.successMarker"),
                    points=_integer(case_value["points"], f"{case_path}.points"),
                ),
            )
        )
    return run_local_arena(profile, matches, models, destination)


def _number(value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be a number")
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise FormatError("SOVA-COMMUNITY-TYPE", f"{path} must be a number") from error


def _agent_arena_document_parts(  # noqa: PLR0915 - complete pre-execution validation
    document: dict[str, Any],
    *,
    provider_calls_authorized: bool,
) -> tuple[
    ArenaProfile,
    AgentArenaBudget,
    tuple[tuple[str, ProviderRoute], ...],
    tuple[tuple[str, OciAgentRuntime], ...],
    tuple[AgentArenaMatch, ...],
]:
    """Parse the complete Arena document without invoking any participant."""
    _fields(
        document,
        "$",
        required=("profile", "budget", "participants", "matches"),
        optional=("ociParticipants",),
    )
    profile_value = _object(document["profile"], "$.profile")
    _fields(
        profile_value,
        "$.profile",
        required=("id", "version", "standard"),
        optional=("sensorPolicy",),
    )
    profile = ArenaProfile(
        _text(profile_value["id"], "$.profile.id"),
        _text(profile_value["version"], "$.profile.version"),
        _boolean(profile_value["standard"], "$.profile.standard"),
        _text(
            profile_value.get("sensorPolicy", "sova-agent-arena-observable/0.1"),
            "$.profile.sensorPolicy",
        ),
    )
    if profile.standard or profile.identifier == STANDARD_ARENA_PROFILE.identifier:
        raise FormatError(
            "SOVA-AGENT-ARENA-PROFILE",
            "provider-capable Arena runs must use a custom non-comparable profile",
        )
    budget_value = _object(document["budget"], "$.budget")
    _fields(
        budget_value,
        "$.budget",
        required=(
            "rounds",
            "maxDurationSeconds",
            "maxOutputBytes",
            "maxTotalTokens",
            "contentCapture",
        ),
    )
    token_budget = budget_value["maxTotalTokens"]
    if token_budget is not None:
        token_budget = _integer(token_budget, "$.budget.maxTotalTokens")
    budget = AgentArenaBudget(
        _integer(budget_value["rounds"], "$.budget.rounds"),
        _integer(budget_value["maxDurationSeconds"], "$.budget.maxDurationSeconds"),
        _integer(budget_value["maxOutputBytes"], "$.budget.maxOutputBytes"),
        token_budget,
        _text(budget_value["contentCapture"], "$.budget.contentCapture"),
    )
    provider_participants = _sequence(document["participants"], "$.participants")
    if provider_participants and not provider_calls_authorized:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "provider-backed Arena participants require explicit provider-call authorization",
        )
    provider_specs: list[tuple[str, ProviderRoute]] = []
    participant_ids: set[str] = set()
    for index, raw_participant in enumerate(provider_participants):
        path = f"$.participants[{index}]"
        participant = _object(raw_participant, path)
        _fields(
            participant,
            path,
            required=(
                "id",
                "provider",
                "model",
                "temperature",
                "maxOutputTokens",
                "timeoutSeconds",
            ),
        )
        identifier = _text(participant["id"], f"{path}.id")
        if identifier in participant_ids:
            raise FormatError("SOVA-AGENT-ARENA-PARTICIPANT", "participant id is duplicated")
        route = ProviderRoute(
            _text(participant["provider"], f"{path}.provider"),
            _text(participant["model"], f"{path}.model"),
            _number(participant["temperature"], f"{path}.temperature"),
            _integer(participant["maxOutputTokens"], f"{path}.maxOutputTokens"),
            _number(participant["timeoutSeconds"], f"{path}.timeoutSeconds"),
        )
        participant_ids.add(identifier)
        provider_specs.append((identifier, route))
    external_specs: list[tuple[str, OciAgentRuntime]] = []
    for index, raw_participant in enumerate(
        _sequence(document.get("ociParticipants", []), "$.ociParticipants")
    ):
        path = f"$.ociParticipants[{index}]"
        participant = _object(raw_participant, path)
        _fields(participant, path, required=("id", "runtime"))
        identifier = _text(participant["id"], f"{path}.id")
        runtime = oci_agent_runtime_from_mapping(_object(participant["runtime"], f"{path}.runtime"))
        if runtime.identifier != identifier:
            raise FormatError(
                "SOVA-AGENT-ARENA-EXTERNAL",
                "OCI participant id must match its runtime id",
            )
        if identifier in participant_ids:
            raise FormatError("SOVA-AGENT-ARENA-PARTICIPANT", "participant id is duplicated")
        participant_ids.add(identifier)
        external_specs.append((identifier, runtime))
    matches: list[AgentArenaMatch] = []
    for index, raw_match in enumerate(_sequence(document["matches"], "$.matches")):
        path = f"$.matches[{index}]"
        match = _object(raw_match, path)
        _fields(match, path, required=("challenger", "defender", "judge", "case"))
        case_path = f"{path}.case"
        case = _object(match["case"], case_path)
        _fields(
            case,
            case_path,
            required=(
                "id",
                "seed",
                "challengerObjective",
                "defenderObjective",
                "successSignal",
                "points",
            ),
        )
        matches.append(
            AgentArenaMatch(
                _text(match["challenger"], f"{path}.challenger"),
                _text(match["defender"], f"{path}.defender"),
                _text(match["judge"], f"{path}.judge"),
                AgentArenaCase(
                    _text(case["id"], f"{case_path}.id"),
                    _text(case["seed"], f"{case_path}.seed"),
                    _text(case["challengerObjective"], f"{case_path}.challengerObjective"),
                    _text(case["defenderObjective"], f"{case_path}.defenderObjective"),
                    _text(case["successSignal"], f"{case_path}.successSignal"),
                    _integer(case["points"], f"{case_path}.points"),
                ),
            )
        )
    if not matches:
        raise FormatError("SOVA-AGENT-ARENA-MATCH", "agent Arena needs at least one match")
    required = {
        participant
        for match in matches
        for participant in (match.challenger, match.defender, match.judge)
    }
    missing = sorted(required - participant_ids)
    if missing:
        raise FormatError(
            "SOVA-AGENT-ARENA-PARTICIPANT",
            "agent Arena participant is unavailable",
            details={"missing": missing},
        )
    return (
        profile,
        budget,
        tuple(provider_specs),
        tuple(external_specs),
        tuple(matches),
    )


def validate_agent_arena_document(
    document: dict[str, Any],
    *,
    provider_calls_authorized: bool,
) -> None:
    """Validate the complete document before any provider or native-code setup."""
    _agent_arena_document_parts(
        document,
        provider_calls_authorized=provider_calls_authorized,
    )


def run_agent_arena_document(
    document: dict[str, Any],
    destination: Path,
    *,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    external_models: Mapping[str, RoleModel] | None = None,
) -> AgentArenaArtifacts:
    """Run strict provider and/or attested OCI agents in a local Arena document."""
    profile, budget, provider_specs, external_specs, matches = _agent_arena_document_parts(
        document,
        provider_calls_authorized=provider_calls_authorized,
    )
    models: dict[str, RoleModel] = {
        identifier: provider_model_from_route(
            route,
            role=f"agent-arena:{identifier}",
            secret_resolver=secret_resolver,
        )
        for identifier, route in provider_specs
    }
    external = {} if external_models is None else dict(external_models)
    for identifier, runtime in external_specs:
        model = external.get(identifier)
        if model is None:
            raise FormatError(
                "SOVA-AGENT-ARENA-EXTERNAL",
                "declared OCI participant has no authorized external model adapter",
                details={"participant": identifier},
            )
        if type(model) is not GVisorOciAgentAdapter:
            raise FormatError(
                "SOVA-AGENT-ARENA-MODEL-TYPE",
                "OCI participants require the exact gVisor OCI agent adapter",
                details={"participant": identifier},
            )
        if model.runtime.digest != runtime.digest:
            raise FormatError(
                "SOVA-AGENT-ARENA-SUBSTITUTION",
                "authorized OCI adapter does not match the declared runtime",
                details={"participant": identifier},
            )
        models[identifier] = model
    declared_external = {identifier for identifier, _runtime in external_specs}
    undeclared = sorted(set(external) - declared_external)
    if undeclared:
        raise FormatError(
            "SOVA-AGENT-ARENA-EXTERNAL",
            "external model adapter was not declared in the Arena document",
            details={"participants": undeclared},
        )
    return run_agent_arena(
        profile,
        matches,
        models,
        budget,
        destination,
        provider_calls_authorized=provider_calls_authorized or bool(external_specs),
    )


def build_leaderboard_document(
    document: dict[str, Any],
    destination: Path,
    *,
    base: Path,
) -> dict[str, Any]:
    """Build a verified static leaderboard from a strict local document."""
    _fields(document, "$", required=("methodologySnapshot", "submissions"))
    submissions: list[LeaderboardSubmission] = []
    for index, raw_submission in enumerate(_sequence(document["submissions"], "$.submissions")):
        path = f"$.submissions[{index}]"
        item = _object(raw_submission, path)
        _fields(
            item,
            path,
            required=(
                "category",
                "component",
                "version",
                "profileId",
                "profileDigest",
                "score",
                "possibleScore",
                "artifact",
                "trace",
                "requiredKeyId",
            ),
        )
        submissions.append(
            LeaderboardSubmission(
                category=_text(item["category"], f"{path}.category"),
                component=_text(item["component"], f"{path}.component"),
                version=_text(item["version"], f"{path}.version"),
                profile_id=_text(item["profileId"], f"{path}.profileId"),
                profile_digest=_text(item["profileDigest"], f"{path}.profileDigest"),
                score=_integer(item["score"], f"{path}.score"),
                possible_score=_integer(item["possibleScore"], f"{path}.possibleScore"),
                artifact=_resolved(base, item["artifact"], f"{path}.artifact"),
                trace=_resolved(base, item["trace"], f"{path}.trace"),
                required_key_id=_text(item["requiredKeyId"], f"{path}.requiredKeyId"),
            )
        )
    return build_static_leaderboard(
        submissions,
        destination,
        methodology_snapshot=_text(document["methodologySnapshot"], "$.methodologySnapshot"),
    )


def build_ctf_document(
    document: dict[str, Any],
    destination: Path,
    *,
    base: Path,
) -> dict[str, Any]:
    """Build an inert CTF catalog from strict, explicitly referenced capsules."""
    _fields(document, "$", required=("scenarios",))
    scenarios: list[CTFScenario] = []
    for index, raw_scenario in enumerate(_sequence(document["scenarios"], "$.scenarios")):
        path = f"$.scenarios[{index}]"
        item = _object(raw_scenario, path)
        _fields(
            item,
            path,
            required=(
                "id",
                "title",
                "difficulty",
                "sourceProject",
                "sourceUrl",
                "sourceLicense",
                "setupMode",
                "artifact",
                "explanation",
            ),
        )
        scenarios.append(
            CTFScenario(
                identifier=_text(item["id"], f"{path}.id"),
                title=_text(item["title"], f"{path}.title"),
                difficulty=_text(item["difficulty"], f"{path}.difficulty"),
                source_project=_text(item["sourceProject"], f"{path}.sourceProject"),
                source_url=_text(item["sourceUrl"], f"{path}.sourceUrl"),
                source_license=_text(item["sourceLicense"], f"{path}.sourceLicense"),
                setup_mode=_text(item["setupMode"], f"{path}.setupMode"),
                artifact=_resolved(base, item["artifact"], f"{path}.artifact"),
                explanation=_text(item["explanation"], f"{path}.explanation"),
            )
        )
    return build_ctf_catalog(scenarios, destination)


def render_replay_clip_document(document: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Render a strictly described, metadata-only replay clip."""
    _fields(
        document,
        "$",
        required=("findingClass", "artifactLink", "verificationLink", "frames"),
        optional=("componentName", "disclosureCleared"),
    )
    frames: list[ReplayFrame] = []
    for index, raw_frame in enumerate(_sequence(document["frames"], "$.frames")):
        path = f"$.frames[{index}]"
        frame = _object(raw_frame, path)
        _fields(frame, path, required=("eventKind", "caption"))
        frames.append(
            ReplayFrame(
                event_kind=_text(frame["eventKind"], f"{path}.eventKind"),
                caption=_text(frame["caption"], f"{path}.caption"),
            )
        )
    component = document.get("componentName")
    if component is not None:
        component = _text(component, "$.componentName")
    return render_replay_clip(
        ReplayClipSpec(
            finding_class=_text(document["findingClass"], "$.findingClass"),
            artifact_link=_text(document["artifactLink"], "$.artifactLink"),
            verification_link=_text(document["verificationLink"], "$.verificationLink"),
            frames=tuple(frames),
            component_name=component,
            disclosure_cleared=_boolean(
                document.get("disclosureCleared", False), "$.disclosureCleared"
            ),
        ),
        destination,
    )


__all__ = [
    "build_ctf_document",
    "build_leaderboard_document",
    "render_replay_clip_document",
    "run_agent_arena_document",
    "run_arena_document",
]
