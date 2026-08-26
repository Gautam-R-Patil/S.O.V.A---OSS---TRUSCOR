# SPDX-License-Identifier: Apache-2.0
"""Strict portable configuration for the unified executor chamber."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from sova.community.chamber_config import (
    _boolean,
    _fields,
    _integer,
    _model,
    _number,
    _object,
    _sequence,
    _text,
)
from sova.community.executor_chamber import (
    CompositeProjectionOracle,
    ExecutorChamberArtifacts,
    ExecutorChamberBudget,
    ExecutorChamberCase,
    ExecutorChamberGrant,
    ExecutorChamberParticipant,
    ProjectionFieldOracle,
    ProjectionPredicateOracle,
    run_executor_chamber,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.providers import ProviderRoute
from sova.runtime import GVisorOciAgentAdapter, OciAgentRuntime, oci_agent_runtime_from_mapping
from sova.trace import Redactor

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.community.executor_chamber import (
        AuthorizationFactory,
        ChamberDeterministicOracle,
        CodecResolver,
        EnvironmentFactory,
    )
    from sova.executors import CancellationToken
    from sova.runtime import RoleModel

_ARTIFACT_TYPE = "sova.executor-chamber"
_SCHEMA_VERSION = "0.1.0"
_PROJECTION_ORACLE = "projection-field-contains"
_TYPED_PROJECTION_ORACLES = {
    "projection-field-equals": "equals",
    "projection-field-exists": "exists",
    "projection-field-number": "number",
    "projection-field-count": "count",
}
_MAX_PROVIDER_ROLE_CHARS = 128


@dataclass(frozen=True, slots=True)
class ExecutorChamberAuthorityPolicy:
    """Document-declared authority that runtime opt-ins may not broaden."""

    authority_target: str
    provider_calls: bool
    offensive: bool


@dataclass(frozen=True, slots=True)
class DeclaredOciParticipant:
    """One participant whose planner is supplied by a digest-pinned OCI adapter."""

    participant: ExecutorChamberParticipant
    runtime: OciAgentRuntime


@dataclass(frozen=True, slots=True)
class ParsedExecutorChamberPlan:
    """Fully parsed immutable execution plan with no raw credential material."""

    case: ExecutorChamberCase
    budget: ExecutorChamberBudget
    grants: tuple[ExecutorChamberGrant, ...]
    models: Mapping[str, RoleModel]
    oracle: ChamberDeterministicOracle
    authority: ExecutorChamberAuthorityPolicy
    oci_participants: tuple[DeclaredOciParticipant, ...]


@dataclass(frozen=True, slots=True)
class ValidatedExecutorChamberGrant:
    """Immutable grant identity retained after effect-free document admission."""

    identifier: str
    binding_id: str
    codec_id: str
    argument_schema_digest: str


@dataclass(frozen=True, slots=True)
class ValidatedExecutorChamberModel:
    """Immutable planner declaration without a materialized model adapter."""

    participant_id: str
    adapter: str
    runtime_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ValidatedExecutorChamberDocument:
    """Effect-free chamber admission metadata safe for CLI OCI preparation."""

    document_digest: str
    case: ExecutorChamberCase
    budget: ExecutorChamberBudget
    grants: tuple[ValidatedExecutorChamberGrant, ...]
    models: tuple[ValidatedExecutorChamberModel, ...]
    oracle: ChamberDeterministicOracle
    authority: ExecutorChamberAuthorityPolicy
    oci_participants: tuple[DeclaredOciParticipant, ...]


@dataclass(frozen=True, slots=True)
class _StaticPlan:
    case: ExecutorChamberCase
    budget: ExecutorChamberBudget
    grants: tuple[ExecutorChamberGrant, ...]
    model_documents: tuple[tuple[str, dict[str, Any]], ...]
    oracle: ChamberDeterministicOracle
    authority: ExecutorChamberAuthorityPolicy
    oci_participants: tuple[DeclaredOciParticipant, ...]


def _validated_metadata(
    document: dict[str, Any],
    static: _StaticPlan,
) -> ValidatedExecutorChamberDocument:
    grants = tuple(
        ValidatedExecutorChamberGrant(
            grant.identifier,
            grant.binding_id,
            grant.codec_id,
            sha256_digest(canonical_json_bytes(grant.argument_schema)),
        )
        for grant in static.grants
    )
    models = tuple(
        [
            ValidatedExecutorChamberModel(identifier, str(model_document["adapter"]))
            for identifier, model_document in static.model_documents
        ]
        + [
            ValidatedExecutorChamberModel(
                declaration.participant.identifier,
                "gvisor-oci",
                declaration.runtime.digest,
            )
            for declaration in static.oci_participants
        ]
    )
    return ValidatedExecutorChamberDocument(
        sha256_digest(canonical_json_bytes(document)),
        static.case,
        static.budget,
        grants,
        models,
        static.oracle,
        static.authority,
        static.oci_participants,
    )


def _reject_secrets(document: dict[str, Any]) -> None:
    inspected = deepcopy(document)
    # `authorization` is a safe schema section name, but the generic redactor
    # intentionally treats that key as sensitive and would otherwise skip all
    # of its children. Relocate the value so its contents are still inspected.
    if "authorization" in inspected:
        inspected["authorityPolicy"] = inspected.pop("authorization")
    oci_rows = inspected.get("ociParticipants", [])
    if isinstance(oci_rows, list):
        for row in oci_rows:
            if not isinstance(row, dict):
                continue
            runtime = row.get("runtime")
            security = runtime.get("security") if isinstance(runtime, dict) else None
            # The exact OCI schema contains the structural declaration
            # `credentials: none`; the runtime parser below verifies it exactly.
            if isinstance(security, dict) and security.get("credentials") == "none":
                del security["credentials"]
    _redacted, disclosures = Redactor(context_id="sova-executor-chamber-document").redact(inspected)
    if disclosures:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-CONFIG-SENSITIVE",
            "executor chamber document must not contain credential-shaped material",
        )


def _validate_scripted_model(value: dict[str, Any], path: str) -> None:
    _fields(value, path, required=("adapter", "modelId", "turns"))
    _text(value["modelId"], f"{path}.modelId")
    for index, raw in enumerate(_sequence(value["turns"], f"{path}.turns")):
        turn_path = f"{path}.turns[{index}]"
        turn = _object(raw, turn_path)
        _fields(
            turn,
            turn_path,
            required=("expectedContains", "responseText", "structured"),
            optional=("toolCalls", "failure", "tokenCount"),
        )
        _text(turn["expectedContains"], f"{turn_path}.expectedContains")
        if not isinstance(turn["responseText"], str):
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                f"{turn_path}.responseText must be a string",
            )
        structured = turn["structured"]
        if structured is not None:
            _object(structured, f"{turn_path}.structured")
        tool_calls = _sequence(turn.get("toolCalls", []), f"{turn_path}.toolCalls")
        for tool_index, tool in enumerate(tool_calls):
            _object(tool, f"{turn_path}.toolCalls[{tool_index}]")
        if tool_calls:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-MODEL-TOOLS",
                "executor chamber planner models cannot declare direct tool calls",
            )
        failure = turn.get("failure")
        if failure is not None and not isinstance(failure, str):
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                f"{turn_path}.failure must be a string or null",
            )
        token_count = turn.get("tokenCount")
        if token_count is not None:
            _integer(token_count, f"{turn_path}.tokenCount")


def _validate_model_document(value: dict[str, Any], path: str, *, role: str) -> str:
    adapter = value.get("adapter")
    if adapter == "scripted":
        _validate_scripted_model(value, path)
        return "scripted"
    if adapter != "provider":
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-CONFIG",
            f"{path}.adapter must be scripted or provider",
        )
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
    if len(role) > _MAX_PROVIDER_ROLE_CHARS:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-CONFIG",
            f"{path} produces an overlong provider role",
        )
    ProviderRoute(
        _text(value["provider"], f"{path}.provider"),
        _text(value["model"], f"{path}.model"),
        _number(value["temperature"], f"{path}.temperature"),
        _integer(value["maxOutputTokens"], f"{path}.maxOutputTokens"),
        _number(value["timeoutSeconds"], f"{path}.timeoutSeconds"),
    )
    return "provider"


def _budget(value: object) -> ExecutorChamberBudget:
    path = "$.budget"
    item = _object(value, path)
    _fields(
        item,
        path,
        required=(
            "rounds",
            "maxActionsPerTurn",
            "maxTotalActions",
            "maxDurationSeconds",
            "maxOutputBytes",
            "maxTotalTokens",
            "maxMutations",
            "maxProcesses",
            "maxFiles",
            "maxNetworkRequests",
            "actionTimeoutSeconds",
            "stopOnSuccess",
            "captureProfile",
        ),
    )
    if _integer(item["maxActionsPerTurn"], f"{path}.maxActionsPerTurn") != 1:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-CONFIG",
            "$.budget.maxActionsPerTurn must be exactly one",
        )
    max_tokens = item["maxTotalTokens"]
    if max_tokens is not None:
        max_tokens = _integer(max_tokens, f"{path}.maxTotalTokens")
    return ExecutorChamberBudget(
        rounds=_integer(item["rounds"], f"{path}.rounds"),
        max_total_actions=_integer(item["maxTotalActions"], f"{path}.maxTotalActions"),
        max_duration_seconds=_integer(item["maxDurationSeconds"], f"{path}.maxDurationSeconds"),
        max_output_bytes=_integer(item["maxOutputBytes"], f"{path}.maxOutputBytes"),
        max_total_tokens=max_tokens,
        max_mutations=_integer(item["maxMutations"], f"{path}.maxMutations"),
        max_processes=_integer(item["maxProcesses"], f"{path}.maxProcesses"),
        max_files=_integer(item["maxFiles"], f"{path}.maxFiles"),
        max_network_requests=_integer(item["maxNetworkRequests"], f"{path}.maxNetworkRequests"),
        action_timeout_seconds=_integer(
            item["actionTimeoutSeconds"], f"{path}.actionTimeoutSeconds"
        ),
        stop_on_success=_boolean(item["stopOnSuccess"], f"{path}.stopOnSuccess"),
        capture_profile=_text(item["captureProfile"], f"{path}.captureProfile"),
    )


def _grants(value: object) -> tuple[ExecutorChamberGrant, ...]:
    grants: list[ExecutorChamberGrant] = []
    identifiers: set[str] = set()
    binding_ids: set[str] = set()
    for index, raw in enumerate(_sequence(value, "$.grants")):
        path = f"$.grants[{index}]"
        item = _object(raw, path)
        _fields(
            item,
            path,
            required=("id", "bindingId", "codecId", "description", "argumentSchema"),
        )
        grant = ExecutorChamberGrant(
            _text(item["id"], f"{path}.id"),
            _text(item["bindingId"], f"{path}.bindingId"),
            _text(item["codecId"], f"{path}.codecId"),
            _text(item["description"], f"{path}.description"),
            _object(item["argumentSchema"], f"{path}.argumentSchema"),
        )
        if grant.identifier in identifiers:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                "grant id is duplicated",
            )
        if grant.binding_id in binding_ids:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                "grant capability binding id is duplicated",
            )
        identifiers.add(grant.identifier)
        binding_ids.add(grant.binding_id)
        grants.append(grant)
    if not grants:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-CONFIG",
            "executor chamber requires at least one grant",
        )
    return tuple(grants)


def _allowed_grants(value: object, path: str) -> tuple[str, ...]:
    return tuple(
        _text(item, f"{path}[{index}]") for index, item in enumerate(_sequence(value, path))
    )


def _oracle(value: object, path: str = "$.oracle") -> ChamberDeterministicOracle:
    item = _object(value, path)
    kind = item.get("kind")
    if kind in {"projection-all", "projection-any"}:
        _fields(item, path, required=("kind", "oracles"), optional=("id",))
        children = tuple(
            _oracle(child, f"{path}.oracles[{index}]")
            for index, child in enumerate(_sequence(item["oracles"], f"{path}.oracles"))
        )
        mode = "all" if kind == "projection-all" else "any"
        return CompositeProjectionOracle(
            mode,
            children,
            _text(item.get("id", f"sova.oracle.{kind}/0.1"), f"{path}.id"),
        )
    if kind == _PROJECTION_ORACLE:
        _fields(item, path, required=("kind", "fieldPath", "contains"), optional=("id",))
        field_path = tuple(
            _text(segment, f"{path}.fieldPath[{index}]")
            for index, segment in enumerate(_sequence(item["fieldPath"], f"{path}.fieldPath"))
        )
        return ProjectionFieldOracle(
            field_path,
            _text(item["contains"], f"{path}.contains"),
            _text(
                item.get("id", "sova.oracle.projection-field-contains/0.1"),
                f"{path}.id",
            ),
        )
    operator_family = _TYPED_PROJECTION_ORACLES.get(str(kind))
    if operator_family is None:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-ORACLE",
            "projection oracle kind is unsupported",
        )
    required = ["kind", "fieldPath"]
    if operator_family in {"equals", "exists"}:
        required.append("value")
        operator = operator_family
    else:
        required.extend(("operator", "value"))
        relation = _text(item.get("operator"), f"{path}.operator")
        if relation not in {"eq", "gt", "gte", "lt", "lte"}:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-ORACLE",
                "numeric/count oracle operator is unsupported",
                path=f"{path}.operator",
            )
        operator = f"{operator_family}-{relation}"
    _fields(item, path, required=tuple(required), optional=("id",))
    field_path = tuple(
        _text(segment, f"{path}.fieldPath[{index}]")
        for index, segment in enumerate(_sequence(item["fieldPath"], f"{path}.fieldPath"))
    )
    return ProjectionPredicateOracle(
        field_path,
        operator,
        item["value"],
        _text(item.get("id", f"sova.oracle.{kind}/0.1"), f"{path}.id"),
    )


def _static_document_parts(  # noqa: PLR0912, PLR0915 - one effect-free validation pass
    document: dict[str, Any],
    *,
    provider_calls_authorized: bool,
    offensive: bool,
) -> _StaticPlan:
    root = _object(document, "$")
    _fields(
        root,
        "$",
        required=(
            "artifactType",
            "schemaVersion",
            "authorization",
            "case",
            "budget",
            "grants",
            "participants",
            "oracle",
        ),
        optional=("ociParticipants",),
    )
    if root["artifactType"] != _ARTIFACT_TYPE or root["schemaVersion"] != _SCHEMA_VERSION:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-VERSION",
            "executor chamber document is unsupported",
        )
    if not isinstance(provider_calls_authorized, bool) or not isinstance(offensive, bool):
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-CONTROL",
            "executor chamber control flags must be booleans",
        )
    _reject_secrets(root)

    authority_value = _object(root["authorization"], "$.authorization")
    _fields(
        authority_value,
        "$.authorization",
        required=("authorityTarget", "providerCalls", "offensive"),
    )
    authority = ExecutorChamberAuthorityPolicy(
        _text(authority_value["authorityTarget"], "$.authorization.authorityTarget"),
        _boolean(authority_value["providerCalls"], "$.authorization.providerCalls"),
        _boolean(authority_value["offensive"], "$.authorization.offensive"),
    )
    if authority.offensive != offensive:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-OFFENSIVE",
            "runtime offensive control must exactly match the document authority policy",
        )

    budget = _budget(root["budget"])
    grants = _grants(root["grants"])
    grant_ids = {grant.identifier for grant in grants}
    participants: list[ExecutorChamberParticipant] = []
    model_documents: list[tuple[str, dict[str, Any]]] = []
    identifiers: set[str] = set()
    provider_participants: set[str] = set()

    for index, raw in enumerate(_sequence(root["participants"], "$.participants")):
        path = f"$.participants[{index}]"
        item = _object(raw, path)
        _fields(item, path, required=("id", "objective", "allowedGrants", "model"))
        identifier = _text(item["id"], f"{path}.id")
        if identifier in identifiers:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                "participant id is duplicated",
            )
        participant = ExecutorChamberParticipant(
            identifier,
            _text(item["objective"], f"{path}.objective"),
            _allowed_grants(item["allowedGrants"], f"{path}.allowedGrants"),
        )
        model_document = _object(item["model"], f"{path}.model")
        role = f"executor-chamber:{identifier}"
        adapter = _validate_model_document(model_document, f"{path}.model", role=role)
        if adapter == "provider":
            provider_participants.add(identifier)
        identifiers.add(identifier)
        participants.append(participant)
        model_documents.append((identifier, model_document))

    oci_participants: list[DeclaredOciParticipant] = []
    for index, raw in enumerate(_sequence(root.get("ociParticipants", []), "$.ociParticipants")):
        path = f"$.ociParticipants[{index}]"
        item = _object(raw, path)
        _fields(item, path, required=("id", "objective", "allowedGrants", "runtime"))
        identifier = _text(item["id"], f"{path}.id")
        if identifier in identifiers:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                "participant id is duplicated",
            )
        participant = ExecutorChamberParticipant(
            identifier,
            _text(item["objective"], f"{path}.objective"),
            _allowed_grants(item["allowedGrants"], f"{path}.allowedGrants"),
        )
        runtime = oci_agent_runtime_from_mapping(_object(item["runtime"], f"{path}.runtime"))
        if runtime.identifier != identifier:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-EXTERNAL",
                "OCI participant id must match its runtime id",
            )
        identifiers.add(identifier)
        participants.append(participant)
        oci_participants.append(DeclaredOciParticipant(participant, runtime))

    case_value = _object(root["case"], "$.case")
    _fields(case_value, "$.case", required=("id", "title", "objective"))
    case = ExecutorChamberCase(
        _text(case_value["id"], "$.case.id"),
        _text(case_value["title"], "$.case.title"),
        _text(case_value["objective"], "$.case.objective"),
        tuple(participants),
    )
    if budget.max_total_actions > budget.rounds * len(case.participants):
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-BUDGET",
            "maxTotalActions exceeds the declared participant-round action ceiling",
        )
    for participant in case.participants:
        unknown = sorted(set(participant.allowed_grants) - grant_ids)
        if unknown:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-CONFIG",
                "participant references an unknown grant",
                details={"participant": participant.identifier, "unknown": unknown},
            )
    oracle = _oracle(root["oracle"])
    if provider_participants and not authority.provider_calls:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "document authority policy does not admit configured provider models",
        )
    if authority.provider_calls and not provider_calls_authorized:
        raise FormatError(
            "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
            "document provider-call authority requires explicit runtime authorization",
        )
    return _StaticPlan(
        case,
        budget,
        grants,
        tuple(model_documents),
        oracle,
        authority,
        tuple(oci_participants),
    )


def _external_models(
    declarations: tuple[DeclaredOciParticipant, ...],
    external_models: Mapping[str, RoleModel] | None,
) -> dict[str, RoleModel]:
    external = {} if external_models is None else dict(external_models)
    if any(not isinstance(identifier, str) for identifier in external):
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-EXTERNAL",
            "external model participant ids must be strings",
        )
    declared = {item.participant.identifier: item for item in declarations}
    missing = sorted(set(declared) - set(external))
    undeclared = sorted(set(external) - set(declared))
    if missing or undeclared:
        raise FormatError(
            "SOVA-EXECUTOR-CHAMBER-EXTERNAL",
            "external model set must exactly match declared OCI participants",
            details={"missing": missing, "undeclared": undeclared},
        )
    for identifier, declaration in declared.items():
        model = external[identifier]
        if type(model) is not GVisorOciAgentAdapter:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-MODEL-TYPE",
                "OCI participants require the exact gVisor OCI agent adapter",
                details={"participant": identifier},
            )
        if model.runtime.digest != declaration.runtime.digest:
            raise FormatError(
                "SOVA-EXECUTOR-CHAMBER-SUBSTITUTION",
                "authorized OCI adapter does not match the declared runtime digest",
                details={"participant": identifier},
            )
    return external


def validate_executor_chamber_document(
    document: dict[str, Any],
    *,
    provider_calls_authorized: bool,
    offensive: bool = False,
) -> ValidatedExecutorChamberDocument:
    """Validate a chamber document without constructing any runtime adapter.

    This is the CLI preflight boundary: it performs exact schema, secret,
    cross-reference, authority, budget, provider-route, and OCI-runtime
    validation but accepts no credential resolver, destination, environment,
    external model, or executor input.
    """
    static = _static_document_parts(
        document,
        provider_calls_authorized=provider_calls_authorized,
        offensive=offensive,
    )
    return _validated_metadata(document, static)


def parse_executor_chamber_document(
    document: dict[str, Any],
    *,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    offensive: bool = False,
    external_models: Mapping[str, RoleModel] | None = None,
) -> ParsedExecutorChamberPlan:
    """Validate and materialize one exact-version, secret-free chamber plan."""
    static = _static_document_parts(
        document,
        provider_calls_authorized=provider_calls_authorized,
        offensive=offensive,
    )
    # Validate every pre-authorized native-code binding before provider adapter
    # construction. Neither this check nor model materialization invokes a model.
    external = _external_models(static.oci_participants, external_models)
    models: dict[str, RoleModel] = {}
    for identifier, model_document in static.model_documents:
        models[identifier] = _model(
            model_document,
            f"$.participants[{len(models)}].model",
            role=f"executor-chamber:{identifier}",
            secret_resolver=secret_resolver,
        )
    models.update(external)
    return ParsedExecutorChamberPlan(
        static.case,
        static.budget,
        static.grants,
        MappingProxyType(models),
        static.oracle,
        static.authority,
        static.oci_participants,
    )


def run_executor_chamber_document(  # noqa: PLR0913
    document: dict[str, Any],
    destination: Path,
    *,
    environment_factory: EnvironmentFactory,
    authorization_factory: AuthorizationFactory,
    codec_resolver: CodecResolver,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    offensive: bool = False,
    external_models: Mapping[str, RoleModel] | None = None,
    cancellation: CancellationToken | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> ExecutorChamberArtifacts:
    """Validate a portable document before creating any target environment."""
    plan = parse_executor_chamber_document(
        document,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        offensive=offensive,
        external_models=external_models,
    )
    return run_executor_chamber(
        plan.case,
        plan.grants,
        plan.models,
        plan.budget,
        destination,
        environment_factory=environment_factory,
        authorization_factory=authorization_factory,
        codec_resolver=codec_resolver,
        oracle=plan.oracle,
        authority_target=plan.authority.authority_target,
        provider_calls_authorized=plan.authority.provider_calls,
        offensive=plan.authority.offensive,
        cancellation=cancellation,
        event_observer=event_observer,
    )


__all__ = [
    "DeclaredOciParticipant",
    "ExecutorChamberAuthorityPolicy",
    "ParsedExecutorChamberPlan",
    "ValidatedExecutorChamberDocument",
    "ValidatedExecutorChamberGrant",
    "ValidatedExecutorChamberModel",
    "parse_executor_chamber_document",
    "run_executor_chamber_document",
    "validate_executor_chamber_document",
]
