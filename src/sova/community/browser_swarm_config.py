# SPDX-License-Identifier: Apache-2.0
"""Strict secret-free configuration for the executor-backed browser Arena."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.community.browser_swarm import (
    BrowserSwarmArtifacts,
    BrowserSwarmBudget,
    BrowserSwarmCase,
    BrowserSwarmParticipant,
    run_browser_swarm,
    validate_browser_swarm_contract,
)
from sova.community.chamber_config import (
    _boolean,
    _fields,
    _integer,
    _model,
    _object,
    _sequence,
    _text,
)
from sova.formats.errors import FormatError
from sova.providers import ProviderRoleModel
from sova.runtime import (
    GVisorOciAgentAdapter,
    OciAgentRuntime,
    oci_agent_runtime_from_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.executors import CancellationToken
    from sova.live import BrowserCampaign
    from sova.live.browser import ApprovalPrompt
    from sova.runtime import BrowserProfileLease, RoleModel
    from sova.safety import ControlProof
    from sova.targets import TargetManifest


def _browser_swarm_document_parts(
    document: dict[str, Any],
    *,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
) -> tuple[
    BrowserSwarmCase,
    BrowserSwarmBudget,
    dict[str, RoleModel],
    tuple[tuple[str, OciAgentRuntime], ...],
]:
    """Parse and validate every participant before any external image executes."""
    _fields(
        document,
        "$",
        required=("artifactType", "schemaVersion", "case", "budget", "participants"),
        optional=("ociParticipants",),
    )
    if document["artifactType"] != "sova.browser-swarm" or document["schemaVersion"] != "0.1.0":
        raise FormatError("SOVA-BROWSER-SWARM-VERSION", "browser swarm document is unsupported")

    case_value = _object(document["case"], "$.case")
    _fields(case_value, "$.case", required=("id", "title"))
    budget_value = _object(document["budget"], "$.budget")
    _fields(
        budget_value,
        "$.budget",
        required=(
            "rounds",
            "maxTurnsPerAgent",
            "maxTotalTurns",
            "maxDurationSeconds",
            "maxOutputBytes",
            "maxTotalTokens",
            "stopOnSuccess",
        ),
    )
    token_budget = budget_value["maxTotalTokens"]
    if token_budget is not None:
        token_budget = _integer(token_budget, "$.budget.maxTotalTokens")
    budget = BrowserSwarmBudget(
        _integer(budget_value["rounds"], "$.budget.rounds"),
        _integer(budget_value["maxTurnsPerAgent"], "$.budget.maxTurnsPerAgent"),
        _integer(budget_value["maxTotalTurns"], "$.budget.maxTotalTurns"),
        _integer(budget_value["maxDurationSeconds"], "$.budget.maxDurationSeconds"),
        _integer(budget_value["maxOutputBytes"], "$.budget.maxOutputBytes"),
        token_budget,
        _boolean(budget_value["stopOnSuccess"], "$.budget.stopOnSuccess"),
    )

    participants: list[BrowserSwarmParticipant] = []
    models: dict[str, RoleModel] = {}
    participant_ids: set[str] = set()
    for index, raw in enumerate(_sequence(document["participants"], "$.participants")):
        path = f"$.participants[{index}]"
        value = _object(raw, path)
        _fields(value, path, required=("id", "objective", "allowedCandidateIndices", "model"))
        identifier = _text(value["id"], f"{path}.id")
        grants = tuple(
            _integer(item, f"{path}.allowedCandidateIndices")
            for item in _sequence(
                value["allowedCandidateIndices"], f"{path}.allowedCandidateIndices"
            )
        )
        if identifier in participant_ids:
            raise FormatError("SOVA-BROWSER-SWARM-CONFIG", "participant id is duplicated")
        participant_ids.add(identifier)
        participants.append(
            BrowserSwarmParticipant(
                identifier,
                _text(value["objective"], f"{path}.objective"),
                grants,
            )
        )
        model = _model(
            _object(value["model"], f"{path}.model"),
            f"{path}.model",
            role=f"browser-swarm:{identifier}",
            secret_resolver=secret_resolver,
        )
        if type(model) is ProviderRoleModel and not provider_calls_authorized:
            raise FormatError(
                "SOVA-PROVIDER-CALLS-NOT-ALLOWED",
                "configured provider models require explicit authorization",
            )
        models[identifier] = model

    external_specs: list[tuple[str, OciAgentRuntime]] = []
    for index, raw in enumerate(
        _sequence(document.get("ociParticipants", []), "$.ociParticipants")
    ):
        path = f"$.ociParticipants[{index}]"
        value = _object(raw, path)
        _fields(
            value,
            path,
            required=("id", "objective", "allowedCandidateIndices", "runtime"),
        )
        identifier = _text(value["id"], f"{path}.id")
        if identifier in participant_ids:
            raise FormatError("SOVA-BROWSER-SWARM-CONFIG", "participant id is duplicated")
        runtime = oci_agent_runtime_from_mapping(_object(value["runtime"], f"{path}.runtime"))
        if runtime.identifier != identifier:
            raise FormatError(
                "SOVA-BROWSER-SWARM-EXTERNAL",
                "OCI participant id must match its runtime id",
            )
        grants = tuple(
            _integer(item, f"{path}.allowedCandidateIndices")
            for item in _sequence(
                value["allowedCandidateIndices"], f"{path}.allowedCandidateIndices"
            )
        )
        participant_ids.add(identifier)
        participants.append(
            BrowserSwarmParticipant(
                identifier,
                _text(value["objective"], f"{path}.objective"),
                grants,
            )
        )
        external_specs.append((identifier, runtime))

    case = BrowserSwarmCase(
        _text(case_value["id"], "$.case.id"),
        _text(case_value["title"], "$.case.title"),
        tuple(participants),
    )
    return case, budget, models, tuple(external_specs)


def validate_browser_swarm_document(
    document: dict[str, Any],
    campaign: BrowserCampaign,
    *,
    provider_calls_authorized: bool,
) -> None:
    """Validate the complete swarm contract before native-code setup."""
    case, budget, _models, _external_specs = _browser_swarm_document_parts(
        document,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=provider_calls_authorized,
    )
    validate_browser_swarm_contract(campaign, case, budget)


def run_browser_swarm_document(  # noqa: PLR0913
    document: dict[str, Any],
    target: TargetManifest,
    campaign: BrowserCampaign,
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    profile_lease: BrowserProfileLease,
    secret_resolver: Callable[[str], str | None],
    control_proof: ControlProof | None = None,
    provider_calls_authorized: bool,
    headless: bool = True,
    record_video: bool = False,
    browser_cache: Path | None = None,
    cancellation: CancellationToken | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
    external_models: Mapping[str, RoleModel] | None = None,
) -> BrowserSwarmArtifacts:
    """Parse one exact-version swarm document and execute its finite grants."""
    case, budget, models, external_specs = _browser_swarm_document_parts(
        document,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
    )
    # This must precede all external-adapter binding or model execution.
    validate_browser_swarm_contract(campaign, case, budget)
    external = {} if external_models is None else dict(external_models)
    for identifier, runtime in external_specs:
        model = external.get(identifier)
        if model is None:
            raise FormatError(
                "SOVA-BROWSER-SWARM-EXTERNAL",
                "declared OCI participant has no authorized external model adapter",
                details={"participant": identifier},
            )
        if type(model) is not GVisorOciAgentAdapter:
            raise FormatError(
                "SOVA-BROWSER-SWARM-MODEL-TYPE",
                "OCI participants require the exact gVisor OCI agent adapter",
                details={"participant": identifier},
            )
        if model.runtime.digest != runtime.digest:
            raise FormatError(
                "SOVA-BROWSER-SWARM-SUBSTITUTION",
                "authorized OCI adapter does not match the declared runtime",
                details={"participant": identifier},
            )
        models[identifier] = model
    declared_external = {identifier for identifier, _runtime in external_specs}
    undeclared = sorted(set(external) - declared_external)
    if undeclared:
        raise FormatError(
            "SOVA-BROWSER-SWARM-EXTERNAL",
            "external model adapter was not declared in the swarm document",
            details={"participants": undeclared},
        )
    return run_browser_swarm(
        target,
        campaign,
        case,
        models,
        budget,
        destination,
        package_runner=package_runner,
        browser_executable=browser_executable,
        approval_prompt=approval_prompt,
        profile_lease=profile_lease,
        control_proof=control_proof,
        provider_calls_authorized=provider_calls_authorized,
        headless=headless,
        record_video=record_video,
        browser_cache=browser_cache,
        cancellation=cancellation,
        event_observer=event_observer,
    )


__all__ = ["run_browser_swarm_document", "validate_browser_swarm_document"]
