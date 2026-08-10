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

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.executors import CancellationToken
    from sova.live import BrowserCampaign
    from sova.live.browser import ApprovalPrompt
    from sova.runtime import BrowserProfileLease, RoleModel
    from sova.safety import ControlProof
    from sova.targets import TargetManifest


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
    cancellation: CancellationToken | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> BrowserSwarmArtifacts:
    """Parse one exact-version swarm document and execute its finite grants."""
    _fields(
        document,
        "$",
        required=("artifactType", "schemaVersion", "case", "budget", "participants"),
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
        if identifier in models:
            raise FormatError("SOVA-BROWSER-SWARM-CONFIG", "participant id is duplicated")
        participants.append(
            BrowserSwarmParticipant(
                identifier,
                _text(value["objective"], f"{path}.objective"),
                grants,
            )
        )
        models[identifier] = _model(
            _object(value["model"], f"{path}.model"),
            f"{path}.model",
            role=f"browser-swarm:{identifier}",
            secret_resolver=secret_resolver,
        )

    case = BrowserSwarmCase(
        _text(case_value["id"], "$.case.id"),
        _text(case_value["title"], "$.case.title"),
        tuple(participants),
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
        cancellation=cancellation,
        event_observer=event_observer,
    )


__all__ = ["run_browser_swarm_document"]
