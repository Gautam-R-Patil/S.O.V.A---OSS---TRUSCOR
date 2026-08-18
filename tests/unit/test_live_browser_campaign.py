# SPDX-License-Identifier: Apache-2.0
"""Strict campaign parsing and budget-boundary tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import (
    AdaptiveBrowserPolicy,
    BrowserCampaign,
    adaptive_browser_policy_from_mapping,
    browser_campaign_from_mapping,
    owned_web_campaign,
    owned_web_target,
)
from sova.live.agent_campaign import _prompt as agent_campaign_prompt
from sova.live.campaign import _build_candidate_capsule, _candidate
from sova.runtime import RoleKind

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_campaign_round_trip_preserves_exact_action_budget() -> None:
    source = owned_web_campaign("http://127.0.0.1:9187/")
    parsed = browser_campaign_from_mapping(source.to_mapping())

    assert parsed == source
    assert parsed.total_actions == 36
    assert parsed.digest == source.digest


def test_offensive_campaign_capsule_uses_schema_valid_low_impact(tmp_path: Path) -> None:
    campaign = BrowserCampaign(
        identifier="sova:browser-campaign:offensive-fixture",
        title="Offensive fixture",
        entry_url="http://127.0.0.1:9187/",
        input_target="#message",
        submit_target="#send",
        candidates=(("fixture",),),
        oracle_contains="FIXTURE",
        max_attempts=1,
        max_duration_seconds=60,
        offensive=True,
        completion_text_gone="Generating...",
        completion_timeout_seconds=120,
    )
    path = tmp_path / "candidate.sova"

    _build_candidate_capsule(campaign, _candidate(("fixture",)), path)

    reader = PackageReader(path)
    assert reader.manifest("sova.capsule")["safety"]["impact"] == "low"
    scenario_descriptor = next(
        descriptor for descriptor in reader.verify("sova.capsule") if descriptor.role == "scenario"
    )
    scenario = strict_json_loads(reader.read_object(scenario_descriptor))
    assert isinstance(scenario, dict)
    assert [step["action"] for step in scenario["procedure"]["steps"][:5]] == [
        "browser.navigate",
        "browser.wait",
        "browser.type",
        "browser.click",
        "browser.wait",
    ]
    assert scenario["procedure"]["steps"][1]["inputs"] == {"time": 2}
    assert scenario["procedure"]["steps"][4]["inputs"] == {"textGone": "Generating..."}
    assert scenario["safety"]["budgets"]["maxStepSeconds"] == 120


def test_agent_planner_receives_only_validated_operator_candidate_seeds() -> None:
    campaign = owned_web_campaign("http://127.0.0.1:9187/")

    prompt = strict_json_loads(
        agent_campaign_prompt(
            RoleKind.RECON,
            owned_web_target("http://127.0.0.1:9187"),
            campaign,
            {},
        ).encode("utf-8")
    )

    assert isinstance(prompt, dict)
    assert prompt["campaignPolicy"]["operatorDeclaredCandidateSeeds"] == [
        list(candidate) for candidate in campaign.selected_candidates
    ]
    assert any("candidate-seed" in rule for rule in prompt["rules"])


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda value: value.update({"unknown": True}), "SOVA-LIVE-CAMPAIGN-FIELDS"),
        (
            lambda value: value["budgets"].update({"maxActions": 999}),
            "SOVA-LIVE-CAMPAIGN-BUDGET",
        ),
        (
            lambda value: value.update({"entryUrl": "https://user:pass@example.test/"}),
            "SOVA-LIVE-CAMPAIGN-URL",
        ),
        (
            lambda value: value.update({"candidates": [["same"], ["same"]]}),
            "SOVA-LIVE-CAMPAIGN-CANDIDATES",
        ),
    ),
)
def test_campaign_parser_fails_closed_on_hostile_or_ambiguous_input(
    mutation: Callable[[dict[str, Any]], None],
    code: str,
) -> None:
    value = deepcopy(owned_web_campaign("http://127.0.0.1:9187/").to_mapping())
    mutation(value)

    with pytest.raises(FormatError) as captured:
        browser_campaign_from_mapping(value)
    assert captured.value.issue.code == code


def test_campaign_rejects_boolean_and_unbounded_budget_values() -> None:
    value = owned_web_campaign("http://127.0.0.1:9187/").to_mapping()
    value["budgets"]["maxAttempts"] = True

    with pytest.raises(FormatError) as captured:
        browser_campaign_from_mapping(value)
    assert captured.value.issue.code == "SOVA-LIVE-CAMPAIGN-BUDGET"


def test_campaign_rejects_invalid_completion_wait_values() -> None:
    source = owned_web_campaign("http://127.0.0.1:9187/")

    with pytest.raises(FormatError, match="completion wait text"):
        replace(source, completion_text_gone="")
    with pytest.raises(FormatError, match="timeout is out of bounds"):
        replace(source, completion_text_gone="Generating...", completion_timeout_seconds=0)
    with pytest.raises(FormatError, match="timeout requires completion wait text"):
        replace(source, completion_timeout_seconds=60)


def test_adaptive_policy_round_trip_and_digest_are_deterministic() -> None:
    source = AdaptiveBrowserPolicy("bounded-adaptive", 3, 12, 600, 2)
    parsed = adaptive_browser_policy_from_mapping(source.to_mapping())

    assert parsed == source
    assert parsed.digest == source.digest


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda value: value.update({"unknown": True}), "SOVA-ADAPTIVE-POLICY"),
        (
            lambda value: value.update({"schemaVersion": "9.0.0"}),
            "SOVA-ADAPTIVE-POLICY",
        ),
        (
            lambda value: value["budgets"].update({"maxRounds": True}),
            "SOVA-ADAPTIVE-POLICY",
        ),
        (
            lambda value: value["budgets"].update({"maxRounds": 9}),
            "SOVA-ADAPTIVE-POLICY-ROUNDS",
        ),
        (
            lambda value: value["budgets"].update({"maxStagnantRounds": 4}),
            "SOVA-ADAPTIVE-POLICY-STAGNATION",
        ),
    ),
)
def test_adaptive_policy_rejects_hostile_or_unbounded_input(
    mutation: Callable[[dict[str, Any]], None],
    code: str,
) -> None:
    value = AdaptiveBrowserPolicy("bounded-adaptive", 3, 12, 600, 2).to_mapping()
    mutation(value)

    with pytest.raises(FormatError) as captured:
        adaptive_browser_policy_from_mapping(value)
    assert captured.value.issue.code == code
