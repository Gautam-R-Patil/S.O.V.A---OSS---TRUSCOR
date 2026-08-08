# SPDX-License-Identifier: Apache-2.0
"""Strict campaign parsing and budget-boundary tests."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats.errors import FormatError
from sova.live import browser_campaign_from_mapping, owned_web_campaign

if TYPE_CHECKING:
    from collections.abc import Callable


def test_campaign_round_trip_preserves_exact_action_budget() -> None:
    source = owned_web_campaign("http://127.0.0.1:9187/")
    parsed = browser_campaign_from_mapping(source.to_mapping())

    assert parsed == source
    assert parsed.total_actions == 32
    assert parsed.digest == source.digest


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
