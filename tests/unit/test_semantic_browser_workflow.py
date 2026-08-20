# SPDX-License-Identifier: Apache-2.0
"""Policy and orchestration tests for autonomous multi-page browser missions."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

import sova.live.semantic_workflow as semantic_module
from sova.formats.errors import FormatError
from sova.live import (
    SemanticBrowserAction,
    SemanticBrowserMission,
    SemanticBrowserObservation,
    SemanticExecutionBatch,
    run_semantic_browser_workflow,
    semantic_browser_action_from_mapping,
    semantic_browser_mission_from_mapping,
)
from sova.models import ScriptedModel, ScriptedTurn
from sova.runtime import ModelRouter, RoleKind


def _mission() -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova:semantic-mission:test",
        title="Multi-page owned fixture",
        entry_url="http://127.0.0.1:9123/start",
        objective="Find the planted observable marker by inspecting and using the owned UI.",
        allowed_actions=(
            "browser.navigate",
            "browser.back",
            "browser.click",
            "browser.type",
            "browser.select",
            "browser.press",
            "browser.hover",
            "browser.drag",
            "browser.dialog",
            "browser.tab-new",
            "browser.tab-close",
            "browser.wait",
        ),
        seed_inputs=("research mode", "blue owl"),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA_WORKFLOW_TRIGGERED",
        max_planner_turns=4,
        max_actions=8,
        max_actions_per_plan=3,
        max_duration_seconds=120,
        max_pages=4,
        max_mutations=8,
        max_consecutive_failures=2,
        max_generated_text_characters=512,
        max_total_tokens=100,
        offensive=True,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


class _Driver:
    def __init__(self, *, reproduce: bool = True) -> None:
        self.execute_calls: list[tuple[SemanticBrowserAction, ...]] = []
        self.reproduce_calls: list[tuple[SemanticBrowserAction, ...]] = []
        self._reproduce = reproduce

    def start(self, mission: SemanticBrowserMission) -> SemanticBrowserObservation:
        assert mission.identifier == "sova:semantic-mission:test"
        return SemanticBrowserObservation(
            mission.entry_url,
            "Owned fixture",
            '- link "Knowledge Base" [ref=f1]\n- textbox "Message" [ref=f2]',
        )

    def execute(
        self,
        mission: SemanticBrowserMission,
        actions: tuple[SemanticBrowserAction, ...],
        *,
        turn: int,
    ) -> SemanticExecutionBatch:
        del mission
        self.execute_calls.append(actions)
        if turn == 1:
            return SemanticExecutionBatch(
                SemanticBrowserObservation(
                    "http://127.0.0.1:9123/knowledge-base",
                    "Knowledge Base",
                    '- button "Add document" [ref=f3]\n- button "Sync" [ref=f4]',
                ),
                tuple("succeeded" for _item in actions),
                ("sova:event:turn-1",),
            )
        return SemanticExecutionBatch(
            SemanticBrowserObservation(
                "http://127.0.0.1:9123/challenge",
                "Challenge",
                "SOVA_WORKFLOW_TRIGGERED",
                oracle_passed=True,
            ),
            tuple("succeeded" for _item in actions),
            ("sova:event:turn-2",),
        )

    def reproduce(
        self,
        mission: SemanticBrowserMission,
        actions: tuple[SemanticBrowserAction, ...],
    ) -> SemanticExecutionBatch:
        del mission
        self.reproduce_calls.append(actions)
        return SemanticExecutionBatch(
            SemanticBrowserObservation(
                "http://127.0.0.1:9123/challenge",
                "Challenge",
                "SOVA_WORKFLOW_TRIGGERED" if self._reproduce else "not reproduced",
                self._reproduce,
            ),
            tuple("succeeded" for _item in actions),
            ("sova:event:reproduction",),
        )


def _router() -> ModelRouter:
    model = ScriptedModel(
        [
            ScriptedTurn(
                '"turn":1',
                "",
                {
                    "status": "continue",
                    "actions": [
                        {
                            "action": "browser.click",
                            "arguments": {"element": "Knowledge Base", "ref": "f1"},
                        }
                    ],
                    "coverage": ["navigation"],
                    "reason": "Open the discovered same-origin workflow page.",
                },
                token_count=11,
            ),
            ScriptedTurn(
                '"turn":2',
                "",
                {
                    "status": "continue",
                    "actions": [
                        {
                            "action": "browser.type",
                            "arguments": {
                                "element": "Message",
                                "target": "#message",
                                "text": "blue owl",
                            },
                        },
                        {
                            "action": "browser.click",
                            "arguments": {"element": "Submit", "target": "#send"},
                        },
                    ],
                    "coverage": ["input", "submission"],
                    "reason": "Exercise the visible input and submit workflow.",
                },
                token_count=13,
            ),
        ]
    )
    return ModelRouter({RoleKind.EXPLORER: (model,)})


def test_mission_round_trip_is_strict_and_deterministic() -> None:
    source = _mission()
    parsed = semantic_browser_mission_from_mapping(source.to_mapping())
    assert parsed == source
    assert parsed.digest == source.digest

    unknown = source.to_mapping()
    unknown["unreviewed"] = True
    with pytest.raises(FormatError, match="missing or unknown"):
        semantic_browser_mission_from_mapping(unknown)

    boolean_budget = source.to_mapping()
    boolean_budget["budgets"]["maxActions"] = True
    with pytest.raises(FormatError, match="budgets must be integers"):
        semantic_browser_mission_from_mapping(boolean_budget)


def test_static_recipes_are_validated_and_round_trip() -> None:
    mission = _mission()
    source = replace(
        mission,
        setup_actions=(
            SemanticBrowserAction(
                "browser.click",
                {"element": "Enable knowledge base", "target": "#enable-kb"},
            ),
        ),
        reset_actions=(
            SemanticBrowserAction(
                "browser.navigate",
                {"url": "http://127.0.0.1:9123/reset"},
            ),
        ),
    )
    assert semantic_browser_mission_from_mapping(source.to_mapping()) == source

    escaped = source.to_mapping()
    escaped["resetActions"][0]["arguments"]["url"] = "https://example.com/reset"
    with pytest.raises(FormatError, match="left the mission origin"):
        semantic_browser_mission_from_mapping(escaped)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (
            {"action": "browser.navigate", "arguments": {"url": "https://example.com/"}},
            "left the mission origin",
        ),
        (
            {"action": "browser.click", "arguments": {"element": "button"}},
            "exactly one ref or target",
        ),
        (
            {
                "action": "browser.type",
                "arguments": {
                    "element": "message",
                    "ref": "f2",
                    "text": "Bearer abcdefghijklmnopqrstuvwxyz",
                },
            },
            "credential-shaped",
        ),
        (
            {"action": "browser.evaluate", "arguments": {"script": "document.cookie"}},
            "unapproved action",
        ),
        (
            {"action": "browser.wait", "arguments": {"time": 1, "text": "ready"}},
            "exactly one condition",
        ),
    ],
)
def test_model_actions_fail_closed(value: dict[str, object], message: str) -> None:
    with pytest.raises(FormatError, match=message):
        semantic_browser_action_from_mapping(value, _mission())


def test_semantic_workflow_explores_multiple_pages_and_reproduces() -> None:
    driver = _Driver()
    result = run_semantic_browser_workflow(_mission(), router=_router(), driver=driver)

    assert result.status == "pass"
    assert result.stop_reason == "confirmed-and-reproduced"
    assert [item.action for item in result.actions] == [
        "browser.click",
        "browser.type",
        "browser.click",
    ]
    assert result.tokens_used == 24
    assert result.reproduction is not None and result.reproduction.oracle_passed
    assert len(result.pages_visited) == 3
    assert driver.reproduce_calls == [result.actions]


def test_planner_prompt_exposes_oracle_state_and_seed_usage_guardrails() -> None:
    mission = _mission()
    observation = SemanticBrowserObservation(
        mission.entry_url,
        "Owned fixture",
        '- textbox "Message" [ref=f2]',
    )
    prompt = json.loads(
        semantic_module._planner_prompt(
            mission,
            observation,
            (),
            turn=1,
            remaining_actions=mission.max_actions,
            remaining_mutations=mission.max_mutations,
        )
    )

    assert prompt["observation"]["oraclePassed"] is False
    assert prompt["mission"]["entryUrl"] == mission.entry_url
    assert prompt["mission"]["seedInputs"] == ["research mode", "blue owl"]
    type_schema = prompt["mission"]["allowedActions"]["browser.type"]
    assert set(type_schema) == {"element", "ref", "target", "text", "submit", "slowly"}
    rules = " ".join(prompt["rules"])
    assert "Return complete only when observation.oraclePassed is true" in rules
    assert "copy its exact ref" in rules
    assert "do not repeat the same action and ref" in rules
    assert "mission.entryUrl" in rules


def test_discovery_without_fresh_reproduction_is_inconclusive() -> None:
    result = run_semantic_browser_workflow(
        _mission(), router=_router(), driver=_Driver(reproduce=False)
    )
    assert result.status == "inconclusive"
    assert result.stop_reason == "discovery-not-reproduced"


def test_token_budget_requires_usage_and_fails_closed() -> None:
    model = ScriptedModel(
        [
            ScriptedTurn(
                '"turn":1',
                "",
                {
                    "status": "blocked",
                    "actions": [],
                    "coverage": [],
                    "reason": "No safe next action.",
                },
            )
        ]
    )
    with pytest.raises(FormatError, match="requires provider-reported usage"):
        run_semantic_browser_workflow(
            _mission(),
            router=ModelRouter({RoleKind.EXPLORER: (model,)}),
            driver=_Driver(),
        )


def test_mission_and_observation_reject_scope_and_sensitive_content() -> None:
    with pytest.raises(FormatError, match="credential-shaped"):
        replace(_mission(), seed_inputs=("Bearer abcdefghijklmnopqrstuvwxyz",))
    with pytest.raises(FormatError, match="not redacted"):
        SemanticBrowserObservation(
            _mission().entry_url,
            "fixture",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        )


def test_driver_scope_drift_is_rejected() -> None:
    class _DriftingDriver(_Driver):
        def execute(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
            *,
            turn: int,
        ) -> SemanticExecutionBatch:
            del mission, turn
            return SemanticExecutionBatch(
                SemanticBrowserObservation(
                    "https://example.com/escaped",
                    "outside",
                    "still observable",
                ),
                tuple("succeeded" for _item in actions),
            )

    with pytest.raises(FormatError, match="left the mission origin"):
        run_semantic_browser_workflow(_mission(), router=_router(), driver=_DriftingDriver())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"identifier": ""}, "id and title"),
        ({"objective": ""}, "objective"),
        ({"allowed_actions": ("browser.click", "browser.click")}, "allowedActions"),
        ({"seed_inputs": ("",)}, "seedInputs"),
        ({"oracle_contains": ""}, "oracle"),
        ({"max_planner_turns": 0}, "maxPlannerTurns"),
        ({"max_actions_per_plan": 9}, "maxActionsPerPlan"),
        ({"max_total_tokens": 0}, "maxTotalTokens"),
        ({"provider_observation_disclosure": "raw-page"}, "redacted accessibility"),
    ],
)
def test_mission_constructor_rejects_invalid_contract(
    change: dict[str, object], message: str
) -> None:
    with pytest.raises(FormatError, match=message):
        replace(_mission(), **change)  # type: ignore[arg-type]


def test_mission_constructor_rejects_static_action_overflow_and_denial() -> None:
    click = SemanticBrowserAction("browser.click", {"element": "x", "target": "#x"})
    with pytest.raises(FormatError, match="static-action budget"):
        replace(_mission(), setup_actions=(click,) * 65)
    with pytest.raises(FormatError, match="unapproved action"):
        replace(
            _mission(),
            allowed_actions=("browser.navigate",),
            setup_actions=(click,),
        )

    with pytest.raises(FormatError, match="cannot exceed maxActions"):
        replace(_mission(), max_actions=1, max_actions_per_plan=2)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value.update(schemaVersion="9"), "unsupported"),
        (lambda value: value.update(allowedActions=[1]), "allowedActions"),
        (lambda value: value.update(seedInputs=[1]), "seedInputs"),
        (lambda value: value.update(setupActions=[1]), "action objects"),
        (lambda value: value.update(oracle={}), "text-containment"),
        (lambda value: value.update(budgets={}), "budget fields"),
        (
            lambda value: value["budgets"].update(maxTotalTokens="many"),
            "integer or null",
        ),
        (lambda value: value.update(offensive="yes"), "boolean"),
    ],
)
def test_mission_parser_rejects_hostile_shapes(change: object, message: str) -> None:
    value = _mission().to_mapping()
    change(value)  # type: ignore[operator]
    with pytest.raises(FormatError, match=message):
        semantic_browser_mission_from_mapping(value)


@pytest.mark.parametrize(
    "value",
    [
        {"action": "browser.navigate", "arguments": {"url": "http://127.0.0.1:9123/a"}},
        {
            "action": "browser.click",
            "arguments": {"element": "button", "target": "#x", "doubleClick": True},
        },
        {
            "action": "browser.type",
            "arguments": {
                "element": "box",
                "ref": "f2",
                "text": "blue owl",
                "submit": True,
                "slowly": False,
            },
        },
        {
            "action": "browser.select",
            "arguments": {"element": "choice", "target": "#x", "values": ["a", "b"]},
        },
        {"action": "browser.press", "arguments": {"key": "Enter"}},
        {"action": "browser.hover", "arguments": {"element": "menu", "ref": "f4"}},
        {"action": "browser.back", "arguments": {}},
        {
            "action": "browser.drag",
            "arguments": {
                "startElement": "source card",
                "startTarget": "f5",
                "endElement": "destination lane",
                "endTarget": "f6",
            },
        },
        {"action": "browser.dialog", "arguments": {"accept": False}},
        {
            "action": "browser.dialog",
            "arguments": {"accept": True, "promptText": "blue owl"},
        },
        {
            "action": "browser.tab-new",
            "arguments": {"url": "http://127.0.0.1:9123/details"},
        },
        {"action": "browser.tab-close", "arguments": {}},
        {"action": "browser.wait", "arguments": {"time": 1}},
        {"action": "browser.wait", "arguments": {"text": "ready"}},
        {"action": "browser.wait", "arguments": {"textGone": "loading"}},
    ],
)
def test_all_typed_semantic_actions_are_admitted(value: dict[str, object]) -> None:
    action = semantic_browser_action_from_mapping(value, _mission())
    assert action.to_mapping() == value
    assert action.digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({"action": "browser.click"}, "fields"),
        ({"action": "browser.click", "arguments": []}, "arguments"),
        (
            {"action": "browser.click", "arguments": {"element": "x", "ref": "!"}},
            "ref is invalid",
        ),
        (
            {"action": "browser.click", "arguments": {"element": "x", "target": ""}},
            "target is invalid",
        ),
        (
            {"action": "browser.click", "arguments": {"element": "", "target": "#x"}},
            "element description",
        ),
        (
            {
                "action": "browser.click",
                "arguments": {"element": "x", "target": "#x", "doubleClick": 1},
            },
            "doubleClick",
        ),
        (
            {
                "action": "browser.type",
                "arguments": {"element": "x", "target": "#x", "text": ""},
            },
            "planned text",
        ),
        (
            {
                "action": "browser.type",
                "arguments": {"element": "x", "target": "#x", "text": "ok", "submit": 1},
            },
            "submit",
        ),
        (
            {
                "action": "browser.type",
                "arguments": {"element": "x", "target": "#x", "text": "ok", "slowly": 1},
            },
            "slowly",
        ),
        (
            {
                "action": "browser.select",
                "arguments": {"element": "x", "target": "#x", "values": []},
            },
            "select values",
        ),
        ({"action": "browser.press", "arguments": {"key": ""}}, "press key"),
        (
            {
                "action": "browser.tab-new",
                "arguments": {"url": "https://example.com/escaped"},
            },
            "left the mission origin",
        ),
        (
            {"action": "browser.navigate", "arguments": {}},
            "require one URL",
        ),
        (
            {
                "action": "browser.navigate",
                "arguments": {"url": "http://127.0.0.1:9123/start#fragment"},
            },
            "without fragments",
        ),
        (
            {"action": "browser.back", "arguments": {"unexpected": True}},
            "arguments are invalid",
        ),
        (
            {
                "action": "browser.drag",
                "arguments": {
                    "startElement": "source",
                    "startTarget": "f1",
                    "endElement": "destination",
                },
            },
            "described source and destination",
        ),
        (
            {
                "action": "browser.drag",
                "arguments": {
                    "startElement": "",
                    "startTarget": "f1",
                    "endElement": "destination",
                    "endTarget": "f2",
                },
            },
            "drag element description",
        ),
        (
            {
                "action": "browser.drag",
                "arguments": {
                    "startElement": "source",
                    "startTarget": "",
                    "endElement": "destination",
                    "endTarget": "f2",
                },
            },
            "drag target",
        ),
        (
            {"action": "browser.dialog", "arguments": {"accept": "yes"}},
            "accept must be a boolean",
        ),
        (
            {
                "action": "browser.dialog",
                "arguments": {"accept": False, "promptText": "not allowed"},
            },
            "prompt text is invalid",
        ),
        ({"action": "browser.wait", "arguments": {"time": 0}}, "wait time"),
        ({"action": "browser.wait", "arguments": {"text": ""}}, "wait text"),
    ],
)
def test_typed_action_argument_guards(value: dict[str, object], message: str) -> None:
    with pytest.raises(FormatError, match=message):
        semantic_browser_action_from_mapping(value, _mission())


def test_observation_and_batch_shape_guards() -> None:
    with pytest.raises(FormatError, match="observation is invalid"):
        SemanticBrowserObservation(_mission().entry_url, "x" * 513, "snapshot")
    with pytest.raises(FormatError, match="action statuses"):
        SemanticExecutionBatch(
            SemanticBrowserObservation(_mission().entry_url, "fixture", "snapshot"),
            (),
        )
    with pytest.raises(FormatError, match="action statuses"):
        SemanticExecutionBatch(
            SemanticBrowserObservation(_mission().entry_url, "fixture", "snapshot"),
            ("unknown",),
        )


def _plan(
    status: str = "blocked",
    actions: object = None,
    *,
    coverage: object = None,
    reason: object = "bounded reason",
) -> dict[str, object]:
    return {
        "status": status,
        "actions": [] if actions is None else actions,
        "coverage": [] if coverage is None else coverage,
        "reason": reason,
    }


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, "fields"),
        ({"status": "blocked"}, "fields"),
        (_plan("invalid"), "status"),
        (_plan(actions=[1]), "actions"),
        (_plan(coverage=[1]), "explanation"),
        (_plan(reason=""), "explanation"),
        (_plan("continue"), "continue requires"),
        (
            _plan("blocked", [{"action": "browser.press", "arguments": {"key": "Enter"}}]),
            "terminal",
        ),
    ],
)
def test_planner_decision_contract_rejects_malformed_output(value: object, message: str) -> None:
    with pytest.raises(FormatError, match=message):
        semantic_module._planner_decision(
            value,  # type: ignore[arg-type]
            _mission(),
            remaining_actions=8,
            remaining_mutations=8,
        )


def test_planner_decision_enforces_batch_and_mutation_budgets() -> None:
    press = {"action": "browser.press", "arguments": {"key": "Enter"}}
    with pytest.raises(FormatError, match="batch exceeds"):
        semantic_module._planner_decision(
            _plan("continue", [press, press]),
            _mission(),
            remaining_actions=1,
            remaining_mutations=8,
        )
    with pytest.raises(FormatError, match="mutations exceed"):
        semantic_module._planner_decision(
            _plan("continue", [press]),
            _mission(),
            remaining_actions=8,
            remaining_mutations=0,
        )


def test_planner_requires_a_fresh_observation_after_each_ui_boundary() -> None:
    click = {
        "action": "browser.click",
        "arguments": {"element": "Continue", "target": "#continue"},
    }
    navigate = {
        "action": "browser.navigate",
        "arguments": {"url": "http://127.0.0.1:9123/next"},
    }
    back = {"action": "browser.back", "arguments": {}}
    with pytest.raises(FormatError, match="one observable UI boundary only"):
        semantic_module._planner_decision(
            _plan("continue", [navigate, back]),
            _mission(),
            remaining_actions=8,
            remaining_mutations=8,
        )
    with pytest.raises(FormatError, match="one observable UI boundary only"):
        semantic_module._planner_decision(
            _plan("continue", [navigate, click]),
            _mission(),
            remaining_actions=8,
            remaining_mutations=8,
        )
    type_value = {
        "action": "browser.type",
        "arguments": {"element": "Message", "target": "#message", "text": "blue owl"},
    }
    submitted_type = {
        "action": "browser.type",
        "arguments": {
            "element": "Message",
            "target": "#message",
            "text": "blue owl",
            "submit": True,
        },
    }
    with pytest.raises(FormatError, match="one observable UI boundary only"):
        semantic_module._planner_decision(
            _plan("continue", [submitted_type, click]),
            _mission(),
            remaining_actions=8,
            remaining_mutations=8,
        )
    dialog = {"action": "browser.dialog", "arguments": {"accept": True}}
    decision, modal_actions, _coverage, _reason = semantic_module._planner_decision(
        _plan("continue", [type_value, click, dialog]),
        _mission(),
        remaining_actions=8,
        remaining_mutations=8,
    )
    assert decision == "continue"
    assert [action.action for action in modal_actions] == [
        "browser.type",
        "browser.click",
        "browser.dialog",
    ]
    decision, actions, _coverage, _reason = semantic_module._planner_decision(
        _plan("continue", [type_value, navigate]),
        _mission(),
        remaining_actions=8,
        remaining_mutations=8,
    )
    assert decision == "continue"
    assert [action.action for action in actions] == ["browser.type", "browser.navigate"]


def _one_turn_router(decision: dict[str, object], *, token_count: int | None = 1) -> ModelRouter:
    return ModelRouter(
        {
            RoleKind.EXPLORER: (
                ScriptedModel([ScriptedTurn('"turn":1', "", decision, token_count=token_count)]),
            )
        }
    )


def test_workflow_router_start_and_preexisting_oracle_guards() -> None:
    unrelated = ScriptedModel([ScriptedTurn("unreachable", "", _plan("blocked"), token_count=1)])
    with pytest.raises(FormatError, match="explorer role"):
        run_semantic_browser_workflow(
            _mission(),
            router=ModelRouter({RoleKind.RECON: (unrelated,)}),
            driver=_Driver(),
        )

    class Outside(_Driver):
        def start(self, mission: SemanticBrowserMission) -> SemanticBrowserObservation:
            del mission
            return SemanticBrowserObservation("https://example.com/", "outside", "snapshot")

    with pytest.raises(FormatError, match="started outside"):
        run_semantic_browser_workflow(_mission(), router=_router(), driver=Outside())

    class AlreadyPassed(_Driver):
        def start(self, mission: SemanticBrowserMission) -> SemanticBrowserObservation:
            return SemanticBrowserObservation(
                mission.entry_url, "fixture", "marker", oracle_passed=True
            )

    result = run_semantic_browser_workflow(_mission(), router=_router(), driver=AlreadyPassed())
    assert result.status == "inconclusive"
    assert result.stop_reason == "oracle-present-before-actions"


def test_workflow_duration_terminal_and_token_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter((0.0, 121.0))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    result = run_semantic_browser_workflow(_mission(), router=_router(), driver=_Driver())
    assert result.stop_reason == "duration-budget"

    monkeypatch.undo()
    terminal = run_semantic_browser_workflow(
        replace(_mission(), max_total_tokens=None),
        router=_one_turn_router(_plan("complete"), token_count=None),
        driver=_Driver(),
    )
    assert terminal.stop_reason == "planner-complete"
    assert terminal.tokens_used is None

    with pytest.raises(FormatError, match="token budget exceeded"):
        run_semantic_browser_workflow(
            _mission(),
            router=_one_turn_router(_plan("blocked"), token_count=101),
            driver=_Driver(),
        )


@pytest.mark.parametrize(
    ("ticks", "expected_invocations"),
    (
        ((0.0, 1.0, 121.0), 0),
        ((0.0, 1.0, 2.0, 3.0, 121.0), 1),
    ),
)
def test_workflow_deadline_stops_before_planning_or_browser_execution(
    monkeypatch: pytest.MonkeyPatch,
    ticks: tuple[float, ...],
    expected_invocations: int,
) -> None:
    values = iter(ticks)
    monkeypatch.setattr(time, "monotonic", lambda: next(values))
    driver = _Driver()
    router = _one_turn_router(
        _plan(
            "continue",
            [
                {
                    "action": "browser.click",
                    "arguments": {"element": "Knowledge Base", "ref": "f1"},
                }
            ],
        )
    )

    result = run_semantic_browser_workflow(_mission(), router=router, driver=driver)

    assert result.status == "not-observed"
    assert result.stop_reason == "duration-budget"
    assert len(result.invocations) == expected_invocations
    assert driver.execute_calls == []


def test_reproduction_page_budget_is_enforced() -> None:
    mission = replace(_mission(), max_pages=1)

    class ReproductionPagesDriver(_Driver):
        def execute(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
            *,
            turn: int,
        ) -> SemanticExecutionBatch:
            del turn
            self.execute_calls.append(actions)
            return SemanticExecutionBatch(
                SemanticBrowserObservation(
                    mission.entry_url,
                    "Challenge",
                    "SOVA_WORKFLOW_TRIGGERED",
                    oracle_passed=True,
                ),
                tuple("succeeded" for _item in actions),
                (),
                (mission.entry_url,),
            )

        def reproduce(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
        ) -> SemanticExecutionBatch:
            self.reproduce_calls.append(actions)
            return SemanticExecutionBatch(
                SemanticBrowserObservation(
                    mission.entry_url,
                    "Challenge",
                    "SOVA_WORKFLOW_TRIGGERED",
                    oracle_passed=True,
                ),
                tuple("succeeded" for _item in actions),
                (),
                (mission.entry_url, "http://127.0.0.1:9123/second"),
            )

    router = _one_turn_router(
        _plan(
            "continue",
            [
                {
                    "action": "browser.click",
                    "arguments": {"element": "Knowledge Base", "ref": "f1"},
                }
            ],
        )
    )
    with pytest.raises(FormatError, match="reproduction visited page budget"):
        run_semantic_browser_workflow(
            mission,
            router=router,
            driver=ReproductionPagesDriver(),
        )


def test_workflow_discards_provider_result_that_returns_after_shared_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(time, "monotonic", lambda: clock.now)

    class LateModel:
        model_id = "late-provider"

        def respond(self, _prompt: str) -> SimpleNamespace:
            clock.now = 121.0
            return SimpleNamespace(
                response_text="",
                structured=_plan(
                    "continue",
                    [
                        {
                            "action": "browser.click",
                            "arguments": {"element": "Knowledge Base", "ref": "f1"},
                        }
                    ],
                ),
                tool_calls=(),
                token_count=7,
                monetary_cost=None,
                resolved_model_id=None,
            )

    driver = _Driver()
    result = run_semantic_browser_workflow(
        _mission(),
        router=ModelRouter({RoleKind.EXPLORER: (LateModel(),)}),
        driver=driver,
    )

    assert result.status == "not-observed"
    assert result.stop_reason == "duration-budget"
    assert result.tokens_used == 7
    assert len(result.invocations) == 1
    assert driver.execute_calls == []
    assert driver.reproduce_calls == []


def test_workflow_cannot_pass_when_execution_or_reproduction_returns_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(time, "monotonic", lambda: clock.now)

    class LateExecution(_Driver):
        def execute(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
            *,
            turn: int,
        ) -> SemanticExecutionBatch:
            batch = super().execute(mission, actions, turn=turn)
            clock.now = 121.0
            return batch

    execution_driver = LateExecution()
    execution = run_semantic_browser_workflow(_mission(), router=_router(), driver=execution_driver)
    assert execution.status == "not-observed"
    assert execution.stop_reason == "duration-budget"
    assert len(execution_driver.execute_calls) == 1
    assert execution_driver.reproduce_calls == []

    clock.now = 0.0

    class LateReproduction(_Driver):
        def reproduce(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
        ) -> SemanticExecutionBatch:
            batch = super().reproduce(mission, actions)
            clock.now = 121.0
            return batch

    reproduction_driver = LateReproduction()
    reproduction = run_semantic_browser_workflow(
        _mission(), router=_router(), driver=reproduction_driver
    )
    assert reproduction.status == "inconclusive"
    assert reproduction.stop_reason == "duration-budget"
    assert reproduction.reproduction is not None
    assert reproduction_driver.reproduce_calls


def test_workflow_rejects_bad_provider_plan_then_replans_without_execution() -> None:
    click = {
        "action": "browser.click",
        "arguments": {"element": "Knowledge Base", "ref": "f1"},
    }
    model = ScriptedModel(
        [
            ScriptedTurn(
                '"turn":1',
                "",
                _plan("continue", [click, click]),
                token_count=2,
            ),
            ScriptedTurn(
                '"plannerRejected"',
                "",
                _plan(
                    "continue",
                    [click],
                    coverage=["navigation"],
                    reason="Retry with one observable UI boundary.",
                ),
                token_count=3,
            ),
        ]
    )
    driver = _Driver()
    result = run_semantic_browser_workflow(
        _mission(),
        router=ModelRouter({RoleKind.EXPLORER: (model,)}),
        driver=driver,
    )

    assert result.stop_reason == "confirmed-and-reproduced"
    assert result.tokens_used == 5
    assert len(result.invocations) == 2
    assert len(driver.execute_calls) == 1
    assert (
        driver.execute_calls[0][0].digest
        == semantic_browser_action_from_mapping(click, _mission()).digest
    )


def test_workflow_bounds_consecutive_provider_plan_rejections() -> None:
    malformed = _plan("continue")
    model = ScriptedModel(
        [
            ScriptedTurn('"turn":1', "", malformed, token_count=1),
            ScriptedTurn('"turn":2', "", malformed, token_count=1),
        ]
    )
    driver = _Driver()
    result = run_semantic_browser_workflow(
        _mission(),
        router=ModelRouter({RoleKind.EXPLORER: (model,)}),
        driver=driver,
    )

    assert result.stop_reason == "consecutive-planner-rejection-budget"
    assert result.tokens_used == 2
    assert len(result.invocations) == 2
    assert driver.execute_calls == []


def test_workflow_action_stagnation_page_and_failure_budgets() -> None:
    press = {"action": "browser.press", "arguments": {"key": "Enter"}}
    continue_plan = _plan("continue", [press])

    action_limited = run_semantic_browser_workflow(
        replace(_mission(), max_actions=1, max_actions_per_plan=1),
        router=_one_turn_router(continue_plan),
        driver=_Driver(),
    )
    assert action_limited.stop_reason == "action-budget"

    class SameState(_Driver):
        def execute(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
            *,
            turn: int,
        ) -> SemanticExecutionBatch:
            del turn
            return SemanticExecutionBatch(self.start(mission), ("succeeded",) * len(actions))

    repeated = ScriptedModel(
        [
            ScriptedTurn('"turn":1', "", continue_plan, token_count=1),
            ScriptedTurn('"turn":2', "", continue_plan, token_count=1),
        ]
    )
    stagnant = run_semantic_browser_workflow(
        _mission(),
        router=ModelRouter({RoleKind.EXPLORER: (repeated,)}),
        driver=SameState(),
    )
    assert stagnant.stop_reason == "stagnation"

    with pytest.raises(FormatError, match="page budget"):
        run_semantic_browser_workflow(
            replace(_mission(), max_pages=1),
            router=_one_turn_router(continue_plan),
            driver=_Driver(),
        )

    class Failed(_Driver):
        def execute(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
            *,
            turn: int,
        ) -> SemanticExecutionBatch:
            del turn
            return SemanticExecutionBatch(self.start(mission), ("failed",) * len(actions))

    failed = run_semantic_browser_workflow(
        replace(_mission(), max_consecutive_failures=1),
        router=_one_turn_router(continue_plan),
        driver=Failed(),
    )
    assert failed.stop_reason == "consecutive-failure-budget"

    class IntermediateEscape(_Driver):
        def execute(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
            *,
            turn: int,
        ) -> SemanticExecutionBatch:
            del turn
            observation = self.start(mission)
            return SemanticExecutionBatch(
                observation,
                ("succeeded",) * len(actions),
                pages_visited=("https://example.com/intermediate", observation.url),
            )

    with pytest.raises(FormatError, match="left the mission origin"):
        run_semantic_browser_workflow(
            _mission(),
            router=_one_turn_router(continue_plan),
            driver=IntermediateEscape(),
        )


def test_workflow_reproduction_scope_is_enforced() -> None:
    class OutsideReproduction(_Driver):
        def reproduce(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
        ) -> SemanticExecutionBatch:
            del mission
            return SemanticExecutionBatch(
                SemanticBrowserObservation("https://example.com/", "outside", "snapshot"),
                ("succeeded",) * len(actions),
            )

    with pytest.raises(FormatError, match="reproduction observation left"):
        run_semantic_browser_workflow(_mission(), router=_router(), driver=OutsideReproduction())

    class IntermediateOutsideReproduction(_Driver):
        def reproduce(
            self,
            mission: SemanticBrowserMission,
            actions: tuple[SemanticBrowserAction, ...],
        ) -> SemanticExecutionBatch:
            observation = SemanticBrowserObservation(
                mission.entry_url,
                "fixture",
                "SOVA_WORKFLOW_TRIGGERED",
                oracle_passed=True,
            )
            return SemanticExecutionBatch(
                observation,
                ("succeeded",) * len(actions),
                pages_visited=("https://example.com/intermediate", observation.url),
            )

    with pytest.raises(FormatError, match="reproduction visited a page outside"):
        run_semantic_browser_workflow(
            _mission(),
            router=_router(),
            driver=IntermediateOutsideReproduction(),
        )
