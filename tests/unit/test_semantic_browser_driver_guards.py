# SPDX-License-Identifier: Apache-2.0
"""Fail-closed semantic browser driver policy-unit tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.live.semantic_browser_driver as driver_module
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    Capability,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.live import SemanticBrowserAction, SemanticBrowserMission
from sova.live.browser import owned_web_target, verified_browser_control
from sova.models import ScriptedModel, ScriptedTurn
from sova.runtime import ModelRouter, RoleKind

if TYPE_CHECKING:
    from pathlib import Path

    from sova.executors import CancellationToken
    from sova.runtime import BrowserProfileLease
    from sova.targets import TargetManifest


def _mission() -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova:semantic-mission:driver-guards",
        title="Driver guards",
        entry_url="http://127.0.0.1:9123/start",
        objective="Exercise the authorized owned fixture through observable typed UI actions.",
        allowed_actions=(
            "browser.navigate",
            "browser.click",
            "browser.type",
            "browser.select",
            "browser.press",
            "browser.hover",
            "browser.wait",
        ),
        seed_inputs=("blue owl",),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA_WORKFLOW_TRIGGERED",
        max_planner_turns=2,
        max_actions=4,
        max_actions_per_plan=2,
        max_duration_seconds=60,
        max_pages=4,
        max_mutations=4,
        max_consecutive_failures=2,
        max_generated_text_characters=128,
        max_total_tokens=100,
        offensive=True,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def _router() -> ModelRouter:
    return ModelRouter(
        {
            RoleKind.EXPLORER: (
                ScriptedModel(
                    [
                        ScriptedTurn(
                            "unreachable",
                            "",
                            {
                                "status": "blocked",
                                "actions": [],
                                "coverage": [],
                                "reason": "No action.",
                            },
                            token_count=1,
                        )
                    ]
                ),
            )
        }
    )


def test_scenario_includes_reset_setup_actions_and_snapshot() -> None:
    mission = replace(
        _mission(),
        reset_actions=(
            SemanticBrowserAction("browser.navigate", {"url": "http://127.0.0.1:9123/reset"}),
        ),
        setup_actions=(SemanticBrowserAction("browser.press", {"key": "Enter"}),),
    )
    scenario, action_ids = driver_module._scenario(
        mission,
        (SemanticBrowserAction("browser.wait", {"time": 1}),),
        key="reproduction",
        reset_and_setup=True,
    )
    steps = scenario["procedure"]["steps"]
    assert [step["id"] for step in steps] == [
        "reproduction-entry-before-reset",
        "reproduction-reset-01",
        "reproduction-entry-after-reset",
        "reproduction-setup-01",
        "reproduction-action-001",
        "reproduction-action-001-snapshot",
    ]
    assert action_ids == ("reproduction-action-001",)
    assert scenario["extensions"]["x-sova-semantic-browser"]["actionSnapshotStepIds"] == [
        "reproduction-action-001-snapshot"
    ]
    assert scenario["safety"]["budgets"]["maxStepSeconds"] == 120
    assert steps[-2]["onFailure"] == "continue"
    assert steps[-2]["inputs"].get("offensive") is None


def test_scenario_keeps_modal_click_and_dialog_atomic_before_snapshot() -> None:
    scenario, action_ids = driver_module._scenario(
        _mission(),
        (
            SemanticBrowserAction(
                "browser.click",
                {"element": "Open prompt", "target": "#prompt"},
            ),
            SemanticBrowserAction("browser.dialog", {"accept": True}),
        ),
        key="modal",
        reset_and_setup=False,
    )
    steps = scenario["procedure"]["steps"]
    assert [step["id"] for step in steps] == [
        "modal-action-001",
        "modal-action-002",
        "modal-action-002-snapshot",
    ]
    assert action_ids == ("modal-action-001", "modal-action-002")
    assert scenario["extensions"]["x-sova-semantic-browser"]["actionSnapshotStepIds"] == [
        "modal-action-002-snapshot"
    ]


@pytest.mark.parametrize("remaining", (0.0, float("nan"), float("inf")))
def test_scenario_rejects_exhausted_or_nonfinite_step_deadline(remaining: float) -> None:
    with pytest.raises(FormatError, match="no remaining execution time"):
        driver_module._scenario(
            _mission(),
            (),
            key="expired",
            reset_and_setup=False,
            max_step_seconds=remaining,
        )

    scenario, _action_ids = driver_module._scenario(
        _mission(),
        (),
        key="subsecond",
        reset_and_setup=False,
        max_step_seconds=0.25,
    )
    assert scenario["safety"]["budgets"]["maxStepSeconds"] == 1


def test_deadline_executor_caps_calls_and_stops_after_failed_prerequisite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Executor:
        name = "fixture-browser"

        def __init__(self) -> None:
            self.calls: list[ActionRequest] = []

        @staticmethod
        def capabilities() -> tuple[Capability, ...]:
            return (
                Capability(
                    "browser.type",
                    "0.1",
                    SideEffect.MUTATE,
                    idempotent=False,
                    evidence=("aria",),
                ),
                Capability(
                    "browser.click",
                    "0.1",
                    SideEffect.MUTATE,
                    idempotent=False,
                    evidence=("aria",),
                ),
                Capability(
                    "browser.snapshot",
                    "0.1",
                    SideEffect.READ,
                    idempotent=True,
                    evidence=("aria",),
                ),
            )

        def execute(
            self,
            request: ActionRequest,
            _context: object,
            _cancellation: object,
        ) -> ActionOutcome:
            self.calls.append(request)
            status = (
                OutcomeStatus.FAILED
                if request.action == "browser.type"
                else OutcomeStatus.SUCCEEDED
            )
            return ActionOutcome(request.id, status, SideEffect.READ, {})

    executor = Executor()
    monkeypatch.setattr(cast("Any", driver_module).time, "monotonic", lambda: 10.0)
    bounded = driver_module._DeadlineBatchExecutor(cast("Any", executor), deadline=15.0)
    requests = (
        ActionRequest("type", "browser.type", {}, 120),
        ActionRequest("failure-snapshot", "browser.snapshot", {}, 120),
        ActionRequest("click", "browser.click", {}, 120),
        ActionRequest("later-snapshot", "browser.snapshot", {}, 120),
    )
    outcomes = [
        bounded.execute(request, object(), cast("Any", SimpleNamespace(cancelled=False)))
        for request in requests
    ]

    assert [request.id for request in executor.calls] == ["type", "failure-snapshot"]
    assert all(request.timeout_seconds == 5.0 for request in executor.calls)
    assert [outcome.status for outcome in outcomes] == [
        OutcomeStatus.FAILED,
        OutcomeStatus.SUCCEEDED,
        OutcomeStatus.DENIED,
        OutcomeStatus.DENIED,
    ]
    assert outcomes[2].output == {
        "executed": False,
        "reason": "an earlier action failed; later batch actions were not executed",
    }


def test_deadline_executor_refuses_before_underlying_call_after_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = SimpleNamespace(
        name="fixture-browser",
        capabilities=lambda: (
            Capability(
                "browser.click",
                "0.1",
                SideEffect.MUTATE,
                idempotent=False,
                evidence=("aria",),
            ),
        ),
        execute=lambda *_args: pytest.fail("expired action reached the browser executor"),
    )
    monkeypatch.setattr(cast("Any", driver_module).time, "monotonic", lambda: 20.0)
    bounded = driver_module._DeadlineBatchExecutor(cast("Any", executor), deadline=20.0)
    outcome = bounded.execute(
        ActionRequest("late", "browser.click", {}, 120),
        object(),
        cast("Any", SimpleNamespace(cancelled=False)),
    )
    assert outcome.status == OutcomeStatus.TIMEOUT
    assert outcome.output["executed"] is False


def test_deadline_executor_fails_closed_when_underlying_call_returns_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = SimpleNamespace(now=10.0)

    def execute(*_args: object) -> ActionOutcome:
        clock.now = 15.0
        return ActionOutcome("late", OutcomeStatus.SUCCEEDED, SideEffect.MUTATE, {})

    executor = SimpleNamespace(
        name="fixture-browser",
        capabilities=lambda: (
            Capability(
                "browser.click",
                "0.1",
                SideEffect.MUTATE,
                idempotent=False,
                evidence=("aria",),
            ),
        ),
        execute=execute,
    )
    monkeypatch.setattr(cast("Any", driver_module).time, "monotonic", lambda: clock.now)
    bounded = driver_module._DeadlineBatchExecutor(cast("Any", executor), deadline=15.0)
    outcome = bounded.execute(
        ActionRequest("late", "browser.click", {}, 120),
        object(),
        cast("Any", SimpleNamespace(cancelled=False)),
    )

    assert outcome.status == OutcomeStatus.TIMEOUT
    assert outcome.error_code == "SOVA-SEMANTIC-BROWSER-DEADLINE"
    assert outcome.output["executed"] is False


def test_deadline_executor_rejects_a_failure_snapshot_that_returns_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = SimpleNamespace(now=10.0)

    def execute(request: ActionRequest, *_args: object) -> ActionOutcome:
        if request.action == "browser.snapshot":
            clock.now = 15.0
            return ActionOutcome(request.id, OutcomeStatus.SUCCEEDED, SideEffect.READ, {})
        return ActionOutcome(request.id, OutcomeStatus.FAILED, SideEffect.MUTATE, {})

    executor = SimpleNamespace(
        name="fixture-browser",
        capabilities=lambda: (),
        execute=execute,
    )
    monkeypatch.setattr(cast("Any", driver_module).time, "monotonic", lambda: clock.now)
    bounded = driver_module._DeadlineBatchExecutor(cast("Any", executor), deadline=15.0)
    cancellation = cast("Any", SimpleNamespace(cancelled=False))

    failed = bounded.execute(
        ActionRequest("type", "browser.type", {}, 120),
        object(),
        cancellation,
    )
    snapshot = bounded.execute(
        ActionRequest("snapshot", "browser.snapshot", {}, 120),
        object(),
        cancellation,
    )

    assert failed.status == OutcomeStatus.FAILED
    assert snapshot.status == OutcomeStatus.TIMEOUT
    assert snapshot.error_code == "SOVA-SEMANTIC-BROWSER-DEADLINE"


def test_playwright_driver_requires_a_finite_live_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    driver = object.__new__(driver_module.PlaywrightSemanticBrowserDriver)
    driver._deadline = None
    with pytest.raises(FormatError, match="did not bind"):
        driver._remaining_seconds()
    with pytest.raises(FormatError, match="deadline is invalid"):
        driver.set_deadline(float("nan"))

    driver.set_deadline(15.0)
    monkeypatch.setattr(cast("Any", driver_module).time, "monotonic", lambda: 15.0)
    with pytest.raises(FormatError, match="duration budget expired"):
        driver._remaining_seconds()

    driver.set_deadline(16.0)
    assert driver._remaining_seconds() == 1.0


def test_snapshot_extraction_bounding_location_and_status_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace = tmp_path / "trace.sova-trace"

    class Reader:
        def __init__(self, _path: Path) -> None:
            pass

        @staticmethod
        def events() -> list[dict[str, object]]:
            return [
                {
                    "kind": "tool.completed",
                    "phase": "snapshot",
                    "payload": {"outcome": {"output": {"text": 7}}},
                }
            ]

    monkeypatch.setattr(driver_module, "TraceReader", Reader)
    with pytest.raises(FormatError, match="no usable final"):
        driver_module._snapshot_text(trace, "snapshot")

    long = "a" * (driver_module._MAX_DISCLOSED_SNAPSHOT_CHARS + 100)
    bounded = driver_module._bounded_snapshot(long)
    assert "[SOVA SNAPSHOT TRUNCATED]" in bounded

    monkeypatch.setattr(driver_module, "_snapshot_text", lambda *_args: "Page title: fixture")
    with pytest.raises(FormatError, match="current page URL"):
        driver_module._observation(trace, "snapshot", oracle_passed=False)

    events = [
        {"kind": "tool.completed", "phase": "one", "payload": {"outcome": {"status": "timeout"}}},
        {"kind": "tool.failed", "phase": "two", "payload": {"outcome": {"status": "bad"}}},
        {"kind": "unrelated", "phase": "one", "payload": {}},
    ]
    monkeypatch.setattr(
        driver_module, "TraceReader", lambda _path: SimpleNamespace(events=lambda: events)
    )
    assert driver_module._action_statuses(trace, ("one", "two", "missing")) == (
        "timeout",
        "failed",
        "failed",
    )


def test_snapshot_extraction_skips_empty_and_unrelated_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        {
            "kind": "tool.completed",
            "phase": "snapshot",
            "payload": {"outcome": {"output": {"text": ["usable"]}}},
        },
        {
            "kind": "tool.completed",
            "phase": "snapshot",
            "payload": {"outcome": {"output": {"text": [""]}}},
        },
        {"kind": "tool.completed", "phase": "different", "payload": {}},
    ]
    monkeypatch.setattr(
        driver_module,
        "TraceReader",
        lambda _path: SimpleNamespace(events=lambda: events),
    )
    assert driver_module._snapshot_text(tmp_path / "trace.sova-trace", "snapshot") == "usable"


def test_snapshot_disclosure_fails_closed_if_redactor_withholds_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redactor = SimpleNamespace(redact=lambda _value: ({"withheld": True}, ("record",)))
    monkeypatch.setattr(driver_module, "Redactor", lambda **_kwargs: redactor)
    with pytest.raises(FormatError, match="credential-shaped material") as caught:
        driver_module._bounded_snapshot("fixture")
    assert caught.value.issue.details == {"redactionCount": 1}


def _live_options(tmp_path: Path) -> dict[str, object]:
    return {
        "router": _router(),
        "package_runner": tmp_path / "npx.cmd",
        "browser_executable": tmp_path / "chrome.exe",
        "approval_prompt": lambda challenge, _intents: challenge.exact_phrase,
    }


def test_loopback_control_proof_covers_the_declared_mission_window() -> None:
    now = datetime(2026, 8, 20, tzinfo=UTC)
    required = timedelta(minutes=15, seconds=30)
    _origins, _host, proof, status = verified_browser_control(
        owned_web_target("http://127.0.0.1:9123/"),
        None,
        now=now,
        minimum_ttl=required,
    )
    assert status == "verified-loopback"
    assert proof.expires_at - now == required

    with pytest.raises(FormatError, match="within two hours"):
        verified_browser_control(
            owned_web_target("http://127.0.0.1:9123/"),
            None,
            now=now,
            minimum_ttl=timedelta(hours=3),
        )


def test_live_driver_rejects_cancellation_profile_scope_proof_and_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = cast("TargetManifest", SimpleNamespace(digest="sha256:" + "1" * 64))
    mission = _mission()
    options = cast("Any", _live_options(tmp_path))
    with pytest.raises(FormatError, match="cancelled"):
        driver_module.run_live_semantic_browser_workflow(
            target,
            mission,
            tmp_path / "cancelled",
            cancellation=cast("CancellationToken", SimpleNamespace(cancelled=True)),
            **options,
        )

    observed: list[str] = []
    profile = cast("BrowserProfileLease", SimpleNamespace(require_target=observed.append))
    monkeypatch.setattr(
        driver_module,
        "verified_browser_control",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FormatError("TEST", "stop after profile")),
    )
    with pytest.raises(FormatError, match="stop after profile"):
        driver_module.run_live_semantic_browser_workflow(
            target,
            mission,
            tmp_path / "profile",
            profile_lease=profile,
            **options,
        )
    assert observed == [target.digest]

    proof = SimpleNamespace(expires_at=datetime.now(UTC) + timedelta(hours=1))
    monkeypatch.setattr(
        driver_module,
        "verified_browser_control",
        lambda *_args, **_kwargs: (
            ("https://different.example",),
            "different.example",
            proof,
            "verified",
        ),
    )
    with pytest.raises(FormatError, match="outside the target"):
        driver_module.run_live_semantic_browser_workflow(
            target, mission, tmp_path / "scope", **options
        )

    short_proof = SimpleNamespace(expires_at=datetime.now(UTC) + timedelta(seconds=5))
    monkeypatch.setattr(
        driver_module,
        "verified_browser_control",
        lambda *_args, **_kwargs: (
            (mission.entry_origin,),
            "127.0.0.1",
            short_proof,
            "verified",
        ),
    )
    with pytest.raises(FormatError, match="expires before"):
        driver_module.run_live_semantic_browser_workflow(
            target, mission, tmp_path / "proof", **options
        )

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "file").write_text("x", encoding="utf-8")
    long_proof = SimpleNamespace(expires_at=datetime.now(UTC) + timedelta(hours=1))
    monkeypatch.setattr(
        driver_module,
        "verified_browser_control",
        lambda *_args, **_kwargs: (
            (mission.entry_origin,),
            "127.0.0.1",
            long_proof,
            "verified",
        ),
    )
    with pytest.raises(FormatError, match="not empty"):
        driver_module.run_live_semantic_browser_workflow(target, mission, occupied, **options)
