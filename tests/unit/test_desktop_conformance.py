# SPDX-License-Identifier: Apache-2.0
"""Portable desktop conformance workflow tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sova.desktop import DesktopConformancePlan, run_desktop_conformance
from sova.executors import OutcomeStatus, ScriptedAction, ScriptedExecutor, SideEffect
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


def _plan() -> DesktopConformancePlan:
    return DesktopConformancePlan(
        "windows",
        "sova-owned-native-fixture",
        "sha256:" + ("a" * 64),
        "sha256:" + ("b" * 64),
        {"strategy": "accessibility id", "value": "arm"},
        {"strategy": "accessibility id", "value": "editor", "text": "blue owl"},
    )


def _action(
    action: str,
    inputs: dict[str, str],
    *,
    side_effect: SideEffect,
    succeeded: bool = True,
) -> ScriptedAction:
    return ScriptedAction(
        action,
        inputs,
        OutcomeStatus.SUCCEEDED if succeeded else OutcomeStatus.FAILED,
        {"postObservationCaptured": succeeded},
        side_effect,
        (("ui-tree", "application/json", b"{}"),),
        "fixture-post-observation",
    )


def test_desktop_conformance_requires_effect_and_post_action_evidence(tmp_path: Path) -> None:
    plan = _plan()
    executor = ScriptedExecutor(
        [
            _action("computer.snapshot", {}, side_effect=SideEffect.READ),
            _action("computer.click", plan.click_inputs, side_effect=SideEffect.MUTATE),
            _action("computer.type", plan.type_inputs, side_effect=SideEffect.MUTATE),
        ]
    )

    report = run_desktop_conformance(plan, executor, tmp_path)

    assert report["accepted"] is True
    assert report["platform"] == "windows"
    assert report["claims"]["hostIsSecuritySandbox"] is False
    assert report["claims"]["arbitraryDesktopCompatibility"] is False
    assert all(row["evidenceCount"] == 1 for row in report["checks"])


def test_desktop_conformance_fails_when_mutation_is_not_verified(tmp_path: Path) -> None:
    plan = _plan()
    executor = ScriptedExecutor(
        [
            _action("computer.snapshot", {}, side_effect=SideEffect.READ),
            _action(
                "computer.click",
                plan.click_inputs,
                side_effect=SideEffect.MUTATE,
                succeeded=False,
            ),
            _action("computer.type", plan.type_inputs, side_effect=SideEffect.MUTATE),
        ]
    )
    assert run_desktop_conformance(plan, executor, tmp_path)["accepted"] is False


def test_desktop_conformance_rejects_bad_attestations_and_capabilities(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="digests"):
        DesktopConformancePlan("linux", "fixture", "bad", "bad", {}, {})
    with pytest.raises(FormatError, match="capabilities"):
        run_desktop_conformance(
            _plan(),
            ScriptedExecutor([_action("computer.snapshot", {}, side_effect=SideEffect.READ)]),
            tmp_path,
        )
