# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: N802, PLR0913, TRY003
"""Linux AT-SPI desktop executor tests using an observable fixture backend."""

from __future__ import annotations

from types import ModuleType, SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.desktop import AtSpiDesktopExecutor, PyAtSpiBackend
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
)
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


class _FixtureAtSpi:
    def __init__(self) -> None:
        self.armed = False
        self.text = ""
        self.calls: list[tuple[str, str, str, str | None]] = []

    def snapshot(self, application: str) -> dict[str, Any]:
        return {
            "role": "application",
            "name": application,
            "children": [
                {"role": "push button", "name": "Arm", "pressed": self.armed},
                {"role": "text", "name": "Editor", "value": self.text},
            ],
        }

    def activate(self, application: str, role: str, name: str) -> None:
        self.calls.append((application, role, name, None))
        if (role, name) == ("push button", "Arm"):
            self.armed = True

    def set_text(self, application: str, role: str, name: str, text: str) -> None:
        self.calls.append((application, role, name, text))
        if (role, name) == ("text", "Editor"):
            self.text = text


def _execute(
    executor: AtSpiDesktopExecutor,
    tmp_path: Path,
    request: ActionRequest,
    cancellation: CancellationToken | None = None,
) -> ActionOutcome:
    return executor.execute(
        request,
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        cancellation or CancellationToken(),
    )


def test_atspi_click_and_type_are_application_bound_and_post_observed(tmp_path: Path) -> None:
    backend = _FixtureAtSpi()
    executor = AtSpiDesktopExecutor("SOVA Owned Fixture", backend=backend)

    click = _execute(
        executor,
        tmp_path,
        ActionRequest(
            "click",
            "computer.click",
            {"role": "push button", "name": "Arm"},
            10,
        ),
    )
    typed = _execute(
        executor,
        tmp_path,
        ActionRequest(
            "type",
            "computer.type",
            {"role": "text", "name": "Editor", "text": "blue owl"},
            10,
        ),
    )

    assert click.status == OutcomeStatus.SUCCEEDED
    assert click.output["applicationBound"] is True
    assert click.output["beforeDigest"] != click.output["afterDigest"]
    assert typed.status == OutcomeStatus.SUCCEEDED
    assert typed.output["beforeDigest"] != typed.output["afterDigest"]
    assert backend.calls == [
        ("SOVA Owned Fixture", "push button", "Arm", None),
        ("SOVA Owned Fixture", "text", "Editor", "blue owl"),
    ]


def test_atspi_rejects_coordinate_and_oversized_text(tmp_path: Path) -> None:
    executor = AtSpiDesktopExecutor("SOVA Owned Fixture", backend=_FixtureAtSpi())
    coordinate = _execute(
        executor,
        tmp_path,
        ActionRequest(
            "coordinate",
            "computer.click",
            {"role": "button", "name": "Arm", "x": 10, "y": 10},
            10,
        ),
    )
    oversized = _execute(
        executor,
        tmp_path,
        ActionRequest(
            "oversized",
            "computer.type",
            {"role": "text", "name": "Editor", "text": "x" * 65_537},
            10,
        ),
    )

    assert coordinate.status == OutcomeStatus.FAILED
    assert coordinate.error_code == "SOVA-ATSPI-INPUT"
    assert oversized.status == OutcomeStatus.FAILED
    assert oversized.error_code == "SOVA-ATSPI-TEXT"


def test_atspi_cancelled_action_never_observes_or_mutates(tmp_path: Path) -> None:
    backend = _FixtureAtSpi()
    executor = AtSpiDesktopExecutor("SOVA Owned Fixture", backend=backend)
    cancellation = CancellationToken()
    cancellation.cancel()

    outcome = _execute(
        executor,
        tmp_path,
        ActionRequest("cancel", "computer.snapshot", {}, 10),
        cancellation,
    )

    assert outcome.status == OutcomeStatus.CANCELLED
    assert backend.calls == []


class _FakeState:
    def getStates(self) -> list[str]:
        return ["enabled", "visible"]


class _FakeAction:
    def __init__(self, name: str = "click", *, succeeds: bool = True) -> None:
        self.nActions = 1
        self._name = name
        self._succeeds = succeeds

    def getName(self, _index: int) -> str:
        return self._name

    def doAction(self, _index: int) -> bool:
        return self._succeeds


class _FakeEditable:
    def __init__(self, *, succeeds: bool = True) -> None:
        self.succeeds = succeeds
        self.value = ""

    def setTextContents(self, value: str) -> bool:
        self.value = value
        return self.succeeds


class _FakeAccessible:
    def __init__(
        self,
        role: str,
        name: str,
        children: list[_FakeAccessible] | None = None,
        *,
        action: _FakeAction | None = None,
        editable: _FakeEditable | None = None,
        state_error: bool = False,
    ) -> None:
        self.role = role
        self.name = name
        self.children = children or []
        self.action = action or _FakeAction()
        self.editable = editable or _FakeEditable()
        self.state_error = state_error

    def __iter__(self) -> Any:
        return iter(self.children)

    def getRoleName(self) -> str:
        return self.role

    def getState(self) -> _FakeState:
        if self.state_error:
            raise RuntimeError("fixture state unavailable")
        return _FakeState()

    def queryAction(self) -> _FakeAction:
        return self.action

    def queryEditableText(self) -> _FakeEditable:
        return self.editable


def _pyatspi_backend(applications: list[_FakeAccessible]) -> PyAtSpiBackend:
    registry = SimpleNamespace(getDesktop=lambda _index: applications)
    module = cast("ModuleType", SimpleNamespace(Registry=registry))
    return PyAtSpiBackend(module)


def test_real_pyatspi_backend_walks_exact_app_and_executes_semantic_actions() -> None:
    action = _FakeAction()
    editable = _FakeEditable()
    button = _FakeAccessible("push button", "Arm", action=action, state_error=True)
    editor = _FakeAccessible("text", "Editor", editable=editable)
    app = _FakeAccessible("application", "Owned", [button, editor])
    backend = _pyatspi_backend([app])

    snapshot = backend.snapshot("Owned")
    backend.activate("Owned", "push button", "Arm")
    backend.set_text("Owned", "text", "Editor", "blue owl")

    assert snapshot["children"][0]["states"] == ["state-unavailable"]
    assert editable.value == "blue owl"


def test_pyatspi_backend_fails_closed_on_app_locator_action_and_tree_bounds() -> None:
    with pytest.raises(FormatError, match="exactly one"):
        _pyatspi_backend([]).snapshot("Missing")

    duplicate = _FakeAccessible("push button", "Same")
    app = _FakeAccessible("application", "Owned", [duplicate, duplicate])
    with pytest.raises(FormatError, match="absent or ambiguous"):
        _pyatspi_backend([app]).activate("Owned", "push button", "Same")

    refused = _FakeAccessible("push button", "Refused", action=_FakeAction(succeeds=False))
    absent = _FakeAccessible("push button", "Absent", action=_FakeAction("inspect"))
    editor = _FakeAccessible("text", "Editor", editable=_FakeEditable(succeeds=False))
    backend = _pyatspi_backend([_FakeAccessible("application", "Owned", [refused, absent, editor])])
    with pytest.raises(FormatError, match="refused"):
        backend.activate("Owned", "push button", "Refused")
    with pytest.raises(FormatError, match="no admitted"):
        backend.activate("Owned", "push button", "Absent")
    with pytest.raises(FormatError, match="refused"):
        backend.set_text("Owned", "text", "Editor", "value")

    root = _FakeAccessible("application", "Deep")
    cursor = root
    for index in range(66):
        child = _FakeAccessible("section", f"level-{index}")
        cursor.children.append(child)
        cursor = child
    with pytest.raises(FormatError, match="tree exceeds"):
        _pyatspi_backend([root]).snapshot("Deep")


def test_atspi_executor_rejects_invalid_application_locator_and_unknown_action(
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError, match="application name"):
        AtSpiDesktopExecutor("", backend=_FixtureAtSpi())
    executor = AtSpiDesktopExecutor("Owned", backend=_FixtureAtSpi())
    unsupported = _execute(
        executor,
        tmp_path,
        ActionRequest("unknown", "computer.drag", {}, 1),
    )
    missing_locator = _execute(
        executor,
        tmp_path,
        ActionRequest("missing", "computer.click", {"role": "", "name": "Arm"}, 1),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    assert missing_locator.error_code == "SOVA-ATSPI-LOCATOR"
