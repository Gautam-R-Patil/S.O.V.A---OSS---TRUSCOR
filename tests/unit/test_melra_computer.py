# SPDX-License-Identifier: Apache-2.0
"""MELRA-backed desktop computer-use executor: narrowing, snapshot, and wiring."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
)
from sova.formats.errors import FormatError
from sova.mcp import MCPTool, MCPToolResult, MelraExecutorAdapter
from sova.runtime.action_codecs import ReviewedComputerTarget
from sova.runtime.computer_surface import ComputerSurfaceSnapshot
from sova.runtime.melra_computer import (
    MelraComputerExecutor,
    MelraComputerSnapshotSource,
    _parse_inspect_elements,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class FakeMCPClient:
    server_name = "fake-melra"

    def __init__(self, tools: tuple[str, ...], results: list[MCPToolResult]) -> None:
        self._tools = tuple(MCPTool(name, name, {"type": "object"}, None, {}) for name in tools)
        self.results = results
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.closed = False

    def list_tools(self) -> tuple[MCPTool, ...]:
        return self._tools

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult:
        assert timeout_seconds > 0
        self.calls.append((name, dict(arguments)))
        if not self.results:
            raise FormatError("SOVA-MCP-TIMEOUT", "synthetic timeout")
        return self.results.pop(0)

    def close(self) -> None:
        self.closed = True


_MELRA_TOOLS = ("melra_capabilities", "melra_plan", "melra_execute")


def _context(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(
        tmp_path,
        {
            "decision": "allowed",
            "scopeDigest": "sha256:" + "1" * 64,
            "decidedBy": "sova.authorization-kernel/0.1",
        },
    )


def _plan(task_id: str, capability: str, inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    kind, action = capability.split(".", 1)
    return {
        "id": task_id,
        "contract": {
            "taskId": task_id,
            "capability": capability,
            "operation": {"kind": kind, "action": action, **(inputs or {})},
            "effect": "read" if action == "inspect" else "mutate",
        },
    }


def _executed(task_id: str, output: dict[str, Any]) -> MCPToolResult:
    return MCPToolResult(
        content=({"type": "text", "text": "done"},),
        structured_content={
            "task": {"id": task_id, "status": "verified_success"},
            "output": output,
        },
        is_error=False,
    )


def test_narrowing_wrapper_exposes_exactly_the_reviewed_computer_algebra() -> None:
    client = FakeMCPClient(_MELRA_TOOLS, [])
    executor = MelraComputerExecutor(MelraExecutorAdapter(client))
    names = {capability.name for capability in executor.capabilities()}
    assert names == {"computer.click", "computer.inspect", "computer.type"}
    assert executor.name == "sova-melra-computer:melra-mcp"


def test_narrowing_wrapper_refuses_actions_outside_the_algebra(tmp_path: Path) -> None:
    client = FakeMCPClient(_MELRA_TOOLS, [])
    executor = MelraComputerExecutor(MelraExecutorAdapter(client))
    with pytest.raises(FormatError, match="outside the reviewed algebra"):
        executor.execute(
            ActionRequest("r1", "browser.navigate", {"url": "https://example.invalid"}, 5),
            _context(tmp_path),
            CancellationToken(),
        )
    assert client.calls == []


def test_narrowing_wrapper_delegates_admitted_actions(tmp_path: Path) -> None:
    task_id = "019fc000-0000-7000-8000-000000000099"
    client = FakeMCPClient(
        _MELRA_TOOLS,
        [
            MCPToolResult((), _plan(task_id, "computer.click", {"x": 10, "y": 20}), is_error=False),
            _executed(task_id, {"clicked": True}),
        ],
    )
    executor = MelraComputerExecutor(MelraExecutorAdapter(client))
    outcome = executor.execute(
        ActionRequest("r1", "computer.click", {"x": 10, "y": 20}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert [name for name, _arguments in client.calls] == ["melra_plan", "melra_execute"]


def test_narrowing_wrapper_rejects_a_delegate_missing_the_full_algebra() -> None:
    # A client that only advertises melra_capabilities/melra_plan (no melra_execute)
    # makes MelraExecutorAdapter itself report unavailable -> capabilities() == ().
    client = FakeMCPClient(("melra_capabilities", "melra_plan"), [])
    with pytest.raises(FormatError, match="exact reviewed computer algebra"):
        MelraComputerExecutor(MelraExecutorAdapter(client))


def test_close_delegates_to_the_underlying_adapter() -> None:
    client = FakeMCPClient(_MELRA_TOOLS, [])
    executor = MelraComputerExecutor(MelraExecutorAdapter(client))
    executor.close()
    assert client.closed is True


# --- inspect-output parsing -------------------------------------------------


def _element(  # noqa: PLR0913 - each flag is an independent test fixture input
    element_id: str,
    *,
    editable: bool = False,
    scrollable: bool = False,
    draggable: bool = False,
    x: int = 5,
    y: int = 5,
) -> dict[str, Any]:
    return {
        "id": element_id,
        "editable": editable,
        "scrollable": scrollable,
        "draggable": draggable,
        "boundingBox": {"x": x, "y": y, "width": 10, "height": 4},
    }


def test_parse_inspect_elements_builds_click_and_type_targets() -> None:
    targets = _parse_inspect_elements(
        {"elements": [_element("btn-1"), _element("field-1", editable=True)]}
    )
    assert len(targets) == 2
    by_reference = {target.reference: target for target in targets}
    assert by_reference["melra-btn-1"].actions == ("computer.click",)
    assert by_reference["melra-field-1"].actions == ("computer.click", "computer.type")
    # bounding box (5,5,10,4) -> center (10, 7)
    assert by_reference["melra-btn-1"].canonical_locator() == {"x": 10, "y": 7}


def test_parse_inspect_elements_rejects_malformed_shapes() -> None:
    with pytest.raises(FormatError, match="element list"):
        _parse_inspect_elements({"elements": "not-a-list"})
    with pytest.raises(FormatError, match="not an object"):
        _parse_inspect_elements({"elements": ["not-a-dict"]})
    with pytest.raises(FormatError, match="missing its id"):
        _parse_inspect_elements({"elements": [{"id": "x"}]})
    with pytest.raises(FormatError, match="duplicate element identity"):
        _parse_inspect_elements({"elements": [_element("dup"), _element("dup")]})


def test_parse_inspect_elements_enforces_the_review_limit() -> None:
    elements = [_element(f"e{index}") for index in range(300)]
    with pytest.raises(FormatError, match="element limit"):
        _parse_inspect_elements({"elements": elements})


def test_parse_inspect_elements_rejects_out_of_bound_coordinates() -> None:
    bad = _element("btn-1")
    bad["boundingBox"]["x"] = -1
    with pytest.raises(FormatError, match="bounded non-negative integer"):
        _parse_inspect_elements({"elements": [bad]})


def test_default_ceiling_ignores_scroll_drag_hints() -> None:
    targets = _parse_inspect_elements(
        {
            "elements": [
                _element("btn-1", scrollable=True, draggable=True),
                _element("field-1", editable=True, scrollable=True, draggable=True),
            ]
        }
    )
    by_reference = {target.reference: target for target in targets}
    assert by_reference["melra-btn-1"].actions == ("computer.click",)
    assert by_reference["melra-field-1"].actions == ("computer.click", "computer.type")


def test_scroll_hint_admits_scroll_when_in_ceiling() -> None:
    ceiling = ("computer.click", "computer.scroll")
    targets = _parse_inspect_elements(
        {
            "elements": [
                _element("scroll-1", scrollable=True),
                _element("static-1", scrollable=False),
            ]
        },
        ceiling,
    )
    by_reference = {target.reference: target for target in targets}
    assert by_reference["melra-scroll-1"].actions == ("computer.click", "computer.scroll")
    assert by_reference["melra-static-1"].actions == ("computer.click",)


def test_drag_hint_admits_drag_when_in_ceiling() -> None:
    ceiling = ("computer.click", "computer.drag")
    targets = _parse_inspect_elements(
        {
            "elements": [
                _element("drag-1", draggable=True),
                _element("drag-2", draggable=True),
            ]
        },
        ceiling,
    )
    assert all("computer.drag" in target.actions for target in targets)


def test_key_follows_editable() -> None:
    ceiling = ("computer.click", "computer.type", "computer.key")
    targets = _parse_inspect_elements(
        {
            "elements": [
                _element("field-1", editable=True),
                _element("btn-1", editable=False),
            ]
        },
        ceiling,
    )
    by_reference = {target.reference: target for target in targets}
    assert "computer.key" in by_reference["melra-field-1"].actions
    assert "computer.key" not in by_reference["melra-btn-1"].actions


def test_element_dropped_when_intersection_empty() -> None:
    ceiling = ("computer.scroll",)
    targets = _parse_inspect_elements(
        {"elements": [_element("static-1", editable=False, scrollable=False)]},
        ceiling,
    )
    assert targets == ()


def test_non_boolean_flag_rejected() -> None:
    bad = _element("btn-1")
    bad["scrollable"] = "yes"
    with pytest.raises(FormatError, match="boolean flag"):
        _parse_inspect_elements({"elements": [bad]})


# --- snapshot source ---------------------------------------------------------


class _FakeLazyExecutor:
    """Minimal stand-in for `LazyStdioExecutor.trusted_observe`."""

    def __init__(self, outcome: Any) -> None:
        self._outcome = outcome
        self.calls: list[dict[str, Any]] = []

    def trusted_observe(
        self,
        *,
        workspace: Path,
        action: str,
        inputs: dict[str, Any],
        timeout_seconds: float = 20.0,
    ) -> Any:
        del timeout_seconds
        self.calls.append({"workspace": workspace, "action": action, "inputs": inputs})
        return self._outcome


class _Outcome:
    def __init__(self, status: OutcomeStatus, output: dict[str, Any]) -> None:
        self.status = status
        self.output = output


def test_snapshot_source_requires_binding_before_use() -> None:
    source = MelraComputerSnapshotSource(_FakeLazyExecutor(None))  # type: ignore[arg-type]
    with pytest.raises(FormatError, match="not workspace-bound"):
        source()


def test_snapshot_source_rejects_moving_to_another_workspace(tmp_path: Path) -> None:
    source = MelraComputerSnapshotSource(_FakeLazyExecutor(None))  # type: ignore[arg-type]
    source.bind_workspace(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(FormatError, match="cannot move to another workspace"):
        source.bind_workspace(other)


def test_snapshot_source_builds_a_computer_surface_snapshot(tmp_path: Path) -> None:
    outcome = _Outcome(
        OutcomeStatus.SUCCEEDED,
        {
            "taskId": "t1",
            "providerOutput": {"elements": [_element("btn-1")]},
        },
    )
    lazy = _FakeLazyExecutor(outcome)
    source = MelraComputerSnapshotSource(lazy)  # type: ignore[arg-type]
    source.bind_workspace(tmp_path)
    result = source()
    assert isinstance(result, ComputerSurfaceSnapshot)
    assert result.projection == {"melra": {"elementCount": 1, "taskId": "t1"}}
    assert len(result.reviewed_targets) == 1
    assert isinstance(result.reviewed_targets[0], ReviewedComputerTarget)
    assert lazy.calls == [{"workspace": tmp_path, "action": "computer.inspect", "inputs": {}}]


def test_snapshot_source_rejects_a_failed_inspect(tmp_path: Path) -> None:
    outcome = _Outcome(OutcomeStatus.FAILED, {})
    source = MelraComputerSnapshotSource(_FakeLazyExecutor(outcome))  # type: ignore[arg-type]
    source.bind_workspace(tmp_path)
    with pytest.raises(FormatError, match="did not succeed"):
        source()


def test_snapshot_source_rejects_missing_provider_output(tmp_path: Path) -> None:
    outcome = _Outcome(OutcomeStatus.SUCCEEDED, {"taskId": "t1"})
    source = MelraComputerSnapshotSource(_FakeLazyExecutor(outcome))  # type: ignore[arg-type]
    source.bind_workspace(tmp_path)
    with pytest.raises(FormatError, match="no provider output"):
        source()


def test_snapshot_source_threads_ceiling(tmp_path: Path) -> None:
    outcome = _Outcome(
        OutcomeStatus.SUCCEEDED,
        {
            "taskId": "t1",
            "providerOutput": {"elements": [_element("scroll-1", scrollable=True)]},
        },
    )
    lazy = _FakeLazyExecutor(outcome)
    source = MelraComputerSnapshotSource(
        cast("Any", lazy), mutations=("computer.click", "computer.scroll")
    )
    source.bind_workspace(tmp_path)
    result = source()
    assert result.reviewed_targets[0].actions == ("computer.click", "computer.scroll")
