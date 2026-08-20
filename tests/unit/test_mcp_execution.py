# SPDX-License-Identifier: Apache-2.0
"""Topic 13 MCP protocol, adapter, MELRA boundary, and fallback contracts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import sova.mcp.adapter as mcp_adapter_module
import sova.mcp.specs as mcp_specs
from sova.cli import main
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.live.startup import start_stdio_client
from sova.mcp import (
    CapabilityExecutionBroker,
    CuaDriverDirectories,
    CuaDriverExecutorAdapter,
    MCPExecutorAdapter,
    MCPTool,
    MCPToolResult,
    MelraDirectories,
    MelraExecutorAdapter,
    StdioMCPClient,
    StdioServerSpec,
    ToolMapping,
    WindowsMCPDirectories,
    chrome_devtools_mappings,
    chrome_devtools_stdio_spec,
    cua_driver_stdio_spec,
    melra_stdio_spec,
    playwright_mappings,
    playwright_stdio_spec,
    windows_mcp_mappings,
    windows_mcp_stdio_spec,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


class FakeMCPClient:
    server_name = "fake"

    def __init__(
        self,
        tools: tuple[str, ...],
        results: list[MCPToolResult],
    ) -> None:
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


def _context(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(
        tmp_path,
        {
            "decision": "allowed",
            "scopeDigest": "sha256:" + "1" * 64,
            "decidedBy": "sova.authorization-kernel/0.1",
        },
    )


def _melra_plan(
    task_id: str,
    capability: str = "browser.inspect",
    inputs: dict[str, Any] | None = None,
    *,
    effect: str = "read",
    approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kind, action = capability.split(".", 1)
    value: dict[str, Any] = {
        "id": task_id,
        "contract": {
            "taskId": task_id,
            "capability": capability,
            "operation": {"kind": kind, "action": action, **dict(inputs or {})},
            "effect": effect,
        },
    }
    if approval is not None:
        value["approval"] = approval
    return value


def test_stdio_client_initializes_lists_and_calls_real_fake_server(tmp_path: Path) -> None:
    server = Path(__file__).parents[1] / "support" / "fake_mcp_server.py"
    spec = StdioServerSpec(
        "fixture",
        (str(Path(sys.executable).resolve()), str(server)),
        tmp_path,
        {},
        "0.1.0",
        "tests/support/fake_mcp_server.py",
        "Apache-2.0",
    )
    with StdioMCPClient(spec) as client:
        assert [tool.name for tool in client.list_tools()] == ["fixture_echo"]
        result = client.call_tool("fixture_echo", {"value": "owl"}, timeout_seconds=5)
        assert result.structured_content == {"echo": "owl"}
        assert result.is_error is False


def test_stdio_spec_rejects_secret_environment_and_invalid_limits(tmp_path: Path) -> None:
    with pytest.raises(FormatError):
        StdioServerSpec("x", ("x",), tmp_path, {"API_TOKEN": "secret"}, "1", "x", "MIT")
    with pytest.raises(FormatError):
        StdioServerSpec("x", ("x",), tmp_path, {}, "1", "x", "MIT", max_message_bytes=1)


def test_stdio_client_reports_server_corruption_after_restart_boundary(tmp_path: Path) -> None:
    server = Path(__file__).parents[1] / "support" / "fake_mcp_server.py"
    spec = StdioServerSpec(
        "interrupted-fixture",
        (
            str(Path(sys.executable).resolve()),
            str(server),
            "--malformed-after-initialize",
        ),
        tmp_path,
        {},
        "0.1.0",
        "tests/support/fake_mcp_server.py",
        "Apache-2.0",
    )
    with StdioMCPClient(spec) as client, pytest.raises(FormatError) as error:
        client.list_tools()
    assert error.value.issue.code == "SOVA-FORMAT-INVALID-JSON"


def test_stdio_startup_retries_only_one_pre_action_timeout(tmp_path: Path) -> None:
    spec = StdioServerSpec(
        "fixture",
        ("fixture",),
        tmp_path,
        {},
        "0.1.0",
        "fixture",
        "Apache-2.0",
    )
    client = object()
    calls = 0

    def transient(_spec: StdioServerSpec) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise FormatError("SOVA-MCP-TIMEOUT", "synthetic startup timeout")
        return client

    assert start_stdio_client(spec, transient) is client
    assert calls == 2

    calls = 0

    def malformed(_spec: StdioServerSpec) -> object:
        nonlocal calls
        calls += 1
        raise FormatError("SOVA-MCP-READ", "synthetic protocol failure")

    with pytest.raises(FormatError, match="protocol failure"):
        start_stdio_client(spec, malformed)
    assert calls == 1


def test_playwright_adapter_discovers_subset_normalizes_and_post_observes(
    tmp_path: Path,
) -> None:
    client = FakeMCPClient(
        ("browser_navigate", "browser_snapshot"),
        [
            MCPToolResult(
                content=({"type": "text", "text": "navigated"},),
                structured_content={"url": "https://example.invalid"},
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": "snapshot"},),
                structured_content=None,
                is_error=False,
            ),
        ],
    )
    adapter = MCPExecutorAdapter("playwright", client, playwright_mappings())
    assert {item.name for item in adapter.capabilities()} == {
        "browser.navigate",
        "browser.snapshot",
    }
    outcome = adapter.execute(
        ActionRequest("navigate", "browser.navigate", {"url": "https://example.invalid"}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.verification == "post-action-observation"
    assert outcome.output["postObservationDigest"].startswith("sha256:")
    assert [call[0] for call in client.calls] == ["browser_navigate", "browser_snapshot"]


def test_playwright_adapter_maps_semantic_form_and_pointer_actions(tmp_path: Path) -> None:
    result = MCPToolResult(
        content=({"type": "text", "text": "- Page URL: https://owned.example/form"},),
        structured_content=None,
        is_error=False,
    )
    client = FakeMCPClient(
        (
            "browser_snapshot",
            "browser_type",
            "browser_click",
            "browser_select_option",
            "browser_press_key",
            "browser_hover",
        ),
        [result] * 10,
    )
    adapter = MCPExecutorAdapter(
        "playwright",
        client,
        playwright_mappings(allowed_origins=("https://owned.example",)),
    )
    assert {item.name for item in adapter.capabilities()} == {
        "browser.snapshot",
        "browser.type",
        "browser.click",
        "browser.select",
        "browser.press",
        "browser.hover",
    }

    for request in (
        ActionRequest(
            "type",
            "browser.type",
            {
                "element": "Message",
                "ref": "f10",
                "text": "blue owl",
                "submit": True,
                "slowly": True,
            },
            5,
        ),
        ActionRequest(
            "click",
            "browser.click",
            {"element": "Send", "ref": "f11"},
            5,
        ),
        ActionRequest(
            "select",
            "browser.select",
            {"element": "Defense level", "ref": "f12", "values": ["L0"]},
            5,
        ),
        ActionRequest("press", "browser.press", {"key": "Enter"}, 5),
        ActionRequest(
            "hover",
            "browser.hover",
            {"element": "Knowledge Base", "ref": "f13"},
            5,
        ),
    ):
        assert (
            adapter.execute(request, _context(tmp_path), CancellationToken()).status
            == OutcomeStatus.SUCCEEDED
        )

    assert client.calls[0] == (
        "browser_type",
        {
            "element": "Message",
            "target": "f10",
            "text": "blue owl",
            "submit": True,
            "slowly": True,
        },
    )
    assert client.calls[2] == (
        "browser_click",
        {"element": "Send", "target": "f11"},
    )
    assert client.calls[4] == (
        "browser_select_option",
        {"element": "Defense level", "target": "f12", "values": ["L0"]},
    )
    assert client.calls[6] == ("browser_press_key", {"key": "Enter"})
    assert client.calls[8] == (
        "browser_hover",
        {"element": "Knowledge Base", "target": "f13"},
    )


def test_playwright_target_normalization_rejects_conflicts_and_accepts_aliases() -> None:
    click = next(mapping for mapping in playwright_mappings() if mapping.action == "browser.click")

    with pytest.raises(FormatError, match="conflicting ref and target"):
        click.argument_builder({"element": "Send", "ref": "f1", "target": "#send"})

    assert click.argument_builder(
        {"element": "Send", "ref": "f1", "target": "f1", "doubleClick": False}
    ) == {"element": "Send", "target": "f1", "doubleClick": False}
    assert click.argument_builder({"element": "Send"}) == {"element": "Send"}


def test_mcp_browser_builders_and_observers_fail_closed_on_malformed_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match=r"HTTP\(S\) origin"):
        playwright_mappings(allowed_origins=("ftp://owned.example",))

    navigate = next(
        mapping for mapping in playwright_mappings() if mapping.action == "browser.navigate"
    )
    with pytest.raises(FormatError, match="requires a URL"):
        navigate.argument_builder({"url": 7})

    snapshot_client = FakeMCPClient(
        ("browser_snapshot",),
        [
            MCPToolResult(
                content=({"type": "text", "text": 7},),
                structured_content=None,
                is_error=False,
            )
        ],
    )
    snapshot_adapter = MCPExecutorAdapter(
        "playwright",
        snapshot_client,
        playwright_mappings(allowed_origins=("https://owned.example",)),
    )
    no_location = snapshot_adapter.execute(
        ActionRequest("snapshot", "browser.snapshot", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert no_location.status == OutcomeStatus.FAILED
    assert no_location.error_code == "SOVA-MCP-BROWSER-LOCATION"

    monkeypatch.setattr(mcp_adapter_module, "_MAX_BINARY_BYTES", 1)
    image_client = FakeMCPClient(
        ("browser_take_screenshot",),
        [
            MCPToolResult(
                content=({"type": "image", "data": "eHg="},),
                structured_content=None,
                is_error=False,
            )
        ],
    )
    image_adapter = MCPExecutorAdapter("playwright", image_client, playwright_mappings())
    oversized = image_adapter.execute(
        ActionRequest("image", "browser.screenshot", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert oversized.status == OutcomeStatus.FAILED
    assert oversized.error_code == "SOVA-MCP-CONTENT-LIMIT"


def test_chrome_devtools_wait_builder_accepts_text_forms_and_rejects_empty() -> None:
    wait = next(
        mapping for mapping in chrome_devtools_mappings() if mapping.action == "browser.wait"
    )
    assert wait.argument_builder({"text": "ready"}) == {"text": ["ready"]}
    assert wait.argument_builder({"text": ["ready", "settled"]}) == {"text": ["ready", "settled"]}
    with pytest.raises(FormatError, match="one or more texts"):
        wait.argument_builder({"text": []})


def test_playwright_adapter_maps_bounded_workflow_navigation_and_interactions(
    tmp_path: Path,
) -> None:
    result = MCPToolResult(
        content=({"type": "text", "text": "- Page URL: https://owned.example/workflow"},),
        structured_content=None,
        is_error=False,
    )
    client = FakeMCPClient(
        (
            "browser_snapshot",
            "browser_navigate_back",
            "browser_drag",
            "browser_handle_dialog",
            "browser_tabs",
        ),
        [result] * 10,
    )
    adapter = MCPExecutorAdapter(
        "playwright",
        client,
        playwright_mappings(allowed_origins=("https://owned.example",)),
    )
    expected = {
        "browser.back",
        "browser.drag",
        "browser.dialog",
        "browser.tab-new",
        "browser.tab-close",
    }
    assert expected <= {item.name for item in adapter.capabilities()}

    requests = (
        ActionRequest("back", "browser.back", {}, 5),
        ActionRequest(
            "drag",
            "browser.drag",
            {
                "startElement": "Source card",
                "startTarget": "f1",
                "endElement": "Destination lane",
                "endTarget": "f2",
            },
            5,
        ),
        ActionRequest("dialog", "browser.dialog", {"accept": True}, 5),
        ActionRequest(
            "tab-new",
            "browser.tab-new",
            {"url": "https://owned.example/details"},
            5,
        ),
        ActionRequest("tab-close", "browser.tab-close", {}, 5),
    )
    for request in requests:
        assert (
            adapter.execute(request, _context(tmp_path), CancellationToken()).status
            == OutcomeStatus.SUCCEEDED
        )

    assert client.calls[0] == ("browser_navigate_back", {})
    assert client.calls[2] == (
        "browser_drag",
        {
            "startElement": "Source card",
            "startTarget": "f1",
            "endElement": "Destination lane",
            "endTarget": "f2",
        },
    )
    assert client.calls[4] == ("browser_handle_dialog", {"accept": True})
    assert client.calls[6] == (
        "browser_tabs",
        {"action": "new", "url": "https://owned.example/details"},
    )
    assert client.calls[8] == ("browser_tabs", {"action": "close"})


def test_playwright_adapter_rejects_cross_origin_tab_before_execution(tmp_path: Path) -> None:
    client = FakeMCPClient(("browser_tabs",), [])
    adapter = MCPExecutorAdapter(
        "playwright",
        client,
        playwright_mappings(allowed_origins=("https://owned.example",)),
    )
    outcome = adapter.execute(
        ActionRequest(
            "tab-new",
            "browser.tab-new",
            {"url": "https://attacker.example/escaped"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-MCP-NAVIGATION-SCOPE"
    assert client.calls == []


def test_playwright_adapter_gracefully_closes_browser_before_transport() -> None:
    client = FakeMCPClient(
        ("browser_close", "browser_navigate"),
        [MCPToolResult(content=(), structured_content=None, is_error=False)],
    )
    adapter = MCPExecutorAdapter("playwright", client, playwright_mappings())

    adapter.close()
    adapter.close()

    assert client.calls == [("browser_close", {})]
    assert client.closed

    unavailable = FakeMCPClient(("browser_close", "browser_navigate"), [])
    MCPExecutorAdapter("playwright", unavailable, playwright_mappings()).close()
    assert unavailable.closed


def test_playwright_adapter_enforces_exact_navigation_origin(tmp_path: Path) -> None:
    client = FakeMCPClient(
        ("browser_navigate",),
        [MCPToolResult(content=(), structured_content=None, is_error=False)],
    )
    adapter = MCPExecutorAdapter(
        "playwright",
        client,
        playwright_mappings(allowed_origins=("https://owned.example",)),
    )
    outcome = adapter.execute(
        ActionRequest(
            "navigate",
            "browser.navigate",
            {"url": "https://attacker.example/redirect"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-MCP-NAVIGATION-SCOPE"
    assert client.calls == []


def test_playwright_adapter_rejects_observed_cross_origin_redirect(tmp_path: Path) -> None:
    client = FakeMCPClient(
        ("browser_navigate", "browser_snapshot"),
        [
            MCPToolResult(
                content=({"type": "text", "text": "- Page URL: https://attacker.example/"},),
                structured_content=None,
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": "- Page URL: https://attacker.example/"},),
                structured_content=None,
                is_error=False,
            ),
        ],
    )
    adapter = MCPExecutorAdapter(
        "playwright",
        client,
        playwright_mappings(allowed_origins=("https://owned.example",)),
    )
    outcome = adapter.execute(
        ActionRequest(
            "navigate",
            "browser.navigate",
            {"url": "https://owned.example/start"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-MCP-BROWSER-ORIGIN-DRIFT"


def test_chrome_devtools_adapter_maps_portable_actions_and_checks_final_origin(
    tmp_path: Path,
) -> None:
    snapshot = (
        '# take_snapshot response\nuid=1_0 RootWebArea "Owned" url="https://owned.example/after"'
    )
    client = FakeMCPClient(
        ("navigate_page", "take_snapshot", "fill", "click", "wait_for"),
        [
            MCPToolResult(
                content=({"type": "text", "text": "navigated"},),
                structured_content=None,
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": snapshot},),
                structured_content=None,
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": snapshot},),
                structured_content=None,
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": snapshot},),
                structured_content=None,
                is_error=False,
            ),
        ],
    )
    adapter = MCPExecutorAdapter(
        "chrome-devtools",
        client,
        chrome_devtools_mappings(allowed_origins=("https://owned.example",)),
    )
    outcome = adapter.execute(
        ActionRequest(
            "navigate",
            "browser.navigate",
            {"url": "https://owned.example/start"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert client.calls[0] == (
        "navigate_page",
        {"type": "url", "url": "https://owned.example/start"},
    )
    typed = adapter.execute(
        ActionRequest(
            "type",
            "browser.type",
            {"target": "1_4", "text": "blue owl"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert typed.status == OutcomeStatus.SUCCEEDED
    assert client.calls[2] == (
        "fill",
        {"includeSnapshot": True, "uid": "1_4", "value": "blue owl"},
    )


def test_chrome_devtools_adapter_rejects_observed_cross_origin_redirect(tmp_path: Path) -> None:
    escaped = 'uid=1_0 RootWebArea "Escaped" url="https://attacker.example/"'
    client = FakeMCPClient(
        ("navigate_page", "take_snapshot"),
        [
            MCPToolResult(
                content=({"type": "text", "text": "navigated"},),
                structured_content=None,
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": escaped},),
                structured_content=None,
                is_error=False,
            ),
        ],
    )
    adapter = MCPExecutorAdapter(
        "chrome-devtools",
        client,
        chrome_devtools_mappings(allowed_origins=("https://owned.example",)),
    )
    outcome = adapter.execute(
        ActionRequest(
            "navigate",
            "browser.navigate",
            {"url": "https://owned.example/start"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-MCP-BROWSER-ORIGIN-DRIFT"


def test_windows_mapping_excludes_dangerous_host_tools() -> None:
    mapping_tools = {item.tool for item in windows_mcp_mappings()}
    assert not mapping_tools & {"PowerShell", "Registry", "FileSystem", "Process", "Clipboard"}
    assert {"Snapshot", "Screenshot", "Click", "Type", "Scroll", "WaitFor"} <= mapping_tools


def _cua_client(results: list[MCPToolResult]) -> FakeMCPClient:
    return FakeMCPClient(
        (
            "start_session",
            "end_session",
            "list_windows",
            "get_window_state",
            "get_desktop_state",
            "click",
            "type_text",
            "press_key",
            "hotkey",
            "scroll",
        ),
        results,
    )


def test_cua_adapter_is_window_bound_and_desktop_capture_is_opt_in(tmp_path: Path) -> None:
    client = _cua_client([])
    adapter = CuaDriverExecutorAdapter(client, session_id="sova-unit")
    capabilities = {item.name for item in adapter.capabilities()}
    assert "computer.desktop" not in capabilities
    assert {
        "computer.windows",
        "computer.inspect",
        "computer.click",
        "computer.type",
    } <= capabilities
    outcome = adapter.execute(
        ActionRequest("click", "computer.click", {"x": 10, "y": 20}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-CUA-WINDOW-BINDING"
    assert client.calls == []


def test_cua_adapter_retries_foreground_only_after_typed_failure_and_fresh_approval(
    tmp_path: Path,
) -> None:
    client = _cua_client(
        [
            MCPToolResult(content=(), structured_content={"started": True}, is_error=False),
            MCPToolResult(
                content=({"type": "text", "text": "background_unavailable"},),
                structured_content=None,
                is_error=True,
            ),
            MCPToolResult(
                content=(),
                structured_content={"verified": True},
                is_error=False,
            ),
            MCPToolResult(
                content=(),
                structured_content={"elements": []},
                is_error=False,
            ),
        ]
    )
    adapter = CuaDriverExecutorAdapter(client, session_id="sova-unit")
    context = ExecutionContext(
        tmp_path,
        {
            "decision": "allowed",
            "scopeDigest": "sha256:" + "1" * 64,
            "decidedBy": "sova.authorization-kernel/0.1",
            "foregroundApproved": True,
        },
    )
    outcome = adapter.execute(
        ActionRequest(
            "type",
            "computer.type",
            {
                "pid": 42,
                "windowId": 99,
                "text": "authorized fixture",
                "allowForegroundEscalation": True,
            },
            5,
        ),
        context,
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.verification == "cua-provider-post-action-observation"
    assert outcome.output["cua"]["foregroundEscalationUsed"] is True
    assert [name for name, _arguments in client.calls] == [
        "start_session",
        "type_text",
        "type_text",
        "get_window_state",
    ]
    assert client.calls[1][1]["delivery_mode"] == "background"
    assert client.calls[2][1]["delivery_mode"] == "foreground"


def test_cua_adapter_refuses_foreground_retry_without_separate_approval(tmp_path: Path) -> None:
    client = _cua_client(
        [
            MCPToolResult(content=(), structured_content={"started": True}, is_error=False),
            MCPToolResult(
                content=({"type": "text", "text": "background_unavailable"},),
                structured_content=None,
                is_error=True,
            ),
        ]
    )
    adapter = CuaDriverExecutorAdapter(client, session_id="sova-unit")
    outcome = adapter.execute(
        ActionRequest(
            "hotkey",
            "computer.hotkey",
            {
                "pid": 42,
                "windowId": 99,
                "keys": ["ctrl", "s"],
                "allowForegroundEscalation": True,
            },
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.DENIED
    assert outcome.error_code == "SOVA-CUA-FOREGROUND-AUTHORIZATION"
    assert [name for name, _arguments in client.calls] == ["start_session", "hotkey"]


def test_cua_adapter_fail_closed_states_are_explicit(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="session id"):
        CuaDriverExecutorAdapter(_cua_client([]), session_id="")

    client = _cua_client([])
    adapter = CuaDriverExecutorAdapter(client, session_id="sova-unit")
    unsupported = adapter.execute(
        ActionRequest("unknown", "computer.unknown", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED

    cancelled = CancellationToken()
    cancelled.cancel()
    outcome = adapter.execute(
        ActionRequest("inspect", "computer.inspect", {}, 5),
        _context(tmp_path),
        cancelled,
    )
    assert outcome.status == OutcomeStatus.CANCELLED

    denied_context = ExecutionContext(tmp_path, {"decision": "denied"})
    outcome = adapter.execute(
        ActionRequest("inspect", "computer.inspect", {}, 5),
        denied_context,
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.DENIED
    assert outcome.error_code == "SOVA-CUA-AUTHORIZATION"

    desktop = adapter.execute(
        ActionRequest("desktop", "computer.desktop", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert desktop.status == OutcomeStatus.DENIED
    assert desktop.error_code == "SOVA-CUA-DESKTOP-SCOPE"
    assert client.calls == []


@pytest.mark.parametrize(
    ("inputs", "error_code"),
    [
        ({"unexpected": True}, "SOVA-CUA-INPUT"),
        ({"pid": 42, "windowId": 99}, "SOVA-CUA-TEXT"),
        (
            {"pid": 42, "windowId": 99, "text": "x" * (16 * 1024 + 1)},
            "SOVA-CUA-TEXT",
        ),
    ],
)
def test_cua_adapter_rejects_invalid_inputs_before_starting_a_session(
    tmp_path: Path,
    inputs: dict[str, Any],
    error_code: str,
) -> None:
    client = _cua_client([])
    adapter = CuaDriverExecutorAdapter(client, session_id="sova-unit")
    action = "computer.inspect" if "unexpected" in inputs else "computer.type"
    outcome = adapter.execute(
        ActionRequest("invalid", action, inputs, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == error_code
    assert client.calls == []


def test_cua_adapter_normalizes_session_and_observation_failures(tmp_path: Path) -> None:
    missing_start = FakeMCPClient(("get_window_state",), [])
    adapter = CuaDriverExecutorAdapter(missing_start, session_id="sova-unit")
    outcome = adapter.execute(
        ActionRequest("inspect", "computer.inspect", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-CUA-SESSION"

    refused = _cua_client([MCPToolResult(content=(), structured_content=None, is_error=True)])
    adapter = CuaDriverExecutorAdapter(refused, session_id="sova-unit")
    outcome = adapter.execute(
        ActionRequest("windows", "computer.windows", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-CUA-SESSION"

    observation_failure = _cua_client(
        [
            MCPToolResult(content=(), structured_content={"started": True}, is_error=False),
            MCPToolResult(content=(), structured_content={"clicked": True}, is_error=False),
            MCPToolResult(content=(), structured_content=None, is_error=True),
            MCPToolResult(content=(), structured_content={"ended": True}, is_error=False),
        ]
    )
    adapter = CuaDriverExecutorAdapter(observation_failure, session_id="sova-unit")
    outcome = adapter.execute(
        ActionRequest(
            "click",
            "computer.click",
            {"pid": 42, "windowId": 99, "x": 10, "y": 20},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.verification == "observation-failed"
    adapter.close()
    adapter.close()
    assert observation_failure.closed
    assert [name for name, _arguments in observation_failure.calls][-1] == "end_session"


def test_cua_desktop_read_requires_opt_in_and_reports_scope(tmp_path: Path) -> None:
    client = _cua_client(
        [
            MCPToolResult(content=(), structured_content={"started": True}, is_error=False),
            MCPToolResult(content=(), structured_content={"screens": []}, is_error=False),
        ]
    )
    adapter = CuaDriverExecutorAdapter(
        client,
        session_id="sova-unit",
        allow_desktop_scope=True,
    )
    assert "computer.desktop" in {item.name for item in adapter.capabilities()}
    outcome = adapter.execute(
        ActionRequest("desktop", "computer.desktop", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["cua"]["sessionScope"] == "desktop"
    assert client.calls[0][1]["capture_scope"] == "desktop"


def test_cua_provider_failure_does_not_escalate_without_typed_reason(tmp_path: Path) -> None:
    client = _cua_client(
        [
            MCPToolResult(content=(), structured_content={"started": True}, is_error=False),
            MCPToolResult(
                content=({"type": "text", "text": "generic provider failure"},),
                structured_content=None,
                is_error=True,
            ),
        ]
    )
    adapter = CuaDriverExecutorAdapter(client, session_id="sova-unit")
    outcome = adapter.execute(
        ActionRequest(
            "scroll",
            "computer.scroll",
            {
                "pid": 42,
                "windowId": 99,
                "direction": "down",
                "amount": 1,
                "allowForegroundEscalation": True,
            },
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert [name for name, _arguments in client.calls] == ["start_session", "scroll"]


def test_pinned_open_source_launch_specs_are_fail_closed(  # noqa: PLR0915
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = tmp_path / "npx.cmd"
    node = tmp_path / "node.exe"
    melra_cli = tmp_path / "melra-cli.js"
    melra_policy = tmp_path / "melra-policy.json"
    cua_policy = tmp_path / "cua-policy.yaml"
    cua_driver = tmp_path / "cua-driver.exe"
    browser = tmp_path / "chrome.exe"
    uvx = tmp_path / "uvx.exe"
    for path in (runner, node, melra_cli, browser, uvx, cua_driver):
        path.write_bytes(b"synthetic executable placeholder")
    melra_policy.write_text('{"version":"test"}', encoding="utf-8")
    cua_policy.write_text("version: 1\nmode: bounded\n", encoding="utf-8")
    playwright = playwright_stdio_spec(
        package_runner=runner,
        workspace=tmp_path,
        browser_executable=browser,
    )
    assert "@playwright/mcp@0.0.78" in playwright.argv
    assert "--isolated" in playwright.argv
    assert "--headless" in playwright.argv
    assert "--block-service-workers" in playwright.argv
    assert "--caps" not in playwright.argv
    assert playwright.startup_timeout_seconds == 120
    assert playwright.environment["PLAYWRIGHT_BROWSERS_PATH"].startswith(str(tmp_path))

    recorded = playwright_stdio_spec(
        package_runner=runner,
        workspace=tmp_path,
        browser_executable=browser,
        record_video=True,
    )
    assert recorded.argv[recorded.argv.index("--caps") + 1] == "devtools"
    assert recorded.argv[recorded.argv.index("--viewport-size") + 1] == "1280x720"
    assert not any(argument.startswith("--save-video") for argument in recorded.argv)

    devtools = chrome_devtools_stdio_spec(
        package_runner=runner,
        workspace=tmp_path,
        browser_executable=browser,
    )
    assert "chrome-devtools-mcp@1.6.0" in devtools.argv
    assert "--isolated=true" in devtools.argv
    assert "--headless=true" in devtools.argv
    assert "--no-usage-statistics" in devtools.argv
    assert "--no-performance-crux" in devtools.argv
    assert "--redact-network-headers=true" in devtools.argv
    assert not any("--allow-unrestricted-paths" in item for item in devtools.argv)
    assert devtools.environment["CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS"] == "1"
    assert devtools.package_digest == (
        "sha512-VZX6f/OjQSYhy2BGGRs+y3LsrsAQAz/HwZCWKBLVyST/4r/3zjVEjjVW7gMCVbRD"
        "uspnVdcp5hQDPrQ5UFrdZw=="
    )

    profile = tmp_path / ".sova" / "browser-profiles" / "persistent"
    profile.mkdir(parents=True)
    monkeypatch.setattr(mcp_specs, "_WINDOWS_PROFILE_COOKIE_MIGRATION", True)
    persistent = playwright_stdio_spec(
        package_runner=runner,
        workspace=tmp_path,
        browser_executable=browser,
        profile_directory=profile,
        headless=False,
    )
    assert "--isolated" not in persistent.argv
    assert "--headless" not in persistent.argv
    profile_index = persistent.argv.index("--user-data-dir")
    assert persistent.argv[profile_index + 1] == str(profile.resolve())
    config_index = persistent.argv.index("--config")
    config_path = Path(persistent.argv[config_index + 1])
    assert json.loads(config_path.read_text(encoding="utf-8")) == {
        "browser": {
            "launchOptions": {
                "args": ["--enable-features=TriggerNetworkDataMigration"],
            }
        }
    }

    external_vault = tmp_path.parent / f"{tmp_path.name}-profile-vault"
    external_profile = external_vault / "profile"
    external_profile.mkdir(parents=True)
    admitted = playwright_stdio_spec(
        package_runner=runner,
        workspace=tmp_path,
        browser_executable=browser,
        profile_directory=external_profile,
        profile_vault_root=external_vault,
    )
    assert str(external_profile.resolve()) in admitted.argv

    melra = melra_stdio_spec(
        node_executable=node,
        cli_entrypoint=melra_cli,
        workspace=tmp_path,
        directories=MelraDirectories(
            state=tmp_path / ".sova" / "melra",
            policy=melra_policy,
            browser_profile=tmp_path / ".sova" / "browser-profiles" / "test",
        ),
        browser_executable=browser,
    )
    assert melra.argv[-1] == "serve"
    assert "--unhinged" not in melra.argv
    assert melra.environment["MELRA_HOME"].startswith(str(tmp_path))
    assert melra.environment["MELRA_BROWSER_PROFILE"].startswith(str(tmp_path))
    assert melra.version == "0.3.0-alpha.10"

    cua = cua_driver_stdio_spec(
        executable=cua_driver,
        workspace=tmp_path,
        directories=CuaDriverDirectories(
            state=tmp_path / ".sova" / "cua",
            policy=cua_policy,
        ),
    )
    assert cua.argv[1:3] == ("mcp", "--socket")
    assert cua.argv[3].startswith(r"\\.\pipe\sova-cua-")
    assert cua.argv[4] == "--no-overlay"
    assert cua.environment["CUA_DRIVER_PERMISSION_MODE"] == "bounded"
    assert cua.environment["CUA_DRIVER_RS_TELEMETRY_ENABLED"] == "0"
    assert cua.environment["CUA_DRIVER_DISABLE_UNRESTRICTED"] == "1"
    assert cua.max_message_bytes == 32 * 1024 * 1024

    windows = windows_mcp_stdio_spec(
        uvx=uvx,
        workspace=tmp_path,
        directories=WindowsMCPDirectories(
            cache=tmp_path / "cache",
            python=tmp_path / "python",
            tools=tmp_path / "tools",
        ),
    )
    assert windows.environment["ANONYMIZED_TELEMETRY"] == "false"
    assert windows.argv[-1] == "Snapshot,Screenshot"
    assert all(
        dangerous not in windows.argv[-1]
        for dangerous in ("PowerShell", "Registry", "FileSystem", "Process", "Clipboard")
    )


def test_executor_receipts_cli_reports_removable_melra(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["executors", "receipts"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["sovaRemainsAuthority"] is True
    assert value["noMelraOperationPreserved"] is True
    by_name = {item["name"]: item for item in value["receipts"]}
    assert by_name["melra"]["commit"] == "b9edeb35b3749de029386c929fbe8a21cc666a08"
    assert by_name["windows-mcp"]["status"] == "optional-high-risk-computer-backend"


class FixtureExecutor:
    def __init__(
        self,
        name: str,
        status: OutcomeStatus,
        *,
        retryable: bool,
        verification: str = "post-action-observation",
    ) -> None:
        self._name = name
        self.status = status
        self.retryable = retryable
        self.verification = verification

    @property
    def name(self) -> str:
        return self._name

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="browser.snapshot",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=("snapshot",),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context, cancellation
        return ActionOutcome(
            request.id,
            self.status,
            SideEffect.READ,
            {"executor": self.name},
            verification=self.verification,
            retryable=self.retryable,
            failure_cause=(
                FailureCause.NONE
                if self.status == OutcomeStatus.SUCCEEDED
                else FailureCause.EXECUTOR
            ),
        )


def test_broker_falls_back_and_preserves_secret_free_checkpoint(tmp_path: Path) -> None:
    broker = CapabilityExecutionBroker(
        (
            FixtureExecutor("melra", OutcomeStatus.FAILED, retryable=True),
            FixtureExecutor("playwright", OutcomeStatus.SUCCEEDED, retryable=False),
        )
    )
    outcome = broker.execute(
        ActionRequest("snapshot", "browser.snapshot", {"cookie": "must-not-persist"}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    attempts = outcome.output["sovaBroker"]["attempts"]
    assert [item["executor"] for item in attempts] == ["melra", "playwright"]
    checkpoint = outcome.output["sovaBroker"]["checkpoint"]
    assert checkpoint["inputsPersisted"] is False
    assert checkpoint["sessionMaterialPersisted"] is False
    assert "must-not-persist" not in str(checkpoint)


def test_broker_does_not_treat_melra_receipt_as_independent_verification(
    tmp_path: Path,
) -> None:
    broker = CapabilityExecutionBroker(
        (
            FixtureExecutor(
                "melra",
                OutcomeStatus.SUCCEEDED,
                retryable=False,
                verification="melra-result-defense-in-depth-only",
            ),
            FixtureExecutor("playwright", OutcomeStatus.SUCCEEDED, retryable=False),
        )
    )
    outcome = broker.execute(
        ActionRequest("snapshot", "browser.snapshot", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    attempts = outcome.output["sovaBroker"]["attempts"]
    assert [item["executor"] for item in attempts] == ["melra", "playwright"]
    assert attempts[0]["verification"]["verified"] is False
    assert outcome.status == OutcomeStatus.SUCCEEDED


def test_melra_adapter_requires_plan_execute_and_never_uses_memory(tmp_path: Path) -> None:
    client = FakeMCPClient(
        ("melra_capabilities", "melra_plan", "melra_execute", "melra_receipt"),
        [
            MCPToolResult(
                content=(),
                structured_content=_melra_plan(
                    "019fc000-0000-7000-8000-000000000013",
                    inputs={"url": "https://example.invalid"},
                ),
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": "done"},),
                structured_content={
                    "task": {
                        "id": "019fc000-0000-7000-8000-000000000013",
                        "status": "verified_success",
                    },
                    "output": {"page": "safe fixture"},
                },
                is_error=False,
            ),
        ],
    )
    adapter = MelraExecutorAdapter(client)
    assert all(not item.name.startswith("memory.") for item in adapter.capabilities())
    outcome = adapter.execute(
        ActionRequest(
            "inspect",
            "browser.inspect",
            {"url": "https://example.invalid"},
            5,
        ),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert [name for name, _arguments in client.calls] == ["melra_plan", "melra_execute"]
    plan = client.calls[0][1]
    assert plan["forbiddenEffects"] == ["destructive"]
    assert plan["constraints"] == []
    assert outcome.verification == "melra-result-defense-in-depth-only"
    assert outcome.output["providerStatus"] == "verified_success"


def test_melra_status_and_cancel_mapping_are_explicit() -> None:
    task_id = "019fc000-0000-7000-8000-000000000013"
    client = FakeMCPClient(
        (
            "melra_capabilities",
            "melra_plan",
            "melra_execute",
            "melra_task_status",
            "melra_task_cancel",
        ),
        [
            MCPToolResult((), {"id": task_id, "status": "running"}, is_error=False),
            MCPToolResult((), {"id": task_id, "status": "cancelled"}, is_error=False),
        ],
    )
    adapter = MelraExecutorAdapter(client)
    running = adapter.task_status(task_id)
    assert running.normalized_status == OutcomeStatus.PARTIAL
    assert running.terminal is False
    cancelled = adapter.cancel_task(task_id)
    assert cancelled.normalized_status == OutcomeStatus.CANCELLED
    assert cancelled.terminal is True
    assert [name for name, _arguments in client.calls] == [
        "melra_task_status",
        "melra_task_cancel",
    ]


def test_melra_private_normalizers_cover_text_state_and_approval_guards() -> None:
    task_id = "019fc000-0000-7000-8000-000000000013"
    assert MelraExecutorAdapter._required_evidence(
        "browser",
        "navigate",
        {"url": "https://owned.example/start"},
        SideEffect.MUTATE,
    ) == [{"type": "url_matches", "pattern": "https://owned.example/start*"}]

    parsed = MelraExecutorAdapter._structured(
        MCPToolResult(
            (
                {"type": "text", "text": "not-json"},
                {"type": "text", "text": '{"status":"ready"}'},
            ),
            None,
            is_error=False,
        )
    )
    assert parsed == {"status": "ready"}
    assert (
        MelraExecutorAdapter._structured(
            MCPToolResult(({"type": "text", "text": "[]"},), None, is_error=False)
        )
        is None
    )

    state = MelraExecutorAdapter._task_state(
        MCPToolResult((), {"id": task_id, "status": "planned"}, is_error=False),
        expected_task_id=task_id,
    )
    assert state.normalized_status == OutcomeStatus.PARTIAL
    with pytest.raises(FormatError, match="unknown MELRA task status"):
        MelraExecutorAdapter._task_state(
            MCPToolResult((), {"id": task_id, "status": "unknown"}, is_error=False),
            expected_task_id=task_id,
        )

    expected = mcp_adapter_module._MelraApprovalExpectation(
        task_id,
        "browser.inspect",
        {"kind": "browser", "action": "inspect"},
        SideEffect.READ,
    )
    authorization = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + "1" * 64,
    }
    with pytest.raises(FormatError, match="omitted its effect contract"):
        MelraExecutorAdapter._provider_approval(
            {},
            expected=expected,
            authorization=authorization,
        )

    plan = _melra_plan(task_id)
    plan["approval"] = {}
    with pytest.raises(FormatError, match="fresh SOVA authorization"):
        MelraExecutorAdapter._provider_approval(
            plan,
            expected=expected,
            authorization={"decision": "denied"},
        )
    plan["approval"] = "malformed"
    with pytest.raises(FormatError, match="challenge was malformed"):
        MelraExecutorAdapter._provider_approval(
            plan,
            expected=expected,
            authorization=authorization,
        )


@pytest.mark.parametrize(
    ("provider_status", "expected"),
    [
        ("policy_blocked", OutcomeStatus.DENIED),
        ("awaiting_approval", OutcomeStatus.DENIED),
        ("waiting_user", OutcomeStatus.DENIED),
        ("partial", OutcomeStatus.PARTIAL),
        ("budget_exhausted", OutcomeStatus.PARTIAL),
        ("recovery_required", OutcomeStatus.PARTIAL),
        ("cancelled", OutcomeStatus.CANCELLED),
        ("failed", OutcomeStatus.FAILED),
        ("running", OutcomeStatus.PARTIAL),
    ],
)
def test_melra_internal_task_status_overrides_transport_success(
    tmp_path: Path,
    provider_status: str,
    expected: OutcomeStatus,
) -> None:
    task_id = "019fc000-0000-7000-8000-000000000013"
    client = FakeMCPClient(
        ("melra_capabilities", "melra_plan", "melra_execute"),
        [
            MCPToolResult((), _melra_plan(task_id), is_error=False),
            MCPToolResult(
                ({"type": "text", "text": "transport completed"},),
                {"task": {"id": task_id, "status": provider_status}},
                is_error=False,
            ),
        ],
    )
    outcome = MelraExecutorAdapter(client).execute(
        ActionRequest("inspect", "browser.inspect", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == expected
    assert outcome.status != OutcomeStatus.SUCCEEDED
    assert outcome.output["providerStatus"] == provider_status


def test_melra_rejects_substituted_task_result(tmp_path: Path) -> None:
    planned = "019fc000-0000-7000-8000-000000000013"
    substituted = "019fc000-0000-7000-8000-000000000014"
    client = FakeMCPClient(
        ("melra_capabilities", "melra_plan", "melra_execute"),
        [
            MCPToolResult((), _melra_plan(planned), is_error=False),
            MCPToolResult(
                (),
                {"task": {"id": substituted, "status": "verified_success"}},
                is_error=False,
            ),
        ],
    )
    outcome = MelraExecutorAdapter(client).execute(
        ActionRequest("inspect", "browser.inspect", {}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-MELRA-EXECUTION-SHAPE"


def test_melra_delegates_provider_challenge_only_after_exact_sova_authorization(
    tmp_path: Path,
) -> None:
    task_id = "019fc000-0000-7000-8000-000000000013"
    digest = "a" * 64
    inputs = {"command": "python", "args": ["-c", "print('safe')"]}
    approval = {
        "approvalId": "019fc000-0000-7000-8000-000000000014",
        "taskId": task_id,
        "actionDigest": digest,
        "phrase": f"APPROVE {digest[:12]}",
        "expiresAt": "2026-08-09T16:00:00Z",
    }
    client = FakeMCPClient(
        ("melra_capabilities", "melra_plan", "melra_execute"),
        [
            MCPToolResult(
                (),
                _melra_plan(
                    task_id,
                    "terminal.run",
                    inputs,
                    effect="mutate",
                    approval=approval,
                ),
                is_error=False,
            ),
            MCPToolResult(
                (),
                {
                    "task": {"id": task_id, "status": "verified_success"},
                    "output": {"exitCode": 0, "stdout": "safe"},
                },
                is_error=False,
            ),
        ],
    )
    outcome = MelraExecutorAdapter(client).execute(
        ActionRequest("run", "terminal.run", inputs, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["providerApprovalDelegated"] is True
    plan = client.calls[0][1]
    assert plan["requiredEvidence"] == [{"type": "exit_code", "value": 0}]
    assert client.calls[1][1] == {
        "taskId": task_id,
        "approval": {
            "approvalId": approval["approvalId"],
            "phrase": approval["phrase"],
        },
    }


@pytest.mark.parametrize(
    "plan",
    [
        _melra_plan("task", "computer.click", {"x": 0.5, "y": 0.5}, effect="destructive"),
        {
            **_melra_plan("task", "computer.click", {"x": 0.5, "y": 0.5}, effect="mutate"),
            "contract": {
                **_melra_plan("other", "computer.click", {"x": 0.5, "y": 0.5}, effect="mutate")[
                    "contract"
                ],
            },
        },
        _melra_plan("task", "computer.type", {"x": 0.5, "y": 0.5}, effect="mutate"),
    ],
)
def test_melra_rejects_plan_substitution_or_effect_escalation(
    tmp_path: Path, plan: dict[str, Any]
) -> None:
    client = FakeMCPClient(
        ("melra_capabilities", "melra_plan", "melra_execute"),
        [MCPToolResult((), plan, is_error=False)],
    )
    outcome = MelraExecutorAdapter(client).execute(
        ActionRequest("click", "computer.click", {"x": 0.5, "y": 0.5}, 5),
        _context(tmp_path),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code in {
        "SOVA-MELRA-PLAN-CONTRACT",
        "SOVA-MELRA-EFFECT-ESCALATION",
    }


def test_adapter_timeout_and_cancellation_are_visible(tmp_path: Path) -> None:
    mapping = ToolMapping(
        action="fixture.read",
        tool="fixture",
        version="0.1",
        side_effect=SideEffect.READ,
        idempotent=True,
        evidence=("text",),
        argument_builder=dict,
    )
    client = FakeMCPClient(("fixture",), [])
    adapter = MCPExecutorAdapter("fixture", client, (mapping,))
    timeout = adapter.execute(
        ActionRequest("read", "fixture.read", {}, 1),
        _context(tmp_path),
        CancellationToken(),
    )
    assert timeout.status == OutcomeStatus.TIMEOUT
    token = CancellationToken()
    token.cancel()
    cancelled = adapter.execute(
        ActionRequest("read", "fixture.read", {}, 1), _context(tmp_path), token
    )
    assert cancelled.status == OutcomeStatus.CANCELLED
