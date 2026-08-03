# SPDX-License-Identifier: Apache-2.0
"""Hostile-input and failure-path coverage for the Topic 13 MCP boundary."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

import pytest

from sova.executors import (
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.mcp import (
    CapabilityExecutionBroker,
    MCPExecutorAdapter,
    MCPTool,
    MCPToolResult,
    MelraExecutorAdapter,
    StdioMCPClient,
    StdioServerSpec,
    ToolMapping,
    UnavailableCapabilityExecutor,
    WindowsMCPDirectories,
    playwright_stdio_spec,
    windows_mcp_stdio_spec,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class EdgeClient:
    server_name = "edge"

    def __init__(self, tools: tuple[str, ...], results: list[MCPToolResult]) -> None:
        self._tools = tuple(MCPTool(name, "", {"type": "object"}, None, {}) for name in tools)
        self.results = results
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
        del name, arguments, timeout_seconds
        if not self.results:
            raise FormatError("SOVA-MCP-BROKEN", "fixture protocol failure")
        return self.results.pop(0)

    def close(self) -> None:
        self.closed = True


def _context(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(tmp_path, {"decision": "allowed"})


def _mapping(*, post_observe: bool = False) -> ToolMapping:
    return ToolMapping(
        action="fixture.read",
        tool="fixture",
        version="0.1",
        side_effect=SideEffect.READ,
        idempotent=True,
        evidence=("fixture",),
        argument_builder=dict,
        post_observe_tool="observe" if post_observe else None,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": ""},
        {"argv": ()},
        {"startup_timeout_seconds": 0},
        {"startup_timeout_seconds": 121},
        {"max_message_bytes": 65 * 1024 * 1024},
    ],
)
def test_stdio_spec_rejects_invalid_process_contract(
    tmp_path: Path, kwargs: dict[str, Any]
) -> None:
    values: dict[str, Any] = {
        "name": "fixture",
        "argv": ("missing",),
        "cwd": tmp_path,
        "environment": {},
        "version": "1",
        "source": "fixture",
        "license": "MIT",
    }
    values.update(kwargs)
    with pytest.raises(FormatError):
        StdioServerSpec(**values)


def test_stdio_start_failure_is_normalized(tmp_path: Path) -> None:
    spec = StdioServerSpec(
        "absent", (str(tmp_path / "does-not-exist"),), tmp_path, {}, "1", "x", "MIT"
    )
    with pytest.raises(FormatError, match="could not start"):
        StdioMCPClient(spec)


def test_stdio_spec_rejects_non_allowlisted_environment(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="non-allowlisted"):
        StdioServerSpec(
            "fixture",
            ("missing",),
            tmp_path,
            {"UNREVIEWED_BACKEND_SETTING": "value"},
            "1",
            "fixture",
            "MIT",
        )


def test_protocol_parsers_cover_pagination_optional_fields_and_rejections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = object.__new__(StdioMCPClient)
    pages = iter(
        (
            {
                "tools": [
                    {
                        "name": "one",
                        "description": "first",
                        "inputSchema": {"type": "object"},
                        "outputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": True},
                    }
                ],
                "nextCursor": "next",
            },
            {"tools": [{"name": "two", "inputSchema": {"type": "object"}}]},
        )
    )

    def request(
        method: str, params: Mapping[str, Any], *, timeout_seconds: float
    ) -> dict[str, Any]:
        assert method == "tools/list"
        assert timeout_seconds == 20
        if params:
            assert params == {"cursor": "next"}
        return next(pages)

    monkeypatch.setattr(client, "_request", request)
    tools = client.list_tools()
    assert [item.name for item in tools] == ["one", "two"]
    assert tools[0].output_schema == {"type": "object"}
    assert tools[0].annotations == {"readOnlyHint": True}
    assert tools[1].description == ""

    invalid_tool_pages = iter(
        (
            {},
            {"tools": ["bad"]},
            {"tools": [{"name": "bad", "inputSchema": []}]},
            {"tools": [], "nextCursor": 4},
        )
    )
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: next(invalid_tool_pages))
    for _index in range(4):
        with pytest.raises(FormatError):
            client.list_tools()

    monkeypatch.setattr(
        client,
        "_request",
        lambda *_args, **_kwargs: {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"ok": True},
            "isError": True,
        },
    )
    result = client.call_tool("x", {}, timeout_seconds=1)
    assert result.is_error and result.structured_content == {"ok": True}
    invalid_tool_results: Any = iter(({"content": "bad"}, {"structuredContent": []}))
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: next(invalid_tool_results))
    for _index in range(2):
        with pytest.raises(FormatError):
            client.call_tool("x", {}, timeout_seconds=1)


def test_adapter_normalizes_every_content_type_and_context_lifecycle(tmp_path: Path) -> None:
    payload = base64.b64encode(b"owl").decode()
    client = EdgeClient(
        ("fixture",),
        [
            MCPToolResult(
                content=(
                    {"type": "text", "text": "hello"},
                    {"type": "image", "data": payload, "mimeType": "image/png"},
                    {"type": "audio", "data": payload},
                    {"type": "resource_link", "uri": "urn:sova:test", "name": "test"},
                    {"type": "unknown"},
                ),
                structured_content={"ok": True},
                is_error=False,
            )
        ],
    )
    with MCPExecutorAdapter("fixture", client, (_mapping(),)) as adapter:
        assert adapter.discovered_tools == ("fixture",)
        outcome = adapter.execute(
            ActionRequest("read", "fixture.read", {}, 1),
            _context(tmp_path),
            CancellationToken(),
        )
        assert outcome.status == OutcomeStatus.SUCCEEDED
        assert len(outcome.evidence) == 4
        assert outcome.output["resourceLinks"][0]["uri"] == "urn:sova:test"
        assert outcome.output["unrecognizedContent"] == ["unknown"]
    assert client.closed


def test_adapter_rejects_malformed_or_oversized_content_and_errors(tmp_path: Path) -> None:
    request = ActionRequest("read", "fixture.read", {}, 1)
    context = _context(tmp_path)
    for result, code in (
        (
            MCPToolResult(
                content=({"type": "image", "data": "%%%"},),
                structured_content=None,
                is_error=False,
            ),
            "SOVA-MCP-CONTENT",
        ),
        (
            MCPToolResult(
                content=(),
                structured_content={"value": "x" * (1024 * 1024)},
                is_error=False,
            ),
            "SOVA-MCP-CONTENT-LIMIT",
        ),
    ):
        outcome = MCPExecutorAdapter(
            "fixture", EdgeClient(("fixture",), [result]), (_mapping(),)
        ).execute(request, context, CancellationToken())
        assert outcome.status == OutcomeStatus.FAILED
        assert outcome.error_code == code

    tool_error = MCPExecutorAdapter(
        "fixture",
        EdgeClient(
            ("fixture",),
            [MCPToolResult(content=(), structured_content=None, is_error=True)],
        ),
        (_mapping(),),
    ).execute(request, context, CancellationToken())
    assert tool_error.status == OutcomeStatus.FAILED
    assert tool_error.error_code == "SOVA-MCP-TOOL-ERROR"

    observed = MCPExecutorAdapter(
        "fixture",
        EdgeClient(
            ("fixture", "observe"),
            [
                MCPToolResult(content=(), structured_content=None, is_error=False),
                MCPToolResult(content=(), structured_content=None, is_error=True),
            ],
        ),
        (_mapping(post_observe=True),),
    ).execute(request, context, CancellationToken())
    assert observed.verification == "observation-failed"


def test_adapter_configuration_unsupported_and_protocol_failure(tmp_path: Path) -> None:
    with pytest.raises(FormatError):
        MCPExecutorAdapter("", EdgeClient(("fixture",), []), (_mapping(),))
    with pytest.raises(FormatError):
        MCPExecutorAdapter("fixture", EdgeClient(("fixture",), []), ())
    adapter = MCPExecutorAdapter("fixture", EdgeClient((), []), (_mapping(),))
    unsupported = adapter.execute(
        ActionRequest("x", "absent", {}, 1), _context(tmp_path), CancellationToken()
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    failed = MCPExecutorAdapter("fixture", EdgeClient(("fixture",), []), (_mapping(),)).execute(
        ActionRequest("x", "fixture.read", {}, 1), _context(tmp_path), CancellationToken()
    )
    assert failed.status == OutcomeStatus.FAILED and failed.retryable


def test_melra_unavailable_malformed_approval_unknown_and_cleanup(tmp_path: Path) -> None:
    unavailable_client = EdgeClient(("melra_plan",), [])
    unavailable = MelraExecutorAdapter(unavailable_client)
    assert unavailable.capabilities() == ()
    assert (
        unavailable.execute(
            ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken()
        ).status
        == OutcomeStatus.UNSUPPORTED
    )
    with pytest.raises(FormatError, match="status tool unavailable"):
        unavailable.task_status("task")
    with pytest.raises(FormatError, match="cancel tool unavailable"):
        unavailable.cancel_task("task")

    tools = ("melra_capabilities", "melra_plan", "melra_execute")
    malformed = MelraExecutorAdapter(
        EdgeClient(
            tools,
            [MCPToolResult(content=(), structured_content=None, is_error=False)],
        )
    )
    assert (
        malformed.execute(
            ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken()
        ).error_code
        == "SOVA-MELRA-PLAN"
    )
    approval = MelraExecutorAdapter(
        EdgeClient(
            tools,
            [
                MCPToolResult(
                    content=(),
                    structured_content={"id": "task", "approval": {}},
                    is_error=False,
                )
            ],
        )
    ).execute(ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken())
    assert approval.status == OutcomeStatus.DENIED

    unknown = MelraExecutorAdapter(
        EdgeClient(
            tools,
            [
                MCPToolResult(content=(), structured_content={"id": "task"}, is_error=False),
                MCPToolResult(
                    content=(),
                    structured_content={"task": {"id": "task", "status": "future"}},
                    is_error=False,
                ),
            ],
        )
    ).execute(ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken())
    assert unknown.error_code == "SOVA-MELRA-UNKNOWN-STATUS"

    client = EdgeClient(tools, [])
    adapter = MelraExecutorAdapter(client)
    adapter.close()
    assert client.closed


def test_melra_text_fallback_state_receipts_cancellation_and_protocol_failure(
    tmp_path: Path,
) -> None:
    task_id = "task-1"
    tools = (
        "melra_capabilities",
        "melra_plan",
        "melra_execute",
        "melra_task_status",
        "melra_task_cancel",
    )
    client = EdgeClient(
        tools,
        [
            MCPToolResult(
                content=({"type": "text", "text": "not json"},),
                structured_content=None,
                is_error=False,
            ),
            MCPToolResult(
                content=({"type": "text", "text": '{"id":"task-1","status":"planned"}'},),
                structured_content=None,
                is_error=False,
            ),
        ],
    )
    adapter = MelraExecutorAdapter(client)
    with pytest.raises(FormatError):
        adapter.task_status(task_id)
    state = adapter.cancel_task(task_id)
    assert state.to_mapping()["providerStatus"] == "planned"

    rich = MelraExecutorAdapter(
        EdgeClient(
            tools,
            [
                MCPToolResult(content=(), structured_content={"id": task_id}, is_error=False),
                MCPToolResult(
                    content=(),
                    structured_content={
                        "task": {"id": task_id, "status": "verified_success"},
                        "output": {"ok": True},
                        "receipt": {"digest": "x"},
                        "certificate": {"issuer": "provider"},
                    },
                    is_error=False,
                ),
            ],
        )
    ).execute(ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken())
    assert rich.status == OutcomeStatus.SUCCEEDED
    assert {item.role for item in rich.evidence} == {
        "melra-output",
        "melra-receipt",
        "melra-certificate",
    }

    cancelled_token = CancellationToken()
    cancelled_token.cancel()
    cancelled = MelraExecutorAdapter(EdgeClient(tools, [])).execute(
        ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), cancelled_token
    )
    assert cancelled.status == OutcomeStatus.CANCELLED
    failed = MelraExecutorAdapter(EdgeClient(tools, [])).execute(
        ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken()
    )
    assert failed.error_code == "SOVA-MCP-BROKEN"


class ClosableUnavailable(UnavailableCapabilityExecutor):
    def __init__(self, capability: Capability) -> None:
        super().__init__("optional", (capability,), "not installed")
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_broker_union_unavailable_placeholder_and_close(tmp_path: Path) -> None:
    capability = Capability(
        name="browser.snapshot",
        version="0.1",
        side_effect=SideEffect.READ,
        idempotent=True,
        evidence=("snapshot",),
    )
    backend = ClosableUnavailable(capability)
    with pytest.raises(FormatError):
        CapabilityExecutionBroker(())
    broker = CapabilityExecutionBroker((backend,))
    assert broker.capabilities() == (capability,)
    outcome = broker.execute(
        ActionRequest("x", "browser.snapshot", {}, 1), _context(tmp_path), CancellationToken()
    )
    assert outcome.status == OutcomeStatus.UNSUPPORTED
    assert outcome.output["backend"] == "optional"
    missing = backend.execute(
        ActionRequest("x", "other", {}, 1), _context(tmp_path), CancellationToken()
    )
    assert missing.side_effect == SideEffect.READ
    broker.close()
    assert backend.closed


def test_fail_closed_specs_reject_missing_launch_dependencies(tmp_path: Path) -> None:
    with pytest.raises(FormatError):
        playwright_stdio_spec(
            package_runner=tmp_path / "npx",
            workspace=tmp_path,
            browser_executable=tmp_path / "chrome",
        )
    uvx = tmp_path / "uvx"
    uvx.write_bytes(b"fixture")
    windows = windows_mcp_stdio_spec(
        uvx=uvx,
        workspace=tmp_path / "workspace",
        directories=WindowsMCPDirectories(tmp_path / "c", tmp_path / "p", tmp_path / "t"),
        allow_input=True,
    )
    assert windows.argv[-1] == "Snapshot,Screenshot,Click,Type,Scroll,WaitFor"
