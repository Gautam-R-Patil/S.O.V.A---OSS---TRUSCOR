# SPDX-License-Identifier: Apache-2.0
"""Hostile-input and failure-path coverage for the Topic 13 MCP boundary."""

from __future__ import annotations

import base64
import io
import subprocess
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

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
    CuaDriverService,
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


class FakeCuaProcess:
    def __init__(self, *, return_code: int | None = None, wait_timeouts: int = 0) -> None:
        self.return_code = return_code
        self.wait_timeouts = wait_timeouts
        self.stderr = io.BytesIO(b"synthetic service stderr")
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.return_code

    def wait(self, timeout: float) -> int:
        if self.wait_timeouts:
            self.wait_timeouts -= 1
            raise subprocess.TimeoutExpired("cua-driver", timeout)
        self.return_code = 0
        return 0

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True
        self.return_code = 0


def _cua_spec(tmp_path: Path, *, policy: bool = True) -> StdioServerSpec:
    environment = (
        {"CUA_DRIVER_SESSION_POLICY_FILE": str(tmp_path / "policy.yaml")} if policy else {}
    )
    return StdioServerSpec(
        "cua-driver",
        (
            str(tmp_path / "cua-driver.exe"),
            "mcp",
            "--socket",
            r"\\.\pipe\sova-cua-00000000000000000000000000000000",
            "--no-overlay",
        ),
        tmp_path,
        environment,
        "0.12.6",
        "fixture",
        "MIT",
    )


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


def test_stdio_close_prefers_graceful_exit_then_bounds_terminate_and_kill() -> None:
    def client_for(process: FakeCuaProcess) -> Any:
        cast("Any", process).stdin = io.BytesIO()
        client = cast("Any", object.__new__(StdioMCPClient))
        client._closed = False
        client._process = process
        client._reader = SimpleNamespace(join=lambda timeout: timeout)
        client._stderr_reader = SimpleNamespace(join=lambda timeout: timeout)
        return client

    graceful_process = FakeCuaProcess(wait_timeouts=0)
    graceful = client_for(graceful_process)
    graceful.close()
    graceful.close()
    assert graceful_process.return_code == 0
    assert graceful_process.terminated is False
    assert graceful_process.killed is False

    stuck_process = FakeCuaProcess(wait_timeouts=2)
    stuck = client_for(stuck_process)
    stuck.close()
    assert stuck_process.terminated is True
    assert stuck_process.killed is True


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


def test_cua_service_rejects_malformed_or_policyless_specs(tmp_path: Path) -> None:
    malformed = StdioServerSpec(
        "other",
        ("x",),
        tmp_path,
        {},
        "1",
        "fixture",
        "MIT",
    )
    with pytest.raises(FormatError) as malformed_error:
        CuaDriverService.start(malformed)
    assert malformed_error.value.issue.code == "SOVA-CUA-SERVICE-SPEC"
    with pytest.raises(FormatError) as policy_error:
        CuaDriverService.start(_cua_spec(tmp_path, policy=False))
    assert policy_error.value.issue.code == "SOVA-CUA-SERVICE-SPEC"


def test_cua_service_starts_probes_and_stops_exact_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeCuaProcess()
    launched: list[tuple[tuple[object, ...], dict[str, object]]] = []
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def popen(argv: tuple[object, ...], **kwargs: object) -> FakeCuaProcess:
        launched.append((argv, kwargs))
        return process

    def run(argv: tuple[object, ...], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("sova.mcp.cua_driver.subprocess.Popen", popen)
    monkeypatch.setattr("sova.mcp.cua_driver.subprocess.run", run)
    spec = _cua_spec(tmp_path)
    with CuaDriverService.start(spec) as service:
        assert service.socket_name == spec.argv[3]
        assert service.__enter__() is service
    service.close()
    assert len(launched) == 1
    assert launched[0][0][1:3] == ("serve", "--socket")
    assert launched[0][0][-1] == "--approve-session-policy"
    assert calls[0][0][1] == "status"
    assert calls[1][0][1] == "stop"
    assert process.return_code == 0
    assert process.stderr.closed


def test_cua_service_normalizes_start_and_early_exit_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(*_args: object, **_kwargs: object) -> FakeCuaProcess:
        message = "synthetic denied"
        raise OSError(message)

    monkeypatch.setattr("sova.mcp.cua_driver.subprocess.Popen", denied)
    with pytest.raises(FormatError) as start_error:
        CuaDriverService.start(_cua_spec(tmp_path))
    assert start_error.value.issue.code == "SOVA-CUA-SERVICE-START"

    exited = FakeCuaProcess(return_code=7)
    monkeypatch.setattr(
        "sova.mcp.cua_driver.subprocess.Popen",
        lambda *_args, **_kwargs: exited,
    )
    with pytest.raises(FormatError) as exit_error:
        CuaDriverService.start(_cua_spec(tmp_path))
    assert exit_error.value.issue.code == "SOVA-CUA-SERVICE-EXIT"
    assert exit_error.value.issue.details is not None
    assert exit_error.value.issue.details["returnCode"] == 7
    assert exited.stderr.closed


def test_cua_service_readiness_timeout_and_kill_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeCuaProcess(wait_timeouts=1)
    spec = _cua_spec(tmp_path)
    service = CuaDriverService(spec, cast("Any", process), spec.argv[3])
    ticks = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr("sova.mcp.cua_driver.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("sova.mcp.cua_driver.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "sova.mcp.cua_driver.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    with pytest.raises(FormatError) as timeout_error:
        service._wait_ready()
    assert timeout_error.value.issue.code == "SOVA-CUA-SERVICE-TIMEOUT"

    process.wait_timeouts = 1

    def failed_stop(*_args: object, **_kwargs: object) -> SimpleNamespace:
        message = "synthetic stop failure"
        raise OSError(message)

    monkeypatch.setattr("sova.mcp.cua_driver.subprocess.run", failed_stop)
    service.close()
    assert process.terminated
    assert process.killed
    assert process.stderr.closed


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
                    structured_content=_melra_plan("task", approval={}),
                    is_error=False,
                )
            ],
        )
    ).execute(ActionRequest("x", "browser.inspect", {}, 1), _context(tmp_path), CancellationToken())
    assert approval.status == OutcomeStatus.FAILED
    assert approval.error_code == "SOVA-MELRA-APPROVAL"

    unknown = MelraExecutorAdapter(
        EdgeClient(
            tools,
            [
                MCPToolResult(content=(), structured_content=_melra_plan("task"), is_error=False),
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
                MCPToolResult(content=(), structured_content=_melra_plan(task_id), is_error=False),
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
    runner = tmp_path / "npx"
    browser = tmp_path / "chrome"
    runner.write_bytes(b"fixture")
    browser.write_bytes(b"fixture")
    outside = tmp_path.parent / "outside-profile"
    outside.mkdir(exist_ok=True)
    with pytest.raises(FormatError, match="admitted workspace"):
        playwright_stdio_spec(
            package_runner=runner,
            workspace=tmp_path,
            browser_executable=browser,
            profile_directory=outside,
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
