# SPDX-License-Identifier: Apache-2.0
"""Topic 13 MCP protocol, adapter, MELRA boundary, and fallback contracts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

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
from sova.mcp import (
    CapabilityExecutionBroker,
    MCPExecutorAdapter,
    MCPTool,
    MCPToolResult,
    MelraExecutorAdapter,
    StdioMCPClient,
    StdioServerSpec,
    ToolMapping,
    WindowsMCPDirectories,
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
    return ExecutionContext(tmp_path, {"decision": "allowed"})


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


def test_windows_mapping_excludes_dangerous_host_tools() -> None:
    mapping_tools = {item.tool for item in windows_mcp_mappings()}
    assert not mapping_tools & {"PowerShell", "Registry", "FileSystem", "Process", "Clipboard"}
    assert {"Snapshot", "Screenshot", "Click", "Type", "Scroll", "WaitFor"} <= mapping_tools


def test_pinned_open_source_launch_specs_are_fail_closed(tmp_path: Path) -> None:
    runner = tmp_path / "npx.cmd"
    browser = tmp_path / "chrome.exe"
    uvx = tmp_path / "uvx.exe"
    for path in (runner, browser, uvx):
        path.write_bytes(b"synthetic executable placeholder")
    playwright = playwright_stdio_spec(
        package_runner=runner,
        workspace=tmp_path,
        browser_executable=browser,
    )
    assert "@playwright/mcp@0.0.78" in playwright.argv
    assert "--isolated" in playwright.argv
    assert "--headless" in playwright.argv

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
    assert by_name["melra"]["commit"] == "a6dd6710f5ae94e8ce825ef99df9b01d7f974b95"
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
                structured_content={"id": "019fc000-0000-7000-8000-000000000013"},
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
            MCPToolResult((), {"id": task_id}, is_error=False),
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
            MCPToolResult((), {"id": planned}, is_error=False),
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
