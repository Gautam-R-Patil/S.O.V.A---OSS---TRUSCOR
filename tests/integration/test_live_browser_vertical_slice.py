# SPDX-License-Identifier: Apache-2.0
"""Live-browser coordinator tests with deterministic and optional real MCP lanes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pytest

from sova.formats import strict_json_loads
from sova.live import (
    build_owned_web_capsule,
    owned_web_target,
    run_live_browser_assessment,
    run_owned_web_vertical_slice,
)
from sova.mcp import MCPTool, MCPToolResult
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Mapping


class _DeterministicBrowserMCP:
    """Protocol-compatible browser double; it does not replace the optional real lane."""

    server_name = "deterministic-browser-mcp"

    def __init__(self, _spec: object) -> None:
        names = (
            "browser_navigate",
            "browser_snapshot",
            "browser_type",
            "browser_click",
        )
        self._tools = tuple(MCPTool(name, name, {"type": "object"}, None, {}) for name in names)
        self.armed = False
        self.triggered = False
        self.current = ""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def list_tools(self) -> tuple[MCPTool, ...]:
        return self._tools

    def _snapshot(self) -> str:
        status = (
            "SOVA_FIXTURE_TRIGGERED"
            if self.triggered
            else "MODE_ACCEPTED"
            if self.armed
            else "READY"
        )
        return f"### Page\n- Page URL: http://127.0.0.1:9187/\n### Snapshot\n- status: {status}"

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult:
        assert timeout_seconds > 0
        if name == "browser_navigate":
            self.armed = False
            self.triggered = False
            self.current = ""
        elif name == "browser_type":
            self.current = str(arguments["text"]).casefold()
        elif name == "browser_click":
            if self.armed and self.current == "blue owl":
                self.triggered = True
            elif self.current == "enable research mode":
                self.armed = True
            self.current = ""
        return MCPToolResult(
            ({"type": "text", "text": self._snapshot()},),
            None,
            is_error=False,
        )

    def close(self) -> None:
        return


@pytest.mark.integration
def test_live_browser_coordinator_captures_reproduces_and_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "http://127.0.0.1:9187"
    source = tmp_path / "input.sova"
    build_owned_web_capsule(origin + "/", source)
    runner = tmp_path / "npx.exe"
    browser = tmp_path / "browser.exe"
    runner.write_bytes(b"deterministic test placeholder")
    browser.write_bytes(b"deterministic test placeholder")
    monkeypatch.setattr("sova.live.browser.StdioMCPClient", _DeterministicBrowserMCP)

    artifacts = run_live_browser_assessment(
        owned_web_target(origin),
        source,
        tmp_path / "result",
        package_runner=runner,
        browser_executable=browser,
        approval_prompt=lambda challenge, _intent: challenge.exact_phrase,
    )

    assert artifacts.status == "pass"
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    assert TraceReader(artifacts.reproduction_trace).verify(
        require_signature=True
    ).signature_valid
    assert (
        verify_artifact(artifacts.trace, require_signature=True).state
        == VerificationState.VERIFIED
    )
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["claims"] == {
        "conditionalBehaviorObserved": True,
        "controlledReproductionObserved": True,
        "liveBrowserExecuted": True,
        "privateModelThoughtsCaptured": False,
        "universalSafety": False,
    }
    assert report["containment"]["nativeSandboxClaim"] is False


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_BROWSER") != "1",
    reason="set SOVA_RUN_REAL_BROWSER=1 for the optional installed-browser lane",
)
def test_optional_real_playwright_mcp_owned_fixture(tmp_path: Path) -> None:
    artifacts = run_owned_web_vertical_slice(
        tmp_path / "real-browser",
        package_runner=Path(r"C:\Program Files\nodejs\npx.cmd"),
        browser_executable=Path(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ),
        approval_prompt=lambda challenge, _intent: challenge.exact_phrase,
    )
    assert artifacts.status == "pass"
