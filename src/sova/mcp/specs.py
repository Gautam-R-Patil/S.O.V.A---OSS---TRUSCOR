# SPDX-License-Identifier: Apache-2.0
"""Fail-closed launch recipes for pinned open-source MCP backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sova.formats.errors import FormatError
from sova.mcp.protocol import StdioServerSpec
from sova.mcp.receipts import PLAYWRIGHT_MCP_RECEIPT, WINDOWS_MCP_RECEIPT

if TYPE_CHECKING:
    from pathlib import Path


def _file(path: Path, role: str) -> str:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FormatError("SOVA-MCP-LAUNCH-PATH", f"{role} must be an existing file")
    return str(resolved)


def playwright_stdio_spec(
    *,
    package_runner: Path,
    workspace: Path,
    browser_executable: Path,
    allowed_origins: tuple[str, ...] = (),
) -> StdioServerSpec:
    """Create a workspace-local isolated Playwright MCP launch.

    On Windows ``npx.cmd`` cannot be launched reliably with ``shell=False``.
    Resolve it to Node's real ``npx-cli.js`` entrypoint instead of invoking a
    command shell.  Cache, browser bookkeeping, and evidence stay inside the
    caller's workspace; no persistent browser profile is used.

    Playwright documents ``--allowed-origins`` as request filtering rather
    than a security boundary.  SOVA therefore also validates every navigation
    target before dispatch and verifies the final observed page separately.
    """
    workspace = workspace.resolve()
    npm_cache = workspace / ".cache" / "npm-playwright"
    browser_cache = workspace / ".cache" / "playwright-browsers"
    local_app_data = workspace / ".cache" / "playwright-local-app-data"
    output = workspace / ".sova" / "playwright-output"
    for directory in (npm_cache, browser_cache, local_app_data, output):
        directory.mkdir(parents=True, exist_ok=True)
    runner = package_runner.resolve()
    if runner.suffix.casefold() in {".cmd", ".bat"}:
        node = runner.with_name("node.exe")
        npx_cli = runner.parent / "node_modules" / "npm" / "bin" / "npx-cli.js"
        argv = (
            (_file(node, "Node executable"), _file(npx_cli, "npx CLI"))
            if node.is_file() and npx_cli.is_file()
            else (_file(runner, "package runner"),)
        )
    else:
        argv = (_file(runner, "package runner"),)
    origin_args: tuple[str, ...] = ()
    if allowed_origins:
        if any(not origin or ";" in origin for origin in allowed_origins):
            raise FormatError("SOVA-MCP-ORIGIN", "allowed origins must be non-empty URI origins")
        origin_args = ("--allowed-origins", ";".join(allowed_origins))
    return StdioServerSpec(
        "microsoft-playwright-mcp",
        (
            *argv,
            "--yes",
            "--cache",
            str(npm_cache),
            "@playwright/mcp@0.0.78",
            "--headless",
            "--isolated",
            "--block-service-workers",
            "--image-responses",
            "omit",
            "--output-dir",
            str(output),
            "--executable-path",
            _file(browser_executable, "browser executable"),
            *origin_args,
        ),
        workspace,
        {
            "LOCALAPPDATA": str(local_app_data),
            "PLAYWRIGHT_BROWSERS_PATH": str(browser_cache),
        },
        PLAYWRIGHT_MCP_RECEIPT.version,
        PLAYWRIGHT_MCP_RECEIPT.source,
        PLAYWRIGHT_MCP_RECEIPT.license,
        PLAYWRIGHT_MCP_RECEIPT.package_digest,
        # A clean per-run npm cache may need one bounded package fetch before
        # the pinned server can initialize. Tool calls retain their shorter
        # independent deadlines and are never retried after target activity.
        startup_timeout_seconds=120.0,
    )


@dataclass(frozen=True, slots=True)
class WindowsMCPDirectories:
    """Workspace-local uv directories for the optional Windows backend."""

    cache: Path
    python: Path
    tools: Path


def windows_mcp_stdio_spec(
    *,
    uvx: Path,
    workspace: Path,
    directories: WindowsMCPDirectories,
    allow_input: bool = False,
) -> StdioServerSpec:
    """Create a telemetry-off Windows-MCP launch with a narrow tool allowlist."""
    tools = ["Snapshot", "Screenshot"]
    if allow_input:
        tools.extend(("Click", "Type", "Scroll", "WaitFor"))
    for path in (workspace, directories.cache, directories.python, directories.tools):
        path.mkdir(parents=True, exist_ok=True)
    return StdioServerSpec(
        "windows-mcp",
        (
            _file(uvx, "uvx executable"),
            "--python",
            "3.13",
            "windows-mcp==0.8.2",
            "serve",
            "--transport",
            "stdio",
            "--tools",
            ",".join(tools),
        ),
        workspace,
        {
            "ANONYMIZED_TELEMETRY": "false",
            "UV_CACHE_DIR": str(directories.cache.resolve()),
            "UV_PYTHON_INSTALL_DIR": str(directories.python.resolve()),
            "UV_TOOL_DIR": str(directories.tools.resolve()),
        },
        WINDOWS_MCP_RECEIPT.version,
        WINDOWS_MCP_RECEIPT.source,
        WINDOWS_MCP_RECEIPT.license,
        WINDOWS_MCP_RECEIPT.package_digest,
    )


__all__ = [
    "WindowsMCPDirectories",
    "playwright_stdio_spec",
    "windows_mcp_stdio_spec",
]
