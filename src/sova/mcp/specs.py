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
) -> StdioServerSpec:
    """Create an isolated headless Playwright MCP launch with exact versions."""
    return StdioServerSpec(
        "microsoft-playwright-mcp",
        (
            _file(package_runner, "package runner"),
            "--yes",
            "@playwright/mcp@0.0.78",
            "--headless",
            "--isolated",
            "--executable-path",
            _file(browser_executable, "browser executable"),
        ),
        workspace,
        {},
        PLAYWRIGHT_MCP_RECEIPT.version,
        PLAYWRIGHT_MCP_RECEIPT.source,
        PLAYWRIGHT_MCP_RECEIPT.license,
        PLAYWRIGHT_MCP_RECEIPT.package_digest,
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
