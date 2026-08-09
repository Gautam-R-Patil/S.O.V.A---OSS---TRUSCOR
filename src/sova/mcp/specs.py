# SPDX-License-Identifier: Apache-2.0
"""Fail-closed launch recipes for pinned open-source MCP backends."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sova.formats.errors import FormatError
from sova.mcp.protocol import StdioServerSpec
from sova.mcp.receipts import (
    CUA_DRIVER_AUDIT_RECEIPT,
    MELRA_AUDIT_RECEIPT,
    PLAYWRIGHT_MCP_RECEIPT,
    WINDOWS_MCP_RECEIPT,
)

if TYPE_CHECKING:
    from pathlib import Path

_CUA_PIPE = re.compile(r"^\\\\\.\\pipe\\sova-cua-[a-f0-9]{32}$")


def _file(path: Path, role: str) -> str:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FormatError("SOVA-MCP-LAUNCH-PATH", f"{role} must be an existing file")
    return str(resolved)


def playwright_stdio_spec(  # noqa: PLR0913 - launch security inputs remain explicit
    *,
    package_runner: Path,
    workspace: Path,
    browser_executable: Path,
    allowed_origins: tuple[str, ...] = (),
    package_cache: Path | None = None,
    profile_directory: Path | None = None,
    profile_vault_root: Path | None = None,
    headless: bool = True,
) -> StdioServerSpec:
    """Create a workspace-local Playwright MCP launch.

    On Windows ``npx.cmd`` cannot be launched reliably with ``shell=False``.
    Resolve it to Node's real ``npx-cli.js`` entrypoint instead of invoking a
    command shell.  Cache, browser bookkeeping, and evidence stay inside the
    caller's workspace.  The default is isolated and ephemeral.  A caller may
    supply an already-exclusive, workspace-contained profile directory at the
    trusted executor boundary to opt into durable browser state.

    Playwright documents ``--allowed-origins`` as request filtering rather
    than a security boundary.  SOVA therefore also validates every navigation
    target before dispatch and verifies the final observed page separately.
    """
    workspace = workspace.resolve()
    npm_cache = (
        workspace / ".cache" / "npm-playwright"
        if package_cache is None
        else package_cache.resolve()
    )
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
    if profile_directory is None:
        profile_args: tuple[str, ...] = ("--isolated",)
    else:
        admission_root = workspace if profile_vault_root is None else profile_vault_root.resolve()
        if not admission_root.is_dir() or admission_root.is_symlink():
            raise FormatError(
                "SOVA-MCP-LAUNCH-PATH",
                "Playwright profile vault root must be a real existing directory",
            )
        profile = _inside(admission_root, profile_directory, "Playwright profile directory")
        if not profile.is_dir() or profile.is_symlink():
            raise FormatError(
                "SOVA-MCP-LAUNCH-PATH",
                "Playwright profile directory must be a real existing directory",
            )
        profile_args = ("--user-data-dir", str(profile))
    display_args = ("--headless",) if headless else ()
    return StdioServerSpec(
        "microsoft-playwright-mcp",
        (
            *argv,
            "--yes",
            "--cache",
            str(npm_cache),
            "@playwright/mcp@0.0.78",
            *display_args,
            *profile_args,
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


def _inside(root: Path, candidate: Path, role: str) -> Path:
    resolved_root = root.resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise FormatError(
            "SOVA-MCP-LAUNCH-PATH",
            f"{role} must stay inside the admitted workspace",
        ) from error
    return resolved


@dataclass(frozen=True, slots=True)
class MelraDirectories:
    """Workspace-contained mutable state admitted to the MELRA backend."""

    state: Path
    policy: Path
    browser_profile: Path | None = None


@dataclass(frozen=True, slots=True)
class CuaDriverDirectories:
    """Workspace-contained state and reviewed policy for CUA Driver."""

    state: Path
    policy: Path


def cua_driver_stdio_spec(
    *,
    executable: Path,
    workspace: Path,
    directories: CuaDriverDirectories,
    socket_name: str | None = None,
) -> StdioServerSpec:
    """Launch pinned CUA Driver in bounded, telemetry-off MCP mode.

    SOVA never launches CUA in unrestricted mode. The operator-reviewed CUA
    manifest is an additional deny-by-default layer; SOVA authorization and
    post-action evidence remain authoritative.
    """
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise FormatError("SOVA-MCP-LAUNCH-PATH", "CUA workspace must exist")
    state = _inside(workspace, directories.state, "CUA state directory")
    policy = _inside(workspace, directories.policy, "CUA session policy")
    state.mkdir(parents=True, exist_ok=True)
    socket_name = socket_name or rf"\\.\pipe\sova-cua-{secrets.token_hex(16)}"
    if _CUA_PIPE.fullmatch(socket_name) is None:
        raise FormatError(
            "SOVA-CUA-PIPE",
            "CUA Driver requires a SOVA-owned per-run Windows named pipe",
        )
    return StdioServerSpec(
        "cua-driver",
        (
            _file(executable, "CUA Driver executable"),
            "mcp",
            "--socket",
            socket_name,
            "--no-overlay",
        ),
        workspace,
        {
            "CUA_DRIVER_DISABLE_UNRESTRICTED": "1",
            "CUA_DRIVER_PERMISSION_MODE": "bounded",
            "CUA_DRIVER_RS_HOME": str(state),
            "CUA_DRIVER_RS_PERMISSIONS_GATE": "0",
            "CUA_DRIVER_RS_TELEMETRY_ENABLED": "0",
            "CUA_DRIVER_SESSION_POLICY_APPROVED": "1",
            "CUA_DRIVER_SESSION_POLICY_FILE": _file(policy, "CUA session policy"),
            "CUA_DRIVER_TELEMETRY_HOME": str(state / "telemetry"),
        },
        CUA_DRIVER_AUDIT_RECEIPT.version,
        CUA_DRIVER_AUDIT_RECEIPT.source,
        CUA_DRIVER_AUDIT_RECEIPT.license,
        CUA_DRIVER_AUDIT_RECEIPT.package_digest,
        startup_timeout_seconds=60.0,
        max_message_bytes=32 * 1024 * 1024,
    )


def melra_stdio_spec(
    *,
    node_executable: Path,
    cli_entrypoint: Path,
    workspace: Path,
    directories: MelraDirectories,
    browser_executable: Path | None = None,
) -> StdioServerSpec:
    """Create a pinned, confined MELRA stdio launch without unhinged mode.

    MELRA remains an executor, not SOVA's policy, authorization, evidence, or
    containment authority.  All mutable backend state, including an optional
    persistent browser profile, must stay inside the explicitly admitted
    workspace.  The profile path is opaque to traces and capsules.
    """
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise FormatError("SOVA-MCP-LAUNCH-PATH", "MELRA workspace must exist")
    state = _inside(workspace, directories.state, "MELRA state directory")
    profile = (
        None
        if directories.browser_profile is None
        else _inside(workspace, directories.browser_profile, "MELRA browser profile")
    )
    state.mkdir(parents=True, exist_ok=True)
    if profile is not None:
        profile.mkdir(parents=True, exist_ok=True)
    policy = _inside(workspace, directories.policy, "MELRA policy file")
    environment = {
        "MELRA_WORKSPACE": str(workspace),
        "MELRA_HOME": str(state),
        "MELRA_POLICY": _file(policy, "MELRA policy file"),
    }
    if browser_executable is not None:
        environment["MELRA_BROWSER"] = _file(browser_executable, "browser executable")
    if profile is not None:
        environment["MELRA_BROWSER_PROFILE"] = str(profile)
    return StdioServerSpec(
        "melra",
        (
            _file(node_executable, "Node executable"),
            _file(cli_entrypoint, "MELRA CLI entrypoint"),
            "serve",
        ),
        workspace,
        environment,
        MELRA_AUDIT_RECEIPT.version,
        MELRA_AUDIT_RECEIPT.source,
        MELRA_AUDIT_RECEIPT.license,
        MELRA_AUDIT_RECEIPT.package_digest,
        startup_timeout_seconds=30.0,
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
    "CuaDriverDirectories",
    "MelraDirectories",
    "WindowsMCPDirectories",
    "cua_driver_stdio_spec",
    "melra_stdio_spec",
    "playwright_stdio_spec",
    "windows_mcp_stdio_spec",
]
