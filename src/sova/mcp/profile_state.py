# SPDX-License-Identifier: Apache-2.0
"""Executor-private persistence bridge for opaque Playwright profiles.

Chromium's native profile database remains the primary durable store.  This
bridge adds a deterministic Playwright storage-state checkpoint because some
installed Chrome/Windows combinations intermittently fail to recover an
otherwise present encrypted cookie after a clean process restart.  The state
file remains inside the already-sensitive, exclusively leased profile.  A
short-lived copy is exposed only to the trusted MCP process, never to a model,
trace, capsule, report, or public artifact.
"""

from __future__ import annotations

import os
import secrets
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.mcp.adapter import MCPExecutorAdapter, ToolMapping
    from sova.mcp.protocol import MCPClient
    from sova.runtime.sessions import BrowserProfileLease

_MAX_STORAGE_STATE_BYTES = 16 * 1024 * 1024
_PROFILE_STATE_FILENAME = ".sova-playwright-storage-state.json"
_REQUIRED_TOOLS = frozenset({"browser_set_storage_state", "browser_storage_state"})


def _validate_state(payload: bytes) -> None:
    if not payload or len(payload) > _MAX_STORAGE_STATE_BYTES:
        raise FormatError(
            "SOVA-PROFILE-STATE-SIZE",
            "browser profile storage state is empty or exceeds its private size bound",
        )
    value = strict_json_loads(payload, max_bytes=_MAX_STORAGE_STATE_BYTES)
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("cookies"), list)
        or not isinstance(value.get("origins"), list)
    ):
        raise FormatError(
            "SOVA-PROFILE-STATE-FORMAT",
            "browser profile storage state is malformed",
        )


def _private_file(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o600)


@dataclass(frozen=True, slots=True)
class PlaywrightProfileStateHooks:
    """Restore/save one lease-bound state checkpoint at the executor boundary."""

    profile: Path
    workspace: Path

    @classmethod
    def create(
        cls,
        profile_lease: BrowserProfileLease,
        workspace: Path,
    ) -> PlaywrightProfileStateHooks:
        profile = profile_lease.path_for_executor().resolve(strict=True)
        root = profile_lease.root_for_executor().resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=True)
        if (
            profile.is_symlink()
            or root.is_symlink()
            or resolved_workspace.is_symlink()
            or not profile.is_dir()
            or not resolved_workspace.is_dir()
            or root not in profile.parents
        ):
            raise FormatError(
                "SOVA-PROFILE-STATE-PATH",
                "browser profile state requires real admitted profile and workspace directories",
            )
        return cls(profile, resolved_workspace)

    @property
    def _state_path(self) -> Path:
        return self.profile / _PROFILE_STATE_FILENAME

    def _staging_path(self) -> Path:
        directory = self.workspace / ".sova" / "playwright-private-state"
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise FormatError(
                "SOVA-PROFILE-STATE-PATH",
                "browser profile staging directory must be a real directory",
            )
        if os.name != "nt":
            directory.chmod(0o700)
        return directory / f"state-{secrets.token_hex(16)}.json"

    @staticmethod
    def require_tools(client: MCPClient) -> None:
        actual = {tool.name for tool in client.list_tools()}
        if _REQUIRED_TOOLS.difference(actual):
            raise FormatError(
                "SOVA-PROFILE-STATE-CAPABILITY",
                "pinned browser backend omitted required private persistence tools",
            )

    def restore(self, client: MCPClient) -> bool:
        """Restore a prior checkpoint before any target action, if one exists."""
        source = self._state_path
        if not source.exists():
            return False
        if source.is_symlink() or not source.is_file():
            raise FormatError(
                "SOVA-PROFILE-STATE-PATH",
                "browser profile storage state was replaced by a non-regular file",
            )
        payload = source.read_bytes()
        _validate_state(payload)
        staging = self._staging_path()
        try:
            with staging.open("xb") as stream:
                stream.write(payload)
            _private_file(staging)
            result = client.call_tool(
                "browser_set_storage_state",
                {"filename": str(staging)},
                timeout_seconds=20.0,
            )
            if result.is_error:
                raise FormatError(
                    "SOVA-PROFILE-STATE-RESTORE",
                    "browser profile storage state could not be restored",
                )
            return True
        finally:
            with suppress(FileNotFoundError):
                staging.unlink()

    def save(self, client: MCPClient) -> None:
        """Atomically refresh the checkpoint before the browser is closed."""
        destination = self._state_path
        if destination.is_symlink() or (destination.exists() and not destination.is_file()):
            raise FormatError(
                "SOVA-PROFILE-STATE-PATH",
                "browser profile storage state destination is not a regular file",
            )
        staging = self._staging_path()
        replacement = self.profile / f".{_PROFILE_STATE_FILENAME}.{secrets.token_hex(16)}.tmp"
        try:
            result = client.call_tool(
                "browser_storage_state",
                {"filename": str(staging)},
                timeout_seconds=20.0,
            )
            if result.is_error or not staging.is_file() or staging.is_symlink():
                raise FormatError(
                    "SOVA-PROFILE-STATE-SAVE",
                    "browser profile storage state could not be checkpointed",
                )
            payload = staging.read_bytes()
            _validate_state(payload)
            with replacement.open("xb") as stream:
                stream.write(payload)
            _private_file(replacement)
            replacement.replace(destination)
        finally:
            for path in (staging, replacement):
                with suppress(FileNotFoundError):
                    path.unlink()


def profiled_playwright_adapter(  # noqa: PLR0913 - each lifecycle boundary is explicit
    name: str,
    client: MCPClient,
    mappings: tuple[ToolMapping, ...],
    *,
    profile_lease: BrowserProfileLease | None,
    workspace: Path,
    lifecycle_observer: Callable[[str], None] | None = None,
) -> MCPExecutorAdapter:
    """Construct an adapter with private profile restore/save lifecycle hooks."""
    from sova.mcp.adapter import MCPExecutorAdapter  # noqa: PLC0415 - avoids package cycle

    if profile_lease is None:
        return MCPExecutorAdapter(name, client, mappings)
    hooks = PlaywrightProfileStateHooks.create(profile_lease, workspace)
    hooks.require_tools(client)
    restored = hooks.restore(client)
    if lifecycle_observer is not None:
        lifecycle_observer("restored" if restored else "empty")

    def save() -> None:
        hooks.save(client)
        if lifecycle_observer is not None:
            lifecycle_observer("saved")

    return MCPExecutorAdapter(
        name,
        client,
        mappings,
        before_close=save,
    )


__all__ = ["PlaywrightProfileStateHooks", "profiled_playwright_adapter"]
