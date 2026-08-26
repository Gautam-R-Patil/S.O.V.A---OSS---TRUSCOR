# SPDX-License-Identifier: Apache-2.0
"""Executor-private Playwright profile checkpoint contracts."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats.errors import FormatError
from sova.mcp import MCPTool, MCPToolResult, playwright_mappings
from sova.mcp.profile_state import PlaywrightProfileStateHooks, profiled_playwright_adapter
from sova.runtime import BrowserProfileLease, BrowserProfileVault

if TYPE_CHECKING:
    from collections.abc import Mapping


class _StorageClient:
    server_name = "microsoft-playwright-mcp"

    def __init__(
        self,
        *,
        tools: tuple[str, ...] | None = None,
        error_tool: str | None = None,
        write_storage_state: bool = True,
    ) -> None:
        names = tools or (
            "browser_close",
            "browser_navigate",
            "browser_set_storage_state",
            "browser_storage_state",
        )
        self._tools = tuple(MCPTool(name, name, {"type": "object"}, None, {}) for name in names)
        self._error_tool = error_tool
        self._write_storage_state = write_storage_state
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
        values = dict(arguments)
        self.calls.append((name, values))
        if name == "browser_storage_state" and self._write_storage_state:
            Path(str(values["filename"])).write_text(
                '{"cookies":[{"name":"fixture","value":"private"}],"origins":[]}',
                encoding="utf-8",
            )
        if name == "browser_set_storage_state":
            payload = Path(str(values["filename"])).read_text(encoding="utf-8")
            assert '"private"' in payload
        return MCPToolResult((), None, is_error=name == self._error_tool)

    def close(self) -> None:
        self.closed = True


def _lease(tmp_path: Path) -> BrowserProfileLease:
    vault = BrowserProfileVault(tmp_path / "vault")
    record = vault.create(identity_id="operator", target="sha256:" + "1" * 64)
    return vault.acquire(record.handle, owner_id="profile-state-test")


def test_profile_checkpoint_is_private_atomic_and_restored(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        hooks = PlaywrightProfileStateHooks.create(lease, workspace)
        first = _StorageClient()
        hooks.require_tools(first)
        assert hooks.restore(first) is False
        hooks.save(first)

        state = lease.path_for_executor() / ".sova-playwright-storage-state.json"
        assert state.is_file()
        assert not list(lease.path_for_executor().glob("*.tmp"))
        assert not list((workspace / ".sova" / "playwright-private-state").glob("*.json"))

        second = _StorageClient()
        assert hooks.restore(second) is True
        assert second.calls[0][0] == "browser_set_storage_state"
        assert not Path(str(second.calls[0][1]["filename"])).exists()


def test_profiled_adapter_restores_then_checkpoints_before_close(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        seed = PlaywrightProfileStateHooks.create(lease, workspace)
        seed.save(_StorageClient())
        client = _StorageClient()
        lifecycle: list[str] = []
        adapter = profiled_playwright_adapter(
            "playwright",
            client,
            playwright_mappings(),
            profile_lease=lease,
            workspace=workspace,
            lifecycle_observer=lifecycle.append,
        )
        adapter.close()
        assert lifecycle == ["restored", "saved"]
        assert [name for name, _arguments in client.calls] == [
            "browser_set_storage_state",
            "browser_storage_state",
            "browser_close",
        ]
        assert client.closed


def test_profile_checkpoint_rejects_missing_tools_and_malformed_state(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        hooks = PlaywrightProfileStateHooks.create(lease, workspace)
        with pytest.raises(FormatError, match="omitted required"):
            hooks.require_tools(_StorageClient(tools=("browser_close",)))

        state = lease.path_for_executor() / ".sova-playwright-storage-state.json"
        state.write_text('{"cookies":"wrong","origins":[]}', encoding="utf-8")
        with pytest.raises(FormatError, match="malformed"):
            hooks.restore(_StorageClient())


def test_profile_checkpoint_rejects_empty_and_nonregular_state(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        hooks = PlaywrightProfileStateHooks.create(lease, workspace)
        state = lease.path_for_executor() / ".sova-playwright-storage-state.json"
        state.write_bytes(b"")
        with pytest.raises(FormatError, match="empty or exceeds"):
            hooks.restore(_StorageClient())

        state.unlink()
        state.mkdir()
        with pytest.raises(FormatError, match="non-regular"):
            hooks.restore(_StorageClient())


def test_profile_checkpoint_fails_closed_on_backend_restore_or_save_error(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        hooks = PlaywrightProfileStateHooks.create(lease, workspace)
        state = lease.path_for_executor() / ".sova-playwright-storage-state.json"
        state.write_text(
            '{"cookies":[{"name":"fixture","value":"private"}],"origins":[]}',
            encoding="utf-8",
        )
        with pytest.raises(FormatError, match="could not be restored"):
            hooks.restore(_StorageClient(error_tool="browser_set_storage_state"))
        assert not list((workspace / ".sova" / "playwright-private-state").glob("*.json"))

        with pytest.raises(FormatError, match="could not be checkpointed"):
            hooks.save(_StorageClient(write_storage_state=False))
        assert not list((workspace / ".sova" / "playwright-private-state").glob("*.json"))


def test_profile_checkpoint_rejects_nonregular_destination(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        hooks = PlaywrightProfileStateHooks.create(lease, workspace)
        state = lease.path_for_executor() / ".sova-playwright-storage-state.json"
        state.mkdir()
        with pytest.raises(FormatError, match="destination is not a regular file"):
            hooks.save(_StorageClient())


def test_profiled_adapter_without_a_profile_has_no_checkpoint_lifecycle(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    client = _StorageClient()
    lifecycle: list[str] = []
    adapter = profiled_playwright_adapter(
        "playwright",
        client,
        playwright_mappings(),
        profile_lease=None,
        workspace=workspace,
        lifecycle_observer=lifecycle.append,
    )
    adapter.close()
    assert lifecycle == []
    assert [name for name, _arguments in client.calls] == ["browser_close"]


def test_profiled_adapter_with_profile_does_not_require_lifecycle_observer(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with _lease(tmp_path) as lease:
        client = _StorageClient()
        adapter = profiled_playwright_adapter(
            "playwright",
            client,
            playwright_mappings(),
            profile_lease=lease,
            workspace=workspace,
        )
        adapter.close()
        assert [name for name, _arguments in client.calls] == [
            "browser_storage_state",
            "browser_close",
        ]


def test_profile_checkpoint_rejects_profile_outside_lease_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    profile = tmp_path / "profile"
    profile.mkdir()
    unrelated_root = tmp_path / "unrelated-root"
    unrelated_root.mkdir()

    class _InvalidLease:
        @staticmethod
        def path_for_executor() -> Path:
            return profile

        @staticmethod
        def root_for_executor() -> Path:
            return unrelated_root

    with pytest.raises(FormatError, match="real admitted profile"):
        PlaywrightProfileStateHooks.create(_InvalidLease(), workspace)  # type: ignore[arg-type]
