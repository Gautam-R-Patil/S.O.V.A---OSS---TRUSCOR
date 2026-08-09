# SPDX-License-Identifier: Apache-2.0
"""Opt-in live conformance for the checksum-pinned CUA Driver release."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from contextlib import suppress
from ctypes import wintypes
from pathlib import Path
from uuid import uuid4

import pytest

from sova.mcp import (
    CuaDriverDirectories,
    CuaDriverService,
    StdioMCPClient,
    cua_driver_stdio_spec,
)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_CUA_DRIVER") != "1",
    reason="set SOVA_RUN_CUA_DRIVER=1 with the verified release executable",
)
def test_pinned_cua_driver_advertises_and_executes_bounded_read_tools(tmp_path: Path) -> None:
    executable = Path(os.environ["SOVA_CUA_DRIVER_EXECUTABLE"])
    policy = tmp_path / "cua-session-policy.yaml"
    policy.write_text(
        """version: 1
mode: bounded
expires_after: 10m
idle_timeout: 2m
resources: {}
allow:
  tools: [start_session, get_session_state, end_session, get_screen_size, list_apps, list_windows]
deny:
  tools: [kill_app, browser_download]
ask:
  tools: []
""",
        encoding="utf-8",
    )
    spec = cua_driver_stdio_spec(
        executable=executable,
        workspace=tmp_path,
        directories=CuaDriverDirectories(
            state=tmp_path / ".sova" / "cua-driver",
            policy=policy,
        ),
    )
    with CuaDriverService.start(spec), StdioMCPClient(spec) as client:
        tool_names = {tool.name for tool in client.list_tools()}
        assert {
            "start_session",
            "get_session_state",
            "end_session",
            "get_screen_size",
            "list_apps",
            "list_windows",
        } <= tool_names
        started = client.call_tool(
            "start_session",
            {"session": "sova-live-conformance", "capture_scope": "window"},
            timeout_seconds=30,
        )
        assert not started.is_error
        screen = client.call_tool("get_screen_size", {}, timeout_seconds=30)
        assert not screen.is_error
        assert screen.structured_content is not None
        assert int(screen.structured_content["width"]) > 0
        assert int(screen.structured_content["height"]) > 0
        windows = client.call_tool("list_windows", {}, timeout_seconds=30)
        assert not windows.is_error
        assert windows.structured_content is not None
        assert isinstance(windows.structured_content.get("windows"), list)
        ended = client.call_tool(
            "end_session",
            {"session": "sova-live-conformance"},
            timeout_seconds=30,
        )
        assert not ended.is_error


def _wait_for_text(path: Path, expected: str, *, timeout_seconds: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with suppress(OSError, UnicodeError):
            if path.read_text(encoding="utf-8") == expected:
                return
        time.sleep(0.05)
    message = f"fixture file did not reach independently verified state: {path}"
    raise AssertionError(message)


def _top_windows() -> dict[int, tuple[int, str, str]]:
    powershell = (
        Path(os.environ["SYSTEMROOT"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    completed = subprocess.run(
        (
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Process | Where-Object {$_.MainWindowHandle -ne 0} | "
            "Select-Object Id,ProcessName,MainWindowHandle,MainWindowTitle | "
            "ConvertTo-Json -Compress",
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
        shell=False,
    )
    raw = json.loads(completed.stdout or "[]")
    records = raw if isinstance(raw, list) else [raw]
    return {
        int(record["MainWindowHandle"]): (
            int(record["Id"]),
            str(record.get("MainWindowTitle", "")),
            str(record.get("ProcessName", "")),
        )
        for record in records
        if isinstance(record, dict) and int(record.get("MainWindowHandle", 0)) != 0
    }


def _fixture_window(
    existing: set[int],
    pid: int,
    title_fragment: str,
    *,
    timeout_seconds: float = 15.0,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        windows = _top_windows()
        matches = [
            hwnd
            for hwnd, (owner, title, process_name) in windows.items()
            if hwnd not in existing
            and (
                owner == pid
                or title_fragment.casefold() in title.casefold()
                or process_name.casefold() == "notepad"
            )
        ]
        if len(matches) == 1:
            return matches[0]
        time.sleep(0.1)
    message = "self-owned Notepad window was not uniquely identified"
    raise AssertionError(message)


def _exact_foreground_available(hwnd: int) -> bool:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = wintypes.HWND
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        foreground = user32.GetForegroundWindow()
        if foreground is not None and int(foreground) == hwnd:
            return True
        time.sleep(0.05)
    return False


def _window_owner(hwnd: int) -> int:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    owner = wintypes.DWORD()
    user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(owner))
    return int(owner.value)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_CUA_DRIVER") != "1" or os.name != "nt",
    reason="set SOVA_RUN_CUA_DRIVER=1 on an interactive Windows desktop",
)
def test_pinned_cua_driver_mutates_only_fixture_window_and_effect_is_independently_verified(
    tmp_path: Path,
) -> None:
    executable = Path(os.environ["SOVA_CUA_DRIVER_EXECUTABLE"])
    target = tmp_path / f"sova-cua-authorized-{uuid4().hex}.txt"
    target.write_text("seed", encoding="utf-8")
    existing_windows = set(_top_windows())
    notepad = Path(os.environ["SYSTEMROOT"]) / "System32" / "notepad.exe"
    fixture = subprocess.Popen(
        (str(notepad), str(target)),
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        shell=False,
    )
    try:
        policy = tmp_path / "cua-session-policy.yaml"
        policy.write_text(
            """version: 1
mode: bounded
expires_after: 10m
idle_timeout: 2m
resources: {}
allow:
  tools: [start_session, get_session_state, end_session, bring_to_front, type_text, hotkey]
deny:
  tools: [kill_app, browser_download]
ask:
  tools: []
""",
            encoding="utf-8",
        )
        spec = cua_driver_stdio_spec(
            executable=executable,
            workspace=tmp_path,
            directories=CuaDriverDirectories(
                state=tmp_path / ".sova" / "cua-driver",
                policy=policy,
            ),
        )
        session = f"sova-fixture-{uuid4().hex}"
        hwnd = _fixture_window(existing_windows, fixture.pid, target.name)
        target_pid = _window_owner(hwnd)
        with CuaDriverService.start(spec), StdioMCPClient(spec) as client:
            started = client.call_tool(
                "start_session",
                {"session": session, "capture_scope": "desktop"},
                timeout_seconds=30,
            )
            assert not started.is_error
            fronted = client.call_tool(
                "bring_to_front",
                {"pid": target_pid, "window_id": hwnd},
                timeout_seconds=30,
            )
            assert not fronted.is_error, fronted.content
            if not _exact_foreground_available(hwnd):
                pytest.skip(
                    "the current runner exposes no independently verifiable foreground desktop"
                )
            selected = client.call_tool(
                "hotkey",
                {"keys": ["ctrl", "a"], "scope": "desktop", "session": session},
                timeout_seconds=30,
            )
            assert not selected.is_error, selected.content
            text = "sova-live-desktop-conformance"
            typed = client.call_tool(
                "type_text",
                {"text": text, "scope": "desktop", "session": session},
                timeout_seconds=30,
            )
            assert not typed.is_error, typed.content
            saved = client.call_tool(
                "hotkey",
                {"keys": ["ctrl", "s"], "scope": "desktop", "session": session},
                timeout_seconds=30,
            )
            assert not saved.is_error, saved.content
            _wait_for_text(target, text)
            ended = client.call_tool(
                "end_session",
                {"session": session},
                timeout_seconds=30,
            )
            assert not ended.is_error
    finally:
        if fixture.poll() is None:
            fixture.terminate()
            with suppress(subprocess.TimeoutExpired):
                fixture.wait(timeout=5)
        if fixture.poll() is None:
            fixture.kill()
            fixture.wait(timeout=5)
        if fixture.stderr is not None:
            fixture.stderr.close()
