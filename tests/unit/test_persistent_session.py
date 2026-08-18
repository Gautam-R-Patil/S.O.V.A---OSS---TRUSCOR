# SPDX-License-Identifier: Apache-2.0
"""Deterministic persistent browser-session workflow contracts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.live.persistent_session as session_module
from sova.formats.errors import FormatError
from sova.live import (
    owned_web_target,
    run_browser_profile_handoff,
    run_owned_persistent_session_restart_probe,
)
from sova.mcp import MCPTool, MCPToolResult, StdioMCPClient
from sova.runtime import BrowserProfileVault

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class _Client:
    server_name = "microsoft-playwright-mcp"

    def __init__(self, process_id: int, marker: str, *, fail_call: int | None = None) -> None:
        self.process_id = process_id
        self._marker = marker
        self._fail_call = fail_call
        self._calls = 0
        self._url = "http://127.0.0.1/"
        self.closed = False

    def list_tools(self) -> tuple[MCPTool, ...]:
        return tuple(
            MCPTool(name, name, {"type": "object"}, None, {})
            for name in ("browser_close", "browser_navigate", "browser_snapshot")
        )

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult:
        assert name in {"browser_close", "browser_navigate", "browser_snapshot"}
        assert timeout_seconds in {10.0, 20, 30}
        self._calls += 1
        if "url" in arguments:
            self._url = str(arguments["url"])
        url = self._url
        text = f"- Page URL: {url}\n{self._marker if self._calls == 3 else 'VISIBLE'}"
        return MCPToolResult(
            ({"type": "text", "text": text},),
            None,
            is_error=self._calls == self._fail_call,
        )

    def close(self) -> None:
        self.closed = True


def test_persistent_session_probe_is_two_process_signed_and_profile_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = tmp_path / "npx"
    browser = tmp_path / "chrome"
    runner.write_bytes(b"fixture")
    browser.write_bytes(b"fixture")
    clients = iter(
        (
            _Client(101, "SOVA_SESSION_MARKER_SET"),
            _Client(202, "SOVA_SESSION_PRESENT"),
        )
    )
    monkeypatch.setattr(
        "sova.live.persistent_session.start_stdio_client",
        lambda _spec, _factory: next(clients),
    )
    artifacts = run_owned_persistent_session_restart_probe(
        tmp_path / "result",
        package_runner=runner,
        browser_executable=browser,
    )
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert artifacts.status == "pass"
    assert report["restart"]["distinctMcpProcesses"] is True
    assert report["integrity"]["signedTraceValid"] is True
    assert report["privacy"]["profilePathIncluded"] is False
    assert report["claims"]["arbitraryProviderLoginVerified"] is False
    rendered = artifacts.report.read_text(encoding="utf-8")
    assert "sova_owned_session=active" not in rendered
    assert str(tmp_path.resolve()) not in rendered
    assert artifacts.to_mapping()["status"] == "pass"


def test_persistent_session_probe_refuses_nonempty_destination(tmp_path: Path) -> None:
    destination = tmp_path / "result"
    destination.mkdir()
    (destination / "occupied").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="not empty"):
        run_owned_persistent_session_restart_probe(
            destination,
            package_runner=tmp_path / "npx",
            browser_executable=tmp_path / "chrome",
        )


def test_browser_profile_handoff_is_manual_signed_and_content_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = tmp_path / "npx"
    browser = tmp_path / "chrome"
    runner.write_bytes(b"fixture")
    browser.write_bytes(b"fixture")
    target = owned_web_target("http://127.0.0.1:9187")
    vault = BrowserProfileVault(tmp_path / "profiles")
    record = vault.create(identity_id="operator", target=target.digest)
    monkeypatch.setattr(
        "sova.live.persistent_session.start_stdio_client",
        lambda _spec, _factory: _Client(303, "SENSITIVE PAGE TEXT"),
    )
    prompts: list[str] = []

    def approve(phrase: str, summary: str) -> str:
        prompts.append(summary)
        return phrase

    with vault.acquire(record.handle, owner_id="handoff") as lease:
        artifacts = run_browser_profile_handoff(
            target,
            "http://127.0.0.1:9187/login",
            tmp_path / "handoff",
            profile_lease=lease,
            package_runner=runner,
            browser_executable=browser,
            handoff_prompt=approve,
        )
        report = json.loads(artifacts.report.read_text(encoding="utf-8"))
        rendered = artifacts.report.read_text(encoding="utf-8")
        assert artifacts.status == "pass"
        assert artifacts.to_mapping()["status"] == "pass"
        assert len(prompts) == 2
        assert report["privacy"]["credentialsCaptured"] is False
        assert report["claims"]["authenticatedStateIndependentlyVerified"] is False
        assert "SENSITIVE PAGE TEXT" not in rendered
        assert record.handle not in rendered
        assert str(lease.path_for_executor()) not in rendered

    second = vault.create(identity_id="operator", target=target.digest)
    with (
        vault.acquire(second.handle, owner_id="denied") as lease,
        pytest.raises(FormatError, match="authorization phrase"),
    ):
        run_browser_profile_handoff(
            target,
            "http://127.0.0.1:9187/login",
            tmp_path / "denied-handoff",
            profile_lease=lease,
            package_runner=runner,
            browser_executable=browser,
            handoff_prompt=lambda _phrase, _summary: "DENY",
        )


def test_persistent_session_failure_paths_are_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert session_module._text({"text": "not-a-list"}) == ""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    origin = "http://127.0.0.1:9187"
    with pytest.raises(FormatError, match="navigation did not succeed"):
        session_module._execute_navigation(
            cast("StdioMCPClient", _Client(1, "x", fail_call=1)),
            origin=origin,
            url=origin + "/",
            workspace=workspace,
            request_id="failed-nav",
        )
    with pytest.raises(FormatError, match="snapshot did not succeed"):
        session_module._execute_navigation(
            cast("StdioMCPClient", _Client(2, "x", fail_call=3)),
            origin=origin,
            url=origin + "/",
            workspace=workspace,
            request_id="failed-snapshot",
        )
    runner = tmp_path / "npx"
    browser = tmp_path / "chrome"
    runner.write_bytes(b"fixture")
    browser.write_bytes(b"fixture")
    target = owned_web_target(origin)
    vault = BrowserProfileVault(tmp_path / "profiles")
    record = vault.create(identity_id="operator", target=target.digest)
    with vault.acquire(record.handle, owner_id="errors") as lease:
        with pytest.raises(FormatError, match="outside"):
            run_browser_profile_handoff(
                target,
                "https://outside.example/login",
                tmp_path / "outside",
                profile_lease=lease,
                package_runner=runner,
                browser_executable=browser,
                handoff_prompt=lambda phrase, _summary: phrase,
            )
        occupied = tmp_path / "occupied"
        occupied.mkdir()
        (occupied / "x").write_text("x", encoding="utf-8")
        with pytest.raises(FormatError, match="not empty"):
            run_browser_profile_handoff(
                target,
                origin + "/login",
                occupied,
                profile_lease=lease,
                package_runner=runner,
                browser_executable=browser,
                handoff_prompt=lambda phrase, _summary: phrase,
            )

        monkeypatch.setattr(
            session_module,
            "start_stdio_client",
            lambda _spec, _factory: _Client(4, "x"),
        )
        confirmations = iter((True, False))

        def incomplete(phrase: str, _summary: str) -> str:
            return phrase if next(confirmations) else "INCOMPLETE"

        with pytest.raises(FormatError, match="did not confirm"):
            run_browser_profile_handoff(
                target,
                origin + "/login",
                tmp_path / "incomplete",
                profile_lease=lease,
                package_runner=runner,
                browser_executable=browser,
                handoff_prompt=incomplete,
            )
        monkeypatch.setattr(
            session_module,
            "start_stdio_client",
            lambda _spec, _factory: _Client(5, "x", fail_call=1),
        )
        with pytest.raises(FormatError, match="navigation did not succeed"):
            run_browser_profile_handoff(
                target,
                origin + "/login",
                tmp_path / "navigation-failure",
                profile_lease=lease,
                package_runner=runner,
                browser_executable=browser,
                handoff_prompt=lambda phrase, _summary: phrase,
            )
        monkeypatch.setattr(
            session_module,
            "start_stdio_client",
            lambda _spec, _factory: _Client(6, "x", fail_call=3),
        )
        with pytest.raises(FormatError, match="snapshot did not succeed"):
            run_browser_profile_handoff(
                target,
                origin + "/login",
                tmp_path / "snapshot-failure",
                profile_lease=lease,
                package_runner=runner,
                browser_executable=browser,
                handoff_prompt=lambda phrase, _summary: phrase,
            )

    monkeypatch.setattr(
        session_module,
        "start_stdio_client",
        lambda _spec, _factory: _Client(7, "WRONG PRIME MARKER"),
    )
    with pytest.raises(FormatError, match="session priming"):
        run_owned_persistent_session_restart_probe(
            tmp_path / "prime-failure",
            package_runner=runner,
            browser_executable=browser,
        )
