# SPDX-License-Identifier: Apache-2.0
"""Consequential-action coordinator integration with real local effects."""

from __future__ import annotations

import base64
import json
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.live import run_owned_action_lab_vertical_slice
from sova.mcp import MCPTool, MCPToolResult
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Mapping


class _ActionLabBrowserMCP:
    """Protocol-compatible browser that drives the real loopback action target."""

    server_name = "deterministic-action-lab-browser"

    def __init__(self, spec: object) -> None:
        names = (
            "browser_navigate",
            "browser_snapshot",
            "browser_wait_for",
            "browser_type",
            "browser_click",
            "browser_take_screenshot",
            "browser_console_messages",
            "browser_network_requests",
            "browser_start_video",
            "browser_stop_video",
            "browser_video_chapter",
            "browser_video_show_actions",
        )
        self._tools = tuple(MCPTool(name, name, {"type": "object"}, None, {}) for name in names)
        argv = getattr(spec, "argv", ())
        self.output = Path(argv[argv.index("--output-dir") + 1])
        self.origin = str(argv[argv.index("--allowed-origins") + 1]).split(";", 1)[0]
        self.current_url = "about:blank"
        self.current_text = ""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def list_tools(self) -> tuple[MCPTool, ...]:
        return self._tools

    def _get(self, url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - owned loopback
            assert response.status == 200
            return bytes(response.read())

    def _post_instruction(self) -> None:
        request = urllib.request.Request(  # noqa: S310 - owned loopback
            self.origin + "/api/agent",
            data=json.dumps({"instruction": self.current_text}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - loopback
            assert response.status == 200
            response.read()
        self.current_text = ""

    def _snapshot(self) -> str:
        state = strict_json_loads(self._get(self.origin + "/api/state"))
        status = state.get("status", "NOT_STARTED") if isinstance(state, dict) else "INVALID"
        effects = sorted(state.get("effects", {})) if isinstance(state, dict) else []
        return (
            f"### Page\n- Page URL: {self.current_url}\n### Snapshot\n"
            f"- status: {status}\n- effects: {','.join(effects)}"
        )

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult:
        assert timeout_seconds > 0
        if name == "browser_navigate":
            self.current_url = str(arguments["url"])
            self._get(self.current_url)
        elif name == "browser_type":
            self.current_text = str(arguments["text"])
        elif name == "browser_click":
            target = arguments.get("target")
            if target == "#send":
                self._post_instruction()
            elif target == "#open-proof":
                self.current_url = self.origin + "/proof"
                self._get(self.current_url)
        elif name == "browser_stop_video":
            self.output.mkdir(parents=True, exist_ok=True)
            (self.output / "sova-browser-session.webm").write_bytes(
                b"\x1a\x45\xdf\xa3sova-action-lab-webm"
            )
        content: tuple[dict[str, Any], ...] = (
            (
                {
                    "type": "image",
                    "data": base64.b64encode(b"contained action pixels").decode(),
                    "mimeType": "image/png",
                },
            )
            if name == "browser_take_screenshot"
            else ({"type": "text", "text": self._snapshot()},)
        )
        return MCPToolResult(content, None, is_error=False)

    def close(self) -> None:
        return


@pytest.mark.integration
def test_action_lab_packages_signed_real_effects_replay_and_registry_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = tmp_path / "npx.exe"
    browser = tmp_path / "browser.exe"
    runner.write_bytes(b"fixture")
    browser.write_bytes(b"fixture")
    monkeypatch.setattr("sova.live.browser.StdioMCPClient", _ActionLabBrowserMCP)

    artifacts = run_owned_action_lab_vertical_slice(
        tmp_path / "result",
        package_runner=runner,
        browser_executable=browser,
        approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        record_video=True,
    )

    assert artifacts.status == "pass"
    mapping = artifacts.to_mapping()
    assert mapping["status"] == "pass"
    assert mapping["visualReplays"] == [str(path) for path in artifacts.browser.visual_replays]
    effects = strict_json_loads(artifacts.effects_receipt.read_bytes())
    assert isinstance(effects, dict)
    assert effects["status"] == "pass"
    assert effects["checks"] == {
        "allEffectFamiliesObserved": True,
        "exactlyTwoRuns": True,
        "primaryAndReproductionEquivalent": True,
        "signedBrowserTraces": True,
    }
    assert len(effects["runs"]) == 2
    assert TraceReader(artifacts.browser.trace).verify(require_signature=True).signature_valid
    assert (
        TraceReader(artifacts.browser.reproduction_trace)
        .verify(require_signature=True)
        .signature_valid
    )
    assert PackageReader(artifacts.evidence_capsule).verify("sova.capsule")
    assert (
        PackageReader(artifacts.evidence_capsule).manifest("sova.capsule")["safety"]["impact"]
        == "low"
    )
    assert verify_artifact(artifacts.evidence_capsule).state == VerificationState.VERIFIED
    assert "<video" in artifacts.replay.read_text(encoding="utf-8")
    entry = strict_json_loads(artifacts.registry_entry.read_bytes())
    assert isinstance(entry, dict)
    assert entry["id"] == "sova:module:contained-consequential-actions"
    assert entry["verificationTier"] == "schema-and-safety-validated"
    registry_verification = strict_json_loads(artifacts.registry_verification.read_bytes())
    assert isinstance(registry_verification, dict)
    assert registry_verification["accepted"] is True
    assert registry_verification["identityTrusted"] is True
    assert (
        artifacts.registry_snapshot / str(entry["objectPath"])
    ).read_bytes() == artifacts.evidence_capsule.read_bytes()
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["registryReady"] is True
    assert report["claims"]["metasploitEquivalentClaimed"] is False
