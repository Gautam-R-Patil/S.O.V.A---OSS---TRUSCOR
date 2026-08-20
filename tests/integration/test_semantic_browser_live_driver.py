# SPDX-License-Identifier: Apache-2.0
"""Semantic planner to authorized Playwright trace integration tests."""

from __future__ import annotations

import base64
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import (
    SemanticBrowserMission,
    owned_web_target,
    run_live_semantic_browser_workflow,
)
from sova.mcp import MCPTool, MCPToolResult
from sova.models import ScriptedModel, ScriptedTurn
from sova.replay import render_capsule_timeline
from sova.runtime import ModelRouter, RoleKind
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Mapping


def _ebml(identifier: bytes, payload: bytes) -> bytes:
    size = len(payload)
    if size < 0x7F:
        encoded_size = bytes((0x80 | size,))
    elif size < 0x3FFF:
        encoded_size = bytes((0x40 | (size >> 8), size & 0xFF))
    else:  # pragma: no cover - fixed tiny fixture
        raise AssertionError
    return identifier + encoded_size + payload


def _bounded_synthetic_webm() -> bytes:
    info = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big")) + _ebml(
        b"\x44\x89", struct.pack(">d", 12_000.0)
    )
    segment = b"".join(
        (
            _ebml(b"\x15\x49\xa9\x66", info),
            _ebml(b"\x16\x54\xae\x6b", b"\xae\x80"),
            _ebml(b"\x1f\x43\xb6\x75", b"\xe7\x81\x00"),
        )
    )
    return _ebml(b"\x1a\x45\xdf\xa3", b"") + _ebml(b"\x18\x53\x80\x67", segment)


class _SemanticBrowserMCP:
    """Deterministic protocol double for the signed semantic-browser path."""

    server_name = "semantic-browser-mcp"

    def __init__(self, spec: object) -> None:
        names = (
            "browser_navigate",
            "browser_snapshot",
            "browser_type",
            "browser_click",
            "browser_start_video",
            "browser_stop_video",
            "browser_video_chapter",
            "browser_video_show_actions",
        )
        self._tools = tuple(MCPTool(name, name, {"type": "object"}, None, {}) for name in names)
        argv = getattr(spec, "argv", ())
        self.output = Path(argv[argv.index("--output-dir") + 1])
        self.origin = str(argv[argv.index("--allowed-origins") + 1]).split(";", 1)[0]
        self.page = "home"
        self.document = ""
        self.message = ""
        self.armed = False
        self.triggered = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def list_tools(self) -> tuple[MCPTool, ...]:
        return self._tools

    def _snapshot(self) -> str:
        if self.page == "knowledge-base":
            body = (
                '- textbox "Document" [ref=f2]\n'
                '- button "Save document" [ref=f3]\n'
                '- link "Challenges" [ref=f4]'
            )
            path = "/knowledge-base"
            title = "Knowledge Base"
        elif self.page == "challenge":
            marker = "\n- status: SOVA_WORKFLOW_TRIGGERED" if self.triggered else ""
            body = '- textbox "Message" [ref=f5]\n- button "Send" [ref=f6]' + marker
            path = "/challenge"
            title = "Challenge"
        else:
            body = '- link "Knowledge Base" [ref=f1]'
            path = "/"
            title = "Owned fixture"
        return (
            f"### Page\n- Page URL: {self.origin}{path}\n"
            f"- Page Title: {title}\n### Snapshot\n{body}"
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
            self.page = "home"
            self.document = ""
            self.message = ""
            self.armed = False
            self.triggered = False
        elif name == "browser_click":
            target = arguments.get("target")
            if target == "f1":
                self.page = "knowledge-base"
            elif target == "f3":
                self.armed = self.document == "blue owl"
            elif target == "f4":
                self.page = "challenge"
            elif target == "f6":
                self.triggered = self.armed and self.message == "blue owl"
        elif name == "browser_type":
            if arguments.get("target") == "f2":
                self.document = str(arguments.get("text", "")).casefold()
            elif arguments.get("target") == "f5":
                self.message = str(arguments.get("text", "")).casefold()
        elif name == "browser_stop_video":
            self.output.mkdir(parents=True, exist_ok=True)
            (self.output / "sova-browser-session.webm").write_bytes(_bounded_synthetic_webm())
        content: tuple[dict[str, Any], ...] = (
            (
                {
                    "type": "image",
                    "data": base64.b64encode(b"fixture pixels").decode(),
                    "mimeType": "image/png",
                },
            )
            if name == "browser_take_screenshot"
            else ({"type": "text", "text": self._snapshot()},)
        )
        return MCPToolResult(content, None, is_error=False)

    def close(self) -> None:
        return


def _mission(origin: str) -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova:semantic-mission:integration",
        title="Autonomous multi-page workflow",
        entry_url=origin + "/",
        objective="Create owned test state, return to the challenge, and expose the marker.",
        allowed_actions=("browser.click", "browser.type"),
        seed_inputs=("blue owl",),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA_WORKFLOW_TRIGGERED",
        max_planner_turns=4,
        max_actions=6,
        max_actions_per_plan=3,
        max_duration_seconds=120,
        max_pages=4,
        max_mutations=6,
        max_consecutive_failures=2,
        max_generated_text_characters=128,
        max_total_tokens=10,
        offensive=True,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def _router() -> ModelRouter:
    return ModelRouter(
        {
            RoleKind.EXPLORER: (
                ScriptedModel(
                    [
                        ScriptedTurn(
                            '"turn":1',
                            "",
                            {
                                "status": "continue",
                                "actions": [
                                    {
                                        "action": "browser.click",
                                        "arguments": {
                                            "element": "Knowledge Base",
                                            "ref": "f1",
                                        },
                                    }
                                ],
                                "coverage": ["home navigation"],
                                "reason": "Open the visible knowledge base workflow.",
                            },
                            token_count=1,
                        ),
                        ScriptedTurn(
                            '"turn":2',
                            "",
                            {
                                "status": "continue",
                                "actions": [
                                    {
                                        "action": "browser.type",
                                        "arguments": {
                                            "element": "Document",
                                            "ref": "f2",
                                            "text": "blue owl",
                                        },
                                    },
                                    {
                                        "action": "browser.click",
                                        "arguments": {
                                            "element": "Save document",
                                            "ref": "f3",
                                        },
                                    },
                                ],
                                "coverage": ["knowledge base mutation"],
                                "reason": "Create the state and observe the saved result.",
                            },
                            token_count=1,
                        ),
                        ScriptedTurn(
                            '"turn":3',
                            "",
                            {
                                "status": "continue",
                                "actions": [
                                    {
                                        "action": "browser.click",
                                        "arguments": {"element": "Challenges", "ref": "f4"},
                                    }
                                ],
                                "coverage": ["page transition"],
                                "reason": "Return to the challenge from the saved state.",
                            },
                            token_count=1,
                        ),
                        ScriptedTurn(
                            '"turn":4',
                            "",
                            {
                                "status": "continue",
                                "actions": [
                                    {
                                        "action": "browser.type",
                                        "arguments": {
                                            "element": "Message",
                                            "ref": "f5",
                                            "text": "blue owl",
                                        },
                                    },
                                    {
                                        "action": "browser.click",
                                        "arguments": {"element": "Send", "ref": "f6"},
                                    },
                                ],
                                "coverage": ["challenge submission"],
                                "reason": "Exercise the challenge with the created state.",
                            },
                            token_count=1,
                        ),
                    ]
                ),
            )
        }
    )


def _assert_complete_trace_history(
    artifacts: Any,
    report: Mapping[str, Any],
    decisive_replay: Path,
) -> None:
    reader = PackageReader(artifacts.discovery_capsule)
    descriptors = reader.verify("sova.capsule")
    trace_descriptors = [item for item in descriptors if item.role == "trace"]
    assert len(trace_descriptors) == 2
    assert report["execution"]["traceFiles"] == [
        "start.sova-trace",
        "turn-001.sova-trace",
        "turn-002.sova-trace",
        "turn-003.sova-trace",
        "turn-004.sova-trace",
        "reproduction.sova-trace",
    ]
    assert {item.path for item in trace_descriptors} == {
        "traces/turn-004.sova-trace",
        "traces/reproduction.sova-trace",
    }
    exploratory_blob_paths = {
        f"blobs/sha256/{digest[7:]}" for digest in report["execution"]["traceDigests"][:4]
    }
    assert exploratory_blob_paths <= {item.path for item in descriptors}
    history_documents = []
    for descriptor in descriptors:
        if descriptor.role != "attachment" or descriptor.mediaType != "application/json":
            continue
        value = strict_json_loads(reader.read_object(descriptor))
        if isinstance(value, dict) and value.get("artifactType") == (
            "sova.semantic-browser-trace-history"
        ):
            history_documents.append(value)
    assert len(history_documents) == 1
    assert [item["file"] for item in history_documents[0]["traces"]] == report["execution"][
        "traceFiles"
    ]
    assert [item["role"] for item in history_documents[0]["traces"]] == [
        "exploration",
        "exploration",
        "exploration",
        "exploration",
        "decisive-discovery",
        "decisive-reproduction",
    ]
    assert len([item for item in descriptors if item.role == "visual-replay"]) == 1
    replay = render_capsule_timeline(artifacts.discovery_capsule, decisive_replay)
    assert replay["opensAtDecisiveMoment"] is True


@pytest.mark.integration
def test_semantic_browser_executes_multi_page_plan_reproduces_and_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "http://127.0.0.1:9187"
    runner = tmp_path / "npx.exe"
    browser = tmp_path / "browser.exe"
    runner.write_bytes(b"deterministic test placeholder")
    browser.write_bytes(b"deterministic test placeholder")
    monkeypatch.setattr("sova.live.semantic_browser_driver.StdioMCPClient", _SemanticBrowserMCP)
    approvals: list[str] = []

    def approve(challenge: Any, _intents: Any) -> str:
        approvals.append(challenge.id)
        return str(challenge.exact_phrase)

    artifacts = run_live_semantic_browser_workflow(
        owned_web_target(origin),
        _mission(origin),
        tmp_path / "semantic-result",
        router=_router(),
        package_runner=runner,
        browser_executable=browser,
        approval_prompt=approve,
        record_video=True,
    )

    assert artifacts.status == "pass"
    assert len(approvals) == 6  # start, four generated batches, fresh reproduction
    assert artifacts.discovery_capsule is not None
    assert artifacts.reproduction_trace is not None
    assert artifacts.replay_cues is not None
    assert len(artifacts.visual_replays) == 1
    assert all(
        TraceReader(path).verify(require_signature=True).signature_valid
        for path in artifacts.traces
    )
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["status"] == "pass"
    assert report["stopReason"] == "confirmed-and-reproduced"
    assert report["evidence"]["reproductionEquivalent"] is True
    assert report["claims"]["autonomousWithinDeclaredActionPolicy"] is True
    assert report["claims"]["allowedOriginRequestFiltering"] is True
    assert report["claims"]["postActionOriginDriftDetection"] is True
    assert report["claims"]["networkEgressSandbox"] is False
    assert "sameOriginConfined" not in report["claims"]
    assert report["claims"]["arbitraryUnreviewedToolUse"] is False
    decisive_replay = tmp_path / "semantic-result" / "decisive-replay.html"
    _assert_complete_trace_history(artifacts, report, decisive_replay)
    rendered = decisive_replay.read_text(encoding="utf-8")
    assert "Play decisive moment" in rendered
    assert "decisive-02" in rendered


@pytest.mark.integration
def test_semantic_browser_fails_before_executor_for_mission_scope_drift(
    tmp_path: Path,
) -> None:
    runner = tmp_path / "npx.exe"
    browser = tmp_path / "browser.exe"
    runner.write_bytes(b"placeholder")
    browser.write_bytes(b"placeholder")
    with pytest.raises(FormatError, match="outside the target"):
        run_live_semantic_browser_workflow(
            owned_web_target("http://127.0.0.1:9187"),
            _mission("http://127.0.0.1:9188"),
            tmp_path / "scope-drift",
            router=_router(),
            package_runner=runner,
            browser_executable=browser,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        )
