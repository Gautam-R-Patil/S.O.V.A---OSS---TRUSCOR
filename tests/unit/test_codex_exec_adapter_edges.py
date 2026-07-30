# SPDX-License-Identifier: Apache-2.0
"""Budget, failure, and event-mapping branches for CodexExecAdapter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.adapters.codex_exec import (
    CodexExecAdapter,
    CommandResult,
    _map_codex_event,
)
from sova.formats.errors import FormatError
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / ".sova-codex-fixture").write_text("synthetic\n", encoding="utf-8")
    schema = fixture / "schema.json"
    schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    return fixture, schema


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ({"type": "thread.started"}, "run.external-started"),
        ({"type": "turn.started"}, "phase.started"),
        ({"type": "turn.completed"}, "run.external-completed"),
        ({"type": "turn.failed"}, "error.external"),
        ({"type": "error"}, "error.external"),
        ({"type": "item.completed", "item": {"type": "reasoning"}}, "model.reasoning-summary"),
        ({"type": "item.completed", "item": {"type": "command_execution"}}, "tool.command"),
        ({"type": "item.completed", "item": {"type": "file_change"}}, "filesystem.change"),
        ({"type": "item.completed", "item": {"type": "mcp_tool_call"}}, "mcp.tool-call"),
        ({"type": "item.completed", "item": {"type": "web_search"}}, "retrieval.web-search"),
        ({"type": "item.completed", "item": {"type": "plan_update"}}, "actor.plan-update"),
        ({"type": "item.completed", "item": {"type": "other"}}, "x.codex.item"),
        ({"type": "future.event"}, "x.codex.event"),
    ],
)
def test_all_documented_and_unknown_jsonl_events_map(
    item: dict[str, object],
    expected: str,
) -> None:
    assert _map_codex_event(item)[0] == expected


def test_no_executable_and_runner_exception_are_visible(tmp_path: Path) -> None:
    fixture, _schema = _fixture(tmp_path)
    assert CodexExecAdapter(executable=None).preflight(fixture).status in {
        "authenticated",
        "unavailable",
    }

    def runner(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del argv, cwd, environment, timeout_seconds
        raise OSError("denied")

    result = CodexExecAdapter(executable="codex", runner=runner).preflight(fixture)
    assert result.status == "unavailable"
    assert "denied" in str(result.reason)


def test_prompt_output_schema_and_output_budgets_fail_closed(tmp_path: Path) -> None:
    fixture, schema = _fixture(tmp_path)

    def runner(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del cwd, environment, timeout_seconds
        if argv[1] == "login":
            return CommandResult(0, b"ok", b"")
        return CommandResult(0, b"{}\n" * 100, b"")

    adapter = CodexExecAdapter(executable="codex", runner=runner, max_output_bytes=10)
    writer = TraceWriter(tmp_path / "budget.sova-trace")
    with pytest.raises(FormatError) as prompt:
        adapter.capture(
            prompt="x" * (33 * 1024),
            fixture_directory=fixture,
            output_schema=schema,
            trace_writer=writer,
        )
    assert prompt.value.issue.code == "SOVA-CODEX-PROMPT-LIMIT"
    with pytest.raises(FormatError) as output:
        adapter.capture(
            prompt="small",
            fixture_directory=fixture,
            output_schema=schema,
            trace_writer=writer,
        )
    assert output.value.issue.code == "SOVA-CODEX-OUTPUT-LIMIT"
    writer.finalize(completion="cancelled")

    marked = tmp_path / "marked"
    marked.mkdir()
    (marked / ".sova-codex-fixture").write_text("synthetic\n", encoding="utf-8")
    with pytest.raises(FormatError) as outside:
        adapter._validate_child(schema, marked)
    assert outside.value.issue.code == "SOVA-CODEX-SCHEMA-PATH"
    with pytest.raises(FormatError) as missing:
        adapter._validate_child(marked / "missing.json", marked)
    assert missing.value.issue.code == "SOVA-CODEX-SCHEMA-PATH"


def test_nonzero_codex_result_is_recorded_as_optional_failure(tmp_path: Path) -> None:
    fixture, schema = _fixture(tmp_path)

    def runner(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del cwd, environment, timeout_seconds
        if argv[1] == "login":
            return CommandResult(0, b"ok", b"")
        return CommandResult(7, b'{"type":"error","message":"rate limit"}\n', b"rate limit")

    writer = TraceWriter(tmp_path / "failed.sova-trace")
    result = CodexExecAdapter(executable="codex", runner=runner).capture(
        prompt="safe fixture",
        fixture_directory=fixture,
        output_schema=schema,
        trace_writer=writer,
    )
    writer.finalize(completion="failed")
    assert result.status == "failed"
    assert result.returncode == 7


def test_fixture_path_with_private_component_is_rejected(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    fixture = tmp_path / "private" / "fixture"
    fixture.mkdir(parents=True)
    (fixture / ".sova-codex-fixture").write_text("synthetic\n", encoding="utf-8")
    with pytest.raises(FormatError) as error:
        CodexExecAdapter._validate_fixture_directory(fixture)
    assert error.value.issue.code == "SOVA-CODEX-UNSAFE-FIXTURE"
