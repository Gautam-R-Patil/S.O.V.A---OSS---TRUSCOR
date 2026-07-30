# SPDX-License-Identifier: Apache-2.0
"""Deterministic tests for the optional official Codex JSONL adapter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.adapters.codex_exec import CodexExecAdapter, CommandResult
from sova.formats.errors import FormatError
from sova.trace import TraceReader, TraceWriter

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "codex-fixture"
    directory.mkdir()
    (directory / ".sova-codex-fixture").write_text("synthetic\n", encoding="utf-8")
    schema = directory / "output.schema.json"
    schema.write_text(
        json.dumps(
            {
                "type": "object",
                "properties": {"label": {"type": "string"}},
                "required": ["label"],
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )
    return directory, schema


def test_adapter_uses_only_bounded_official_flags_and_maps_jsonl(tmp_path: Path) -> None:
    fixture, schema = _fixture(tmp_path)
    calls: list[list[str]] = []

    def runner(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del cwd, environment, timeout_seconds
        calls.append(list(argv))
        if argv[1:3] == ["login", "status"]:
            return CommandResult(0, b"Logged in using ChatGPT\n", b"")
        stream = b"\n".join(
            [
                b'{"type":"thread.started","thread_id":"fixture"}',
                b'{"type":"turn.started"}',
                (
                    b'{"type":"item.completed","item":{"id":"1",'
                    b'"type":"agent_message","text":"{\\"label\\":\\"SAFE\\"}"}}'
                ),
                b'{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":2}}',
            ]
        )
        return CommandResult(0, stream + b"\n", b"")

    trace = tmp_path / "codex.sova-trace"
    writer = TraceWriter(trace)
    adapter = CodexExecAdapter(executable="codex", runner=runner)
    result = adapter.capture(
        prompt="Return the fixture label only.",
        fixture_directory=fixture,
        output_schema=schema,
        trace_writer=writer,
    )
    writer.finalize()

    assert result.status == "completed"
    command = calls[1]
    assert command[:2] == ["codex", "exec"]
    assert "--ephemeral" in command
    assert command[command.index("--sandbox") + 1] == "read-only"
    assert "--json" in command
    assert "--output-schema" in command
    assert {event["kind"] for event in TraceReader(trace).events()} >= {
        "run.external-started",
        "model.response",
    }


def test_unavailable_login_is_a_visible_optional_result(tmp_path: Path) -> None:
    fixture, _schema = _fixture(tmp_path)

    def runner(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del argv, cwd, environment, timeout_seconds
        return CommandResult(1, b"", b"not authenticated")

    result = CodexExecAdapter(executable="codex", runner=runner).preflight(fixture)
    assert result.status == "unavailable"
    assert result.returncode == 1


def test_adapter_refuses_project_or_unmarked_directories(tmp_path: Path) -> None:
    writer = TraceWriter(tmp_path / "never-finalized.sova-trace")
    adapter = CodexExecAdapter(executable="codex")
    with pytest.raises(FormatError) as error:
        adapter.capture(
            prompt="do nothing",
            fixture_directory=tmp_path,
            output_schema=tmp_path / "missing.json",
            trace_writer=writer,
        )
    assert error.value.issue.code == "SOVA-CODEX-UNSAFE-FIXTURE"
    writer.finalize(completion="cancelled")
