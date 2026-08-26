# SPDX-License-Identifier: Apache-2.0
"""Strict configuration tests for built-in Executor Engine runtime surfaces."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import pytest

import sova.community.executor_engine_runtime_config as config_module
from sova.community.executor_engine import EngineSurfaceGeneration
from sova.community.executor_engine_runtime_config import (
    ExecutorEngineRuntimeSurfaceBuilder,
    ParsedExecutorEngineRuntimeConfig,
    WorkspaceRuntimeSurfaceConfig,
    build_executor_engine_runtime_surfaces,
    parse_executor_engine_runtime_document,
)
from sova.community.executor_surfaces import ExactProcessSurfaceSpec
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.community.executor_chamber import ChamberObservation


def _process(
    identifier: str,
    executable: Path,
    *,
    prefix: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "executable": str(executable),
        "argvPrefix": [] if prefix is None else prefix,
        "maxArgs": 16,
        "maxArgBytes": 16 * 1024,
        "maxOutputBytes": 1024 * 1024,
        "trustedHostProcessAcknowledged": True,
    }


def _document(
    *,
    workspace: bool = True,
    processes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-engine-runtime",
        "schemaVersion": "0.1.0",
        "workspace": {
            "enabled": workspace,
            "maxReadBytes": 8192,
            "maxWriteBytes": 4096,
        },
        "hostProcesses": [] if processes is None else processes,
    }


def _observation() -> ChamberObservation:
    return object()  # type: ignore[return-value]


def test_workspace_only_document_parses_to_frozen_exact_config() -> None:
    document = _document()
    config = parse_executor_engine_runtime_document(document)

    assert isinstance(config, ParsedExecutorEngineRuntimeConfig)
    assert config.document_digest.startswith("sha256:")
    assert config.workspace == WorkspaceRuntimeSurfaceConfig(
        enabled=True,
        max_read_bytes=8192,
        max_write_bytes=4096,
    )
    assert config.host_processes == ()
    assert config.codec_ids == ("sova.action-codec.workspace/0.1.0",)
    document["workspace"]["maxReadBytes"] = 1
    assert config.workspace.max_read_bytes == 8192
    with pytest.raises(FrozenInstanceError):
        config.workspace.enabled = False  # type: ignore[misc]


def test_process_document_materializes_exact_acknowledged_spec_after_admission() -> None:
    executable = Path(sys.executable).resolve()
    config = parse_executor_engine_runtime_document(
        _document(workspace=False, processes=[_process("python", executable, prefix=["-I"])])
    )

    assert len(config.host_processes) == 1
    spec = config.host_processes[0]
    assert type(spec) is ExactProcessSurfaceSpec
    assert spec.identifier == "python"
    assert spec.executable == executable
    assert spec.argv_prefix == ("-I",)
    assert spec.trusted_host_process_acknowledged is True
    assert config.codec_ids == ("sova.action-codec.process.python/0.1.0",)


@pytest.mark.parametrize("mutation", ["later-fields", "later-duplicate", "later-secret"])
def test_invalid_later_rows_reject_before_any_spec_or_executable_touch(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = (tmp_path / "missing-first.exe").absolute()
    first = _process("first", missing)
    second = _process("second", missing)
    if mutation == "later-fields":
        second["unexpected"] = True
    elif mutation == "later-duplicate":
        second["id"] = "first"
    else:
        second["argvPrefix"] = ["Bearer abcdefghijklmnopqrstuvwxyz"]
    calls = {"spec": 0, "link": 0}

    def spec(*_args: object, **_kwargs: object) -> NoReturn:
        calls["spec"] += 1
        raise AssertionError

    def link(_path: Path) -> bool:
        calls["link"] += 1
        raise AssertionError

    monkeypatch.setattr(config_module, "ExactProcessSurfaceSpec", spec)
    monkeypatch.setattr(config_module, "_path_is_link", link)
    with pytest.raises(FormatError):
        parse_executor_engine_runtime_document(
            _document(workspace=False, processes=[first, second])
        )
    assert calls == {"spec": 0, "link": 0}


def test_invalid_workspace_rejects_before_process_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document(
        workspace=True,
        processes=[_process("missing", (tmp_path / "missing.exe").absolute())],
    )
    document["workspace"]["maxWriteBytes"] = 0
    calls = {"spec": 0, "link": 0}

    def spec(*_args: object, **_kwargs: object) -> NoReturn:
        calls["spec"] += 1
        raise AssertionError

    def link(_path: Path) -> bool:
        calls["link"] += 1
        raise AssertionError

    monkeypatch.setattr(config_module, "ExactProcessSurfaceSpec", spec)
    monkeypatch.setattr(config_module, "_path_is_link", link)
    with pytest.raises(FormatError, match="outside the admitted range"):
        parse_executor_engine_runtime_document(document)
    assert calls == {"spec": 0, "link": 0}


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("version", "unsupported"),
        ("root-field", "fields are invalid"),
        ("workspace-field", "fields are invalid"),
        ("process-field", "fields are invalid"),
        ("ack", "exactly true"),
        ("id", "portable exact process id"),
        ("relative", "absolute non-shell"),
        ("shell", "absolute non-shell"),
        ("shell-script", "absolute non-shell"),
        ("max-args", "outside the admitted range"),
        ("max-output", "outside the admitted range"),
        ("prefix-count", "exceeds maxArgs"),
        ("prefix-bytes", "exceeds 4096"),
        ("total-prefix", "exceeds maxArgBytes"),
    ),
)
def test_hostile_schema_paths_shells_acknowledgement_and_budgets_are_rejected(  # noqa: PLR0912
    mutation: str,
    message: str,
    tmp_path: Path,
) -> None:
    executable = (tmp_path / "fixture.exe").absolute()
    row = _process("fixture", executable)
    document = _document(workspace=False, processes=[row])
    if mutation == "version":
        document["schemaVersion"] = "0.2.0"
    elif mutation == "root-field":
        document["unexpected"] = True
    elif mutation == "workspace-field":
        document["workspace"]["unexpected"] = True
    elif mutation == "process-field":
        row["unexpected"] = True
    elif mutation == "ack":
        row["trustedHostProcessAcknowledged"] = False
    elif mutation == "id":
        row["id"] = "Not Portable"
    elif mutation == "relative":
        row["executable"] = "relative/tool.exe"
    elif mutation == "shell":
        row["executable"] = str((tmp_path / "powershell.exe").absolute())
    elif mutation == "shell-script":
        row["executable"] = str((tmp_path / "fixture.cmd").absolute())
    elif mutation == "max-args":
        row["maxArgs"] = 0
    elif mutation == "max-output":
        row["maxOutputBytes"] = 100
    elif mutation == "prefix-count":
        row["maxArgs"] = 1
        row["argvPrefix"] = ["one", "two"]
    elif mutation == "prefix-bytes":
        row["argvPrefix"] = ["x" * 4097]
    else:
        row["maxArgBytes"] = 1

    with pytest.raises(FormatError, match=message):
        parse_executor_engine_runtime_document(document)


def test_at_least_one_surface_and_exact_boolean_types_are_required() -> None:
    with pytest.raises(FormatError, match="at least one enabled surface"):
        parse_executor_engine_runtime_document(_document(workspace=False))

    document = _document()
    document["workspace"]["enabled"] = 1
    with pytest.raises(FormatError, match="must be a boolean"):
        parse_executor_engine_runtime_document(document)


def test_link_or_junction_chain_rejects_before_spec_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "linked-tool.exe"
    executable.write_bytes(b"fixture")
    calls = {"spec": 0}

    def link(path: Path) -> bool:
        return path == executable

    def spec(*_args: object, **_kwargs: object) -> NoReturn:
        calls["spec"] += 1
        raise AssertionError

    monkeypatch.setattr(config_module, "_path_is_link", link)
    monkeypatch.setattr(config_module, "ExactProcessSurfaceSpec", spec)
    with pytest.raises(FormatError, match="symbolic link or junction"):
        parse_executor_engine_runtime_document(
            _document(workspace=False, processes=[_process("linked", executable)])
        )
    assert calls["spec"] == 0


def test_missing_executable_is_rejected_only_after_complete_static_admission(
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError, match="existing non-shell absolute executable"):
        parse_executor_engine_runtime_document(
            _document(
                workspace=False,
                processes=[_process("missing", (tmp_path / "missing.exe").absolute())],
            )
        )


def test_builder_returns_fresh_workspace_and_multiple_exact_process_generations() -> None:
    executable = Path(sys.executable).resolve()
    config = parse_executor_engine_runtime_document(
        _document(
            processes=[
                _process("python_a", executable, prefix=["-I"]),
                _process("python_b", executable, prefix=["-B"]),
            ]
        )
    )
    builder = build_executor_engine_runtime_surfaces(config)
    assert isinstance(builder, ExecutorEngineRuntimeSurfaceBuilder)
    assert tuple(builder.codec_factories) == config.codec_ids
    assert config.codec_ids == (
        "sova.action-codec.process.python_a/0.1.0",
        "sova.action-codec.process.python_b/0.1.0",
        "sova.action-codec.workspace/0.1.0",
    )

    primary = builder("primary")
    reproduction = builder("reproduction")
    try:
        assert all(type(item) is EngineSurfaceGeneration for item in primary)
        assert [item.sensor_name for item in primary] == [
            "workspace",
            "process_python_a",
            "process_python_b",
        ]
        assert [item.sensor_name for item in reproduction] == [
            "workspace",
            "process_python_a",
            "process_python_b",
        ]
        assert all(
            first.backend.executor is not second.backend.executor
            for first, second in zip(primary, reproduction, strict=True)
        )
    finally:
        for surface in reversed((*primary, *reproduction)):
            surface.close()


def test_template_codec_registry_is_immutable_fresh_and_process_specific() -> None:
    executable = Path(sys.executable).resolve()
    config = parse_executor_engine_runtime_document(
        _document(
            processes=[
                _process("isolated", executable, prefix=["-I"]),
                _process("bytesafe", executable, prefix=["-B"]),
            ]
        )
    )
    builder = build_executor_engine_runtime_surfaces(config)
    first_factory = builder.codec_factories["sova.action-codec.process.isolated/0.1.0"]
    first = first_factory(_observation())
    second = first_factory(_observation())
    other = builder.codec_factories["sova.action-codec.process.bytesafe/0.1.0"](_observation())

    assert first is not second
    assert first.codec_id == "sova.action-codec.process.isolated/0.1.0"
    assert other.codec_id == "sova.action-codec.process.bytesafe/0.1.0"
    request = first.decode(
        {"action": "process.exec", "arguments": {"args": ["-V"], "cwd": "."}},
        request_id="process",
        timeout_seconds=5,
    )
    assert request.inputs["argv"] == [str(executable), "-I", "-V"]
    assert (
        builder.codec_factories["sova.action-codec.workspace/0.1.0"](_observation()).codec_id
        == "sova.action-codec.workspace/0.1.0"
    )
    with pytest.raises(TypeError):
        builder.codec_factories["intruder"] = first_factory  # type: ignore[index]


def test_builder_rejects_substitution_and_unsupported_phase() -> None:
    config = parse_executor_engine_runtime_document(_document())
    builder = build_executor_engine_runtime_surfaces(config)
    with pytest.raises(FormatError, match="phase is unsupported"):
        builder("arbitrary")
    with pytest.raises(FormatError, match="exact parsed runtime config"):
        ExecutorEngineRuntimeSurfaceBuilder(object())  # type: ignore[arg-type]


def test_source_document_mutation_cannot_change_parsed_process_specs() -> None:
    executable = Path(sys.executable).resolve()
    document = _document(processes=[_process("python", executable, prefix=["-I"])])
    parsed = parse_executor_engine_runtime_document(document)
    document["hostProcesses"][0]["argvPrefix"].append("--mutated")
    document["hostProcesses"][0]["executable"] = "relative.exe"

    assert parsed.host_processes[0].argv_prefix == ("-I",)
    assert parsed.host_processes[0].executable == executable
    assert (
        parsed.document_digest
        != parse_executor_engine_runtime_document(
            _document(processes=[_process("python", executable, prefix=["-B"])])
        ).document_digest
    )
