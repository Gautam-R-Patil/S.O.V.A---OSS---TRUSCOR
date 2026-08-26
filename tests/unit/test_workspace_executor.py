# SPDX-License-Identifier: Apache-2.0
"""Disposable-workspace and exact-prefix process executor contracts."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.executors import workspace as workspace_module
from sova.executors.workspace import ExactProcessExecutor, WorkspaceExecutor
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import ProcessActionCodec, WorkspaceActionCodec


def _context(workspace: Path) -> ExecutionContext:
    return ExecutionContext(workspace=workspace, authorization={"decision": "allowed"})


def _workspace_request(
    codec: WorkspaceActionCodec,
    action: str,
    arguments: dict[str, object],
    *,
    identifier: str,
) -> ActionRequest:
    return codec.decode(
        {"action": action, "arguments": arguments},
        request_id=identifier,
        timeout_seconds=5,
    )


def test_workspace_executor_writes_reads_overwrites_and_deletes_with_evidence(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "notes").mkdir()
    context = _context(workspace)
    codec = WorkspaceActionCodec(max_content_bytes=64)
    executor = WorkspaceExecutor(max_read_bytes=64, max_write_bytes=64)

    assert [item.identifier for item in executor.capabilities()] == [
        "filesystem.read/0.1",
        "filesystem.write/0.1",
        "filesystem.delete/0.1",
        "filesystem.move/0.1",
    ]
    write = executor.execute(
        _workspace_request(
            codec,
            "filesystem.write",
            {"path": "notes/result.txt", "content": "first", "overwrite": False},
            identifier="write",
        ),
        context,
        CancellationToken(),
    )
    assert write.status == OutcomeStatus.SUCCEEDED
    assert write.side_effect == SideEffect.MUTATE
    assert write.verification == "exclusive-create-or-atomic-replace-and-byte-compare"
    assert write.evidence[0].digest == write.output["digest"]
    assert (workspace / "notes" / "result.txt").read_text(encoding="utf-8") == "first"
    assert any("not a security sandbox" in item for item in write.limitations)

    denied = executor.execute(
        _workspace_request(
            codec,
            "filesystem.write",
            {"path": "notes/result.txt", "content": "second", "overwrite": False},
            identifier="denied",
        ),
        context,
        CancellationToken(),
    )
    assert denied.status == OutcomeStatus.DENIED
    assert denied.error_code == "SOVA-WORKSPACE-OVERWRITE-DENIED"

    replaced = executor.execute(
        _workspace_request(
            codec,
            "filesystem.write",
            {"path": "notes/result.txt", "content": "second", "overwrite": True},
            identifier="replace",
        ),
        context,
        CancellationToken(),
    )
    assert replaced.status == OutcomeStatus.SUCCEEDED
    assert replaced.output["replacedExisting"] is True

    read = executor.execute(
        _workspace_request(
            codec,
            "filesystem.read",
            {"path": "notes/result.txt"},
            identifier="read",
        ),
        context,
        CancellationToken(),
    )
    assert read.status == OutcomeStatus.SUCCEEDED
    assert read.output["text"] == "second"
    assert read.output["digest"] == replaced.output["digest"]

    deleted = executor.execute(
        _workspace_request(
            codec,
            "filesystem.delete",
            {"path": "notes/result.txt"},
            identifier="delete",
        ),
        context,
        CancellationToken(),
    )
    assert deleted.status == OutcomeStatus.SUCCEEDED
    assert deleted.side_effect == SideEffect.DESTRUCTIVE
    assert deleted.output["deletedDigest"] == replaced.output["digest"]
    assert not (workspace / "notes" / "result.txt").exists()


def test_workspace_executor_moves_with_bound_digests_and_explicit_overwrite(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    source_dir = workspace / "source"
    destination_dir = workspace / "destination"
    source_dir.mkdir(parents=True)
    destination_dir.mkdir()
    source = source_dir / "result.bin"
    destination = destination_dir / "result.bin"
    source.write_bytes(b"source-bytes")
    destination.write_bytes(b"old-destination")
    context = _context(workspace)
    codec = WorkspaceActionCodec()
    executor = WorkspaceExecutor(max_read_bytes=64)

    denied = executor.execute(
        _workspace_request(
            codec,
            "filesystem.move",
            {
                "source": "source/result.bin",
                "destination": "destination/result.bin",
                "overwrite": False,
            },
            identifier="move-denied",
        ),
        context,
        CancellationToken(),
    )
    assert denied.status == OutcomeStatus.DENIED
    assert denied.error_code == "SOVA-WORKSPACE-OVERWRITE-DENIED"
    assert source.read_bytes() == b"source-bytes"
    assert destination.read_bytes() == b"old-destination"

    moved = executor.execute(
        _workspace_request(
            codec,
            "filesystem.move",
            {
                "source": "source/result.bin",
                "destination": "destination/result.bin",
                "overwrite": True,
            },
            identifier="move",
        ),
        context,
        CancellationToken(),
    )
    assert moved.status == OutcomeStatus.SUCCEEDED
    assert moved.side_effect == SideEffect.MUTATE
    assert moved.output["preMoveDigest"] == moved.output["postMoveDigest"]
    assert moved.output["sourceAbsent"] is True
    assert moved.output["destinationBytesVerified"] is True
    assert moved.output["replacedExisting"] is True
    assert moved.evidence[0].digest == moved.evidence[1].digest
    assert moved.verification == (
        "same-volume-move-with-source-absence-and-destination-byte-compare"
    )
    assert not source.exists()
    assert destination.read_bytes() == b"source-bytes"

    second_source = source_dir / "second.txt"
    second_destination = destination_dir / "second.txt"
    second_source.write_text("second", encoding="utf-8")
    exclusive = executor.execute(
        _workspace_request(
            codec,
            "filesystem.move",
            {
                "source": "source/second.txt",
                "destination": "destination/second.txt",
                "overwrite": False,
            },
            identifier="move-exclusive",
        ),
        context,
        CancellationToken(),
    )
    assert exclusive.status == OutcomeStatus.SUCCEEDED
    assert exclusive.output["replacedExisting"] is False
    assert not second_source.exists()
    assert second_destination.read_text(encoding="utf-8") == "second"


def test_workspace_move_rejects_missing_parent_links_directories_and_limits(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "source.txt").write_text("12345", encoding="utf-8")
    (workspace / "directory").mkdir()
    context = _context(workspace)
    executor = WorkspaceExecutor(max_read_bytes=4)

    with pytest.raises(FormatError, match="parent"):
        executor.execute(
            ActionRequest(
                "missing-parent",
                "filesystem.move",
                {
                    "source": "source.txt",
                    "destination": "missing/result.txt",
                    "overwrite": False,
                },
                1,
            ),
            context,
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="limit"):
        executor.execute(
            ActionRequest(
                "limit",
                "filesystem.move",
                {
                    "source": "source.txt",
                    "destination": "result.txt",
                    "overwrite": False,
                },
                1,
            ),
            context,
            CancellationToken(),
        )
    directory = executor.execute(
        ActionRequest(
            "directory",
            "filesystem.move",
            {
                "source": "directory",
                "destination": "moved-directory",
                "overwrite": False,
            },
            1,
        ),
        context,
        CancellationToken(),
    )
    assert directory.status == OutcomeStatus.FAILED
    assert directory.error_code == "SOVA-WORKSPACE-FILE-MISSING"

    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    linked = workspace / "linked.txt"
    try:
        linked.symlink_to(outside)
    except OSError:
        return
    with pytest.raises(FormatError, match="symbolic links"):
        executor.execute(
            ActionRequest(
                "link",
                "filesystem.move",
                {
                    "source": "linked.txt",
                    "destination": "moved.txt",
                    "overwrite": False,
                },
                1,
            ),
            context,
            CancellationToken(),
        )
    assert outside.read_text(encoding="utf-8") == "outside"


def test_workspace_executor_fails_closed_on_escape_links_limits_and_bad_roots(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = _context(workspace)
    executor = WorkspaceExecutor(max_read_bytes=4, max_write_bytes=4)

    with pytest.raises(FormatError, match="path"):
        executor.execute(
            ActionRequest("escape", "filesystem.read", {"path": "../outside.txt"}, 1),
            context,
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="parent"):
        executor.execute(
            ActionRequest(
                "missing-parent",
                "filesystem.write",
                {"path": "missing/out.txt", "content": "safe", "overwrite": False},
                1,
            ),
            context,
            CancellationToken(),
        )
    large = workspace / "large.txt"
    large.write_text("12345", encoding="utf-8")
    with pytest.raises(FormatError, match="limit"):
        executor.execute(
            ActionRequest("large", "filesystem.read", {"path": "large.txt"}, 1),
            context,
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="user home"):
        WorkspaceExecutor().execute(
            ActionRequest("home", "filesystem.read", {"path": "missing.txt"}, 1),
            _context(Path.home()),
            CancellationToken(),
        )

    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    linked = workspace / "linked.txt"
    try:
        linked.symlink_to(outside)
    except OSError:
        return
    with pytest.raises(FormatError, match="symbolic links"):
        executor.execute(
            ActionRequest("link", "filesystem.read", {"path": "linked.txt"}, 1),
            context,
            CancellationToken(),
        )
    assert outside.read_text(encoding="utf-8") == "outside"


def test_workspace_executor_cancellation_unknown_action_and_missing_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = _context(workspace)
    executor = WorkspaceExecutor()
    token = CancellationToken()
    token.cancel()

    cancelled = executor.execute(
        ActionRequest("cancelled", "filesystem.read", {"path": "missing.txt"}, 1),
        context,
        token,
    )
    assert cancelled.status == OutcomeStatus.CANCELLED
    unsupported = executor.execute(
        ActionRequest("unknown", "filesystem.mkdir", {}, 1),
        context,
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    missing = executor.execute(
        ActionRequest("missing", "filesystem.read", {"path": "missing.txt"}, 1),
        context,
        CancellationToken(),
    )
    assert missing.status == OutcomeStatus.FAILED
    assert missing.error_code == "SOVA-WORKSPACE-FILE-MISSING"


def test_exact_process_executor_runs_literal_args_without_shell_interpretation(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    code = (
        "import pathlib,sys;"
        "pathlib.Path('process-output.txt').write_text(sys.argv[1],encoding='utf-8');"
        "print(sys.argv[1])"
    )
    executable = Path(sys.executable).resolve()
    codec = ProcessActionCodec(executable, ("-c", code))
    request = codec.decode(
        {
            "action": "process.exec",
            "arguments": {"args": ["; echo not-a-shell"], "cwd": "."},
        },
        request_id="process",
        timeout_seconds=10,
    )

    with ExactProcessExecutor(executable, ("-c", code)) as executor:
        assert [item.identifier for item in executor.capabilities()] == ["process.exec/0.1"]
        outcome = executor.execute(request, _context(workspace), CancellationToken())

    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["stdout"].strip() == "; echo not-a-shell"
    assert (workspace / "process-output.txt").read_text(encoding="utf-8") == ("; echo not-a-shell")
    assert not (workspace / "not-a-shell").exists()
    assert any("not a security sandbox" in item for item in outcome.limitations)


def test_exact_process_executor_revalidates_prefix_workspace_and_cancellation(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = Path(sys.executable).resolve()
    context = _context(workspace)
    executor = ExactProcessExecutor(executable, ("--version",))
    valid = ProcessActionCodec(executable, ("--version",)).decode(
        {"action": "process.exec", "arguments": {"args": [], "cwd": "."}},
        request_id="valid",
        timeout_seconds=5,
    )
    tampered = ActionRequest(
        "tampered",
        "process.exec",
        {"argv": [str(executable), "--help"], "cwd": "."},
        5,
    )
    with pytest.raises(FormatError, match="prefix"):
        executor.execute(tampered, context, CancellationToken())

    escaped = ActionRequest(
        "escaped",
        "process.exec",
        {"argv": list(valid.inputs["argv"]), "cwd": "../outside"},
        5,
    )
    with pytest.raises(FormatError, match="path"):
        executor.execute(escaped, context, CancellationToken())

    token = CancellationToken()
    token.cancel()
    cancelled = executor.execute(valid, context, token)
    assert cancelled.status == OutcomeStatus.CANCELLED
    unsupported = executor.execute(
        ActionRequest("other", "filesystem.read", {}, 1),
        context,
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    executor.close()


def test_workspace_internal_move_admission_rejects_identity_parent_and_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.txt"
    source.write_text("source", encoding="utf-8")
    request = ActionRequest(
        "move", "filesystem.move", {"source": "source.txt", "destination": "dest.txt"}, 1
    )
    inputs = {"source": "source.txt", "destination": "dest.txt", "overwrite": False}
    with pytest.raises(FormatError, match="same path"):
        workspace_module._move_destination_admission(request, source, source, inputs)
    with pytest.raises(FormatError, match="existing real destination parent"):
        workspace_module._move_destination_admission(
            request, source, workspace / "missing" / "dest.txt", inputs
        )
    destination_directory = workspace / "dest.txt"
    destination_directory.mkdir()
    with pytest.raises(FormatError, match="not a regular file"):
        workspace_module._move_destination_admission(request, source, destination_directory, inputs)
    destination_directory.rmdir()
    destination_directory.write_text("destination", encoding="utf-8")

    monkeypatch.setattr(Path, "samefile", lambda *_args: (_ for _ in ()).throw(OSError()))
    with pytest.raises(FormatError, match="could not compare"):
        workspace_module._move_destination_admission(request, source, destination_directory, inputs)
    monkeypatch.setattr(Path, "samefile", lambda *_args: True)
    with pytest.raises(FormatError, match="identify the same file"):
        workspace_module._move_destination_admission(request, source, destination_directory, inputs)


def test_workspace_move_preimage_perform_and_result_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.txt"
    destination = workspace / "destination.txt"
    source.write_text("source", encoding="utf-8")

    original_stat = Path.stat

    def cross_volume(path: Path, *args: object, **kwargs: Any) -> object:
        value = original_stat(path, *args, **kwargs)
        if path == workspace:
            values = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            values["st_dev"] = value.st_dev + 1
            return type("Stat", (), values)()
        return value

    monkeypatch.setattr(Path, "stat", cross_volume)
    with pytest.raises(FormatError, match="cross-volume"):
        workspace_module._stable_move_preimage(source, workspace, 100)
    monkeypatch.setattr(Path, "stat", original_stat)

    original_read = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda path: (_ for _ in ()).throw(OSError()) if path == source else original_read(path),
    )
    with pytest.raises(FormatError, match="became unreadable"):
        workspace_module._stable_move_preimage(source, workspace, 100)
    monkeypatch.setattr(Path, "read_bytes", original_read)

    monkeypatch.setattr(
        Path, "hardlink_to", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(FormatError, match="move was refused"):
        workspace_module._perform_workspace_move(source, destination, overwrite=False)

    with pytest.raises(FormatError, match="could not be read"):
        workspace_module._verified_move_result(source, tmp_path / "missing", b"source")
    destination.write_text("wrong", encoding="utf-8")
    with pytest.raises(FormatError, match="could not be verified"):
        workspace_module._verified_move_result(source, destination, b"source")


def test_workspace_executor_limits_binary_directory_and_delete_failures(tmp_path: Path) -> None:
    for value in (0, True, 1024 * 1024 + 1):
        with pytest.raises(FormatError, match="between 1 byte"):
            WorkspaceExecutor(max_read_bytes=value)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = _context(workspace)
    executor = WorkspaceExecutor(max_read_bytes=4, max_write_bytes=4)
    binary = workspace / "binary.txt"
    binary.write_bytes(b"\xff")
    with pytest.raises(FormatError, match="not UTF-8"):
        executor.execute(
            ActionRequest("binary", "filesystem.read", {"path": "binary.txt"}, 1),
            context,
            CancellationToken(),
        )

    directory = workspace / "directory"
    directory.mkdir()
    with pytest.raises(FormatError, match="target is not a file"):
        executor.execute(
            ActionRequest(
                "write-directory",
                "filesystem.write",
                {"path": "directory", "content": "x", "overwrite": True},
                1,
            ),
            context,
            CancellationToken(),
        )
    large = workspace / "large.txt"
    large.write_text("12345", encoding="utf-8")
    with pytest.raises(FormatError, match="delete exceeds"):
        executor.execute(
            ActionRequest("delete-large", "filesystem.delete", {"path": "large.txt"}, 1),
            context,
            CancellationToken(),
        )


def test_workspace_root_and_exact_process_input_cwd_guards(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    executable = Path(sys.executable).resolve()
    executor = ExactProcessExecutor(executable)
    context = _context(workspace)
    with pytest.raises(FormatError, match="accept only argv and cwd"):
        executor.execute(
            ActionRequest("bad-input", "process.exec", {"argv": [str(executable)]}, 1),
            context,
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="string array"):
        executor.execute(
            ActionRequest(
                "bad-argv", "process.exec", {"argv": [str(executable), 1], "cwd": "."}, 1
            ),
            context,
            CancellationToken(),
        )
    not_directory = workspace / "file.txt"
    not_directory.write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="cwd must be a real directory"):
        executor.execute(
            ActionRequest(
                "bad-cwd",
                "process.exec",
                {"argv": [str(executable)], "cwd": "file.txt"},
                1,
            ),
            context,
            CancellationToken(),
        )
    executor.close()
