# SPDX-License-Identifier: Apache-2.0
"""Disposable-workspace file and exact-prefix host process executors."""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any, Self

from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.executors.local import RestrictedLocalExecutor
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import (
    ProcessActionCodec,
    WorkspaceActionCodec,
    normalize_workspace_relative_path,
)

_MAX_FILE_BYTES = 1024 * 1024


def _workspace_root(context: ExecutionContext) -> Path:
    supplied = context.workspace
    if supplied.is_symlink() or not supplied.is_dir():
        raise FormatError(
            "SOVA-WORKSPACE-ROOT",
            "workspace executor requires a real existing directory",
        )
    root = supplied.resolve()
    if root in {Path(root.anchor).resolve(), Path.home().resolve()}:
        raise FormatError(
            "SOVA-WORKSPACE-ROOT",
            "filesystem roots and the user home are not disposable workspaces",
        )
    return root


def _workspace_path(root: Path, relative: object, *, allow_root: bool = False) -> Path:
    normalized = normalize_workspace_relative_path(relative, allow_root=allow_root)
    parts = () if normalized == "." else PurePosixPath(normalized).parts
    current = root
    for index, part in enumerate(parts):
        current = current / part
        if current.is_symlink():
            raise FormatError(
                "SOVA-WORKSPACE-SYMLINK",
                "workspace paths cannot traverse or replace symbolic links",
            )
        if index + 1 < len(parts) and (not current.exists() or not current.is_dir()):
            raise FormatError(
                "SOVA-WORKSPACE-PARENT",
                "workspace file parent must already exist as a real directory",
            )
    resolved = current.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise FormatError("SOVA-WORKSPACE-ESCAPE", "workspace path escaped its root")
    return current


def _cancelled(
    request: ActionRequest,
    side_effect: SideEffect = SideEffect.READ,
) -> ActionOutcome:
    return ActionOutcome(
        request.id,
        OutcomeStatus.CANCELLED,
        side_effect,
        {},
        error_code="SOVA-EXECUTOR-CANCELLED",
    )


def _move_destination_admission(
    request: ActionRequest,
    source: Path,
    destination: Path,
    inputs: dict[str, Any],
) -> tuple[bool, ActionOutcome | None]:
    source_name = str(inputs["source"])
    destination_name = str(inputs["destination"])
    if source == destination:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move source and destination resolve to the same path",
        )
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir() or destination.is_symlink():
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move requires real files and an existing real destination parent",
        )
    existed = destination.exists()
    if not existed:
        return False, None
    if not destination.is_file():
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move destination is not a regular file",
        )
    try:
        same_file = source.samefile(destination)
    except OSError as error:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move could not compare source and destination identities",
        ) from error
    if same_file:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move source and destination identify the same file",
        )
    if inputs["overwrite"] is True:
        return True, None
    return True, ActionOutcome(
        request.id,
        OutcomeStatus.DENIED,
        SideEffect.MUTATE,
        {
            "source": source_name,
            "destination": destination_name,
            "destinationExisted": True,
        },
        error_code="SOVA-WORKSPACE-OVERWRITE-DENIED",
    )


def _stable_move_preimage(source: Path, destination_parent: Path, max_bytes: int) -> bytes:
    before = source.stat()
    if before.st_dev != destination_parent.stat().st_dev:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "cross-volume workspace moves are not admitted",
        )
    if before.st_size > max_bytes:
        raise FormatError(
            "SOVA-WORKSPACE-LIMIT",
            "workspace move exceeds the evidence byte limit",
        )
    try:
        data = source.read_bytes()
        stable = source.stat()
    except OSError as error:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move source became unreadable",
        ) from error
    signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    stable_signature = (stable.st_dev, stable.st_ino, stable.st_size, stable.st_mtime_ns)
    if len(data) != before.st_size or signature != stable_signature:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move source changed before mutation",
        )
    return data


def _perform_workspace_move(source: Path, destination: Path, *, overwrite: bool) -> None:
    try:
        if overwrite:
            source.replace(destination)
        else:
            destination.hardlink_to(source)
            try:
                source.unlink()
            except OSError:
                destination.unlink(missing_ok=True)
                raise
    except OSError as error:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move was refused before a verified same-volume result",
        ) from error


def _verified_move_result(source: Path, destination: Path, expected: bytes) -> tuple[bool, bytes]:
    try:
        source_absent = not source.exists() and not source.is_symlink()
        destination_data = destination.read_bytes()
    except OSError as error:
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move result could not be read for verification",
        ) from error
    if (
        not source_absent
        or destination.is_symlink()
        or not destination.is_file()
        or destination_data != expected
    ):
        raise FormatError(
            "SOVA-WORKSPACE-MOVE",
            "workspace move source absence or destination bytes could not be verified",
        )
    return source_absent, destination_data


class WorkspaceExecutor:
    """Perform bounded text-file operations beneath one disposable workspace.

    This constrains path traversal and link following. It is not a security
    sandbox and does not defend against an independently malicious process racing
    filesystem names inside the same workspace.
    """

    name = "sova-disposable-workspace"

    def __init__(
        self,
        *,
        max_read_bytes: int = _MAX_FILE_BYTES,
        max_write_bytes: int = _MAX_FILE_BYTES,
    ) -> None:
        for value in (max_read_bytes, max_write_bytes):
            if isinstance(value, bool) or not 1 <= value <= _MAX_FILE_BYTES:
                raise FormatError(
                    "SOVA-WORKSPACE-LIMIT",
                    "workspace file limits must be between 1 byte and 1 MiB",
                )
        self._max_read_bytes = max_read_bytes
        self._codec = WorkspaceActionCodec(max_write_bytes)

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="filesystem.read",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=("path", "content-digest", "size"),
            ),
            Capability(
                name="filesystem.write",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("path", "content-digest", "size"),
            ),
            Capability(
                name="filesystem.delete",
                version="0.1",
                side_effect=SideEffect.DESTRUCTIVE,
                idempotent=False,
                evidence=("path", "deleted-content-digest", "size"),
            ),
            Capability(
                name="filesystem.move",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=(
                    "source-path",
                    "destination-path",
                    "pre-move-content-digest",
                    "post-move-content-digest",
                    "source-absence",
                ),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        effects = {
            "filesystem.read": SideEffect.READ,
            "filesystem.write": SideEffect.MUTATE,
            "filesystem.delete": SideEffect.DESTRUCTIVE,
            "filesystem.move": SideEffect.MUTATE,
        }
        if cancellation.cancelled:
            return _cancelled(request, effects.get(request.action, SideEffect.READ))
        if request.action not in {
            "filesystem.read",
            "filesystem.write",
            "filesystem.delete",
            "filesystem.move",
        }:
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-WORKSPACE-UNSUPPORTED",
                limitations=("Only bounded disposable-workspace file operations are supported.",),
            )
        validated = self._codec.decode(
            {"action": request.action, "arguments": request.inputs},
            request_id=request.id,
            timeout_seconds=request.timeout_seconds,
        )
        root = _workspace_root(context)
        if request.action == "filesystem.move":
            source = _workspace_path(root, validated.inputs["source"])
            destination = _workspace_path(root, validated.inputs["destination"])
            return self._move(request, source, destination, validated.inputs)
        path = _workspace_path(root, validated.inputs["path"])
        if request.action == "filesystem.read":
            return self._read(request, path)
        if request.action == "filesystem.write":
            return self._write(request, path, validated.inputs)
        return self._delete(request, path)

    def _move(
        self,
        request: ActionRequest,
        source: Path,
        destination: Path,
        inputs: dict[str, Any],
    ) -> ActionOutcome:
        source_name = str(inputs["source"])
        destination_name = str(inputs["destination"])
        if source.is_symlink() or not source.is_file():
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.MUTATE,
                {"source": source_name, "destination": destination_name},
                error_code="SOVA-WORKSPACE-FILE-MISSING",
            )
        existed, denied = _move_destination_admission(
            request,
            source,
            destination,
            inputs,
        )
        if denied is not None:
            return denied
        data = _stable_move_preimage(source, destination.parent, self._max_read_bytes)
        _perform_workspace_move(
            source,
            destination,
            overwrite=inputs["overwrite"] is True,
        )
        source_absent, destination_data = _verified_move_result(source, destination, data)
        pre_digest = sha256_digest(data)
        post_digest = sha256_digest(destination_data)
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {
                "source": source_name,
                "destination": destination_name,
                "preMoveDigest": pre_digest,
                "postMoveDigest": post_digest,
                "size": len(data),
                "replacedExisting": existed,
                "sourceAbsent": source_absent,
                "destinationBytesVerified": True,
            },
            evidence=(
                EvidenceReference(
                    "workspace-file-before-move",
                    "application/octet-stream",
                    pre_digest,
                    len(data),
                ),
                EvidenceReference(
                    "workspace-file-after-move",
                    "application/octet-stream",
                    post_digest,
                    len(destination_data),
                ),
            ),
            verification="same-volume-move-with-source-absence-and-destination-byte-compare",
            limitations=(
                "The supplied disposable workspace is a path boundary, not a security sandbox.",
                "Concurrent hostile name races require stronger OS or VM isolation.",
            ),
        )

    def _read(self, request: ActionRequest, path: Path) -> ActionOutcome:
        if path.is_symlink() or not path.is_file():
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.READ,
                {"path": request.inputs["path"]},
                error_code="SOVA-WORKSPACE-FILE-MISSING",
            )
        before = path.stat()
        if before.st_size > self._max_read_bytes:
            raise FormatError("SOVA-WORKSPACE-LIMIT", "workspace read exceeds its byte limit")
        try:
            data = path.read_bytes()
            after = path.stat()
            text = data.decode("utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as error:
            raise FormatError(
                "SOVA-WORKSPACE-READ",
                "workspace file changed, became unreadable, or is not UTF-8 text",
            ) from error
        if before.st_size != len(data) or (before.st_size, before.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            raise FormatError("SOVA-WORKSPACE-READ", "workspace file changed during read")
        digest = sha256_digest(data)
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.READ,
            {
                "path": request.inputs["path"],
                "text": text,
                "digest": digest,
                "size": len(data),
            },
            evidence=(EvidenceReference("workspace-file", "text/plain", digest, len(data)),),
            verification="regular-file-stable-read-and-digest",
            limitations=(
                "The supplied disposable workspace is a path boundary, not a security sandbox.",
            ),
        )

    def _write(
        self,
        request: ActionRequest,
        path: Path,
        inputs: dict[str, Any],
    ) -> ActionOutcome:
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise FormatError(
                "SOVA-WORKSPACE-WRITE",
                "workspace write requires a real existing parent and non-link target",
            )
        existed = path.exists()
        if existed and not path.is_file():
            raise FormatError("SOVA-WORKSPACE-WRITE", "workspace write target is not a file")
        if existed and inputs["overwrite"] is not True:
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {"path": request.inputs["path"], "existed": True},
                error_code="SOVA-WORKSPACE-OVERWRITE-DENIED",
            )
        data = str(inputs["content"]).encode("utf-8")
        if existed:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".sova-write-", dir=parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0))
            descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise FormatError("SOVA-WORKSPACE-WRITE", "workspace write verification failed")
        digest = sha256_digest(data)
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {
                "path": request.inputs["path"],
                "digest": digest,
                "size": len(data),
                "replacedExisting": existed,
            },
            evidence=(EvidenceReference("workspace-file", "text/plain", digest, len(data)),),
            verification="exclusive-create-or-atomic-replace-and-byte-compare",
            limitations=(
                "The supplied disposable workspace is a path boundary, not a security sandbox.",
                "Concurrent hostile name races require stronger OS or VM isolation.",
            ),
        )

    def _delete(self, request: ActionRequest, path: Path) -> ActionOutcome:
        if path.is_symlink() or not path.is_file():
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.DESTRUCTIVE,
                {"path": request.inputs["path"]},
                error_code="SOVA-WORKSPACE-FILE-MISSING",
            )
        before = path.stat()
        if before.st_size > self._max_read_bytes:
            raise FormatError(
                "SOVA-WORKSPACE-LIMIT",
                "workspace delete exceeds the evidence byte limit",
            )
        data = path.read_bytes()
        after = path.stat()
        if before.st_size != len(data) or (before.st_size, before.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            raise FormatError("SOVA-WORKSPACE-DELETE", "workspace file changed before deletion")
        path.unlink()
        if path.exists() or path.is_symlink():
            raise FormatError("SOVA-WORKSPACE-DELETE", "workspace deletion could not be verified")
        digest = sha256_digest(data)
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.DESTRUCTIVE,
            {"path": request.inputs["path"], "deletedDigest": digest, "size": len(data)},
            evidence=(
                EvidenceReference(
                    "deleted-workspace-file",
                    "application/octet-stream",
                    digest,
                    len(data),
                ),
            ),
            verification="stable-preimage-digest-and-verified-absence",
            limitations=(
                "Deletion is confined to a regular file in the supplied disposable workspace.",
                "The supplied disposable workspace is a path boundary, not a security sandbox.",
            ),
        )


class ExactProcessExecutor:
    """Run one exact executable/prefix through the restricted shell-free host backend."""

    name = "sova-exact-workspace-process"

    def __init__(
        self,
        executable: Path,
        argv_prefix: tuple[str, ...] = (),
        *,
        max_args: int = 64,
        max_arg_bytes: int = 64 * 1024,
        max_output_bytes: int = _MAX_FILE_BYTES,
    ) -> None:
        self._codec = ProcessActionCodec(
            executable,
            argv_prefix,
            max_args=max_args,
            max_arg_bytes=max_arg_bytes,
        )
        self._delegate = RestrictedLocalExecutor(
            executable_allowlist=(self._codec.executable,),
            max_output_bytes=max_output_bytes,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._delegate.close()

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="process.exec",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("stdout", "stderr", "returncode", "exact-argv-prefix"),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        if request.action != "process.exec":
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-EXACT-PROCESS-UNSUPPORTED",
                limitations=("Only the exact configured process.exec template is supported.",),
            )
        root = _workspace_root(context)
        if cancellation.cancelled:
            return _cancelled(request, SideEffect.MUTATE)
        if not isinstance(request.inputs, dict) or set(request.inputs) != {"argv", "cwd"}:
            raise FormatError(
                "SOVA-EXACT-PROCESS-INPUT",
                "exact process requests accept only argv and cwd",
            )
        argv = request.inputs.get("argv")
        cwd = request.inputs.get("cwd")
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise FormatError("SOVA-EXACT-PROCESS-ARGV", "process argv must be a string array")
        prefix = [str(self._codec.executable), *self._codec.argv_prefix]
        if argv[: len(prefix)] != prefix:
            raise FormatError(
                "SOVA-EXACT-PROCESS-PREFIX",
                "process request does not match the exact admitted executable and prefix",
            )
        trailing = argv[len(prefix) :]
        rebuilt = self._codec.decode(
            {
                "action": "process.exec",
                "arguments": {"args": trailing, "cwd": cwd},
            },
            request_id=request.id,
            timeout_seconds=request.timeout_seconds,
        )
        if rebuilt.inputs != request.inputs:
            raise FormatError(
                "SOVA-EXACT-PROCESS-SUBSTITUTION",
                "process request changed after exact template validation",
            )
        cwd_path = _workspace_path(root, cwd, allow_root=True)
        if cwd_path.is_symlink() or not cwd_path.is_dir():
            raise FormatError(
                "SOVA-EXACT-PROCESS-CWD",
                "process cwd must be a real directory inside the disposable workspace",
            )
        outcome = self._delegate.execute(request, context, cancellation)
        return replace(
            outcome,
            limitations=tuple(
                dict.fromkeys(
                    (
                        *outcome.limitations,
                        "Exact-prefix host process execution is not a security sandbox.",
                        "Use gVisor, a container, or a VM when hostile native code is in scope.",
                    )
                )
            ),
        )


__all__ = ["ExactProcessExecutor", "WorkspaceExecutor"]
