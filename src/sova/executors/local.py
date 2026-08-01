# SPDX-License-Identifier: Apache-2.0
"""Restricted local executor; explicitly not a security sandbox."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Protocol, Self

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
from sova.formats import sha256_digest
from sova.formats.errors import FormatError

_SECRET_ENV = re.compile(
    r"(?:token|secret|password|credential|cookie|authorization|api[_-]?key)",
    re.IGNORECASE,
)
_OPAQUE_SECRET_REFERENCE = re.compile(r"^sova-secret:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DEFAULT_ENV = frozenset({"SYSTEMROOT", "WINDIR", "TEMP", "TMP"})
_MIN_OUTPUT_BYTES = 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MIN_MEMORY_BYTES = 16 * 1024 * 1024
_MAX_MEMORY_BYTES = 1024 * 1024 * 1024 * 1024
_MAX_CPU_SECONDS = 86_400
_MAX_PROCESSES = 1024
_BACKGROUND_CLEANUP_ATTEMPTS = 100
_BACKGROUND_CLEANUP_RETRY_SECONDS = 0.01


class _CleanupResource(Protocol):
    def cleanup(self) -> None: ...


def _cleanup_temporary(
    temporary: _CleanupResource,
    *,
    attempts: int = _BACKGROUND_CLEANUP_ATTEMPTS,
    retry_seconds: float = _BACKGROUND_CLEANUP_RETRY_SECONDS,
) -> None:
    """Retry deletion while Windows releases inherited process I/O handles."""
    for attempt in range(attempts):
        try:
            temporary.cleanup()
        except PermissionError:
            if attempt + 1 == attempts:
                raise
            time.sleep(retry_seconds)
        else:
            return


@dataclass(frozen=True, slots=True)
class _RequestedLimits:
    max_output_bytes: int
    max_cpu_seconds: int | None
    max_memory_bytes: int | None
    max_processes: int | None


@dataclass(frozen=True, slots=True)
class _PreparedProcess:
    argv: tuple[str, ...]
    cwd: Path
    environment: dict[str, str]
    creationflags: int
    limits: _RequestedLimits


@dataclass(slots=True)
class _SupervisedProcess:
    handle: str
    process: subprocess.Popen[bytes]
    temporary: tempfile.TemporaryDirectory[str]
    stdout_handle: IO[bytes]
    stderr_handle: IO[bytes]
    stdout_path: Path
    stderr_path: Path
    deadline: float
    max_output_bytes: int
    cancellation: CancellationToken
    terminal: OutcomeStatus | None = None
    monitor: threading.Thread | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class RestrictedLocalExecutor:
    """Read capsule artifacts and run explicitly allowlisted argv without a shell."""

    name = "sova-restricted-local"

    def __init__(
        self,
        *,
        executable_allowlist: tuple[Path, ...] = (),
        environment_allowlist: frozenset[str] = _DEFAULT_ENV,
        max_output_bytes: int = 1024 * 1024,
    ) -> None:
        if not _MIN_OUTPUT_BYTES <= max_output_bytes <= _MAX_OUTPUT_BYTES:
            raise FormatError(
                "SOVA-LOCAL-OUTPUT-LIMIT",
                "local output limit must be between 1 KiB and 64 MiB",
            )
        self._executables = {str(path.resolve()).casefold() for path in executable_allowlist}
        self._environment_allowlist = environment_allowlist
        self._max_output_bytes = max_output_bytes
        self._background: dict[str, _SupervisedProcess] = {}
        self._background_lock = threading.Lock()
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Terminate and remove every supervised child owned by this executor."""
        with self._background_lock:
            records = tuple(self._background.values())
            self._background.clear()
        for record in records:
            with record.lock:
                if record.process.poll() is None:
                    self._terminate_tree(record.process)
                if record.terminal is None:
                    record.terminal = OutcomeStatus.CANCELLED
                self._close_background_handles(record)
            if record.monitor is not None and record.monitor is not threading.current_thread():
                record.monitor.join(timeout=10)
            _cleanup_temporary(record.temporary)
        self._closed = True

    def capabilities(self) -> tuple[Capability, ...]:
        capabilities = [
            Capability(
                name="artifact.read",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=("artifact-digest",),
            )
        ]
        if self._executables:
            capabilities.extend(
                (
                    Capability(
                        name="process.exec",
                        version="0.1",
                        side_effect=SideEffect.MUTATE,
                        idempotent=False,
                        evidence=("stdout", "stderr", "returncode"),
                    ),
                    Capability(
                        name="process.spawn",
                        version="0.1",
                        side_effect=SideEffect.MUTATE,
                        idempotent=False,
                        evidence=("supervised-handle",),
                    ),
                    Capability(
                        name="process.status",
                        version="0.1",
                        side_effect=SideEffect.READ,
                        idempotent=True,
                        evidence=("stdout", "stderr", "returncode"),
                    ),
                    Capability(
                        name="process.stop",
                        version="0.1",
                        side_effect=SideEffect.MUTATE,
                        idempotent=True,
                        evidence=("stdout", "stderr", "returncode"),
                    ),
                )
            )
        return tuple(capabilities)

    def execute(  # noqa: PLR0911 - action dispatch remains explicit and fail closed
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        if self._closed:
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.READ,
                {},
                error_code="SOVA-LOCAL-CLOSED",
            )
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                SideEffect.READ,
                {},
                error_code="SOVA-EXECUTOR-CANCELLED",
            )
        if request.action == "artifact.read":
            return self._read_artifact(request, context)
        if request.action == "process.exec" and self._executables:
            return self._run_process(request, context, cancellation)
        if request.action == "process.spawn" and self._executables:
            return self._spawn_process(request, context, cancellation)
        if request.action == "process.status" and self._executables:
            return self._background_status(request)
        if request.action == "process.stop" and self._executables:
            return self._stop_process(request)
        return ActionOutcome(
            request.id,
            OutcomeStatus.UNSUPPORTED,
            SideEffect.READ,
            {},
            error_code="SOVA-EXECUTOR-UNSUPPORTED",
            limitations=(
                "Browser and computer capabilities are explicitly unsupported.",
                "Host execution is not equivalent to a security sandbox.",
            ),
        )

    def _read_artifact(
        self,
        request: ActionRequest,
        context: ExecutionContext,
    ) -> ActionOutcome:
        requested = request.inputs.get("digest")
        if not isinstance(requested, str) or requested not in context.artifacts:
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.READ,
                {},
                error_code="SOVA-LOCAL-ARTIFACT-MISSING",
            )
        data = context.artifacts[requested]
        media_type = str(request.inputs.get("mediaType", "application/octet-stream"))
        output: dict[str, Any] = {
            "digest": sha256_digest(data),
            "size": len(data),
            "mediaType": media_type,
        }
        if media_type.startswith("text/"):
            output["text"] = data.decode("utf-8", errors="strict")
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.READ,
            output,
            evidence=(
                EvidenceReference(
                    "artifact",
                    media_type,
                    sha256_digest(data),
                    len(data),
                ),
            ),
            verification="digest-and-size-checked",
            limitations=("Read from capsule-provided bytes; no host path was opened.",),
        )

    def _run_process(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        prepared = self._prepare_process(request, context)
        if isinstance(prepared, ActionOutcome):
            return prepared
        temporary = tempfile.TemporaryDirectory(
            prefix=".sova-process-",
            dir=context.workspace,
        )
        try:
            temporary_path = Path(temporary.name)
            stdout_path = temporary_path / "stdout"
            stderr_path = temporary_path / "stderr"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    process = subprocess.Popen(  # noqa: S603
                        list(prepared.argv),
                        cwd=prepared.cwd,
                        env=prepared.environment,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                        start_new_session=os.name != "nt",
                        creationflags=prepared.creationflags,
                    )
                except OSError:
                    return ActionOutcome(
                        request.id,
                        OutcomeStatus.FAILED,
                        SideEffect.MUTATE,
                        {},
                        error_code="SOVA-LOCAL-PROCESS-START",
                        limitations=("Process creation failed; no child was started.",),
                    )
                status = self._wait(
                    process,
                    stdout_path,
                    stderr_path,
                    request.timeout_seconds,
                    prepared.limits.max_output_bytes,
                    cancellation,
                )
            if status is None and (
                stdout_path.stat().st_size > prepared.limits.max_output_bytes
                or stderr_path.stat().st_size > prepared.limits.max_output_bytes
            ):
                status = OutcomeStatus.PARTIAL
            stdout_data = stdout_path.read_bytes()[: prepared.limits.max_output_bytes]
            stderr_data = stderr_path.read_bytes()[: prepared.limits.max_output_bytes]
        finally:
            _cleanup_temporary(temporary)
        returncode = process.returncode
        outcome_status = (
            status
            if status is not None
            else OutcomeStatus.SUCCEEDED
            if returncode == 0
            else OutcomeStatus.FAILED
        )
        return ActionOutcome(
            request.id,
            outcome_status,
            SideEffect.MUTATE,
            {
                "returncode": returncode,
                "stdout": stdout_data.decode("utf-8", errors="replace"),
                "stderr": stderr_data.decode("utf-8", errors="replace"),
            },
            evidence=(
                EvidenceReference(
                    "stdout",
                    "text/plain",
                    sha256_digest(stdout_data),
                    len(stdout_data),
                ),
                EvidenceReference(
                    "stderr",
                    "text/plain",
                    sha256_digest(stderr_data),
                    len(stderr_data),
                ),
            ),
            verification="process-exit-and-bounded-output-observed",
            retryable=False,
            error_code=(
                None
                if outcome_status == OutcomeStatus.SUCCEEDED
                else f"SOVA-LOCAL-{outcome_status.value.upper()}"
            ),
            limitations=(
                "Restricted host process execution is not a security sandbox.",
                "Only an allowlisted executable and confined cwd were enforced.",
                "CPU, memory, and process-count quotas require a stronger containment backend.",
                "Resolved secret values may exist transiently in child-process memory.",
            ),
        )

    def _prepare_process(  # noqa: PLR0911 - each rejection has a distinct public code
        self,
        request: ActionRequest,
        context: ExecutionContext,
    ) -> _PreparedProcess | ActionOutcome:
        limits = self._requested_limits(request.inputs.get("resources", {}))
        if any(
            value is not None
            for value in (limits.max_cpu_seconds, limits.max_memory_bytes, limits.max_processes)
        ):
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-LOCAL-RESOURCE-LIMIT-UNSUPPORTED",
                limitations=(
                    "This host-process backend cannot enforce portable CPU, memory, "
                    "or process-count quotas.",
                    "The request was rejected before process creation.",
                    "Use a stronger container, VM, or operating-system isolation backend.",
                ),
            )
        argv = request.inputs.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(value, str) and value for value in argv)
        ):
            raise FormatError(
                "SOVA-LOCAL-ARGV",
                "process action requires a non-empty string argv array",
            )
        executable_path = Path(argv[0])
        executable = str(executable_path.resolve())
        if not executable_path.is_absolute():
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-LOCAL-EXECUTABLE-NOT-ABSOLUTE",
            )
        if executable.casefold() not in self._executables:
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-LOCAL-EXECUTABLE-DENIED",
            )
        workspace = context.workspace.resolve()
        relative_cwd = request.inputs.get("cwd", ".")
        if not isinstance(relative_cwd, str):
            raise FormatError("SOVA-LOCAL-CWD", "process cwd must be a relative string")
        cwd = (workspace / relative_cwd).resolve()
        try:
            cwd.relative_to(workspace)
        except ValueError:
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-LOCAL-WORKSPACE-ESCAPE",
            )
        if not cwd.is_dir():
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-LOCAL-CWD-MISSING",
            )
        for argument in argv[1:]:
            if argument.startswith("-") or not any(mark in argument for mark in ("/", "\\")):
                continue
            argument_path = Path(argument)
            resolved_argument = (
                argument_path.resolve()
                if argument_path.is_absolute()
                else (cwd / argument_path).resolve()
            )
            try:
                resolved_argument.relative_to(workspace)
            except ValueError:
                return ActionOutcome(
                    request.id,
                    OutcomeStatus.DENIED,
                    SideEffect.MUTATE,
                    {},
                    error_code="SOVA-LOCAL-ARGUMENT-ESCAPE",
                )
        try:
            environment = self._environment(
                request.inputs.get("env", {}),
                request.inputs.get("secretEnv", {}),
                context,
            )
        except FormatError as error:
            if not error.issue.code.startswith("SOVA-LOCAL-SECRET"):
                raise
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                SideEffect.MUTATE,
                {},
                error_code=error.issue.code,
                limitations=("Secret-provider failures never include secret values.",),
            )
        creationflags = (
            int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) if os.name == "nt" else 0
        )
        return _PreparedProcess(
            (executable, *argv[1:]),
            cwd,
            environment,
            creationflags,
            limits,
        )

    def _requested_limits(self, requested: Any) -> _RequestedLimits:
        if not isinstance(requested, dict):
            raise FormatError(
                "SOVA-LOCAL-RESOURCE-LIMIT",
                "process resources must be an object",
            )
        allowed = {"maxOutputBytes", "maxCpuSeconds", "maxMemoryBytes", "maxProcesses"}
        unknown = sorted(set(requested) - allowed)
        if unknown:
            raise FormatError(
                "SOVA-LOCAL-RESOURCE-LIMIT",
                "process resources contain unknown fields",
                details={"fields": unknown},
            )

        def optional_integer(name: str, maximum: int, minimum: int = 1) -> int | None:
            value = requested.get(name)
            if value is None:
                return None
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise FormatError(
                    "SOVA-LOCAL-RESOURCE-LIMIT",
                    f"{name} must be an integer between {minimum} and {maximum}",
                )
            return value

        output = requested.get("maxOutputBytes", self._max_output_bytes)
        if (
            isinstance(output, bool)
            or not isinstance(output, int)
            or not _MIN_OUTPUT_BYTES <= output <= self._max_output_bytes
        ):
            raise FormatError(
                "SOVA-LOCAL-RESOURCE-LIMIT",
                "maxOutputBytes must be at least 1 KiB and no greater than the executor limit",
            )
        return _RequestedLimits(
            output,
            optional_integer("maxCpuSeconds", _MAX_CPU_SECONDS),
            optional_integer("maxMemoryBytes", _MAX_MEMORY_BYTES, _MIN_MEMORY_BYTES),
            optional_integer("maxProcesses", _MAX_PROCESSES),
        )

    def _spawn_process(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        prepared = self._prepare_process(request, context)
        if isinstance(prepared, ActionOutcome):
            return prepared
        temporary = tempfile.TemporaryDirectory(prefix=".sova-background-", dir=context.workspace)
        temporary_path = Path(temporary.name)
        stdout_path = temporary_path / "stdout"
        stderr_path = temporary_path / "stderr"
        stdout_handle = stdout_path.open("wb")
        stderr_handle = stderr_path.open("wb")
        try:
            process = subprocess.Popen(  # noqa: S603
                list(prepared.argv),
                cwd=prepared.cwd,
                env=prepared.environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                shell=False,
                start_new_session=os.name != "nt",
                creationflags=prepared.creationflags,
            )
        except OSError:
            stdout_handle.close()
            stderr_handle.close()
            temporary.cleanup()
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.MUTATE,
                {},
                error_code="SOVA-LOCAL-PROCESS-START",
            )
        handle = f"sova-process:{uuid.uuid4()}"
        record = _SupervisedProcess(
            handle,
            process,
            temporary,
            stdout_handle,
            stderr_handle,
            stdout_path,
            stderr_path,
            time.monotonic() + request.timeout_seconds,
            prepared.limits.max_output_bytes,
            cancellation,
        )
        monitor = threading.Thread(
            target=self._monitor_background,
            args=(record,),
            name=f"sova-supervisor-{handle[-8:]}",
            daemon=True,
        )
        record.monitor = monitor
        with self._background_lock:
            self._background[handle] = record
        monitor.start()
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {"handle": handle, "state": "running"},
            verification="child-start-and-supervisor-observed",
            limitations=(
                "The supervised child is still ordinary host-process execution, "
                "not a security sandbox.",
                "CPU, memory, and process-count quotas were not requested.",
            ),
        )

    def _monitor_background(self, record: _SupervisedProcess) -> None:
        while True:
            with record.lock:
                if record.terminal is not None:
                    self._close_background_handles(record)
                    return
                returncode = record.process.poll()
                if returncode is not None:
                    record.terminal = (
                        OutcomeStatus.SUCCEEDED if returncode == 0 else OutcomeStatus.FAILED
                    )
                    self._close_background_handles(record)
                    return
                if record.cancellation.cancelled:
                    self._terminate_tree(record.process)
                    record.terminal = OutcomeStatus.CANCELLED
                    self._close_background_handles(record)
                    return
                if time.monotonic() >= record.deadline:
                    self._terminate_tree(record.process)
                    record.terminal = OutcomeStatus.TIMEOUT
                    self._close_background_handles(record)
                    return
                if (
                    record.stdout_path.stat().st_size > record.max_output_bytes
                    or record.stderr_path.stat().st_size > record.max_output_bytes
                ):
                    self._terminate_tree(record.process)
                    record.terminal = OutcomeStatus.PARTIAL
                    self._close_background_handles(record)
                    return
            time.sleep(0.01)

    def _background_status(self, request: ActionRequest) -> ActionOutcome:
        record = self._background_record(request)
        if isinstance(record, ActionOutcome):
            return record
        with record.lock:
            terminal = record.terminal
            if terminal is None and record.process.poll() is not None:
                terminal = (
                    OutcomeStatus.SUCCEEDED
                    if record.process.returncode == 0
                    else OutcomeStatus.FAILED
                )
                record.terminal = terminal
                self._close_background_handles(record)
            output, evidence = self._background_snapshot(record)
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.READ,
            output,
            evidence=evidence,
            verification="supervisor-state-observed",
        )

    def _stop_process(self, request: ActionRequest) -> ActionOutcome:
        record = self._background_record(request)
        if isinstance(record, ActionOutcome):
            return record
        with record.lock:
            if record.process.poll() is None:
                self._terminate_tree(record.process)
                record.terminal = OutcomeStatus.CANCELLED
            elif record.terminal is None:
                record.terminal = (
                    OutcomeStatus.SUCCEEDED
                    if record.process.returncode == 0
                    else OutcomeStatus.FAILED
                )
            self._close_background_handles(record)
            output, evidence = self._background_snapshot(record)
        if record.monitor is not None and record.monitor is not threading.current_thread():
            record.monitor.join(timeout=10)
        with self._background_lock:
            self._background.pop(record.handle, None)
        _cleanup_temporary(record.temporary)
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            output,
            evidence=evidence,
            verification="process-tree-terminal-state-observed",
        )

    def _background_record(
        self,
        request: ActionRequest,
    ) -> _SupervisedProcess | ActionOutcome:
        handle = request.inputs.get("handle")
        if not isinstance(handle, str) or not handle:
            raise FormatError(
                "SOVA-LOCAL-PROCESS-HANDLE",
                "process status/stop requires a non-empty handle",
            )
        with self._background_lock:
            record = self._background.get(handle)
        if record is None:
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                SideEffect.READ,
                {},
                error_code="SOVA-LOCAL-PROCESS-HANDLE-MISSING",
            )
        return record

    @staticmethod
    def _close_background_handles(record: _SupervisedProcess) -> None:
        if not record.stdout_handle.closed:
            record.stdout_handle.close()
        if not record.stderr_handle.closed:
            record.stderr_handle.close()

    @staticmethod
    def _background_snapshot(
        record: _SupervisedProcess,
    ) -> tuple[dict[str, Any], tuple[EvidenceReference, ...]]:
        terminal = record.terminal
        if terminal is None:
            return (
                {
                    "handle": record.handle,
                    "state": "running",
                    "stdoutBytes": record.stdout_path.stat().st_size,
                    "stderrBytes": record.stderr_path.stat().st_size,
                },
                (),
            )
        stdout_data = record.stdout_path.read_bytes()[: record.max_output_bytes]
        stderr_data = record.stderr_path.read_bytes()[: record.max_output_bytes]
        output = {
            "handle": record.handle,
            "state": "terminal",
            "childStatus": terminal.value,
            "returncode": record.process.returncode,
            "stdout": stdout_data.decode("utf-8", errors="replace"),
            "stderr": stderr_data.decode("utf-8", errors="replace"),
        }
        evidence = (
            EvidenceReference(
                "stdout",
                "text/plain",
                sha256_digest(stdout_data),
                len(stdout_data),
            ),
            EvidenceReference(
                "stderr",
                "text/plain",
                sha256_digest(stderr_data),
                len(stderr_data),
            ),
        )
        return output, evidence

    def _environment(
        self,
        requested: Any,
        secret_requested: Any,
        context: ExecutionContext,
    ) -> dict[str, str]:
        if not isinstance(requested, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in requested.items()
        ):
            raise FormatError(
                "SOVA-LOCAL-ENVIRONMENT",
                "process environment must be a string mapping",
            )
        if not isinstance(secret_requested, dict) or not all(
            isinstance(key, str)
            and isinstance(value, str)
            and _OPAQUE_SECRET_REFERENCE.fullmatch(value)
            for key, value in secret_requested.items()
        ):
            raise FormatError(
                "SOVA-LOCAL-SECRET-REFERENCE",
                "secretEnv must map allowlisted environment keys to sova-secret: references",
            )
        result = {
            key: os.environ[key]
            for key in self._environment_allowlist
            if key in os.environ and not _SECRET_ENV.search(key)
        }
        for key, value in {**context.environment, **requested}.items():
            if key not in self._environment_allowlist or _SECRET_ENV.search(key):
                raise FormatError(
                    "SOVA-LOCAL-ENVIRONMENT-DENIED",
                    "environment key is not allowlisted or is secret-shaped",
                    details={"key": key},
                )
            result[key] = value
        if secret_requested and context.secret_provider is None:
            raise FormatError(
                "SOVA-LOCAL-SECRET-PROVIDER",
                "secret references require an explicitly supplied ephemeral secret provider",
            )
        for key, reference in secret_requested.items():
            if key not in self._environment_allowlist:
                raise FormatError(
                    "SOVA-LOCAL-ENVIRONMENT-DENIED",
                    "secret environment key is not allowlisted",
                    details={"key": key},
                )
            if key in requested or key in context.environment:
                raise FormatError(
                    "SOVA-LOCAL-SECRET-CONFLICT",
                    "an environment key cannot be supplied as both plaintext "
                    "and a secret reference",
                    details={"key": key},
                )
            if context.secret_provider is None:
                raise FormatError(
                    "SOVA-LOCAL-SECRET-PROVIDER",
                    "secret provider became unavailable before resolution",
                )
            try:
                secret = context.secret_provider.resolve(reference)
            except Exception as error:
                raise FormatError(
                    "SOVA-LOCAL-SECRET-RESOLUTION",
                    "the secret provider failed without exposing its reference or value",
                ) from error
            if not isinstance(secret, str):
                raise FormatError(
                    "SOVA-LOCAL-SECRET-RESOLUTION",
                    "the secret provider returned a non-string value",
                )
            result[key] = secret
        return result

    def _wait(  # noqa: PLR0913, PLR0917 - explicit I/O limits avoid hidden state
        self,
        process: subprocess.Popen[bytes],
        stdout_path: Path,
        stderr_path: Path,
        timeout_seconds: float,
        max_output_bytes: int,
        cancellation: CancellationToken,
    ) -> OutcomeStatus | None:
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if cancellation.cancelled:
                self._terminate_tree(process)
                return OutcomeStatus.CANCELLED
            if time.monotonic() >= deadline:
                self._terminate_tree(process)
                return OutcomeStatus.TIMEOUT
            if (
                stdout_path.stat().st_size > max_output_bytes
                or stderr_path.stat().st_size > max_output_bytes
            ):
                self._terminate_tree(process)
                return OutcomeStatus.PARTIAL
            time.sleep(0.01)
        return None

    @staticmethod
    def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            taskkill = (
                Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
            )
            if taskkill.is_file():
                try:
                    completed = subprocess.run(  # noqa: S603
                        [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        capture_output=True,
                        timeout=10,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
                else:
                    if completed.returncode != 0 and process.poll() is None:
                        process.kill()
            else:
                process.kill()
        else:
            killpg = getattr(os, "killpg", None)
            sigkill = getattr(signal, "SIGKILL", signal.SIGTERM)
            if killpg is None:
                process.kill()
            else:
                killpg(process.pid, sigkill)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


__all__ = ["RestrictedLocalExecutor"]
