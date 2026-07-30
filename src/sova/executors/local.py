# SPDX-License-Identifier: Apache-2.0
"""Restricted local executor; explicitly not a security sandbox."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

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
_DEFAULT_ENV = frozenset({"SYSTEMROOT", "WINDIR", "TEMP", "TMP"})
_MIN_OUTPUT_BYTES = 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


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
            capabilities.append(
                Capability(
                    name="process.exec",
                    version="0.1",
                    side_effect=SideEffect.MUTATE,
                    idempotent=False,
                    evidence=("stdout", "stderr", "returncode"),
                )
            )
        return tuple(capabilities)

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
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
        argv = request.inputs.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(value, str) and value for value in argv)
        ):
            raise FormatError(
                "SOVA-LOCAL-ARGV",
                "process.exec requires a non-empty string argv array",
            )
        executable = str(Path(argv[0]).resolve())
        if not Path(argv[0]).is_absolute():
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
        environment = self._environment(request.inputs.get("env", {}), context)
        creationflags = (
            int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) if os.name == "nt" else 0
        )
        with tempfile.TemporaryDirectory(prefix=".sova-process-", dir=workspace) as temporary:
            temporary_path = Path(temporary)
            stdout_path = temporary_path / "stdout"
            stderr_path = temporary_path / "stderr"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(  # noqa: S603
                    [executable, *argv[1:]],
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    start_new_session=os.name != "nt",
                    creationflags=creationflags,
                )
                status = self._wait(
                    process,
                    stdout_path,
                    stderr_path,
                    request.timeout_seconds,
                    cancellation,
                )
            if status is None and (
                stdout_path.stat().st_size > self._max_output_bytes
                or stderr_path.stat().st_size > self._max_output_bytes
            ):
                status = OutcomeStatus.PARTIAL
            stdout_data = stdout_path.read_bytes()[: self._max_output_bytes]
            stderr_data = stderr_path.read_bytes()[: self._max_output_bytes]
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
            ),
        )

    def _environment(
        self,
        requested: Any,
        context: ExecutionContext,
    ) -> dict[str, str]:
        if not isinstance(requested, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in requested.items()
        ):
            raise FormatError(
                "SOVA-LOCAL-ENVIRONMENT",
                "process environment must be a string mapping",
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
        return result

    def _wait(
        self,
        process: subprocess.Popen[bytes],
        stdout_path: Path,
        stderr_path: Path,
        timeout_seconds: float,
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
                stdout_path.stat().st_size > self._max_output_bytes
                or stderr_path.stat().st_size > self._max_output_bytes
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
                subprocess.run(  # noqa: S603
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
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
