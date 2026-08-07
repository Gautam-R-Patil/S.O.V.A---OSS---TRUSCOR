# SPDX-License-Identifier: Apache-2.0
"""Shell-free subprocess runner for untrusted-by-default extension processes."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from typing import BinaryIO

    from sova.extensions.model import ExtensionManifest

_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 60
_MAX_COMMAND_ARGUMENTS = 64
_MAX_ARGUMENT_LENGTH = 4096
_READ_CHUNK_BYTES = 64 * 1024


def _bounded_read(
    stream: BinaryIO,
    chunks: list[bytes],
    *,
    overflow: threading.Event,
    fatal_overflow: bool,
) -> None:
    retained = 0
    while True:
        chunk = stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            return
        available = max(0, _MAX_OUTPUT_BYTES - retained)
        if available:
            chunks.append(chunk[:available])
            retained += min(len(chunk), available)
        if len(chunk) > available:
            overflow.set()
            if fatal_overflow:
                return


@dataclass(frozen=True, slots=True)
class ExtensionRunResult:
    manifest_digest: str
    operation: str
    response: dict[str, Any]
    stderr_truncated: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "manifestDigest": self.manifest_digest,
            "operation": self.operation,
            "response": self.response,
            "stderrTruncated": self.stderr_truncated,
        }


class SubprocessExtensionRunner:
    """Run one explicitly allowed executable; this is isolation, not a security sandbox."""

    def __init__(
        self,
        manifest: ExtensionManifest,
        command: tuple[str, ...],
        *,
        executable_allowlist: tuple[Path, ...],
        working_directory: Path,
        timeout_seconds: float = 10.0,
    ) -> None:
        if manifest.isolation != "subprocess":
            raise FormatError("SOVA-EXTENSION-ISOLATION", "subprocess isolation is required")
        if not command:
            raise FormatError("SOVA-EXTENSION-COMMAND", "extension command is empty")
        if len(command) > _MAX_COMMAND_ARGUMENTS or any(
            not item or len(item) > _MAX_ARGUMENT_LENGTH or "\x00" in item for item in command
        ):
            raise FormatError("SOVA-EXTENSION-COMMAND", "extension command exceeds limits")
        executable = Path(command[0]).resolve()
        if executable not in {item.resolve() for item in executable_allowlist}:
            raise FormatError("SOVA-EXTENSION-EXECUTABLE", "executable is not exactly allowlisted")
        if not working_directory.resolve().is_dir():
            raise FormatError("SOVA-EXTENSION-CWD", "working directory does not exist")
        if not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise FormatError("SOVA-EXTENSION-TIMEOUT", "timeout must be within 60 seconds")
        self.manifest = manifest
        self.command = command
        self.working_directory = working_directory.resolve()
        self.timeout_seconds = timeout_seconds

    def _communicate_bounded(self, request: dict[str, Any]) -> tuple[bytes, bool, int]:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
            "SOVA_EXTENSION_ID": self.manifest.identifier,
        }
        process = subprocess.Popen(  # noqa: S603 - exact executable allowlist above
            list(self.command),
            cwd=self.working_directory,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            process.kill()
            raise FormatError("SOVA-EXTENSION-PIPE", "extension pipes are unavailable")
        output_chunks: list[bytes] = []
        error_chunks: list[bytes] = []
        output_overflow = threading.Event()
        error_overflow = threading.Event()
        readers = (
            threading.Thread(
                target=_bounded_read,
                args=(process.stdout, output_chunks),
                kwargs={"overflow": output_overflow, "fatal_overflow": True},
                daemon=True,
            ),
            threading.Thread(
                target=_bounded_read,
                args=(process.stderr, error_chunks),
                kwargs={"overflow": error_overflow, "fatal_overflow": False},
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        try:
            process.stdin.write(canonical_json_bytes(request) + b"\n")
            process.stdin.close()
        except BrokenPipeError:
            process.stdin.close()
        deadline = time.monotonic() + self.timeout_seconds
        timed_out = False
        while process.poll() is None:
            if output_overflow.wait(timeout=0.02):
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
        process.wait()
        for reader in readers:
            reader.join(timeout=1)
        process.stdout.close()
        process.stderr.close()
        if timed_out:
            raise FormatError("SOVA-EXTENSION-TIMEOUT", "extension exceeded its time budget")
        if output_overflow.is_set():
            raise FormatError("SOVA-EXTENSION-OUTPUT-LIMIT", "extension output exceeded limit")
        return b"".join(output_chunks), error_overflow.is_set(), process.returncode

    def run(self, operation: str, payload: dict[str, Any]) -> ExtensionRunResult:
        if operation not in {"describe", "self-test", "invoke"}:
            raise FormatError("SOVA-EXTENSION-OPERATION", "unsupported extension operation")
        request = {
            "protocol": "sova.extension-jsonl/0.1",
            "manifestDigest": self.manifest.digest,
            "operation": operation,
            "payload": payload,
        }
        output, error_truncated, return_code = self._communicate_bounded(request)
        if return_code != 0:
            raise FormatError(
                "SOVA-EXTENSION-FAILED",
                "extension process failed",
                details={"returnCode": return_code},
            )
        rows = output.splitlines()
        if len(rows) != 1:
            raise FormatError(
                "SOVA-EXTENSION-PROTOCOL", "extension must return exactly one JSON row"
            )
        response = strict_json_loads(rows[0], max_bytes=_MAX_OUTPUT_BYTES)
        if not isinstance(response, dict):
            raise FormatError("SOVA-EXTENSION-PROTOCOL", "extension response must be an object")
        if response.get("manifestDigest") != self.manifest.digest:
            raise FormatError("SOVA-EXTENSION-SUBSTITUTION", "extension manifest binding failed")
        if (
            response.get("protocol") != "sova.extension-jsonl/0.1"
            or response.get("operation") != operation
            or not isinstance(response.get("accepted"), bool)
        ):
            raise FormatError(
                "SOVA-EXTENSION-PROTOCOL",
                "extension response protocol, operation, or acceptance is invalid",
            )
        return ExtensionRunResult(
            self.manifest.digest,
            operation,
            response,
            error_truncated,
        )

    def conform(self) -> dict[str, Any]:
        described = self.run("describe", {})
        tested = self.run("self-test", {})
        return {
            "artifactType": "sova.extension-conformance",
            "manifestDigest": self.manifest.digest,
            "describePassed": described.response.get("accepted") is True,
            "selfTestPassed": tested.response.get("accepted") is True,
            "isolation": "subprocess-not-security-sandbox",
        }
