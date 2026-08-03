# SPDX-License-Identifier: Apache-2.0
"""Fail-closed local process tracing through the existing executor contract."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from time import monotonic_ns
from typing import Any

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
    RestrictedLocalExecutor,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import TraceWriter, generate_ed25519_keypair
from sova.trace.kinds import validate_event_kind

_MAX_TIMEOUT_SECONDS = 3600


def _process_specification(value: Mapping[str, Any]) -> tuple[tuple[str, ...], Path, float, str]:
    argv = value.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        raise FormatError("SOVA-TRACE-ARGV", "argv must be a non-empty string array")
    cwd = value.get("workingDirectory")
    if not isinstance(cwd, str) or not cwd:
        raise FormatError("SOVA-TRACE-CWD", "workingDirectory must be a path string")
    timeout = value.get("timeoutSeconds", 60)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise FormatError("SOVA-TRACE-TIMEOUT", "timeoutSeconds must be numeric")
    if not 0 < float(timeout) <= _MAX_TIMEOUT_SECONDS:
        raise FormatError("SOVA-TRACE-TIMEOUT", "timeoutSeconds is outside the supported range")
    capture = value.get("captureProfile", "standard")
    if capture not in {"lite", "standard", "forensic", "interpretability"}:
        raise FormatError("SOVA-TRACE-PROFILE", "captureProfile is unsupported")
    if value.get("authorizationConfirmed") is not True:
        raise FormatError(
            "SOVA-TRACE-AUTHORIZATION",
            "local process recording requires explicit authorization confirmation",
        )
    return tuple(argv), Path(cwd).resolve(), float(timeout), str(capture)


def record_local_process(
    specification: Mapping[str, Any],
    destination: Path,
) -> dict[str, Any]:
    """Record one allowlisted shell-free process invocation into a signed trace."""
    argv, cwd, timeout, capture = _process_specification(specification)
    if not cwd.is_dir():
        raise FormatError("SOVA-TRACE-CWD", "workingDirectory must exist")
    executable = Path(argv[0]).resolve()
    allowlist = specification.get("executableAllowlist")
    if not isinstance(allowlist, list) or any(not isinstance(item, str) for item in allowlist):
        raise FormatError("SOVA-TRACE-ALLOWLIST", "executableAllowlist must contain paths")
    allowed = tuple(Path(item).resolve() for item in allowlist)
    if executable not in allowed:
        raise FormatError("SOVA-TRACE-EXECUTABLE", "executable is not in the exact allowlist")
    observed = specification.get("observedEvents", [])
    if not isinstance(observed, list) or any(not isinstance(item, Mapping) for item in observed):
        raise FormatError("SOVA-TRACE-EVENTS", "observedEvents must contain objects")
    key = generate_ed25519_keypair()
    writer = TraceWriter(
        destination,
        capture_profile=capture,
        signing_key=key,
        authorization={
            "decision": "allowed",
            "scopeDigest": sha256_digest(canonical_json_bytes({"cwd": str(cwd)})),
            "decidedBy": "explicit-human-confirmation",
        },
        executor={
            "id": "sova:executor:restricted-local",
            "name": "sova-restricted-local",
            "version": "0.1.0",
            "capabilityDigest": None,
        },
    )
    recorder_start = monotonic_ns()
    start = writer.append("run.started", {"argv": list(argv), "cwd": str(cwd)})
    request_event = writer.append(
        "process.requested",
        {"executable": str(executable), "argumentCount": len(argv) - 1},
        parents=[start] if start else [],
    )
    request = ActionRequest("trace-process", "process.exec", {"argv": list(argv)}, timeout)
    process_start = monotonic_ns()
    with RestrictedLocalExecutor(executable_allowlist=allowed) as executor:
        outcome = executor.execute(
            request,
            ExecutionContext(cwd, {"decision": "allowed"}),
            CancellationToken(),
        )
    process_elapsed = monotonic_ns() - process_start
    parent = writer.append(
        "process.completed",
        {
            "status": outcome.status.value,
            "returncode": outcome.output.get("returncode"),
            "stdout": outcome.output.get("stdout", ""),
            "stderr": outcome.output.get("stderr", ""),
            "errorCode": outcome.error_code,
            "limitations": list(outcome.limitations),
        },
        parents=[request_event] if request_event else [],
    )
    for item in observed:
        kind = item.get("kind")
        payload = item.get("payload", {})
        if not isinstance(kind, str) or not isinstance(payload, dict):
            raise FormatError("SOVA-TRACE-EVENTS", "observed event requires kind and payload")
        validate_event_kind(kind)
        parent = writer.append(kind, payload, parents=[parent] if parent else [])
    terminal_kind = "run.completed" if outcome.status == OutcomeStatus.SUCCEEDED else "run.failed"
    writer.append(
        terminal_kind,
        {"status": outcome.status.value},
        parents=[parent] if parent else [],
    )
    completion = {
        OutcomeStatus.SUCCEEDED: "completed",
        OutcomeStatus.TIMEOUT: "timeout",
        OutcomeStatus.CANCELLED: "cancelled",
        OutcomeStatus.PARTIAL: "partial",
    }.get(outcome.status, "failed")
    digest = writer.finalize(completion=completion)
    recording_elapsed = monotonic_ns() - recorder_start
    instrumentation_elapsed = max(0, recording_elapsed - process_elapsed)
    return {
        "artifactType": "sova.trace-run-report",
        "schemaVersion": "0.1.0",
        "trace": str(destination.resolve()),
        "traceDigest": digest,
        "signed": True,
        "trustPolicy": "included-key-integrity-only",
        "processStatus": outcome.status.value,
        "returncode": outcome.output.get("returncode"),
        "recordedEventCount": writer.event_count,
        "recordingElapsedNs": recording_elapsed,
        "processElapsedNs": process_elapsed,
        "instrumentationElapsedNs": instrumentation_elapsed,
        "instrumentationOverheadRatio": (
            str(instrumentation_elapsed / process_elapsed) if process_elapsed else None
        ),
        "captureProfile": capture,
        "instrumentationCoverage": {
            "process": "direct",
            "modelToolMcpMemoryRetrievalBrowserComputerEgress": "adapter-emitted-when-available",
        },
        "limitations": [
            "Restricted local execution is not a security sandbox.",
            "Recording overhead is elapsed instrumentation-path time, not a causal benchmark.",
        ],
    }


__all__ = ["record_local_process"]
