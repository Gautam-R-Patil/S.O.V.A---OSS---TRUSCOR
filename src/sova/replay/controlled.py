# SPDX-License-Identifier: Apache-2.0
"""Controlled re-execution linked to immutable source evidence."""

from __future__ import annotations

import platform
import sys
from typing import TYPE_CHECKING, Any

from sova.executors import CancellationToken, Executor, SecretProvider, run_capsule
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.replay.model import (
    ConditionDrift,
    ControlledReexecutionReport,
    ReplayMode,
)
from sova.replay.verification import verify_artifact
from sova.reproduction import compare_observable_outcomes
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from sova.safety.authorization import ApprovalToken, AuthorizationSession


def _condition_drift(source: dict[str, Any], executor: Executor) -> tuple[ConditionDrift, ...]:
    declared = {
        "platform": source["environment"]["platform"],
        "python": source["environment"]["python"],
        "executor": source["executor"]["name"],
    }
    current = {
        "platform": platform.system().casefold(),
        "python": platform.python_version() or sys.version.split()[0],
        "executor": executor.name,
    }
    return tuple(
        ConditionDrift(
            name,
            declared[name],
            current[name],
            "equivalent" if declared[name] == current[name] else "changed",
        )
        for name in sorted(declared)
    )


def controlled_reexecute(  # noqa: PLR0913 - explicit authority inputs stay visible
    capsule: Path,
    source_trace: Path,
    destination: Path,
    *,
    executor: Executor,
    workspace: Path,
    authorization: dict[str, Any] | None = None,
    authorization_session: AuthorizationSession | None = None,
    approvals: Mapping[str, ApprovalToken] | None = None,
    cancellation: CancellationToken | None = None,
    secret_provider: SecretProvider | None = None,
) -> ControlledReexecutionReport:
    """Perform a fresh run, preserving source bytes and reporting condition drift."""
    resolved_source = source_trace.resolve()
    resolved_destination = destination.resolve()
    if resolved_source == resolved_destination or resolved_destination.exists():
        raise FormatError(
            "SOVA-REPLAY-IMMUTABLE-SOURCE",
            "controlled re-execution requires a new destination path",
        )
    source_verification = verify_artifact(source_trace)
    if not source_verification.accepted:
        raise FormatError(
            "SOVA-REPLAY-SOURCE-INVALID",
            "source trace must pass offline integrity verification",
        )
    capsule_verification = verify_artifact(capsule)
    if not capsule_verification.accepted:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-INVALID",
            "capsule must pass offline integrity verification",
        )
    source_manifest = TraceReader(source_trace).manifest()
    drift = _condition_drift(source_manifest, executor)
    source_digest = sha256_digest(source_trace.read_bytes())
    result = run_capsule(
        capsule,
        destination,
        executor=executor,
        workspace=workspace,
        authorization=authorization,
        authorization_session=authorization_session,
        approvals=approvals,
        cancellation=cancellation,
        secret_provider=secret_provider,
        source_trace_digest=source_digest,
        condition_drift=tuple(item.to_mapping() for item in drift),
    )
    comparison = compare_observable_outcomes(
        source_trace,
        destination,
        kinds=("oracle.completed",),
    )
    return ControlledReexecutionReport(
        ReplayMode.CONTROLLED_REEXECUTION,
        source_digest,
        str(destination),
        result.completion,
        comparison.status,
        drift,
        (
            "A fresh authorization applies only to this re-execution.",
            "Equivalent observable outcomes do not imply identical hidden model state.",
            "Changed conditions are reported, not silently normalized away.",
        ),
    )


__all__ = ["controlled_reexecute"]
