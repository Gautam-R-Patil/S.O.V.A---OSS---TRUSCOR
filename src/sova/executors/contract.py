# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral executor contract with explicit effects and outcomes."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_TIMEOUT_SECONDS = 3600

class SideEffect(StrEnum):
    """Maximum declared side effect of an executor capability."""

    READ = "read"
    MUTATE = "mutate"
    DESTRUCTIVE = "destructive"


class OutcomeStatus(StrEnum):
    """Normalized terminal state of one attempted action."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    DENIED = "denied"
    UNSUPPORTED = "unsupported"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class Capability:
    """One exact executor feature and its retry/effect contract."""

    name: str
    version: str
    side_effect: SideEffect
    idempotent: bool
    evidence: tuple[str, ...]

    @property
    def identifier(self) -> str:
        return f"{self.name}/{self.version}"


@dataclass(frozen=True, slots=True)
class CapabilityReport:
    """Negotiation result that never silently substitutes a required feature."""

    supported: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def compatible(self) -> bool:
        return not self.missing


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """One bounded abstract action request."""

    id: str
    action: str
    inputs: dict[str, Any]
    timeout_seconds: float
    retry_attempt: int = 0

    def __post_init__(self) -> None:
        if not self.id or not self.action:
            raise FormatError(
                "SOVA-EXECUTOR-REQUEST",
                "action request requires non-empty id and action",
            )
        if self.timeout_seconds <= 0 or self.timeout_seconds > _MAX_TIMEOUT_SECONDS:
            raise FormatError(
                "SOVA-EXECUTOR-TIMEOUT",
                "action timeout must be greater than zero and at most one hour",
            )
        if self.retry_attempt < 0:
            raise FormatError(
                "SOVA-EXECUTOR-RETRY",
                "retry attempt cannot be negative",
            )


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Content identity for output captured by an executor."""

    role: str
    media_type: str
    digest: str
    size: int


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    """Normalized provider result with explicit verification and limitations."""

    request_id: str
    status: OutcomeStatus
    side_effect: SideEffect
    output: dict[str, Any]
    evidence: tuple[EvidenceReference, ...] = ()
    verification: str = "not-performed"
    retryable: bool = False
    error_code: str | None = None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Secret-free confined context supplied by the SOVA orchestration layer."""

    workspace: Path
    authorization: dict[str, Any]
    artifacts: dict[str, bytes] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.workspace.resolve().is_dir():
            raise FormatError(
                "SOVA-EXECUTOR-WORKSPACE",
                "executor workspace must be an existing directory",
            )


class CancellationToken:
    """Thread-safe cooperative cancellation signal."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class Executor(Protocol):
    """Minimal adapter boundary; security policy and judging stay outside it."""

    @property
    def name(self) -> str: ...

    def capabilities(self) -> tuple[Capability, ...]: ...

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome: ...


def negotiate(
    capabilities: tuple[Capability, ...],
    required: list[str] | tuple[str, ...],
) -> CapabilityReport:
    """Compare exact required feature identifiers against advertised support."""
    supported = tuple(sorted(capability.identifier for capability in capabilities))
    available = set(supported)
    missing = tuple(sorted(set(required) - available))
    return CapabilityReport(supported=supported, missing=missing)


__all__ = [
    "ActionOutcome",
    "ActionRequest",
    "CancellationToken",
    "Capability",
    "CapabilityReport",
    "EvidenceReference",
    "ExecutionContext",
    "Executor",
    "OutcomeStatus",
    "SideEffect",
    "negotiate",
]
