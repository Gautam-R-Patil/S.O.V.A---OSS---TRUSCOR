# SPDX-License-Identifier: Apache-2.0
"""Executor selection, verification, bounded recovery, and failover policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.executors import Capability, Executor

_MAX_RECOVERY_ATTEMPTS = 10


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Independent observation of the requested postcondition."""

    verified: bool
    method: str
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class OutcomeVerifier(Protocol):
    def __call__(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        context: ExecutionContext,
    ) -> VerificationResult: ...


@dataclass(frozen=True, slots=True)
class BackendCandidate:
    executor: Executor
    priority: int


@dataclass(frozen=True, slots=True)
class ReliabilityAttempt:
    executor: str
    attempt: int
    outcome_status: str
    failure_cause: str
    verification: VerificationResult
    fallback_allowed: bool

    def to_mapping(self) -> dict[str, object]:
        return {
            "executor": self.executor,
            "attempt": self.attempt,
            "outcomeStatus": self.outcome_status,
            "failureCause": self.failure_cause,
            "verification": {
                "verified": self.verification.verified,
                "method": self.verification.method,
                "evidenceIds": list(self.verification.evidence_ids),
                "limitations": list(self.verification.limitations),
            },
            "fallbackAllowed": self.fallback_allowed,
        }


@dataclass(frozen=True, slots=True)
class ReliableExecutionResult:
    outcome: ActionOutcome
    attempts: tuple[ReliabilityAttempt, ...]
    checkpoint: dict[str, object]


class ExecutionReliabilityPlane:
    """Route one action while preserving SOVA policy outside adapters."""

    def __init__(
        self,
        candidates: tuple[BackendCandidate, ...],
        *,
        max_attempts: int = 3,
    ) -> None:
        if not candidates or not 1 <= max_attempts <= _MAX_RECOVERY_ATTEMPTS:
            raise FormatError("SOVA-RELIABILITY-CONFIG", "invalid reliability-plane config")
        names = [candidate.executor.name for candidate in candidates]
        if len(names) != len(set(names)):
            raise FormatError("SOVA-RELIABILITY-CONFIG", "executor names must be unique")
        self._candidates = tuple(
            sorted(candidates, key=lambda item: (item.priority, item.executor.name))
        )
        self._max_attempts = max_attempts

    @staticmethod
    def _capability(executor: Executor, request: ActionRequest) -> Capability | None:
        return next(
            (item for item in executor.capabilities() if item.name == request.action),
            None,
        )

    @staticmethod
    def _can_fallback(capability: Capability, outcome: ActionOutcome) -> bool:
        if outcome.status in {OutcomeStatus.UNSUPPORTED, OutcomeStatus.DENIED}:
            return outcome.status == OutcomeStatus.UNSUPPORTED
        if capability.idempotent and outcome.status in {
            OutcomeStatus.FAILED,
            OutcomeStatus.TIMEOUT,
            OutcomeStatus.PARTIAL,
        }:
            return outcome.retryable or outcome.failure_cause in {
                FailureCause.EXECUTOR,
                FailureCause.ENVIRONMENT,
                FailureCause.TIMEOUT,
                FailureCause.EVIDENCE,
            }
        return False

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
        verifier: OutcomeVerifier,
    ) -> ReliableExecutionResult:
        attempts: list[ReliabilityAttempt] = []
        final = ActionOutcome(
            request.id,
            OutcomeStatus.UNSUPPORTED,
            SideEffect.READ,
            {},
            verification="not-performed",
            error_code="SOVA-RELIABILITY-NO-BACKEND",
            failure_cause=FailureCause.UNSUPPORTED,
        )
        for candidate in self._candidates:
            if len(attempts) >= self._max_attempts or cancellation.cancelled:
                break
            capability = self._capability(candidate.executor, request)
            if capability is None:
                continue
            retried = ActionRequest(
                request.id,
                request.action,
                request.inputs,
                request.timeout_seconds,
                retry_attempt=len(attempts),
            )
            try:
                outcome = candidate.executor.execute(retried, context, cancellation)
            except Exception:  # noqa: BLE001 - adapter boundary is normalized
                outcome = ActionOutcome(
                    request.id,
                    OutcomeStatus.FAILED,
                    capability.side_effect,
                    {},
                    verification="adapter-exception-message-omitted",
                    retryable=True,
                    error_code="SOVA-EXECUTOR-EXCEPTION",
                    failure_cause=FailureCause.EXECUTOR,
                )
            if outcome.status == OutcomeStatus.SUCCEEDED:
                verification = verifier(retried, outcome, context)
                if verification.verified:
                    attempts.append(
                        ReliabilityAttempt(
                            executor=candidate.executor.name,
                            attempt=len(attempts),
                            outcome_status=outcome.status.value,
                            failure_cause=outcome.failure_cause.value,
                            verification=verification,
                            fallback_allowed=False,
                        )
                    )
                    return ReliableExecutionResult(
                        outcome,
                        tuple(attempts),
                        self._checkpoint(request, attempts, "verified"),
                    )
                outcome = ActionOutcome(
                    outcome.request_id,
                    OutcomeStatus.PARTIAL,
                    outcome.side_effect,
                    outcome.output,
                    outcome.evidence,
                    verification=verification.method,
                    retryable=capability.idempotent,
                    error_code="SOVA-POSTCONDITION-NOT-VERIFIED",
                    limitations=(*outcome.limitations, *verification.limitations),
                    failure_cause=FailureCause.EVIDENCE,
                )
            else:
                verification = VerificationResult(
                    verified=False,
                    method="not-applicable-unsuccessful-action",
                    limitations=("Postcondition verification requires a succeeded action.",),
                )
            fallback_allowed = self._can_fallback(capability, outcome)
            attempts.append(
                ReliabilityAttempt(
                    candidate.executor.name,
                    len(attempts),
                    outcome.status.value,
                    outcome.failure_cause.value,
                    verification,
                    fallback_allowed,
                )
            )
            final = outcome
            if not fallback_allowed:
                break
        if cancellation.cancelled:
            final = ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                final.side_effect,
                {},
                verification="cancelled-before-verified-completion",
                error_code="SOVA-RELIABILITY-CANCELLED",
                failure_cause=FailureCause.CANCELLATION,
            )
        return ReliableExecutionResult(
            final,
            tuple(attempts),
            self._checkpoint(request, attempts, final.status.value),
        )

    @staticmethod
    def _checkpoint(
        request: ActionRequest,
        attempts: list[ReliabilityAttempt],
        state: str,
    ) -> dict[str, object]:
        """Return restart metadata without action inputs, cookies, or credentials."""
        return {
            "requestId": request.id,
            "action": request.action,
            "state": state,
            "attemptCount": len(attempts),
            "executors": [attempt.executor for attempt in attempts],
            "inputsPersisted": False,
            "sessionMaterialPersisted": False,
        }


__all__ = [
    "BackendCandidate",
    "ExecutionReliabilityPlane",
    "OutcomeVerifier",
    "ReliabilityAttempt",
    "ReliableExecutionResult",
    "VerificationResult",
]
