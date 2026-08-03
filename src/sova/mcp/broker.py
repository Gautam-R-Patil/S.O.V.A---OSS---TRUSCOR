# SPDX-License-Identifier: Apache-2.0
"""Capability-routed execution broker that preserves permanent no-MELRA operation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    Executor,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.runtime import BackendCandidate, ExecutionReliabilityPlane, VerificationResult

if TYPE_CHECKING:
    from collections.abc import Sequence


class CapabilityExecutionBroker:
    """Expose a union of executor capabilities while preserving explicit fallback."""

    name = "sova-capability-broker"

    def __init__(self, executors: Sequence[Executor], *, max_attempts: int = 3) -> None:
        if not executors:
            raise FormatError("SOVA-BROKER-CONFIG", "at least one executor is required")
        self._executors = tuple(executors)
        self._plane = ExecutionReliabilityPlane(
            tuple(
                BackendCandidate(executor=executor, priority=index)
                for index, executor in enumerate(self._executors)
            ),
            max_attempts=max_attempts,
        )

    def capabilities(self) -> tuple[Capability, ...]:
        selected: dict[str, Capability] = {}
        for executor in self._executors:
            for capability in executor.capabilities():
                selected.setdefault(capability.identifier, capability)
        return tuple(selected[key] for key in sorted(selected))

    @staticmethod
    def _verify(
        request: ActionRequest,
        outcome: ActionOutcome,
        context: ExecutionContext,
    ) -> VerificationResult:
        del request, context
        verified = outcome.verification not in {
            "not-performed",
            "provider-result-only",
            "observation-failed",
            "melra-result-defense-in-depth-only",
        }
        return VerificationResult(
            verified,
            outcome.verification,
            tuple(item.digest for item in outcome.evidence),
            () if verified else ("No independent post-action observation was available.",),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        result = self._plane.execute(request, context, cancellation, self._verify)
        output = dict(result.outcome.output)
        output["sovaBroker"] = {
            "attempts": [attempt.to_mapping() for attempt in result.attempts],
            "checkpoint": result.checkpoint,
        }
        return ActionOutcome(
            result.outcome.request_id,
            result.outcome.status,
            result.outcome.side_effect,
            output,
            result.outcome.evidence,
            result.outcome.verification,
            result.outcome.retryable,
            result.outcome.error_code,
            result.outcome.limitations,
            result.outcome.failure_cause,
        )

    def close(self) -> None:
        for executor in self._executors:
            close = getattr(executor, "close", None)
            if callable(close):
                close()


class UnavailableCapabilityExecutor:
    """Visible placeholder used when an optional external backend is absent."""

    def __init__(self, name: str, capabilities: tuple[Capability, ...], reason: str) -> None:
        self._name = name
        self._capabilities = capabilities
        self._reason = reason

    @property
    def name(self) -> str:
        return self._name

    def capabilities(self) -> tuple[Capability, ...]:
        return self._capabilities

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context, cancellation
        capability = next(
            (item for item in self._capabilities if item.name == request.action), None
        )
        return ActionOutcome(
            request.id,
            OutcomeStatus.UNSUPPORTED,
            SideEffect.READ if capability is None else capability.side_effect,
            {"backend": self.name, "reason": self._reason},
            error_code="SOVA-OPTIONAL-BACKEND-UNAVAILABLE",
        )


__all__ = ["CapabilityExecutionBroker", "UnavailableCapabilityExecutor"]
