# SPDX-License-Identifier: Apache-2.0
"""Deterministic executor for conformance, replay, and fault injection."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError


@dataclass(frozen=True, slots=True)
class ScriptedAction:
    """One exact expected action and deterministic outcome."""

    action: str
    expected_inputs: dict[str, Any]
    status: OutcomeStatus
    output: dict[str, Any]
    side_effect: SideEffect = SideEffect.READ
    evidence: tuple[tuple[str, str, bytes], ...] = ()
    verification: str = "scripted-observation"
    retryable: bool = False
    error_code: str | None = None
    limitations: tuple[str, ...] = ("Synthetic deterministic executor result.",)
    failure_cause: FailureCause = FailureCause.NONE


class ScriptedExecutor:
    """Consume a fixed script and fail visibly if orchestration drifts."""

    name = "sova-scripted"

    def __init__(
        self,
        script: list[ScriptedAction],
        *,
        advertised: tuple[Capability, ...] | None = None,
    ) -> None:
        self._script = deque(script)
        if advertised is None:
            pairs = {(step.action, step.side_effect) for step in script}
            advertised = tuple(
                Capability(
                    name=action,
                    version="0.1",
                    side_effect=effect,
                    idempotent=effect == SideEffect.READ,
                    evidence=("scripted-result",),
                )
                for action, effect in sorted(pairs, key=lambda item: item[0])
            )
        self._capabilities = advertised

    @property
    def complete(self) -> bool:
        return not self._script

    def capabilities(self) -> tuple[Capability, ...]:
        return self._capabilities

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        capability = next(
            (item for item in self._capabilities if item.name == request.action),
            None,
        )
        if capability is None:
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-EXECUTOR-UNSUPPORTED",
                limitations=("No scripted capability was advertised.",),
            )
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                capability.side_effect,
                {},
                error_code="SOVA-EXECUTOR-CANCELLED",
            )
        if not self._script:
            raise FormatError(
                "SOVA-SCRIPTED-EXHAUSTED",
                "scripted executor received more actions than declared",
            )
        step = self._script.popleft()
        if step.action != request.action or canonical_json_bytes(step.expected_inputs) != (
            canonical_json_bytes(request.inputs)
        ):
            raise FormatError(
                "SOVA-SCRIPTED-MISMATCH",
                "scripted executor request differs from the expected fixture",
                details={
                    "expectedAction": step.action,
                    "actualAction": request.action,
                },
            )
        evidence = tuple(
            EvidenceReference(
                role=role,
                media_type=media_type,
                digest=sha256_digest(data),
                size=len(data),
            )
            for role, media_type, data in step.evidence
        )
        return ActionOutcome(
            request_id=request.id,
            status=step.status,
            side_effect=step.side_effect,
            output=step.output,
            evidence=evidence,
            verification=step.verification,
            retryable=step.retryable,
            error_code=step.error_code,
            limitations=step.limitations,
            failure_cause=step.failure_cause,
        )


__all__ = ["ScriptedAction", "ScriptedExecutor"]
