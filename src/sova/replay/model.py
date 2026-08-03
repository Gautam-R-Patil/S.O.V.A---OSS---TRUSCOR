# SPDX-License-Identifier: Apache-2.0
"""Typed results for playback, re-execution, and semantic reproduction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


def _decimal(value: float) -> str:
    return format(value, ".12g")


class ReplayMode(StrEnum):
    """Operations that must never be presented as interchangeable."""

    PLAYBACK = "trace-playback"
    CONTROLLED_REEXECUTION = "controlled-reexecution"
    SEMANTIC_REPRODUCTION = "semantic-reproduction"


class VerificationState(StrEnum):
    """Bounded artifact verification result."""

    VERIFIED = "verified"
    PARTIAL = "partial"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class CheckState(StrEnum):
    """State of one independently reportable verification check."""

    PASSED = "passed"
    NOT_PRESENT = "not-present"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class ReproductionClass(StrEnum):
    """Evidence-limited repeated-trial description."""

    STRUCTURAL = "structural-under-declared-conditions"
    FLAKY = "flaky-under-declared-conditions"
    NOT_REPRODUCED = "not-reproduced-under-declared-conditions"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class VerificationCheck:
    """One named check with no hidden downgrade."""

    name: str
    state: CheckState
    detail: str

    def to_mapping(self) -> dict[str, str]:
        return {"name": self.name, "state": self.state.value, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class ArtifactVerification:
    """Complete offline verification scope and limitations."""

    artifact_type: str
    state: VerificationState
    checks: tuple[VerificationCheck, ...]
    limitations: tuple[str, ...]
    error_code: str | None = None

    @property
    def accepted(self) -> bool:
        return self.state in {VerificationState.VERIFIED, VerificationState.PARTIAL}

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": self.artifact_type,
            "state": self.state.value,
            "checks": [check.to_mapping() for check in self.checks],
            "limitations": list(self.limitations),
            "errorCode": self.error_code,
            "offline": True,
        }


@dataclass(frozen=True, slots=True)
class ConditionDrift:
    """Difference between an original condition and a fresh run condition."""

    dimension: str
    original: Any
    current: Any
    status: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "original": self.original,
            "current": self.current,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class ControlledReexecutionReport:
    """Fresh run result linked to, but separate from, the source evidence."""

    mode: ReplayMode
    source_trace_digest: str
    new_trace: str
    completion: str
    outcome_status: str
    drift: tuple[ConditionDrift, ...]
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "sourceTraceDigest": self.source_trace_digest,
            "newTrace": self.new_trace,
            "completion": self.completion,
            "outcomeStatus": self.outcome_status,
            "conditionDrift": [item.to_mapping() for item in self.drift],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class SemanticTrial:
    """One independent trial evaluated against a declared observable outcome."""

    trace: str
    condition: str
    status: str
    reproduced: bool | None
    method: str
    limitations: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, Any]:
        return {
            "trace": self.trace,
            "condition": self.condition,
            "status": self.status,
            "reproduced": self.reproduced,
            "method": self.method,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class SensitivityResult:
    """Reproduction count for one explicitly named condition."""

    condition: str
    reproduced: int
    eligible: int
    inconclusive: int
    interval_low: float
    interval_high: float

    def to_mapping(self) -> dict[str, Any]:
        return {
            "condition": self.condition,
            "reproduced": self.reproduced,
            "eligible": self.eligible,
            "inconclusive": self.inconclusive,
            "interval95": [_decimal(self.interval_low), _decimal(self.interval_high)],
        }


@dataclass(frozen=True, slots=True)
class SemanticReproductionReport:
    """Repeated-trial result with numerator, denominator, and uncertainty."""

    mode: ReplayMode
    classification: ReproductionClass
    reproduced: int
    eligible: int
    total: int
    inconclusive: int
    interval_low: float
    interval_high: float
    trials: tuple[SemanticTrial, ...]
    sensitivity: tuple[SensitivityResult, ...]
    limitations: tuple[str, ...]
    method: str = "sova.observable-outcome-reproduction/0.1"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "classification": self.classification.value,
            "reproduced": self.reproduced,
            "eligible": self.eligible,
            "total": self.total,
            "inconclusive": self.inconclusive,
            "rate": (None if self.eligible == 0 else _decimal(self.reproduced / self.eligible)),
            "interval95": [_decimal(self.interval_low), _decimal(self.interval_high)],
            "trials": [trial.to_mapping() for trial in self.trials],
            "sensitivity": [item.to_mapping() for item in self.sensitivity],
            "limitations": list(self.limitations),
            "method": self.method,
        }


@dataclass(frozen=True, slots=True)
class JudgeCalibration:
    """Agreement summary for an optional isolated semantic judge."""

    total: int
    correct: int
    agreement: float
    false_positive: int
    false_negative: int

    def to_mapping(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "correct": self.correct,
            "agreement": _decimal(self.agreement),
            "falsePositive": self.false_positive,
            "falseNegative": self.false_negative,
        }


__all__ = [
    "ArtifactVerification",
    "CheckState",
    "ConditionDrift",
    "ControlledReexecutionReport",
    "JudgeCalibration",
    "ReplayMode",
    "ReproductionClass",
    "SemanticReproductionReport",
    "SemanticTrial",
    "SensitivityResult",
    "VerificationCheck",
    "VerificationState",
]
