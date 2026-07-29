# SPDX-License-Identifier: Apache-2.0
"""Bounded observed-coverage contracts without universal-safety scoring."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from fractions import Fraction

from sova.contracts.errors import ContractError

_MAX_COVERAGE_LABEL_LENGTH = 256


class CoverageDimension(StrEnum):
    """Declared surface dimensions tracked independently."""

    CONDITIONS = "conditions"
    SEQUENCES = "sequences"
    TOOLS = "tools"
    CAPABILITIES = "capabilities"
    STATES = "states"
    EFFECTS = "effects"


@dataclass(frozen=True, slots=True)
class DimensionCoverage:
    """Observed coverage against one frozen declared denominator."""

    dimension: CoverageDimension
    declared: frozenset[str]
    exercised: frozenset[str]

    def __post_init__(self) -> None:
        _validate_labels(self.declared, "declared")
        _validate_labels(self.exercised, "exercised")

    @property
    def covered(self) -> frozenset[str]:
        """Declared elements for which at least one exercise was observed."""
        return self.declared & self.exercised

    @property
    def out_of_declaration(self) -> frozenset[str]:
        """Observed elements excluded from the frozen denominator."""
        return self.exercised - self.declared

    @property
    def ratio(self) -> Fraction | None:
        """Return an exact per-dimension ratio, or None for an empty denominator."""
        if not self.declared:
            return None
        return Fraction(len(self.covered), len(self.declared))


class BudgetUnit(StrEnum):
    """Resource dimensions that can bound exploration."""

    ATTEMPTS = "attempts"
    WALL_TIME_MILLISECONDS = "wall-time-milliseconds"
    MODEL_TOKENS = "model-tokens"
    COST_MICROUNITS = "cost-microunits"
    EXECUTOR_ACTIONS = "executor-actions"


@dataclass(frozen=True, slots=True)
class BudgetLimit:
    """One non-negative exploration resource limit."""

    unit: BudgetUnit
    limit: int

    def __post_init__(self) -> None:
        if self.limit < 0:
            raise ContractError(
                "SOVA-COVERAGE-INVALID-BUDGET",
                "exploration limits cannot be negative",
                field=self.unit.value,
            )


class StoppingReason(StrEnum):
    """Why exploration ended."""

    BUDGET_EXHAUSTED = "budget-exhausted"
    OBJECTIVE_REACHED = "objective-reached"
    NO_IMPROVEMENT_WINDOW = "no-improvement-window"
    OPERATOR_CANCELLED = "operator-cancelled"
    SAFETY_STOP = "safety-stop"
    EXECUTOR_FAILURE = "executor-failure"


@dataclass(frozen=True, slots=True)
class ExplorationRecord:
    """Predeclared limits, measured consumption, and the actual stop."""

    limits: tuple[BudgetLimit, ...]
    consumed: tuple[BudgetLimit, ...]
    stopping_reason: StoppingReason
    stopping_detail: str

    def __post_init__(self) -> None:
        if not self.limits:
            raise ContractError(
                "SOVA-COVERAGE-MISSING-BUDGET",
                "at least one exploration limit must be declared before a run",
                field="limits",
            )
        if not self.stopping_detail.strip():
            raise ContractError(
                "SOVA-COVERAGE-MISSING-STOPPING-RULE",
                "the stopping decision requires a non-empty explanation",
                field="stopping_detail",
            )
        limit_units = _unique_units(self.limits, "limits")
        consumed_units = _unique_units(self.consumed, "consumed")
        if not consumed_units <= limit_units:
            raise ContractError(
                "SOVA-COVERAGE-UNDECLARED-CONSUMPTION",
                "consumption contains a resource without a predeclared limit",
                field="consumed",
            )


@dataclass(frozen=True, slots=True)
class ObservedCoverage:
    """The complete six-dimensional observed-coverage vector."""

    dimensions: tuple[DimensionCoverage, ...]
    exploration: ExplorationRecord

    def __post_init__(self) -> None:
        present = [item.dimension for item in self.dimensions]
        if len(present) != len(set(present)):
            raise ContractError(
                "SOVA-COVERAGE-DUPLICATE-DIMENSION",
                "each coverage dimension must appear exactly once",
                field="dimensions",
            )
        missing = set(CoverageDimension) - set(present)
        if missing:
            raise ContractError(
                "SOVA-COVERAGE-MISSING-DIMENSION",
                "the observed-coverage vector is incomplete",
                field="dimensions",
                details={"missing": sorted(item.value for item in missing)},
            )

    def by_dimension(self) -> dict[CoverageDimension, DimensionCoverage]:
        """Return the vector keyed by dimension without producing an overall score."""
        return {item.dimension: item for item in self.dimensions}


def _validate_labels(values: frozenset[str], field: str) -> None:
    if any(not value.strip() or len(value) > _MAX_COVERAGE_LABEL_LENGTH for value in values):
        raise ContractError(
            "SOVA-COVERAGE-INVALID-LABEL",
            "coverage labels must be non-empty and at most 256 characters",
            field=field,
        )


def _unique_units(values: tuple[BudgetLimit, ...], field: str) -> set[BudgetUnit]:
    units = [item.unit for item in values]
    if len(units) != len(set(units)):
        raise ContractError(
            "SOVA-COVERAGE-DUPLICATE-BUDGET",
            "each budget unit may appear only once",
            field=field,
        )
    return set(units)


__all__ = [
    "BudgetLimit",
    "BudgetUnit",
    "CoverageDimension",
    "DimensionCoverage",
    "ExplorationRecord",
    "ObservedCoverage",
    "StoppingReason",
]
