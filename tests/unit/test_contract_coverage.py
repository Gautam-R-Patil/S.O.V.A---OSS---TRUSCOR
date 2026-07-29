# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for bounded observed coverage."""

from __future__ import annotations

from fractions import Fraction

import pytest

from sova.contracts import (
    BudgetLimit,
    BudgetUnit,
    ContractError,
    CoverageDimension,
    DimensionCoverage,
    ExplorationRecord,
    ObservedCoverage,
    StoppingReason,
)


def _dimension(dimension: CoverageDimension) -> DimensionCoverage:
    return DimensionCoverage(
        dimension,
        frozenset({f"{dimension.value}:a", f"{dimension.value}:b"}),
        frozenset({f"{dimension.value}:a", f"{dimension.value}:outside"}),
    )


def test_coverage_uses_frozen_denominator_and_separates_discoveries() -> None:
    coverage = _dimension(CoverageDimension.CONDITIONS)
    assert coverage.covered == frozenset({"conditions:a"})
    assert coverage.out_of_declaration == frozenset({"conditions:outside"})
    assert coverage.ratio == Fraction(1, 2)


def test_empty_denominator_is_not_applicable() -> None:
    coverage = DimensionCoverage(CoverageDimension.TOOLS, frozenset(), frozenset())
    assert coverage.ratio is None


def test_complete_vector_has_no_universal_score() -> None:
    report = ObservedCoverage(
        dimensions=tuple(_dimension(dimension) for dimension in CoverageDimension),
        exploration=ExplorationRecord(
            limits=(BudgetLimit(BudgetUnit.ATTEMPTS, 200),),
            consumed=(BudgetLimit(BudgetUnit.ATTEMPTS, 200),),
            stopping_reason=StoppingReason.BUDGET_EXHAUSTED,
            stopping_detail="the predeclared attempt budget was exhausted",
        ),
    )
    assert set(report.by_dimension()) == set(CoverageDimension)
    assert not hasattr(report, "overall_score")
    assert not hasattr(report, "safety_percentage")


def test_missing_dimension_fails_closed() -> None:
    with pytest.raises(ContractError) as caught:
        ObservedCoverage(
            dimensions=(_dimension(CoverageDimension.CONDITIONS),),
            exploration=ExplorationRecord(
                limits=(BudgetLimit(BudgetUnit.ATTEMPTS, 1),),
                consumed=(),
                stopping_reason=StoppingReason.OPERATOR_CANCELLED,
                stopping_detail="operator cancelled",
            ),
        )
    assert caught.value.code == "SOVA-COVERAGE-MISSING-DIMENSION"


def test_budget_requires_a_declared_limit() -> None:
    with pytest.raises(ContractError) as caught:
        ExplorationRecord(
            limits=(),
            consumed=(),
            stopping_reason=StoppingReason.SAFETY_STOP,
            stopping_detail="authorization boundary reached",
        )
    assert caught.value.code == "SOVA-COVERAGE-MISSING-BUDGET"


def test_negative_budget_fails_closed() -> None:
    with pytest.raises(ContractError) as caught:
        BudgetLimit(BudgetUnit.ATTEMPTS, -1)
    assert caught.value.code == "SOVA-COVERAGE-INVALID-BUDGET"


def test_stopping_detail_is_required() -> None:
    with pytest.raises(ContractError) as caught:
        ExplorationRecord(
            limits=(BudgetLimit(BudgetUnit.ATTEMPTS, 1),),
            consumed=(),
            stopping_reason=StoppingReason.SAFETY_STOP,
            stopping_detail=" ",
        )
    assert caught.value.code == "SOVA-COVERAGE-MISSING-STOPPING-RULE"


def test_consumption_requires_predeclared_unit() -> None:
    with pytest.raises(ContractError) as caught:
        ExplorationRecord(
            limits=(BudgetLimit(BudgetUnit.ATTEMPTS, 1),),
            consumed=(BudgetLimit(BudgetUnit.MODEL_TOKENS, 1),),
            stopping_reason=StoppingReason.BUDGET_EXHAUSTED,
            stopping_detail="token budget exhausted",
        )
    assert caught.value.code == "SOVA-COVERAGE-UNDECLARED-CONSUMPTION"


def test_duplicate_dimensions_fail_closed() -> None:
    condition = _dimension(CoverageDimension.CONDITIONS)
    with pytest.raises(ContractError) as caught:
        ObservedCoverage(
            dimensions=(condition, condition),
            exploration=ExplorationRecord(
                limits=(BudgetLimit(BudgetUnit.ATTEMPTS, 1),),
                consumed=(),
                stopping_reason=StoppingReason.OPERATOR_CANCELLED,
                stopping_detail="operator cancelled",
            ),
        )
    assert caught.value.code == "SOVA-COVERAGE-DUPLICATE-DIMENSION"


@pytest.mark.parametrize("label", ["", " ", "x" * 257])
def test_invalid_coverage_labels_fail_closed(label: str) -> None:
    with pytest.raises(ContractError) as caught:
        DimensionCoverage(
            CoverageDimension.STATES,
            frozenset({label}),
            frozenset(),
        )
    assert caught.value.code == "SOVA-COVERAGE-INVALID-LABEL"


def test_duplicate_budget_units_fail_closed() -> None:
    with pytest.raises(ContractError) as caught:
        ExplorationRecord(
            limits=(
                BudgetLimit(BudgetUnit.ATTEMPTS, 1),
                BudgetLimit(BudgetUnit.ATTEMPTS, 2),
            ),
            consumed=(),
            stopping_reason=StoppingReason.BUDGET_EXHAUSTED,
            stopping_detail="attempt budget exhausted",
        )
    assert caught.value.code == "SOVA-COVERAGE-DUPLICATE-BUDGET"
