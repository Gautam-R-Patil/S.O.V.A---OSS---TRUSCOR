# SPDX-License-Identifier: Apache-2.0
"""Evidence-aware differential and metamorphic comparisons."""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from sova.formats import canonical_json_bytes
from sova.oracle_lab.contracts import (
    ComparisonObservation,
    ComparisonRelation,
    ComparisonResult,
    OracleVerdict,
)


def _as_set(value: Any) -> set[str] | None:
    if isinstance(value, Mapping):
        return {str(item) for item in value}
    if isinstance(value, (set, frozenset, list, tuple)):
        return {str(item) for item in value}
    return None


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _relation(observation: ComparisonObservation) -> bool | None:
    left = observation.left_value
    right = observation.right_value
    if observation.relation == ComparisonRelation.EQUAL:
        result = canonical_json_bytes(left) == canonical_json_bytes(right)
    elif observation.relation == ComparisonRelation.NOT_EQUAL:
        result = canonical_json_bytes(left) != canonical_json_bytes(right)
    elif observation.relation in {ComparisonRelation.SUBSET, ComparisonRelation.SUPERSET}:
        left_set = _as_set(left)
        right_set = _as_set(right)
        if left_set is None or right_set is None:
            result = None
        else:
            result = (
                left_set <= right_set
                if observation.relation == ComparisonRelation.SUBSET
                else left_set >= right_set
            )
    else:
        left_number = _decimal(left)
        right_number = _decimal(right)
        if left_number is None or right_number is None:
            result = None
        elif observation.relation == ComparisonRelation.NONDECREASING:
            result = right_number >= left_number
        else:
            result = right_number <= left_number
    return result


def evaluate_comparison(observation: ComparisonObservation) -> ComparisonResult:
    """Evaluate one predeclared relation without inferring causality or safety."""
    limitations = [
        "The result is bounded to the predeclared relation and supplied observations.",
        "A satisfied relation does not establish universal invariance or causality.",
    ]
    if observation.infrastructure_failure:
        return ComparisonResult(
            observation,
            OracleVerdict.INFRASTRUCTURE_FAILURE,
            None,
            "sova.oracle-comparison/0.1.0",
            (*limitations, "Infrastructure failure prevented comparison."),
        )
    if not observation.evidence_complete:
        return ComparisonResult(
            observation,
            OracleVerdict.INCONCLUSIVE,
            None,
            "sova.oracle-comparison/0.1.0",
            (*limitations, "Required comparison evidence was incomplete."),
        )
    satisfied = _relation(observation)
    if satisfied is None:
        verdict = OracleVerdict.UNSUPPORTED
        limitations.append("Values were incompatible with the declared relation.")
    else:
        verdict = OracleVerdict.POSITIVE if satisfied else OracleVerdict.NEGATIVE
    return ComparisonResult(
        observation,
        verdict,
        satisfied,
        "sova.oracle-comparison/0.1.0",
        tuple(limitations),
    )


__all__ = ["evaluate_comparison"]
