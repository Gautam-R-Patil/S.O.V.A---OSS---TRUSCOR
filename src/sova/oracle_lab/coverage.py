# SPDX-License-Identifier: Apache-2.0
"""Eight-dimensional P4 coverage accounting without a universal score."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.oracle_lab.contracts import (
    SCHEMA_VERSION,
    CoverageDimension,
    CoverageEntry,
    CoverageState,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


_POSITIVE_STATES = {CoverageState.EXERCISED, CoverageState.REPRODUCED}
_GAP_STATES = {
    CoverageState.NOT_OBSERVED,
    CoverageState.UNSUPPORTED,
    CoverageState.BLOCKED,
    CoverageState.INCONCLUSIVE,
    CoverageState.INFRASTRUCTURE_FAILURE,
    CoverageState.UNKNOWN,
}
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


def build_coverage_report(
    entries: Sequence[CoverageEntry],
    *,
    target_profile_digest: str,
    methodology_plan_digest: str,
) -> dict[str, Any]:
    """Build per-dimension counts, denominators, and named evidence gaps."""
    if not entries:
        raise FormatError("SOVA-ORACLE-LAB-COVERAGE", "coverage entries are required")
    keys = [(item.dimension, item.subject) for item in entries]
    if len(keys) != len(set(keys)):
        raise FormatError(
            "SOVA-ORACLE-LAB-COVERAGE", "one terminal state is allowed per coverage subject"
        )
    for value in (target_profile_digest, methodology_plan_digest):
        if _SHA256_PATTERN.fullmatch(value) is None:
            raise FormatError("SOVA-ORACLE-LAB-COVERAGE", "coverage binding digest is invalid")

    grouped: dict[CoverageDimension, list[CoverageEntry]] = defaultdict(list)
    for item in entries:
        grouped[item.dimension].append(item)
    dimensions = []
    for dimension in CoverageDimension:
        items = sorted(grouped.get(dimension, []), key=lambda item: item.subject)
        counts = Counter(item.state.value for item in items)
        positive = sum(item.state in _POSITIVE_STATES for item in items)
        known_denominator = sum(item.state != CoverageState.UNKNOWN for item in items)
        dimensions.append(
            {
                "dimension": dimension.value,
                "items": [
                    {
                        "subject": item.subject,
                        "state": item.state.value,
                        "evidenceDigests": list(item.evidence_digests),
                        "reason": item.reason,
                    }
                    for item in items
                ],
                "counts": {state.value: counts[state.value] for state in CoverageState},
                "knownDenominator": known_denominator,
                "positiveEvidenceCount": positive,
                "positiveEvidenceRatio": (
                    None if not known_denominator else format(positive / known_denominator, ".12g")
                ),
            }
        )
    gaps = [
        {
            "dimension": item.dimension.value,
            "subject": item.subject,
            "state": item.state.value,
            "reason": item.reason,
        }
        for item in sorted(entries, key=lambda value: (value.dimension.value, value.subject))
        if item.state in _GAP_STATES
    ]
    body: dict[str, Any] = {
        "artifactType": "sova.assessment-coverage",
        "schemaVersion": SCHEMA_VERSION,
        "targetProfileDigest": target_profile_digest,
        "methodologyPlanDigest": methodology_plan_digest,
        "dimensions": dimensions,
        "gaps": gaps,
        "claims": {
            "exhaustive": False,
            "allWorkflowsUnderstood": False,
            "allAttackSurfacesEnumerated": False,
            "allVulnerabilitiesFound": False,
            "safeOrClean": False,
            "unknownIsPass": False,
            "notObservedIsSafe": False,
            "infrastructureFailureIsPass": False,
        },
        "limitations": [
            "Coverage measures named declared and observed subjects, not unknown target behavior.",
            "Per-dimension ratios are not combined into an overall safety or completeness score.",
        ],
    }
    body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    return body


__all__ = ["build_coverage_report"]
