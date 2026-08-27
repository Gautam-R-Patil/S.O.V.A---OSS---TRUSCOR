# SPDX-License-Identifier: Apache-2.0
"""Fresh-state, independent-runner reproduction assessment."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sova.formats import canonical_json_bytes, sha256_digest
from sova.oracle_lab.contracts import (
    FreshReproduction,
    OracleCalibration,
    OracleDisposition,
    OracleVerdict,
    ReproductionState,
)
from sova.oracle_lab.io import validate_oracle_lab_artifact

if TYPE_CHECKING:
    from collections.abc import Sequence


def assess_fresh_reproduction(  # noqa: PLR0912, PLR0913 - trust bindings stay explicit
    *,
    finding_digest: str,
    calibration: OracleCalibration,
    primary_target_generation: str,
    reproduction_target_generation: str,
    primary_environment_fingerprint: str,
    reproduction_environment_fingerprint: str,
    primary_runner_identity: str,
    reproduction_runner_identity: str,
    primary_trace_digest: str,
    reproduction_trace_digest: str,
    reset_receipt_digest: str,
    causal_evidence_digests: Sequence[str],
    evidence_set: dict[str, object],
    oracle_verdict: OracleVerdict,
    reproduction_evidence_complete: bool,
    evaluated_at: str,
) -> FreshReproduction:
    """Confirm only a positive result from a promoted oracle and genuinely fresh run."""
    reasons: list[str] = []
    validate_oracle_lab_artifact(calibration.to_mapping())
    validate_oracle_lab_artifact(evidence_set)
    if calibration.disposition != OracleDisposition.PROMOTED:
        reasons.append("oracle-not-promoted")
    if primary_target_generation == reproduction_target_generation:
        reasons.append("target-generation-not-fresh")
    if primary_runner_identity == reproduction_runner_identity:
        reasons.append("runner-not-independent")
    if primary_trace_digest == reproduction_trace_digest:
        reasons.append("trace-not-fresh")
    if not reproduction_evidence_complete:
        reasons.append("reproduction-evidence-incomplete")
    try:
        evaluated = datetime.strptime(evaluated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        valid_from = datetime.strptime(calibration.valid_from, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
        valid_until = datetime.strptime(calibration.valid_until, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
    except ValueError:
        reasons.append("invalid-validity-time")
    else:
        if not valid_from <= evaluated < valid_until:
            reasons.append("oracle-validity-window-expired")

    if oracle_verdict == OracleVerdict.INFRASTRUCTURE_FAILURE:
        state = ReproductionState.INFRASTRUCTURE_FAILURE
        reasons.append("oracle-infrastructure-failure")
    elif oracle_verdict == OracleVerdict.BLOCKED:
        state = ReproductionState.BLOCKED
        reasons.append("reproduction-blocked")
    elif oracle_verdict == OracleVerdict.UNSUPPORTED:
        state = ReproductionState.UNSUPPORTED
        reasons.append("reproduction-unsupported")
    elif reasons or oracle_verdict in {
        OracleVerdict.ABSTAIN,
        OracleVerdict.INCONCLUSIVE,
        OracleVerdict.NOT_OBSERVED,
    }:
        state = ReproductionState.INCONCLUSIVE
        if oracle_verdict in {
            OracleVerdict.ABSTAIN,
            OracleVerdict.INCONCLUSIVE,
            OracleVerdict.NOT_OBSERVED,
        }:
            reasons.append(f"oracle-{oracle_verdict.value}")
    elif oracle_verdict == OracleVerdict.NEGATIVE:
        state = ReproductionState.NOT_REPRODUCED
        reasons.append("promoted-oracle-negative")
    else:
        state = ReproductionState.CONFIRMED

    return FreshReproduction(
        finding_digest=finding_digest,
        promoted_oracle_digest=calibration.digest,
        primary_target_generation=primary_target_generation,
        reproduction_target_generation=reproduction_target_generation,
        primary_environment_fingerprint=primary_environment_fingerprint,
        reproduction_environment_fingerprint=reproduction_environment_fingerprint,
        primary_runner_identity=primary_runner_identity,
        reproduction_runner_identity=reproduction_runner_identity,
        primary_trace_digest=primary_trace_digest,
        reproduction_trace_digest=reproduction_trace_digest,
        reset_receipt_digest=reset_receipt_digest,
        causal_evidence_digests=tuple(causal_evidence_digests),
        evidence_set_digest=sha256_digest(canonical_json_bytes(evidence_set)),
        oracle_verdict=oracle_verdict,
        evaluated_at=evaluated_at,
        state=state,
        reasons=tuple(dict.fromkeys(reasons)),
    )


__all__ = ["assess_fresh_reproduction"]
