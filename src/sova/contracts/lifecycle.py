# SPDX-License-Identifier: Apache-2.0
"""Finding lifecycle axes and append-only transition rules."""

from __future__ import annotations

from enum import StrEnum

from sova.contracts.errors import ContractError


class LifecycleAxis(StrEnum):
    """Independent axes that together describe a finding."""

    EVIDENCE = "evidence"
    DISCLOSURE = "disclosure"
    REMEDIATION = "remediation"
    ADJUDICATION = "adjudication"
    RECORD = "record"


class EvidenceState(StrEnum):
    """What the recorded experiments currently support."""

    CANDIDATE = "candidate"
    NOT_OBSERVED = "not-observed"
    OBSERVED = "observed"
    REPRODUCED = "reproduced"
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"
    DISPUTED = "disputed"


class DisclosureState(StrEnum):
    """Who is permitted to know the finding."""

    CONFIDENTIAL = "confidential"
    EMBARGOED = "embargoed"
    DISCLOSED = "disclosed"
    PUBLISHED = "published"


class RemediationState(StrEnum):
    """Whether the affected behavior is currently remediated."""

    OPEN = "open"
    FIXED = "fixed"
    REGRESSED = "regressed"


class AdjudicationState(StrEnum):
    """Status of scanner disagreement and adjudication."""

    NOT_REQUIRED = "not-required"
    PENDING = "pending"
    SCANNER_DISAGREEMENT = "scanner-disagreement"
    RESOLVED = "resolved"


class RecordState(StrEnum):
    """Whether this immutable finding record remains the current record."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"


_STATE_TYPES = {
    LifecycleAxis.EVIDENCE: EvidenceState,
    LifecycleAxis.DISCLOSURE: DisclosureState,
    LifecycleAxis.REMEDIATION: RemediationState,
    LifecycleAxis.ADJUDICATION: AdjudicationState,
    LifecycleAxis.RECORD: RecordState,
}

_ALLOWED: dict[LifecycleAxis, dict[str, frozenset[str]]] = {
    LifecycleAxis.EVIDENCE: {
        EvidenceState.CANDIDATE: frozenset(
            {
                EvidenceState.NOT_OBSERVED,
                EvidenceState.OBSERVED,
                EvidenceState.INCONCLUSIVE,
            }
        ),
        EvidenceState.NOT_OBSERVED: frozenset({EvidenceState.OBSERVED, EvidenceState.INCONCLUSIVE}),
        EvidenceState.OBSERVED: frozenset(
            {
                EvidenceState.REPRODUCED,
                EvidenceState.INCONCLUSIVE,
                EvidenceState.DISPUTED,
            }
        ),
        EvidenceState.REPRODUCED: frozenset(
            {EvidenceState.VERIFIED, EvidenceState.INCONCLUSIVE, EvidenceState.DISPUTED}
        ),
        EvidenceState.VERIFIED: frozenset({EvidenceState.DISPUTED}),
        EvidenceState.INCONCLUSIVE: frozenset(
            {
                EvidenceState.NOT_OBSERVED,
                EvidenceState.OBSERVED,
                EvidenceState.REPRODUCED,
                EvidenceState.DISPUTED,
            }
        ),
        EvidenceState.DISPUTED: frozenset(
            {
                EvidenceState.INCONCLUSIVE,
                EvidenceState.NOT_OBSERVED,
                EvidenceState.OBSERVED,
                EvidenceState.REPRODUCED,
                EvidenceState.VERIFIED,
            }
        ),
    },
    LifecycleAxis.DISCLOSURE: {
        DisclosureState.CONFIDENTIAL: frozenset(
            {DisclosureState.EMBARGOED, DisclosureState.DISCLOSED}
        ),
        DisclosureState.EMBARGOED: frozenset(
            {DisclosureState.DISCLOSED, DisclosureState.PUBLISHED}
        ),
        DisclosureState.DISCLOSED: frozenset({DisclosureState.PUBLISHED}),
        DisclosureState.PUBLISHED: frozenset(),
    },
    LifecycleAxis.REMEDIATION: {
        RemediationState.OPEN: frozenset({RemediationState.FIXED}),
        RemediationState.FIXED: frozenset({RemediationState.REGRESSED}),
        RemediationState.REGRESSED: frozenset({RemediationState.FIXED}),
    },
    LifecycleAxis.ADJUDICATION: {
        AdjudicationState.NOT_REQUIRED: frozenset(
            {AdjudicationState.PENDING, AdjudicationState.SCANNER_DISAGREEMENT}
        ),
        AdjudicationState.PENDING: frozenset(
            {AdjudicationState.SCANNER_DISAGREEMENT, AdjudicationState.RESOLVED}
        ),
        AdjudicationState.SCANNER_DISAGREEMENT: frozenset(
            {AdjudicationState.PENDING, AdjudicationState.RESOLVED}
        ),
        AdjudicationState.RESOLVED: frozenset({AdjudicationState.SCANNER_DISAGREEMENT}),
    },
    LifecycleAxis.RECORD: {
        RecordState.ACTIVE: frozenset({RecordState.SUPERSEDED}),
        RecordState.SUPERSEDED: frozenset(),
    },
}


def allowed_transitions(axis: LifecycleAxis, state: str) -> frozenset[str]:
    """Return legal next states on one lifecycle axis."""
    state_type = _STATE_TYPES[axis]
    try:
        normalized = state_type(state).value
    except ValueError as error:
        raise ContractError(
            "SOVA-LIFECYCLE-UNKNOWN-STATE",
            f"{state!r} is not a state on the {axis.value} axis",
            field=axis.value,
        ) from error
    return _ALLOWED[axis][normalized]


def require_transition(axis: LifecycleAxis, source: str, destination: str) -> None:
    """Reject backward, cross-axis, or history-rewriting transitions."""
    allowed = allowed_transitions(axis, source)
    if destination not in allowed:
        raise ContractError(
            "SOVA-LIFECYCLE-ILLEGAL-TRANSITION",
            f"{source!r} cannot transition to {destination!r} on the {axis.value} axis",
            field=axis.value,
            details={"allowed": sorted(allowed)},
        )


__all__ = [
    "AdjudicationState",
    "DisclosureState",
    "EvidenceState",
    "LifecycleAxis",
    "RecordState",
    "RemediationState",
    "allowed_transitions",
    "require_transition",
]
