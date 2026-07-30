# SPDX-License-Identifier: Apache-2.0
"""`.sova` disclosure and correction lifecycle."""

from __future__ import annotations

from enum import StrEnum


class CapsuleLifecycle(StrEnum):
    """Lifecycle states stored in capsule manifests."""

    DRAFT = "draft"
    EMBARGOED = "embargoed"
    DISCLOSED = "disclosed"
    VERIFIED = "verified"
    CORRECTED = "corrected"
    REVOKED = "revoked"
    WITHDRAWN = "withdrawn"
    SUPERSEDED = "superseded"


_TRANSITIONS = {
    CapsuleLifecycle.DRAFT: {
        CapsuleLifecycle.EMBARGOED,
        CapsuleLifecycle.DISCLOSED,
        CapsuleLifecycle.WITHDRAWN,
        CapsuleLifecycle.REVOKED,
    },
    CapsuleLifecycle.EMBARGOED: {
        CapsuleLifecycle.DISCLOSED,
        CapsuleLifecycle.WITHDRAWN,
        CapsuleLifecycle.REVOKED,
    },
    CapsuleLifecycle.DISCLOSED: {
        CapsuleLifecycle.VERIFIED,
        CapsuleLifecycle.CORRECTED,
        CapsuleLifecycle.WITHDRAWN,
        CapsuleLifecycle.REVOKED,
        CapsuleLifecycle.SUPERSEDED,
    },
    CapsuleLifecycle.VERIFIED: {
        CapsuleLifecycle.CORRECTED,
        CapsuleLifecycle.WITHDRAWN,
        CapsuleLifecycle.REVOKED,
        CapsuleLifecycle.SUPERSEDED,
    },
    CapsuleLifecycle.CORRECTED: {
        CapsuleLifecycle.VERIFIED,
        CapsuleLifecycle.WITHDRAWN,
        CapsuleLifecycle.REVOKED,
        CapsuleLifecycle.SUPERSEDED,
    },
    CapsuleLifecycle.WITHDRAWN: set(),
    CapsuleLifecycle.REVOKED: set(),
    CapsuleLifecycle.SUPERSEDED: set(),
}


def can_transition(source: CapsuleLifecycle, destination: CapsuleLifecycle) -> bool:
    """Return whether an explicit lifecycle transition is permitted."""
    return destination in _TRANSITIONS[source]


__all__ = ["CapsuleLifecycle", "can_transition"]
