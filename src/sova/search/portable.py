# SPDX-License-Identifier: Apache-2.0
"""Convert minimized trigger conditions into portable scenario material."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sova.search.model import SearchSpace, TriggerCandidate


def candidate_to_scenario_fragment(
    candidate: TriggerCandidate,
    space: SearchSpace,
) -> dict[str, Any]:
    """Represent conditions and sequence without executor-specific mechanics."""
    triggers = [
        {
            "kind": space.dimensions[name].value,
            "parameter": name,
            "value": candidate.values.get(name),
        }
        for name in sorted(candidate.values)
    ]
    return {
        "parameters": dict(candidate.values),
        "triggers": triggers,
        "sequence": list(candidate.sequence),
        "candidateDigest": candidate.digest,
        "portableIntentOnly": True,
        "executorMechanicsIncluded": False,
    }


__all__ = ["candidate_to_scenario_fragment"]
