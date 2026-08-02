# SPDX-License-Identifier: Apache-2.0
"""Abuse-resistant publication and registry release decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class VulnerabilityState(StrEnum):
    UNKNOWN = "unknown"
    REPORTED = "reported"
    COORDINATED = "coordinated"
    PATCHED = "patched"
    PUBLIC = "public"
    WITHDRAWN = "withdrawn"


@dataclass(frozen=True, slots=True)
class DisclosureRequest:
    target_kind: str
    vulnerability_state: VulnerabilityState
    contains_working_payload: bool
    authorization_redacted: bool
    secrets_scan_clean: bool
    human_reviewed: bool
    limitations_present: bool
    coordinated_disclosure_reference: str | None = None


@dataclass(frozen=True, slots=True)
class DisclosureDecision:
    allowed: bool
    reasons: tuple[str, ...]

    def to_mapping(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "method": "sova.disclosure-gate/0.1",
        }


class DisclosureGate:
    """Prevent live victim ranking and unpatched exploit publication."""

    def assess(self, request: DisclosureRequest) -> DisclosureDecision:
        reasons: list[str] = []
        if request.target_kind not in {"component", "framework", "synthetic"}:
            reasons.append("organizations-and-victims-must-not-be-ranked")
        if request.contains_working_payload and request.vulnerability_state not in {
            VulnerabilityState.PATCHED,
            VulnerabilityState.PUBLIC,
        }:
            reasons.append("working-unpatched-payload-cannot-be-published")
        if (
            request.vulnerability_state
            in {
                VulnerabilityState.REPORTED,
                VulnerabilityState.COORDINATED,
            }
            and not request.coordinated_disclosure_reference
        ):
            reasons.append("coordinated-disclosure-reference-required")
        if not request.authorization_redacted:
            reasons.append("authorization-material-not-reviewed")
        if not request.secrets_scan_clean:
            reasons.append("secret-scan-not-clean")
        if not request.human_reviewed:
            reasons.append("human-export-review-required")
        if not request.limitations_present:
            reasons.append("limitations-required")
        return DisclosureDecision(not reasons, tuple(reasons))


__all__ = [
    "DisclosureDecision",
    "DisclosureGate",
    "DisclosureRequest",
    "VulnerabilityState",
]
