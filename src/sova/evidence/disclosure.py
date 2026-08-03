# SPDX-License-Identifier: Apache-2.0
"""Local-only coordinated-disclosure preparation with explicit release gates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.safety.disclosure import DisclosureGate, DisclosureRequest

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from sova.evidence.model import EvidenceBundle


@dataclass(frozen=True, slots=True)
class DisclosurePackage:
    evidence_id: str
    contacts: tuple[dict[str, str], ...]
    clock: dict[str, Any]
    vendor_responses: tuple[dict[str, str], ...]
    remediation: dict[str, Any]
    release_allowed: bool
    release_reasons: tuple[str, ...]
    redacted_preview: dict[str, Any]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.disclosure-package",
            "schemaVersion": "0.1.0",
            "evidenceId": self.evidence_id,
            "contacts": list(self.contacts),
            "clock": self.clock,
            "vendorResponses": list(self.vendor_responses),
            "remediation": self.remediation,
            "releaseDecision": {
                "allowed": self.release_allowed,
                "reasons": list(self.release_reasons),
            },
            "redactedPreview": self.redacted_preview,
            "externalMessageSent": False,
            "published": False,
            "limitations": [
                "SOVA prepares local records and never contacts a maintainer automatically.",
                "Contact provenance must be reviewed by a human before use.",
                "Release permission does not replace legal, safety, or coordinated-disclosure "
                "review.",
            ],
        }


def prepare_disclosure_package(  # noqa: PLR0913
    bundle: EvidenceBundle,
    request: DisclosureRequest,
    *,
    contacts: Sequence[Mapping[str, str]],
    clock: Mapping[str, Any],
    vendor_responses: Sequence[Mapping[str, str]] = (),
    remediation: Mapping[str, Any] | None = None,
) -> DisclosurePackage:
    """Prepare, but never transmit, a redacted coordinated-disclosure record."""
    decision = DisclosureGate().assess(request)
    evidence = bundle.to_mapping()
    preview = {
        "finding": evidence["finding"],
        "conditionsTested": evidence["conditionsTested"],
        "coverage": evidence["coverage"],
        "taxonomyMappings": evidence["taxonomyMappings"],
        "limitations": evidence["limitations"],
        "assuranceBoundary": evidence["assuranceBoundary"],
        "evidenceReferences": [
            {
                "role": item["role"],
                "digest": item["digest"],
                "mediaType": item["mediaType"],
                "uriOmittedFromPreview": True,
            }
            for item in evidence["evidence"]
        ],
    }
    return DisclosurePackage(
        evidence_id=bundle.finding_id,
        contacts=tuple(dict(item) for item in contacts),
        clock=dict(clock),
        vendor_responses=tuple(dict(item) for item in vendor_responses),
        remediation=dict(remediation or {"state": "not-recorded", "regressionEvidence": []}),
        release_allowed=decision.allowed,
        release_reasons=decision.reasons,
        redacted_preview=preview,
    )


__all__ = ["DisclosurePackage", "prepare_disclosure_package"]
