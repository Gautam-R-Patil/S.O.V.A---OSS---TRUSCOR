# SPDX-License-Identifier: Apache-2.0
"""Local-only coordinated-disclosure preparation with explicit release gates."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sova.formats.errors import FormatError
from sova.safety.disclosure import DisclosureGate, DisclosureRequest

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from sova.evidence.model import EvidenceBundle

_DEFAULT_DISCLOSURE_DAYS = 90
_ACTIVE_EXPLOITATION_MINIMUM_DAYS = 7
_EXTENSION_LIMIT_DAYS = 14
_MAX_CONTACT_FILE_BYTES = 1_048_576
_CONTACT_FILES = (
    "SECURITY.md",
    ".github/SECURITY.md",
    "pyproject.toml",
    "package.json",
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
    r"(?![A-Za-z0-9_%+-])"
)


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


def default_disclosure_clock(reported_at: str) -> dict[str, Any]:
    """Build the approved 90-day local clock from one timezone-aware timestamp."""
    try:
        reported = datetime.fromisoformat(reported_at)
    except ValueError as error:
        raise FormatError(
            "SOVA-DISCLOSE-CLOCK", "reportedAt must be an ISO 8601 timestamp"
        ) from error
    if reported.tzinfo is None:
        raise FormatError("SOVA-DISCLOSE-CLOCK", "reportedAt must include a timezone")
    deadline = reported + timedelta(days=_DEFAULT_DISCLOSURE_DAYS)
    reminders = tuple(
        (reported + timedelta(days=day)).isoformat()
        for day in (30, 60, 83, _DEFAULT_DISCLOSURE_DAYS)
    )
    return {
        "policy": "SECURITY.md/1.0",
        "reportedAt": reported.isoformat(),
        "embargoEndsAt": deadline.isoformat(),
        "embargoState": "embargoed",
        "defaultPeriodDays": _DEFAULT_DISCLOSURE_DAYS,
        "activeExploitationMinimumDays": _ACTIVE_EXPLOITATION_MINIMUM_DAYS,
        "extensionLimitDays": _EXTENSION_LIMIT_DAYS,
        "localReminderTimes": list(reminders),
        "automaticReminderSent": False,
    }


def discover_maintainer_contacts(root: Path) -> tuple[dict[str, str], ...]:
    """Discover bounded email contacts from local project metadata without network use."""
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise FormatError("SOVA-DISCLOSE-CONTACTS", "contact discovery root must be a directory")
    discovered: dict[str, dict[str, str]] = {}
    for relative in _CONTACT_FILES:
        path = (resolved_root / relative).resolve()
        if not path.is_relative_to(resolved_root) or not path.is_file():
            continue
        if path.stat().st_size > _MAX_CONTACT_FILE_BYTES:
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for match in _EMAIL.finditer(content):
            address = match.group(1).casefold()
            discovered.setdefault(
                address,
                {
                    "kind": "email",
                    "address": address,
                    "source": path.relative_to(resolved_root).as_posix(),
                    "discoveredBy": "local-static-metadata",
                },
            )
    return tuple(discovered[key] for key in sorted(discovered))


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


__all__ = [
    "DisclosurePackage",
    "default_disclosure_clock",
    "discover_maintainer_contacts",
    "prepare_disclosure_package",
]
