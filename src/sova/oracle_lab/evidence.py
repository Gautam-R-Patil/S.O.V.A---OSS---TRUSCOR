# SPDX-License-Identifier: Apache-2.0
"""Digest-bound decisive evidence sets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.oracle_lab.contracts import SCHEMA_VERSION, DecisiveEvidenceBinding, EvidenceRole

if TYPE_CHECKING:
    from collections.abc import Sequence


def bind_decisive_evidence(bindings: Sequence[DecisiveEvidenceBinding]) -> dict[str, Any]:
    """Require every decisive evidence role and return a content-addressed record."""
    by_role = {item.role: item for item in bindings}
    if len(by_role) != len(bindings):
        raise FormatError("SOVA-ORACLE-LAB-EVIDENCE", "decisive evidence roles must be unique")
    missing = set(EvidenceRole) - set(by_role)
    if missing:
        raise FormatError(
            "SOVA-ORACLE-LAB-EVIDENCE",
            "decisive evidence set is incomplete",
            details={"missing": sorted(item.value for item in missing)},
        )
    if not all(item.verified for item in bindings):
        raise FormatError(
            "SOVA-ORACLE-LAB-EVIDENCE", "all decisive evidence digests must be verified"
        )
    body: dict[str, Any] = {
        "artifactType": "sova.decisive-evidence-set",
        "schemaVersion": SCHEMA_VERSION,
        "bindings": [by_role[role].to_mapping() for role in EvidenceRole],
        "complete": True,
        "allDigestsVerified": True,
        "claims": {"findingConfirmed": False, "recorderHonestyEstablished": False},
    }
    body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    return body


__all__ = ["bind_decisive_evidence"]
