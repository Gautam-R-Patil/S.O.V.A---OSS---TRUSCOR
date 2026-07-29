# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for stable and external identifiers."""

from __future__ import annotations

import uuid

import pytest

from sova.contracts import (
    ContractError,
    ExternalReference,
    IdentifierKind,
    ReferenceRelationship,
    StableIdentifier,
    new_stable_identifier,
)


def test_uuid7_sova_identifier_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sova.contracts.identifiers.time.time_ns", lambda: 1_700_000_000_123_000_000
    )
    monkeypatch.setattr("sova.contracts.identifiers.secrets.randbits", lambda bits: (1 << bits) - 1)

    identifier = new_stable_identifier(IdentifierKind.FINDING)

    assert str(identifier).startswith("sova:finding:018bcfe5-687b-7")
    assert StableIdentifier.parse(str(identifier)) == identifier
    assert identifier.uuid_value.version == 7


def test_non_uuid7_identifier_is_rejected() -> None:
    with pytest.raises(ContractError) as caught:
        StableIdentifier.parse("sova:finding:00000000-0000-4000-8000-000000000000")
    assert caught.value.code == "SOVA-CONTRACT-INVALID-ID"

    with pytest.raises(ContractError) as direct:
        StableIdentifier(
            IdentifierKind.FINDING,
            uuid.UUID("00000000-0000-4000-8000-000000000000"),
        )
    assert direct.value.code == "SOVA-CONTRACT-INVALID-ID"


def test_uuid7_clock_range_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sova.contracts.identifiers.time.time_ns", lambda: -1_000_000)
    with pytest.raises(ContractError) as caught:
        new_stable_identifier(IdentifierKind.RUN)
    assert caught.value.code == "SOVA-CONTRACT-ID-CLOCK-RANGE"


def test_cve_reference_keeps_external_identity_separate() -> None:
    reference = ExternalReference(
        system="cve",
        identifier="CVE-2026-12345",
        catalog_version="5.2.0",
        relationship=ReferenceRelationship.RELATED,
        url="https://www.cve.org/CVERecord?id=CVE-2026-12345",
    )
    assert reference.identifier == "CVE-2026-12345"


def test_invalid_cve_syntax_fails_closed() -> None:
    with pytest.raises(ContractError) as caught:
        ExternalReference(
            system="cve",
            identifier="CVE-26-1",
            catalog_version="5.2.0",
            relationship=ReferenceRelationship.RELATED,
            url="https://www.cve.org/",
        )
    assert caught.value.code == "SOVA-CONTRACT-INVALID-EXTERNAL-ID"


@pytest.mark.parametrize(
    ("system", "identifier", "catalog_version", "url", "field"),
    [
        ("Bad System", "X-1", "1.0", "https://example.org/X-1", "system"),
        ("vendor", "", "1.0", "https://example.org/X-1", "identifier"),
        ("vendor", "X-1", "", "https://example.org/X-1", "identifier"),
        ("vendor", "X-1", "1.0", "http://example.org/X-1", "url"),
        ("vendor", "X-1", "1.0", "https:///X-1", "url"),
    ],
)
def test_external_reference_fields_are_strict(
    system: str,
    identifier: str,
    catalog_version: str,
    url: str,
    field: str,
) -> None:
    with pytest.raises(ContractError) as caught:
        ExternalReference(
            system=system,
            identifier=identifier,
            catalog_version=catalog_version,
            relationship=ReferenceRelationship.RELATED,
            url=url,
        )
    assert caught.value.field == field
