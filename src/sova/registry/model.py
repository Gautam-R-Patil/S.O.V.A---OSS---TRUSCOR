# SPDX-License-Identifier: Apache-2.0
"""Typed public-registry metadata with explicit verification and lifecycle states."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats.errors import FormatError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9A-Za-z](?:[0-9A-Za-z.-]{0,63})$")


class VerificationTier(StrEnum):
    SUBMITTED = "submitted"
    VALIDATED = "schema-and-safety-validated"
    CI_REPRODUCED = "reproduced-by-ci-where-safe"
    INDEPENDENTLY_REPRODUCED = "independently-reproduced"
    EMBARGOED = "embargoed"
    WITHDRAWN = "withdrawn"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    entry_id: str
    version: str
    object_path: str | None
    digest: str | None
    size: int
    component: str
    component_version: str
    taxonomy: tuple[str, ...]
    disclosure_state: str
    reproduction: dict[str, Any]
    provenance: dict[str, Any]
    license_expression: str
    verification_tier: VerificationTier
    supersedes: str | None = None

    def __post_init__(self) -> None:
        if not self.entry_id or not self.version or not self.component:
            raise FormatError("SOVA-REGISTRY-ENTRY", "entry identity fields are required")
        if self.size < 0:
            raise FormatError("SOVA-REGISTRY-SIZE", "entry size cannot be negative")
        payload_absent = self.verification_tier in {
            VerificationTier.EMBARGOED,
            VerificationTier.WITHDRAWN,
        }
        if payload_absent:
            if self.object_path is not None or self.digest is not None or self.size != 0:
                raise FormatError(
                    "SOVA-REGISTRY-LIFECYCLE",
                    "embargoed and withdrawn entries cannot expose payload bytes",
                )
        elif (
            self.object_path is None
            or self.digest is None
            or _DIGEST.fullmatch(self.digest) is None
            or self.object_path != f"objects/sha256/{self.digest[7:]}"
        ):
            raise FormatError(
                "SOVA-REGISTRY-OBJECT",
                "public entry object path must be derived from its SHA-256 digest",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.entry_id,
            "version": self.version,
            "objectPath": self.object_path,
            "digest": self.digest,
            "size": self.size,
            "component": {"name": self.component, "version": self.component_version},
            "taxonomy": list(self.taxonomy),
            "disclosureState": self.disclosure_state,
            "reproduction": self.reproduction,
            "provenance": self.provenance,
            "license": self.license_expression,
            "verificationTier": self.verification_tier.value,
            "truscorAttestation": False,
            "supersedes": self.supersedes,
        }


@dataclass(frozen=True, slots=True)
class RegistryIndex:
    registry_version: str
    taxonomy_version: str
    taxonomy_digest: str
    entries: tuple[RegistryEntry, ...]

    def __post_init__(self) -> None:
        if _VERSION.fullmatch(self.registry_version) is None:
            raise FormatError("SOVA-REGISTRY-VERSION", "registry version is unsafe")
        if _VERSION.fullmatch(self.taxonomy_version) is None:
            raise FormatError("SOVA-REGISTRY-VERSION", "taxonomy version is unsafe")
        if _DIGEST.fullmatch(self.taxonomy_digest) is None:
            raise FormatError("SOVA-REGISTRY-TAXONOMY", "taxonomy digest must use SHA-256")
        keys = [(entry.entry_id, entry.version) for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise FormatError("SOVA-REGISTRY-DUPLICATE", "entry id/version pairs must be unique")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.registry-index",
            "schemaVersion": "0.1.0",
            "registryVersion": self.registry_version,
            "taxonomy": {
                "version": self.taxonomy_version,
                "digest": self.taxonomy_digest,
                "historicalResultsRewritten": False,
            },
            "entries": [
                entry.to_mapping()
                for entry in sorted(self.entries, key=lambda item: (item.entry_id, item.version))
            ],
            "distribution": {
                "offlineClone": True,
                "mirrorable": True,
                "accountRequired": False,
                "telemetry": False,
            },
            "corpusBoundary": {
                "privateCorpusIncluded": False,
                "matchedLossPairsIncluded": False,
                "automaticCollection": False,
                "privateCorpusReuseConsent": False,
            },
        }


def entry_from_mapping(value: Mapping[str, Any]) -> RegistryEntry:
    component = value.get("component")
    if not isinstance(component, Mapping):
        raise FormatError("SOVA-REGISTRY-ENTRY", "component must be an object")
    reproduction = value.get("reproduction", {})
    provenance = value.get("provenance", {})
    taxonomy = value.get("taxonomy", [])
    if not isinstance(reproduction, dict) or not isinstance(provenance, dict):
        raise FormatError("SOVA-REGISTRY-ENTRY", "reproduction and provenance must be objects")
    if not isinstance(taxonomy, list) or any(not isinstance(item, str) for item in taxonomy):
        raise FormatError("SOVA-REGISTRY-ENTRY", "taxonomy must contain strings")

    def required_string(mapping: Mapping[str, Any], name: str) -> str:
        item = mapping.get(name)
        if not isinstance(item, str) or not item:
            raise FormatError("SOVA-REGISTRY-ENTRY", f"{name} must be a non-empty string")
        return item

    size = value.get("size")
    if not isinstance(size, int) or isinstance(size, bool):
        raise FormatError("SOVA-REGISTRY-ENTRY", "size must be an integer")
    try:
        tier = VerificationTier(required_string(value, "verificationTier"))
    except ValueError as error:
        raise FormatError("SOVA-REGISTRY-TIER", "unsupported verification tier") from error
    object_path = value.get("objectPath")
    digest = value.get("digest")
    supersedes = value.get("supersedes")
    if object_path is not None and not isinstance(object_path, str):
        raise FormatError("SOVA-REGISTRY-ENTRY", "objectPath must be string or null")
    if digest is not None and not isinstance(digest, str):
        raise FormatError("SOVA-REGISTRY-ENTRY", "digest must be string or null")
    if supersedes is not None and not isinstance(supersedes, str):
        raise FormatError("SOVA-REGISTRY-ENTRY", "supersedes must be string or null")
    return RegistryEntry(
        required_string(value, "id"),
        required_string(value, "version"),
        object_path,
        digest,
        size,
        required_string(component, "name"),
        required_string(component, "version"),
        tuple(taxonomy),
        required_string(value, "disclosureState"),
        reproduction,
        provenance,
        required_string(value, "license"),
        tier,
        supersedes,
    )


__all__ = ["RegistryEntry", "RegistryIndex", "VerificationTier", "entry_from_mapping"]
