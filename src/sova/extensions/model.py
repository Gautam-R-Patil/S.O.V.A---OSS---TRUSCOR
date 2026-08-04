# SPDX-License-Identifier: Apache-2.0
"""Portable extension metadata that can be inspected without importing plugin code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

EXTENSION_API_VERSION = "0.1"
ENTRY_POINT_GROUP = "sova.extensions"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,126}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_VERSION_LENGTH = 64


class ExtensionKind(StrEnum):
    ATTACKER = "attacker"
    JUDGE = "judge"
    MUTATOR = "mutator"
    ORACLE = "oracle"
    EXECUTOR = "executor"
    TARGET = "target"
    SANDBOX = "sandbox"
    REPORT = "report"


@dataclass(frozen=True, slots=True)
class ExtensionManifest:
    """Declared capability and risk envelope for one extension distribution."""

    identifier: str
    version: str
    api_version: str
    kind: ExtensionKind
    capabilities: tuple[str, ...]
    side_effects: tuple[str, ...]
    isolation: str = "subprocess"
    trust: str = "untrusted"
    distribution_digest: str | None = None

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.identifier):
            raise FormatError("SOVA-EXTENSION-ID", "extension identifier is invalid")
        if not self.version or len(self.version) > _MAX_VERSION_LENGTH:
            raise FormatError("SOVA-EXTENSION-VERSION", "extension version is invalid")
        if self.api_version != EXTENSION_API_VERSION:
            raise FormatError(
                "SOVA-EXTENSION-API",
                "extension API version is unsupported",
                details={"supported": EXTENSION_API_VERSION},
            )
        if self.isolation not in {"subprocess", "in-process"}:
            raise FormatError("SOVA-EXTENSION-ISOLATION", "unsupported extension isolation")
        if self.trust not in {"untrusted", "verified-publisher", "first-party"}:
            raise FormatError("SOVA-EXTENSION-TRUST", "unsupported extension trust declaration")
        if self.isolation == "in-process" and self.trust != "first-party":
            raise FormatError(
                "SOVA-EXTENSION-INPROCESS-TRUST",
                "only explicitly pinned first-party extensions may run in process",
            )
        for value in (*self.capabilities, *self.side_effects):
            if not _IDENTIFIER.fullmatch(value):
                raise FormatError("SOVA-EXTENSION-CAPABILITY", "invalid capability declaration")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise FormatError("SOVA-EXTENSION-CAPABILITY", "capabilities must be unique")
        if self.distribution_digest is not None and not _DIGEST.fullmatch(self.distribution_digest):
            raise FormatError("SOVA-EXTENSION-DIGEST", "distribution digest is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.extension-manifest",
            "schemaVersion": "0.1.0",
            "identifier": self.identifier,
            "version": self.version,
            "apiVersion": self.api_version,
            "kind": self.kind.value,
            "capabilities": sorted(self.capabilities),
            "sideEffects": sorted(self.side_effects),
            "isolation": self.isolation,
            "trust": self.trust,
            "distributionDigest": self.distribution_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> ExtensionManifest:
        try:
            return cls(
                identifier=str(value["identifier"]),
                version=str(value["version"]),
                api_version=str(value["apiVersion"]),
                kind=ExtensionKind(str(value["kind"])),
                capabilities=tuple(str(item) for item in value.get("capabilities", [])),
                side_effects=tuple(str(item) for item in value.get("sideEffects", [])),
                isolation=str(value.get("isolation", "subprocess")),
                trust=str(value.get("trust", "untrusted")),
                distribution_digest=(
                    None
                    if value.get("distributionDigest") is None
                    else str(value["distributionDigest"])
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FormatError(
                "SOVA-EXTENSION-MANIFEST", "extension manifest is malformed"
            ) from error


@dataclass(frozen=True, slots=True)
class ExtensionMetadata:
    """Import-free PyPA entry-point metadata; this is not a trust decision."""

    name: str
    value: str
    group: str
    distribution: str | None


def _metadata(item: EntryPoint) -> ExtensionMetadata:
    distribution = None if item.dist is None else item.dist.name
    return ExtensionMetadata(item.name, item.value, item.group, distribution)


def discover_extension_metadata() -> tuple[ExtensionMetadata, ...]:
    """Discover installed metadata without loading or executing extension modules."""
    discovered = entry_points(group=ENTRY_POINT_GROUP)
    return tuple(sorted((_metadata(item) for item in discovered), key=lambda item: item.name))
