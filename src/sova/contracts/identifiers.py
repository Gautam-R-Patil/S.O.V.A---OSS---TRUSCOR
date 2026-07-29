# SPDX-License-Identifier: Apache-2.0
"""Stable logical identifiers and external-reference rules."""

from __future__ import annotations

import re
import secrets
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse

from sova.contracts.errors import ContractError

_SOVA_ID = re.compile(
    r"^sova:(agent|component|mcp-server|skill|plugin|sub-agent|tool|model|target|"
    r"scenario|trace|finding|campaign|run|artifact|registry-entry):"
    r"([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_EXTERNAL_SYSTEM = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_UUID_VERSION = 7


class IdentifierKind(StrEnum):
    """Kinds that may receive a stable SOVA logical identity."""

    AGENT = "agent"
    COMPONENT = "component"
    MCP_SERVER = "mcp-server"
    SKILL = "skill"
    PLUGIN = "plugin"
    SUB_AGENT = "sub-agent"
    TOOL = "tool"
    MODEL = "model"
    TARGET = "target"
    SCENARIO = "scenario"
    TRACE = "trace"
    FINDING = "finding"
    CAMPAIGN = "campaign"
    RUN = "run"
    ARTIFACT = "artifact"
    REGISTRY_ENTRY = "registry-entry"


@dataclass(frozen=True, slots=True)
class StableIdentifier:
    """A stable SOVA logical identifier backed by an RFC 9562 UUIDv7."""

    kind: IdentifierKind
    uuid_value: uuid.UUID

    def __post_init__(self) -> None:
        if self.uuid_value.version != _UUID_VERSION or self.uuid_value.variant != uuid.RFC_4122:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-ID",
                "stable identifiers require an RFC 9562 UUIDv7",
                field="id",
            )

    @classmethod
    def parse(cls, value: str) -> StableIdentifier:
        """Parse the canonical lowercase SOVA identifier form."""
        match = _SOVA_ID.fullmatch(value)
        if match is None:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-ID",
                "expected sova:<kind>:<lowercase UUIDv7>",
                field="id",
                details={"value": value},
            )
        kind, raw_uuid = match.groups()
        return cls(IdentifierKind(kind), uuid.UUID(raw_uuid))

    def __str__(self) -> str:
        return f"sova:{self.kind.value}:{self.uuid_value}"


def new_stable_identifier(kind: IdentifierKind) -> StableIdentifier:
    """Create a time-sortable opaque identifier without embedding host identity."""
    timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms < 1 << 48:
        raise ContractError(
            "SOVA-CONTRACT-ID-CLOCK-RANGE",
            "system time is outside the UUIDv7 48-bit Unix-millisecond range",
            field="clock",
        )
    random_value = secrets.randbits(74)
    rand_a = random_value >> 62
    rand_b = random_value & ((1 << 62) - 1)
    raw = (timestamp_ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return StableIdentifier(kind, uuid.UUID(int=raw))


class ReferenceRelationship(StrEnum):
    """How an external identifier relates to a SOVA record."""

    EQUIVALENT = "equivalent"
    RELATED = "related"
    BROADER = "broader"
    NARROWER = "narrower"
    SUPERSEDES = "supersedes"
    SUPERSEDED_BY = "superseded-by"


@dataclass(frozen=True, slots=True)
class ExternalReference:
    """A version-qualified link to an identifier owned outside SOVA."""

    system: str
    identifier: str
    catalog_version: str
    relationship: ReferenceRelationship
    url: str

    def __post_init__(self) -> None:
        if _EXTERNAL_SYSTEM.fullmatch(self.system) is None:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-EXTERNAL-ID",
                "external system must be a lowercase identifier",
                field="system",
            )
        if not self.identifier.strip() or not self.catalog_version.strip():
            raise ContractError(
                "SOVA-CONTRACT-INVALID-EXTERNAL-ID",
                "external identifier and catalog version are required",
                field="identifier",
            )
        if self.system == "cve" and _CVE_ID.fullmatch(self.identifier) is None:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-EXTERNAL-ID",
                "CVE identifiers require CVE-YYYY-NNNN with four or more sequence digits",
                field="identifier",
            )
        parsed = urlparse(self.url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-EXTERNAL-ID",
                "external references require an absolute HTTPS URL",
                field="url",
            )


__all__ = [
    "ExternalReference",
    "IdentifierKind",
    "ReferenceRelationship",
    "StableIdentifier",
    "new_stable_identifier",
]
