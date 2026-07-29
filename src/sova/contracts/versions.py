# SPDX-License-Identifier: Apache-2.0
"""Version and fingerprint primitives shared by future SOVA artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from sova.contracts.errors import ContractError

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._/-]{0,126}[a-z0-9])?$")
_MAX_MODEL_IDENTIFIER_LENGTH = 256


@dataclass(frozen=True, slots=True)
class SemanticVersion:
    """A strict Semantic Versioning 2.0.0 value."""

    major: int
    minor: int
    patch: int
    prerelease: str | None = None
    build: str | None = None

    @classmethod
    def parse(cls, value: str) -> SemanticVersion:
        """Parse an exact semantic version without coercion."""
        match = _SEMVER.fullmatch(value)
        if match is None:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-VERSION",
                "expected an exact Semantic Versioning 2.0.0 value",
                field="version",
                details={"value": value},
            )
        major, minor, patch, prerelease, build = match.groups()
        return cls(int(major), int(minor), int(patch), prerelease, build)

    def __str__(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease is not None:
            value += f"-{self.prerelease}"
        if self.build is not None:
            value += f"+{self.build}"
        return value


@dataclass(frozen=True, slots=True)
class ContentDigest:
    """An immutable SHA-256 content identity."""

    value: str

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.value) is None:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-DIGEST",
                "expected lowercase sha256:<64 hexadecimal characters>",
                field="digest",
                details={"value": self.value},
            )

    @property
    def algorithm(self) -> str:
        """Return the fixed digest algorithm."""
        return "sha256"

    @property
    def hex_digest(self) -> str:
        """Return the lowercase hexadecimal digest."""
        return self.value.removeprefix("sha256:")


class AbsenceReason(StrEnum):
    """Explicit reasons why a context slot has no concrete value."""

    NOT_APPLICABLE = "not-applicable"
    NOT_RECORDED = "not-recorded"
    UNKNOWN_AFTER_MIGRATION = "unknown-after-migration"


@dataclass(frozen=True, slots=True)
class ExplicitAbsence:
    """An explicit absence that cannot be confused with an omitted field."""

    reason: AbsenceReason
    explanation: str

    def __post_init__(self) -> None:
        if not self.explanation.strip():
            raise ContractError(
                "SOVA-CONTRACT-MISSING-CONTEXT",
                "an explicit absence requires a non-empty explanation",
                field="explanation",
            )


@dataclass(frozen=True, slots=True)
class VersionedReference:
    """An exact name and version for a schema, method, or component."""

    name: str
    version: SemanticVersion
    digest: ContentDigest | ExplicitAbsence

    def __post_init__(self) -> None:
        _require_name(self.name, "name")


@dataclass(frozen=True, slots=True)
class FingerprintedReference:
    """An exact identity for mutable or externally versioned state."""

    name: str
    fingerprint: ContentDigest

    def __post_init__(self) -> None:
        _require_name(self.name, "name")


@dataclass(frozen=True, slots=True)
class ModelReference:
    """Model/provider identity with a secret-free configuration fingerprint."""

    provider: str
    model: str
    configuration_fingerprint: ContentDigest
    provider_revision: str | ExplicitAbsence

    def __post_init__(self) -> None:
        _require_name(self.provider, "provider")
        if not self.model.strip() or len(self.model) > _MAX_MODEL_IDENTIFIER_LENGTH:
            raise ContractError(
                "SOVA-CONTRACT-INVALID-NAME",
                "model must be a non-empty identifier of at most 256 characters",
                field="model",
            )
        if isinstance(self.provider_revision, str) and not self.provider_revision.strip():
            raise ContractError(
                "SOVA-CONTRACT-MISSING-CONTEXT",
                "provider revision must be recorded or explicitly absent",
                field="provider_revision",
            )


ContextValue = VersionedReference | FingerprintedReference | ModelReference | ExplicitAbsence


@dataclass(frozen=True, slots=True)
class InterpretationContext:
    """The minimum context required to interpret a result historically."""

    schema: VersionedReference
    taxonomy: VersionedReference
    methodology: VersionedReference
    executor: VersionedReference
    adapter: VersionedReference | ExplicitAbsence
    model: ModelReference | ExplicitAbsence
    target: FingerprintedReference
    environment: FingerprintedReference
    judge: VersionedReference | ExplicitAbsence
    oracle: VersionedReference
    registry_snapshot: FingerprintedReference | ExplicitAbsence

    def as_mapping(self) -> dict[str, ContextValue]:
        """Return all context axes without silently dropping absent values."""
        return {
            "schema": self.schema,
            "taxonomy": self.taxonomy,
            "methodology": self.methodology,
            "executor": self.executor,
            "adapter": self.adapter,
            "model": self.model,
            "target": self.target,
            "environment": self.environment,
            "judge": self.judge,
            "oracle": self.oracle,
            "registry_snapshot": self.registry_snapshot,
        }


def _require_name(value: str, field: str) -> None:
    if _NAME.fullmatch(value) is None:
        raise ContractError(
            "SOVA-CONTRACT-INVALID-NAME",
            "expected a lowercase namespaced identifier",
            field=field,
            details={"value": value},
        )


__all__ = [
    "AbsenceReason",
    "ContentDigest",
    "ExplicitAbsence",
    "FingerprintedReference",
    "InterpretationContext",
    "ModelReference",
    "SemanticVersion",
    "VersionedReference",
]
