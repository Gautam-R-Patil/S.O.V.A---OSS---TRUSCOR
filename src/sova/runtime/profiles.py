# SPDX-License-Identifier: Apache-2.0
"""Comparable standard and visibly non-standard orchestration profiles."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sova.formats.errors import FormatError


class ProfileKind(StrEnum):
    STANDARD = "standard"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class RunProfile:
    """A run profile whose comparability cannot be inferred from a label alone."""

    kind: ProfileKind
    taxonomy_version: str
    methodology_version: str = "0.1.0"
    customization_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.taxonomy_version or not self.methodology_version:
            raise FormatError(
                "SOVA-RUNTIME-PROFILE",
                "profile requires taxonomy and methodology versions",
            )
        if self.kind == ProfileKind.STANDARD and self.customization_digest is not None:
            raise FormatError(
                "SOVA-RUNTIME-PROFILE",
                "standard profile cannot carry custom configuration",
            )
        if self.kind == ProfileKind.CUSTOM and not (
            isinstance(self.customization_digest, str)
            and self.customization_digest.startswith("sha256:")
        ):
            raise FormatError(
                "SOVA-RUNTIME-PROFILE",
                "custom profile requires a canonical customization digest",
            )

    @property
    def comparable(self) -> bool:
        return self.kind == ProfileKind.STANDARD

    def to_mapping(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "taxonomyVersion": self.taxonomy_version,
            "methodologyVersion": self.methodology_version,
            "customizationDigest": self.customization_digest,
            "sharedComparisonEligible": self.comparable,
            "watermark": "STANDARD" if self.comparable else "CUSTOM / NON-STANDARD",
        }


def standard_profile() -> RunProfile:
    return RunProfile(ProfileKind.STANDARD, "0.1.0")


__all__ = ["ProfileKind", "RunProfile", "standard_profile"]
