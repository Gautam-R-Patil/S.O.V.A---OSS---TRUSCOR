# SPDX-License-Identifier: Apache-2.0
"""Pluggable rehearsal-preparation boundary without implementing a microVM."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from sova.formats.errors import FormatError
from sova.rehearsal.environment import prepare_rehearsal_environment

if TYPE_CHECKING:
    from pathlib import Path

    from sova.rehearsal.model import EnvironmentPreparation


class RehearsalIsolationBackend(Protocol):
    """Minimal backend contract; SOVA keeps review, evidence, and policy outside it."""

    @property
    def name(self) -> str: ...

    @property
    def isolation_claim(self) -> str: ...

    def prepare(
        self,
        source: Path,
        destination: Path,
        *,
        substitutes: tuple[str, ...],
    ) -> EnvironmentPreparation: ...


@dataclass(frozen=True, slots=True)
class FilesystemSubstituteBackend:
    """Built-in developer backend; explicitly not a security sandbox."""

    name: str = "filesystem-substitute"
    isolation_claim: str = "filesystem-scoped-substitute-workspace-not-a-security-sandbox"

    def prepare(
        self,
        source: Path,
        destination: Path,
        *,
        substitutes: tuple[str, ...],
    ) -> EnvironmentPreparation:
        return prepare_rehearsal_environment(source, destination, substitutes=substitutes)


def prepare_with_backend(
    backend: RehearsalIsolationBackend,
    source: Path,
    destination: Path,
    *,
    substitutes: tuple[str, ...],
) -> EnvironmentPreparation:
    """Prepare through a selected backend while rejecting overstated isolation metadata."""
    if not backend.name or not backend.isolation_claim:
        raise FormatError(
            "SOVA-REHEARSE-BACKEND",
            "rehearsal backend must declare name and isolation claim",
        )
    return backend.prepare(source, destination, substitutes=substitutes)


__all__ = [
    "FilesystemSubstituteBackend",
    "RehearsalIsolationBackend",
    "prepare_with_backend",
]
