# SPDX-License-Identifier: Apache-2.0
"""Typed errors for untrusted SOVA format input."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One stable machine-readable validation issue."""

    code: str
    message: str
    path: str = "$"
    details: dict[str, Any] | None = None


class FormatError(ValueError):
    """A safe, bounded failure while parsing or validating an artifact."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.issue = ValidationIssue(code, message, path, details)


__all__ = ["FormatError", "ValidationIssue"]
