# SPDX-License-Identifier: Apache-2.0
"""Stable failure semantics for SOVA public contracts."""

from __future__ import annotations

from typing import Any


class ContractError(ValueError):
    """A machine-classifiable violation of a public SOVA contract."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.field = field
        self.details = details or {}
        location = f" [{field}]" if field else ""
        super().__init__(f"{code}{location}: {message}")


__all__ = ["ContractError"]
