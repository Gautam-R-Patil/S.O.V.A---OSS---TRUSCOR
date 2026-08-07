# SPDX-License-Identifier: Apache-2.0
"""Bounded recovery for MCP process startup before any target action exists."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable

    from sova.mcp import StdioServerSpec

ClientT = TypeVar("ClientT")
_MAX_START_ATTEMPTS = 2


def start_stdio_client(
    spec: StdioServerSpec,
    factory: Callable[[StdioServerSpec], ClientT],
    *,
    attempts: int = 2,
) -> ClientT:
    """Retry only a pre-initialization timeout, never a tool or target action."""
    if not 1 <= attempts <= _MAX_START_ATTEMPTS:
        raise FormatError("SOVA-MCP-START-ATTEMPTS", "startup attempts must be one or two")
    for attempt in range(attempts):
        try:
            return factory(spec)
        except FormatError as error:
            if error.issue.code != "SOVA-MCP-TIMEOUT" or attempt + 1 == attempts:
                raise
    raise AssertionError


__all__ = ["start_stdio_client"]
