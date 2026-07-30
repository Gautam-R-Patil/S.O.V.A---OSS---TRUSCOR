# SPDX-License-Identifier: Apache-2.0
"""Deterministic no-network model adapter for mandatory tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class ScriptedModelError(RuntimeError):
    """A deliberate fixture mismatch or injected deterministic failure."""


@dataclass(frozen=True, slots=True)
class ScriptedTurn:
    """One expected request and deterministic observable response."""

    expected_contains: str
    response_text: str
    structured: dict[str, Any] | None = None
    tool_calls: tuple[dict[str, Any], ...] = ()
    failure: str | None = None


class ScriptedModel:
    """Consume a fixed response script without network or credentials."""

    def __init__(self, turns: list[ScriptedTurn], *, model_id: str = "sova-scripted/0.1") -> None:
        self._turns = tuple(turns)
        self._position = 0
        self.model_id = model_id

    @property
    def consumed(self) -> int:
        return self._position

    @property
    def complete(self) -> bool:
        return self._position == len(self._turns)

    def respond(self, prompt: str) -> ScriptedTurn:
        """Return the next scripted turn or fail visibly on fixture drift."""
        if self._position >= len(self._turns):
            raise ScriptedModelError("script exhausted")  # noqa: TRY003
        turn = self._turns[self._position]
        self._position += 1
        if turn.expected_contains not in prompt:
            raise ScriptedModelError(  # noqa: TRY003
                f"expected prompt containing {turn.expected_contains!r}, received {prompt!r}"
            )
        if turn.failure is not None:
            raise ScriptedModelError(turn.failure)
        return turn


__all__ = ["ScriptedModel", "ScriptedModelError", "ScriptedTurn"]
