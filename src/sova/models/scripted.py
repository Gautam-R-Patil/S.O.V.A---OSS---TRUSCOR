# SPDX-License-Identifier: Apache-2.0
"""Deterministic no-network model adapter for mandatory tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

_OBSERVATION_DIGEST_PLACEHOLDER = "$SOVA_OBSERVATION_DIGEST"
_COMPUTER_BINDING_PLACEHOLDER = "$SOVA_COMPUTER_BINDING"


def _bind_prompt_fixtures(
    value: object,
    *,
    observation_digest: str,
    computer_binding: dict[str, Any] | None,
) -> object:
    if value == _OBSERVATION_DIGEST_PLACEHOLDER:
        return observation_digest
    if value == _COMPUTER_BINDING_PLACEHOLDER and computer_binding is not None:
        return dict(computer_binding)
    if isinstance(value, dict):
        return {
            key: _bind_prompt_fixtures(
                child,
                observation_digest=observation_digest,
                computer_binding=computer_binding,
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            _bind_prompt_fixtures(
                child,
                observation_digest=observation_digest,
                computer_binding=computer_binding,
            )
            for child in value
        ]
    return value


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
    token_count: int | None = None
    monetary_cost: str | None = None
    resolved_model_id: str | None = None


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
        if turn.structured is not None:
            try:
                prompt_document = json.loads(prompt)
            except (json.JSONDecodeError, TypeError):
                prompt_document = None
            observation = (
                prompt_document.get("observation") if isinstance(prompt_document, dict) else None
            )
            observation_digest = (
                observation.get("digest") if isinstance(observation, dict) else None
            )
            projection = observation.get("projection") if isinstance(observation, dict) else None
            computer = projection.get("computer") if isinstance(projection, dict) else None
            computer_binding = computer.get("binding") if isinstance(computer, dict) else None
            if isinstance(observation_digest, str):
                structured = _bind_prompt_fixtures(
                    turn.structured,
                    observation_digest=observation_digest,
                    computer_binding=(
                        dict(computer_binding) if isinstance(computer_binding, dict) else None
                    ),
                )
                if not isinstance(structured, dict):  # pragma: no cover - source is a dict
                    raise TypeError
                return ScriptedTurn(
                    turn.expected_contains,
                    turn.response_text,
                    structured,
                    turn.tool_calls,
                    turn.failure,
                    turn.token_count,
                    turn.monetary_cost,
                    turn.resolved_model_id,
                )
        return turn


__all__ = ["ScriptedModel", "ScriptedModelError", "ScriptedTurn"]
