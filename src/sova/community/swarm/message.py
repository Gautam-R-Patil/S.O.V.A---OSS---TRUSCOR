# SPDX-License-Identifier: Apache-2.0
"""Typed inter-agent swarm message contract.

Every message crosses the shared `SwarmBlackboard` boundary, so its payload
must already be bounded and redaction-checked before construction succeeds;
the blackboard itself re-checks at `post()` time as an independent second
layer (see `sova.community.swarm.blackboard`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_PAYLOAD_BYTES = 256 * 1024
_MAX_REFS = 64
_MAX_AGENT_ID_CHARS = 128


class SwarmMessageKind(StrEnum):
    """Bounded vocabulary for what a swarm agent is telling its peers."""

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    FINDING = "finding"
    TASK_CLAIM = "task-claim"
    TASK_RELEASE = "task-release"
    HELP_REQUEST = "help-request"
    STATUS = "status"


@dataclass(frozen=True, slots=True)
class SwarmMessage:
    """One bounded, canonical, author-attributed message on the swarm blackboard."""

    author_agent_id: str
    seq: int
    kind: SwarmMessageKind
    refs: tuple[str, ...]
    payload: dict[str, Any]
    posted_unix_ms: int
    _canonical_payload: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.author_agent_id, str)
            or not self.author_agent_id
            or len(self.author_agent_id) > _MAX_AGENT_ID_CHARS
            or "\x00" in self.author_agent_id
        ):
            raise FormatError(
                "SOVA-SWARM-MESSAGE-AUTHOR",
                "swarm message author id must be a bounded non-empty string",
            )
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:
            raise FormatError(
                "SOVA-SWARM-MESSAGE-SEQ",
                "swarm message sequence must be a non-negative integer",
            )
        if type(self.kind) is not SwarmMessageKind:
            raise FormatError(
                "SOVA-SWARM-MESSAGE-KIND",
                "swarm message kind must be one exact declared kind",
            )
        if (
            not isinstance(self.refs, tuple)
            or len(self.refs) > _MAX_REFS
            or any(not isinstance(item, str) or not item for item in self.refs)
            or len(set(self.refs)) != len(self.refs)
        ):
            raise FormatError(
                "SOVA-SWARM-MESSAGE-REFS",
                "swarm message refs must be a bounded tuple of unique non-empty ids",
            )
        if not isinstance(self.payload, dict):
            raise FormatError(
                "SOVA-SWARM-MESSAGE-PAYLOAD",
                "swarm message payload must be an object",
            )
        if isinstance(self.posted_unix_ms, bool) or not isinstance(self.posted_unix_ms, int):
            raise FormatError(
                "SOVA-SWARM-MESSAGE-TIME",
                "swarm message posted_unix_ms must be an integer",
            )
        encoded = canonical_json_bytes(self.payload)
        if len(encoded) > _MAX_PAYLOAD_BYTES:
            raise FormatError(
                "SOVA-SWARM-MESSAGE-LIMIT",
                "swarm message payload exceeds 256 KiB",
            )
        object.__setattr__(self, "_canonical_payload", encoded)

    @property
    def id(self) -> str:
        return "swarm-msg:" + self.digest[7:23]

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.canonical_mapping()))

    def canonical_mapping(self) -> dict[str, Any]:
        return {
            "authorAgentId": self.author_agent_id,
            "seq": self.seq,
            "kind": self.kind.value,
            "refs": list(self.refs),
            "payload": self.payload,
            "postedUnixMs": self.posted_unix_ms,
        }


__all__ = ["SwarmMessage", "SwarmMessageKind"]
