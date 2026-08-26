# SPDX-License-Identifier: Apache-2.0
"""Thread-safe, redacted, hash-chained shared blackboard for a SOVA swarm.

This is the "seamless communication and data transfer" layer: every message
any worker posts is redaction-checked, hash-chained to the prior message, and
readable by every other worker.  It is an in-memory structure guarded by one
lock; durable evidence comes from the coordinator embedding the full
transcript (`transcript()`) into a signed `.sova-trace`
(`sova.community.swarm.coordinator`), not from the blackboard itself.
"""

from __future__ import annotations

import threading

from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import Redactor

_GENESIS_DIGEST = "sha256:" + "0" * 64


class SwarmBlackboard:
    """Append-only shared message log with a running integrity chain."""

    def __init__(
        self,
        *,
        redactor: Redactor | None = None,
        max_messages: int = 4096,
        max_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if max_messages < 1 or max_bytes < 1:
            raise FormatError(
                "SOVA-SWARM-BLACKBOARD-CONFIG",
                "swarm blackboard limits must be positive",
            )
        self._redactor = redactor or Redactor(context_id="sova-swarm-blackboard")
        self._max_messages = max_messages
        self._max_bytes = max_bytes
        self._lock = threading.RLock()
        self._messages: list[SwarmMessage] = []
        self._known_ids: set[str] = set()
        self._chain_head = _GENESIS_DIGEST
        self._total_bytes = 0

    def post(self, message: SwarmMessage) -> str:
        """Redact, verify, hash-chain, and append one message. Returns the new chain head."""
        if type(message) is not SwarmMessage:
            raise FormatError(
                "SOVA-SWARM-BLACKBOARD-MESSAGE",
                "swarm blackboard requires one exact SwarmMessage",
            )
        _redacted, disclosures = self._redactor.redact(message.payload)
        if disclosures:
            raise FormatError(
                "SOVA-SWARM-BLACKBOARD-SENSITIVE",
                "swarm message payload contains credential-shaped material",
            )
        with self._lock:
            unknown_refs = sorted(set(message.refs) - self._known_ids)
            if unknown_refs:
                raise FormatError(
                    "SOVA-SWARM-BLACKBOARD-REF",
                    "swarm message references an unknown prior message",
                    details={"unknownRefs": unknown_refs},
                )
            if message.id in self._known_ids:
                raise FormatError(
                    "SOVA-SWARM-BLACKBOARD-DUPLICATE",
                    "swarm message id was already posted",
                )
            encoded = canonical_json_bytes(message.canonical_mapping())
            if (
                len(self._messages) >= self._max_messages
                or self._total_bytes + len(encoded) > self._max_bytes
            ):
                raise FormatError(
                    "SOVA-SWARM-BLACKBOARD-LIMIT",
                    "swarm blackboard exceeds its message count or byte budget",
                )
            self._messages.append(message)
            self._known_ids.add(message.id)
            self._total_bytes += len(encoded)
            self._chain_head = sha256_digest(
                canonical_json_bytes(
                    {"previous": self._chain_head, "message": message.canonical_mapping()}
                )
            )
            return self._chain_head

    def read(
        self,
        *,
        since_seq_by_author: dict[str, int] | None = None,
        kinds: tuple[SwarmMessageKind, ...] | None = None,
    ) -> tuple[SwarmMessage, ...]:
        """Return a point-in-time snapshot of messages newer than the given cursor."""
        cursor = since_seq_by_author or {}
        with self._lock:
            snapshot = tuple(self._messages)
        return tuple(
            message
            for message in snapshot
            if message.seq > cursor.get(message.author_agent_id, -1)
            and (kinds is None or message.kind in kinds)
        )

    def transcript(self) -> tuple[SwarmMessage, ...]:
        with self._lock:
            return tuple(self._messages)

    def chain_head_digest(self) -> str:
        with self._lock:
            return self._chain_head

    def __len__(self) -> int:
        with self._lock:
            return len(self._messages)


__all__ = ["SwarmBlackboard"]
