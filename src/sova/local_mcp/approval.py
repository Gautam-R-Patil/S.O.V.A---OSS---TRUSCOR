# SPDX-License-Identifier: Apache-2.0
"""Filesystem control channel for exact, expiring, single-use MCP approvals."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

    from sova.local_mcp.model import InvocationDescriptor

_MIN_KEY_BYTES = 32
_MAX_RECORD_BYTES = 64 * 1024


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise FormatError("SOVA-LOCAL-MCP-TIME", "approval timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise FormatError("SOVA-LOCAL-MCP-TIME", "approval timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise FormatError("SOVA-LOCAL-MCP-TIME", "approval timestamp needs a timezone")
    return parsed


def create_control_key(path: Path) -> None:
    """Create an exclusive local control-channel key without printing its value."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError as error:
        raise FormatError("SOVA-LOCAL-MCP-KEY-EXISTS", "control key already exists") from error
    try:
        os.write(descriptor, secrets.token_bytes(_MIN_KEY_BYTES))
    finally:
        os.close(descriptor)


def load_control_key(path: Path) -> bytes:
    value = path.resolve().read_bytes()
    if len(value) < _MIN_KEY_BYTES:
        raise FormatError("SOVA-LOCAL-MCP-KEY", "control key must contain at least 32 bytes")
    return value


class LocalApprovalStore:
    """Persist challenge metadata and signed tokens outside the agent workspace."""

    def __init__(self, root: Path, key: bytes, *, workspace: Path) -> None:
        self.root = root.resolve()
        self.workspace = workspace.resolve()
        if self.root == self.workspace or self.workspace in self.root.parents:
            raise FormatError(
                "SOVA-LOCAL-MCP-CONTROL-LOCATION",
                "control records must be outside the agent-visible workspace",
            )
        if len(key) < _MIN_KEY_BYTES:
            raise FormatError("SOVA-LOCAL-MCP-KEY", "control key must contain at least 32 bytes")
        self._key = key
        self._challenges = self.root / "challenges"
        self._tokens = self.root / "tokens"
        self._consumed = self.root / "consumed"
        for directory in (self._challenges, self._tokens, self._consumed):
            directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _safe_id(value: str) -> str:
        if not value.startswith("sova-mcp-") or not value[9:].isalnum():
            raise FormatError("SOVA-LOCAL-MCP-CHALLENGE", "challenge identifier is invalid")
        return value

    def _path(self, directory: Path, challenge_id: str) -> Path:
        return directory / f"{self._safe_id(challenge_id)}.json"

    def _sign(self, value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(
            hmac.digest(self._key, canonical_json_bytes(value), hashlib.sha256)
        ).decode("ascii")

    def challenge_record(self, challenge_id: str) -> dict[str, Any]:
        """Read the bounded public review record; never expose key or token material."""
        value = strict_json_loads(
            self._path(self._challenges, challenge_id).read_bytes(),
            max_bytes=_MAX_RECORD_BYTES,
        )
        if not isinstance(value, dict):
            raise FormatError("SOVA-LOCAL-MCP-CHALLENGE", "challenge record is malformed")
        return value

    def challenge(
        self,
        invocation: InvocationDescriptor,
        *,
        ttl: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now or datetime.now(UTC)
        if not timedelta(seconds=1) <= ttl <= timedelta(minutes=15):
            raise FormatError("SOVA-LOCAL-MCP-TTL", "challenge TTL is outside policy")
        challenge_id = "sova-mcp-" + secrets.token_hex(16)
        nonce = secrets.token_urlsafe(18)
        phrase = f"APPROVE SOVA {invocation.digest[7:19]} {nonce[:8]}"
        document = {
            "artifactType": "sova.mcp-authorization-challenge",
            "schemaVersion": "0.1.0",
            "challengeId": challenge_id,
            "invocation": invocation.to_mapping(),
            "invocationDigest": invocation.digest,
            "exactPhrase": phrase,
            "createdAt": _timestamp(current),
            "expiresAt": _timestamp(current + ttl),
            "nonce": nonce,
            "status": "awaiting-out-of-band-human-approval",
            "approvalViaMcpAllowed": False,
        }
        self._path(self._challenges, challenge_id).write_bytes(
            canonical_json_bytes(document) + b"\n"
        )
        return document

    def approve(
        self,
        challenge_id: str,
        *,
        exact_phrase: str,
        reviewed_effects: bool,
        human_confirmed: bool,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        challenge_path = self._path(self._challenges, challenge_id)
        challenge = strict_json_loads(challenge_path.read_bytes(), max_bytes=_MAX_RECORD_BYTES)
        if not isinstance(challenge, dict):
            raise FormatError("SOVA-LOCAL-MCP-CHALLENGE", "challenge record is malformed")
        current = now or datetime.now(UTC)
        if current >= _parse_timestamp(challenge.get("expiresAt")):
            raise FormatError("SOVA-LOCAL-MCP-EXPIRED", "approval challenge has expired")
        if exact_phrase != challenge.get("exactPhrase"):
            raise FormatError("SOVA-LOCAL-MCP-PHRASE", "approval phrase did not match")
        if not human_confirmed or not reviewed_effects:
            raise FormatError(
                "SOVA-LOCAL-MCP-HUMAN-REVIEW",
                "approval requires an interactive human effect review",
            )
        unsigned = {
            "artifactType": "sova.mcp-approval-token",
            "schemaVersion": "0.1.0",
            "challengeId": challenge_id,
            "invocationDigest": challenge.get("invocationDigest"),
            "expiresAt": challenge.get("expiresAt"),
            "nonce": challenge.get("nonce"),
            "reviewedEffects": True,
            "channel": "local-out-of-band-control",
            "singleUse": True,
        }
        token = {**unsigned, "signature": self._sign(unsigned)}
        token_path = self._path(self._tokens, challenge_id)
        try:
            token_path.write_bytes(canonical_json_bytes(token) + b"\n")
        except OSError as error:
            raise FormatError(
                "SOVA-LOCAL-MCP-TOKEN-WRITE", "approval token write failed"
            ) from error
        return {key: value for key, value in token.items() if key != "signature"}

    def consume(
        self,
        challenge_id: str,
        invocation: InvocationDescriptor,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        token_path = self._path(self._tokens, challenge_id)
        consumed_path = self._path(self._consumed, challenge_id)
        if consumed_path.exists():
            raise FormatError("SOVA-LOCAL-MCP-REPLAY", "approval token was already consumed")
        token = strict_json_loads(token_path.read_bytes(), max_bytes=_MAX_RECORD_BYTES)
        if not isinstance(token, dict):
            raise FormatError("SOVA-LOCAL-MCP-TOKEN", "approval token is malformed")
        signature = token.pop("signature", None)
        if not isinstance(signature, str) or not hmac.compare_digest(signature, self._sign(token)):
            raise FormatError("SOVA-LOCAL-MCP-TOKEN-SIGNATURE", "approval token is invalid")
        if token.get("invocationDigest") != invocation.digest:
            raise FormatError("SOVA-LOCAL-MCP-SCOPE", "approval does not match this invocation")
        if (now or datetime.now(UTC)) >= _parse_timestamp(token.get("expiresAt")):
            raise FormatError("SOVA-LOCAL-MCP-EXPIRED", "approval token has expired")
        if token.get("reviewedEffects") is not True or token.get("singleUse") is not True:
            raise FormatError("SOVA-LOCAL-MCP-TOKEN", "approval token policy is invalid")
        token_path.replace(consumed_path)
        return {
            "decision": "allowed",
            "challengeId": challenge_id,
            "invocationDigest": invocation.digest,
            "channel": token.get("channel"),
            "singleUseConsumed": True,
            "decidedAt": _timestamp(now or datetime.now(UTC)),
        }


__all__ = ["LocalApprovalStore", "create_control_key", "load_control_key"]
