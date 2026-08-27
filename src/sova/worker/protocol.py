# SPDX-License-Identifier: Apache-2.0
"""Mutually authenticated, signed, replay-resistant worker protocol primitives."""

from __future__ import annotations

import hashlib
import re
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace.integrity import Ed25519Keypair, sign_dsse_payload, verify_dsse_payload
from sova.worker.contracts import PROTOCOL_VERSION

if TYPE_CHECKING:
    from pathlib import Path

WORKER_PROTOCOL_MEDIA_TYPE = "application/vnd.sova.worker-message+json"
MAX_MESSAGE_AUTHORITY_SECONDS = 300
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,190}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class ProtocolRole(StrEnum):
    CONTROLLER = "controller"
    WORKER = "worker"


class ProtocolMessageType(StrEnum):
    SUBMIT_JOB = "submit-job"
    ACCEPT_JOB = "accept-job"
    REJECT_JOB = "reject-job"
    CANCEL_JOB = "cancel-job"
    JOB_RESULT = "job-result"
    HEARTBEAT = "heartbeat"


def _time(value: str, role: str) -> datetime:
    if _RFC3339.fullmatch(value) is None:
        raise FormatError("SOVA-WORKER-PROTOCOL-TIME", f"{role} must be second-precision UTC")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise FormatError("SOVA-WORKER-PROTOCOL-FIELD", f"{key} must be a string")
    return value


@dataclass(frozen=True, slots=True)
class ProtocolMessage:
    """Signed application message whose transport is separately protected by mTLS."""

    message_type: ProtocolMessageType
    message_id: str
    job_id: str
    sender_role: ProtocolRole
    sender_id: str
    recipient_id: str
    issued_at: str
    expires_at: str
    nonce: str
    sender_certificate_digest: str
    payload_digest: str
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != PROTOCOL_VERSION:
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-VERSION",
                f"protocol version must be {PROTOCOL_VERSION}",
            )
        for role, value in (
            ("message", self.message_id),
            ("job", self.job_id),
            ("sender", self.sender_id),
            ("recipient", self.recipient_id),
        ):
            if _IDENTIFIER.fullmatch(value) is None:
                raise FormatError("SOVA-WORKER-PROTOCOL-ID", f"{role} identifier is invalid")
        issued = _time(self.issued_at, "message issue time")
        expires = _time(self.expires_at, "message expiry time")
        authority = (expires - issued).total_seconds()
        if authority <= 0 or authority > MAX_MESSAGE_AUTHORITY_SECONDS:
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-TIME",
                "message authority must be positive and at most five minutes",
            )
        if _NONCE.fullmatch(self.nonce) is None:
            raise FormatError("SOVA-WORKER-PROTOCOL-NONCE", "message nonce is invalid")
        for role, value in (
            ("sender certificate", self.sender_certificate_digest),
            ("payload", self.payload_digest),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise FormatError("SOVA-WORKER-PROTOCOL-DIGEST", f"{role} digest is invalid")
        expected_role = (
            ProtocolRole.CONTROLLER
            if self.message_type in {ProtocolMessageType.SUBMIT_JOB, ProtocolMessageType.CANCEL_JOB}
            else ProtocolRole.WORKER
        )
        if self.message_type != ProtocolMessageType.HEARTBEAT and self.sender_role != expected_role:
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-ROLE",
                "message type is not permitted for the claimed sender role",
            )

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-protocol-message",
            "schemaVersion": "0.1.0",
            "protocolVersion": self.protocol_version,
            "messageType": self.message_type.value,
            "messageId": self.message_id,
            "jobId": self.job_id,
            "sender": {"role": self.sender_role.value, "id": self.sender_id},
            "recipientId": self.recipient_id,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "nonce": self.nonce,
            "senderCertificateDigest": self.sender_certificate_digest,
            "payloadDigest": self.payload_digest,
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> ProtocolMessage:
        expected = {
            "artifactType",
            "schemaVersion",
            "protocolVersion",
            "messageType",
            "messageId",
            "jobId",
            "sender",
            "recipientId",
            "issuedAt",
            "expiresAt",
            "nonce",
            "senderCertificateDigest",
            "payloadDigest",
            "contentDigest",
        }
        if set(mapping) != expected:
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-FIELD",
                "protocol message contains missing or unexpected fields",
            )
        if mapping.get("artifactType") != "sova.worker-protocol-message":
            raise FormatError("SOVA-WORKER-PROTOCOL-TYPE", "protocol artifact type is invalid")
        unsigned = dict(mapping)
        claimed_digest = _string(unsigned, "contentDigest")
        del unsigned["contentDigest"]
        if claimed_digest != sha256_digest(canonical_json_bytes(unsigned)):
            raise FormatError("SOVA-WORKER-PROTOCOL-DIGEST", "message content digest is invalid")
        sender = mapping.get("sender")
        if not isinstance(sender, dict) or set(sender) != {"role", "id"}:
            raise FormatError("SOVA-WORKER-PROTOCOL-FIELD", "sender binding is malformed")
        try:
            message_type = ProtocolMessageType(_string(mapping, "messageType"))
            sender_role = ProtocolRole(_string(sender, "role"))
        except ValueError as error:
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-FIELD", "protocol enum value is unsupported"
            ) from error
        return cls(
            message_type=message_type,
            message_id=_string(mapping, "messageId"),
            job_id=_string(mapping, "jobId"),
            sender_role=sender_role,
            sender_id=_string(sender, "id"),
            recipient_id=_string(mapping, "recipientId"),
            issued_at=_string(mapping, "issuedAt"),
            expires_at=_string(mapping, "expiresAt"),
            nonce=_string(mapping, "nonce"),
            sender_certificate_digest=_string(mapping, "senderCertificateDigest"),
            payload_digest=_string(mapping, "payloadDigest"),
            protocol_version=_string(mapping, "protocolVersion"),
        )


@dataclass(slots=True)
class ReplayCache:
    """Fail closed on a reused message identifier or nonce within the authority window."""

    maximum_entries: int = 100_000
    _entries: dict[str, datetime] = field(default_factory=dict)

    def admit(self, message: ProtocolMessage, *, now: datetime) -> None:
        if now.tzinfo is None:
            raise FormatError("SOVA-WORKER-PROTOCOL-TIME", "replay clock must be timezone-aware")
        instant = now.astimezone(UTC)
        issued = _time(message.issued_at, "message issue time")
        expires = _time(message.expires_at, "message expiry time")
        if instant < issued or instant >= expires:
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-EXPIRED", "message is outside its authority window"
            )
        self._entries = {key: expiry for key, expiry in self._entries.items() if expiry > instant}
        keys = (f"message:{message.message_id}", f"nonce:{message.nonce}")
        if any(key in self._entries for key in keys):
            raise FormatError(
                "SOVA-WORKER-PROTOCOL-REPLAY", "message or nonce was already admitted"
            )
        if len(self._entries) + len(keys) > self.maximum_entries:
            raise FormatError("SOVA-WORKER-PROTOCOL-CAPACITY", "replay cache capacity is exhausted")
        self._entries.update(dict.fromkeys(keys, expires))


def certificate_digest(der_certificate: bytes) -> str:
    """Return the immutable SHA-256 pin for the actual TLS peer certificate."""
    if not der_certificate:
        raise FormatError("SOVA-WORKER-TLS-CERTIFICATE", "peer certificate is required")
    return f"sha256:{hashlib.sha256(der_certificate).hexdigest()}"


def build_controller_tls_context(
    *, ca_file: Path, certificate_file: Path, private_key_file: Path
) -> ssl.SSLContext:
    """Create a TLS 1.3 client context that requires a trusted worker certificate."""
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(ca_file.resolve(strict=True))
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=str(certificate_file.resolve(strict=True)),
        keyfile=str(private_key_file.resolve(strict=True)),
    )
    return context


def build_worker_tls_context(
    *, ca_file: Path, certificate_file: Path, private_key_file: Path
) -> ssl.SSLContext:
    """Create a TLS 1.3 server context that requires a trusted controller certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca_file.resolve(strict=True)))
    context.load_cert_chain(
        certfile=str(certificate_file.resolve(strict=True)),
        keyfile=str(private_key_file.resolve(strict=True)),
    )
    return context


def sign_protocol_message(message: ProtocolMessage, keypair: Ed25519Keypair) -> dict[str, Any]:
    """Sign the canonical application message; TLS and DSSE serve different layers."""
    return sign_dsse_payload(
        WORKER_PROTOCOL_MEDIA_TYPE,
        canonical_json_bytes(message.to_mapping()),
        keypair,
    )


def verify_protocol_message(  # noqa: PLR0913 - independent trust bindings stay explicit
    envelope: dict[str, Any],
    public_key: bytes,
    *,
    expected_sender_role: ProtocolRole,
    expected_sender_id: str,
    expected_recipient_id: str,
    peer_certificate_der: bytes,
    now: datetime,
    replay_cache: ReplayCache,
) -> ProtocolMessage:
    """Verify signature, peer binding, direction, authority window, and replay state."""
    payload = verify_dsse_payload(
        envelope,
        public_key,
        expected_payload_type=WORKER_PROTOCOL_MEDIA_TYPE,
    )
    parsed = strict_json_loads(payload, max_bytes=256 * 1024, max_items=4096)
    if not isinstance(parsed, dict):
        raise FormatError("SOVA-WORKER-PROTOCOL-FIELD", "signed message root must be an object")
    message = ProtocolMessage.from_mapping(parsed)
    if message.sender_role != expected_sender_role or message.sender_id != expected_sender_id:
        raise FormatError("SOVA-WORKER-PROTOCOL-PEER", "signed sender identity is unexpected")
    if message.recipient_id != expected_recipient_id:
        raise FormatError("SOVA-WORKER-PROTOCOL-PEER", "signed recipient identity is unexpected")
    if message.sender_certificate_digest != certificate_digest(peer_certificate_der):
        raise FormatError(
            "SOVA-WORKER-PROTOCOL-CERTIFICATE",
            "signed message is not bound to the authenticated TLS peer certificate",
        )
    replay_cache.admit(message, now=now)
    return message


__all__ = [
    "MAX_MESSAGE_AUTHORITY_SECONDS",
    "WORKER_PROTOCOL_MEDIA_TYPE",
    "ProtocolMessage",
    "ProtocolMessageType",
    "ProtocolRole",
    "ReplayCache",
    "build_controller_tls_context",
    "build_worker_tls_context",
    "certificate_digest",
    "sign_protocol_message",
    "verify_protocol_message",
]
