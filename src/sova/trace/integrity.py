# SPDX-License-Identifier: Apache-2.0
"""Hash-chain and optional DSSE-compatible Ed25519 integrity material."""

from __future__ import annotations

import base64
import binascii
import copy
import importlib as _importlib
import re
from dataclasses import dataclass
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_PREDICATE_TYPE = "https://sova-oss.org/attestation/trace/v0.1"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_URLSAFE_BASE64 = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")
importlib = _importlib


@dataclass(frozen=True, slots=True)
class Ed25519Keypair:
    """Raw Ed25519 key bytes; private material is never stored in a trace."""

    private_key: bytes
    public_key: bytes
    key_id: str


def _crypto() -> tuple[Any, Any, Any]:
    try:
        serialization = importlib.import_module("cryptography.hazmat.primitives.serialization")
        ed25519 = importlib.import_module(
            "cryptography.hazmat.primitives.asymmetric.ed25519"
        )
    except ImportError as error:
        raise FormatError(
            "SOVA-INTEGRITY-SIGNING-UNAVAILABLE",
            "Ed25519 signing requires the 'sova-oss[signing]' extra",
        ) from error
    return ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, serialization


def generate_ed25519_keypair() -> Ed25519Keypair:
    """Generate an ephemeral keypair for tests or explicitly local signing."""
    private_cls, _public_cls, serialization = _crypto()
    private = private_cls.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return Ed25519Keypair(private_raw, public_raw, sha256_digest(public_raw))


def event_hash(event_without_hash: dict[str, Any]) -> str:
    """Hash a canonical event body, including its previousHash field."""
    value = copy.deepcopy(event_without_hash)
    value.pop("eventHash", None)
    return sha256_digest(canonical_json_bytes(value))


def unsigned_manifest_digest(manifest: dict[str, Any]) -> str:
    """Digest the trace manifest with self-referential integrity fields blanked."""
    value = copy.deepcopy(manifest)
    integrity = value["integrity"]
    integrity["manifestDigest"] = None
    integrity["signature"] = None
    return sha256_digest(canonical_json_bytes(value))


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def sign_trace_manifest(
    manifest: dict[str, Any],
    keypair: Ed25519Keypair,
    *,
    verification_material: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a DSSE-compatible envelope over an in-toto-style trace statement."""
    private_cls, _public_cls, _serialization = _crypto()
    digest = unsigned_manifest_digest(manifest)
    statement = {
        "_type": _STATEMENT_TYPE,
        "subject": [{"name": "sova.trace.manifest", "digest": {"sha256": digest[7:]}}],
        "predicateType": _PREDICATE_TYPE,
        "predicate": {
            "traceId": manifest["id"],
            "runId": manifest["runId"],
            "eventCount": manifest["eventCount"],
            "chainRoot": manifest["chainRoot"],
            "verificationMaterialDigest": (
                sha256_digest(canonical_json_bytes(verification_material))
                if verification_material is not None
                else None
            ),
        },
    }
    payload = canonical_json_bytes(statement)
    signature = private_cls.from_private_bytes(keypair.private_key).sign(
        _pae(_PAYLOAD_TYPE, payload)
    )
    return {
        "envelope": {
            "payloadType": _PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {
                    "keyid": keypair.key_id,
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
        "publicKey": {
            "algorithm": "ed25519",
            "keyid": keypair.key_id,
            "raw": base64.b64encode(keypair.public_key).decode("ascii"),
        },
        "trustPolicy": "included-key-integrity-only",
        "verificationMaterial": verification_material,
    }


def _decode_base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise FormatError(
            "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
            "signature base64 value is not a string",
        )
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        if _URLSAFE_BASE64.fullmatch(value) is None:
            raise FormatError(
                "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
                "signature value is not valid standard or URL-safe base64",
            ) from None
        padded = value + "=" * (-len(value) % 4)
        try:
            return base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError) as error:
            raise FormatError(
                "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
                "signature value is not valid standard or URL-safe base64",
            ) from error


def verify_trace_signature(manifest: dict[str, Any]) -> str:
    """Verify an included-key signature and return its deliberately weak trust policy."""
    _private_cls, public_cls, _serialization = _crypto()
    material = manifest["integrity"].get("signature")
    if not isinstance(material, dict):
        raise FormatError(
            "SOVA-INTEGRITY-UNSIGNED",
            "trace does not contain a signature",
        )
    try:
        envelope = material["envelope"]
        public = material["publicKey"]
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise FormatError(
            "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
            "trace signature material is malformed",
        ) from error
    if not isinstance(envelope, dict) or set(envelope) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        raise FormatError(
            "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
            "DSSE envelope contains missing or unexpected fields",
        )
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise FormatError(
            "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
            "reference verifier requires exactly one DSSE signature",
        )
    signature_item = signatures[0]
    if not isinstance(signature_item, dict):
        raise FormatError(
            "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
            "DSSE signature entry must be an object",
        )
    try:
        payload_type = envelope["payloadType"]
        payload = _decode_base64(envelope["payload"])
        signature = _decode_base64(signature_item["sig"])
        public_raw = _decode_base64(public["raw"])
    except (KeyError, TypeError) as error:
        raise FormatError(
            "SOVA-INTEGRITY-MALFORMED-SIGNATURE",
            "trace signature material is malformed",
        ) from error
    if payload_type != _PAYLOAD_TYPE or public.get("algorithm") != "ed25519":
        raise FormatError(
            "SOVA-INTEGRITY-UNSUPPORTED-SIGNATURE",
            "signature algorithm or payload type is unsupported",
        )
    key_id = sha256_digest(public_raw)
    if key_id != public.get("keyid") or key_id != signature_item.get("keyid"):
        raise FormatError(
            "SOVA-INTEGRITY-KEY-MISMATCH",
            "signature key identifier does not match the included key",
        )
    try:
        public_cls.from_public_bytes(public_raw).verify(signature, _pae(payload_type, payload))
    except Exception as error:
        raise FormatError(
            "SOVA-INTEGRITY-SIGNATURE-INVALID",
            "trace signature verification failed",
        ) from error
    statement = strict_json_loads(payload)
    if not isinstance(statement, dict):
        raise FormatError("SOVA-INTEGRITY-STATEMENT", "signed statement is not an object")
    expected_digest = unsigned_manifest_digest(manifest)
    try:
        subject_digest = statement["subject"][0]["digest"]["sha256"]
        predicate = statement["predicate"]
    except (KeyError, IndexError, TypeError) as error:
        raise FormatError("SOVA-INTEGRITY-STATEMENT", "signed statement is malformed") from error
    if (
        statement.get("_type") != _STATEMENT_TYPE
        or statement.get("predicateType") != _PREDICATE_TYPE
        or not isinstance(statement.get("subject"), list)
        or len(statement["subject"]) != 1
        or statement["subject"][0].get("name") != "sova.trace.manifest"
        or subject_digest != expected_digest[7:]
        or predicate.get("traceId") != manifest["id"]
        or predicate.get("runId") != manifest["runId"]
        or predicate.get("eventCount") != manifest["eventCount"]
        or predicate.get("chainRoot") != manifest["chainRoot"]
        or predicate.get("verificationMaterialDigest")
        != (
            sha256_digest(canonical_json_bytes(material["verificationMaterial"]))
            if material.get("verificationMaterial") is not None
            else None
        )
    ):
        raise FormatError(
            "SOVA-INTEGRITY-STATEMENT-MISMATCH",
            "signed statement does not match the trace manifest",
        )
    return "included-key-integrity-only"


__all__ = [
    "Ed25519Keypair",
    "event_hash",
    "generate_ed25519_keypair",
    "sign_trace_manifest",
    "unsigned_manifest_digest",
    "verify_trace_signature",
]
