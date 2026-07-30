# SPDX-License-Identifier: Apache-2.0
"""Capture-time secret removal and typed structural placeholders."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

_SECRET_KEY = re.compile(
    r"(?:^|[_-])(api[_-]?key|authorization|cookie|credential|password|secret|session|token)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:bearer\s+[a-z0-9._~+/=-]{12,}|sk-[a-z0-9_-]{12,}|gh[oprsu]_[a-z0-9]{20,})"
)
_AES256_KEY_BYTES = 32
_SAFE_ENVIRONMENT_KEYS = frozenset(
    {
        "CI",
        "LANG",
        "LC_ALL",
        "PYTHONHASHSEED",
        "SOVA_CAPTURE_PROFILE",
        "SOVA_TEST_SEED",
        "TERM",
    }
)


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """A declared capture-time privacy policy."""

    name: str = "sova.default"
    version: str = "0.1.0"
    method: str = "omitted"
    commitment_key: bytes | None = None
    encryption_key: bytes | None = None
    key_id: str | None = None

    def __post_init__(self) -> None:
        if self.method not in {"omitted", "keyed-commitment", "encrypted"}:
            raise FormatError(
                "SOVA-REDACTION-METHOD",
                "redaction method must be omitted, keyed-commitment, or encrypted",
            )
        if self.method == "keyed-commitment" and not self.commitment_key:
            raise FormatError(
                "SOVA-REDACTION-KEY",
                "keyed-commitment redaction requires an operator-supplied key",
            )
        if self.method == "encrypted" and (
            self.encryption_key is None or len(self.encryption_key) != _AES256_KEY_BYTES
        ):
            raise FormatError(
                "SOVA-REDACTION-ENCRYPTION-KEY",
                "encrypted redaction requires a 32-byte operator-supplied key",
            )


class Redactor:
    """Remove secret-shaped data before any event bytes are persisted."""

    def __init__(
        self,
        policy: RedactionPolicy | None = None,
        *,
        context_id: str = "unscoped",
    ) -> None:
        self.policy = policy or RedactionPolicy()
        self.context_id = context_id

    def redact(self, value: Any) -> tuple[Any, list[dict[str, str]]]:
        """Return a structurally equivalent redacted value and disclosure records."""
        records: list[dict[str, str]] = []
        return self._walk(value, "$", records), records

    def _walk(self, value: Any, path: str, records: list[dict[str, str]]) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if _SECRET_KEY.search(str(key)):
                    result[str(key)] = self._placeholder(child, child_path, records, "credential")
                else:
                    result[str(key)] = self._walk(child, child_path, records)
            return result
        if isinstance(value, list):
            return [
                self._walk(child, f"{path}[{index}]", records)
                for index, child in enumerate(value)
            ]
        if isinstance(value, str) and _SECRET_VALUE.search(value):
            return self._placeholder(value, path, records, "credential")
        return value

    def _placeholder(
        self,
        value: Any,
        path: str,
        records: list[dict[str, str]],
        secret_class: str,
    ) -> dict[str, Any]:
        record = {"path": path, "class": secret_class, "method": self.policy.method}
        records.append(record)
        marker: dict[str, Any] = {
            "$redacted": {
                "class": secret_class,
                "method": self.policy.method,
                "present": True,
                "encoding": "sova-canonical-json/0.1",
            }
        }
        if self.policy.method == "keyed-commitment":
            commitment_key = self.policy.commitment_key
            if commitment_key is None:
                raise FormatError(
                    "SOVA-REDACTION-KEY",
                    "keyed-commitment redaction requires a key",
                )
            derived_key = hmac.new(
                commitment_key,
                b"SOVA-REDACTION-DERIVE-v1\x00" + self.context_id.encode("utf-8"),
                hashlib.sha256,
            ).digest()
            material = _redaction_material(value, path)
            commitment = hmac.new(
                derived_key,
                b"SOVA-REDACTION-COMMIT-v1\x00" + material,
                hashlib.sha256,
            ).digest()
            marker["$redacted"].update(
                {
                    "algorithm": "HMAC-SHA-256",
                    "commitment": base64.urlsafe_b64encode(commitment).decode("ascii"),
                    "keyId": self.policy.key_id,
                    "linkability": "within-context",
                    "contextDigest": sha256_digest(self.context_id.encode("utf-8")),
                }
            )
        elif self.policy.method == "encrypted":
            encryption_key = self.policy.encryption_key
            if encryption_key is None:
                raise FormatError(
                    "SOVA-REDACTION-ENCRYPTION-KEY",
                    "encrypted redaction requires a key",
                )
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
            except ImportError as error:
                raise FormatError(
                    "SOVA-REDACTION-ENCRYPTION-UNAVAILABLE",
                    "encrypted redaction requires the 'sova-oss[signing]' extra",
                ) from error
            nonce = secrets.token_bytes(12)
            plaintext = canonical_json_bytes(value)
            aad = canonical_json_bytes(
                {
                    "class": secret_class,
                    "encoding": "sova-canonical-json/0.1",
                    "path": path,
                    "policy": self.policy.name,
                    "policyVersion": self.policy.version,
                }
            )
            ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, aad)
            marker["$redacted"].update(
                {
                    "algorithm": "AES-256-GCM",
                    "keyId": self.policy.key_id,
                    "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
                    "aad": base64.urlsafe_b64encode(aad).decode("ascii"),
                    "recoverableSensitiveData": True,
                }
            )
        return marker


def _redaction_material(value: Any, path: str) -> bytes:
    type_name = (
        "null"
        if value is None
        else "boolean"
        if isinstance(value, bool)
        else "integer"
        if isinstance(value, int)
        else "string"
        if isinstance(value, str)
        else "array"
        if isinstance(value, list)
        else "object"
        if isinstance(value, dict)
        else type(value).__name__
    )
    return canonical_json_bytes(
        {
            "path": path,
            "schema": "sova.redaction-value/0.1",
            "type": type_name,
            "value": value,
        }
    )


@dataclass(frozen=True, slots=True)
class RedactionVerification:
    """Result of checking placeholder/record consistency and residual patterns."""

    placeholders: int
    records: int
    best_effort_secret_scan: bool


class RedactionVerifier:
    """Verify structural redaction claims without claiming perfect secret detection."""

    def verify(
        self,
        payload: Any,
        records: list[dict[str, str]],
    ) -> RedactionVerification:
        found: list[dict[str, str]] = []
        self._walk(payload, "$", found)
        expected = sorted(
            (item["path"], item["class"], item["method"])
            for item in records
            if {"path", "class", "method"} <= item.keys()
        )
        actual = sorted(
            (item["path"], item["class"], item["method"]) for item in found
        )
        if expected != actual:
            raise FormatError(
                "SOVA-REDACTION-RECORD-MISMATCH",
                "redaction records do not match durable placeholders",
                details={"records": expected, "placeholders": actual},
            )
        return RedactionVerification(
            placeholders=len(found),
            records=len(records),
            best_effort_secret_scan=True,
        )

    def _walk(self, value: Any, path: str, found: list[dict[str, str]]) -> None:
        if isinstance(value, dict):
            marker = value.get("$redacted")
            if marker is not None:
                if not isinstance(marker, dict):
                    raise FormatError(
                        "SOVA-REDACTION-PLACEHOLDER",
                        "redaction placeholder body must be an object",
                        path=path,
                    )
                required = {"class", "method", "present", "encoding"}
                if not required <= marker.keys() or marker["present"] is not True:
                    raise FormatError(
                        "SOVA-REDACTION-PLACEHOLDER",
                        "redaction placeholder is missing typed metadata",
                        path=path,
                    )
                found.append(
                    {
                        "path": path,
                        "class": str(marker["class"]),
                        "method": str(marker["method"]),
                    }
                )
                return
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if _SECRET_KEY.search(str(key)):
                    if isinstance(child, dict) and "$redacted" in child:
                        self._walk(child, child_path, found)
                        continue
                    raise FormatError(
                        "SOVA-REDACTION-RESIDUAL-SECRET",
                        "secret-shaped field remains after redaction",
                        path=child_path,
                    )
                self._walk(child, child_path, found)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._walk(child, f"{path}[{index}]", found)
            return
        if isinstance(value, str) and _SECRET_VALUE.search(value):
            raise FormatError(
                "SOVA-REDACTION-RESIDUAL-SECRET",
                "secret-shaped value remains after redaction",
                path=path,
            )


def decrypt_placeholder(
    placeholder: dict[str, Any],
    *,
    encryption_key: bytes,
) -> Any:
    """Decrypt one encrypted placeholder when the operator explicitly supplies its key."""
    marker = placeholder.get("$redacted")
    if not isinstance(marker, dict) or marker.get("method") != "encrypted":
        raise FormatError(
            "SOVA-REDACTION-DECRYPT",
            "value is not an encrypted SOVA placeholder",
        )
    if len(encryption_key) != _AES256_KEY_BYTES:
        raise FormatError(
            "SOVA-REDACTION-ENCRYPTION-KEY",
            "encrypted redaction requires a 32-byte operator-supplied key",
        )
    try:
        from cryptography.exceptions import InvalidTag  # noqa: PLC0415
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
    except ImportError as error:
        raise FormatError(
            "SOVA-REDACTION-DECRYPT",
            "encrypted redaction support is unavailable",
        ) from error
    try:
        nonce = base64.urlsafe_b64decode(marker["nonce"])
        ciphertext = base64.urlsafe_b64decode(marker["ciphertext"])
        aad = base64.urlsafe_b64decode(marker["aad"])
        plaintext = AESGCM(encryption_key).decrypt(nonce, ciphertext, aad)
    except (KeyError, TypeError, ValueError, InvalidTag) as error:
        raise FormatError(
            "SOVA-REDACTION-DECRYPT",
            "encrypted placeholder is malformed or cannot be decrypted",
        ) from error
    return strict_json_loads(plaintext)


def safe_environment(source: dict[str, str]) -> dict[str, str]:
    """Capture only a small allowlist and never snapshot the raw environment."""
    return {
        key: source[key]
        for key in sorted(_SAFE_ENVIRONMENT_KEYS)
        if key in source and not _SECRET_KEY.search(key)
    }


__all__ = [
    "RedactionPolicy",
    "RedactionVerification",
    "RedactionVerifier",
    "Redactor",
    "decrypt_placeholder",
    "safe_environment",
]
