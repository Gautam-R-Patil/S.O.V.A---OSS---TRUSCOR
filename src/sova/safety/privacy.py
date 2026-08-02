# SPDX-License-Identifier: Apache-2.0
"""Local-first secret, consent, export, and retention primitives."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self

from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class PrivacyDefaults:
    telemetry_enabled: bool = False
    account_required: bool = False
    raw_environment_capture: bool = False
    contribution_enabled: bool = False

    def __post_init__(self) -> None:
        if any(
            (
                self.telemetry_enabled,
                self.account_required,
                self.raw_environment_capture,
                self.contribution_enabled,
            )
        ):
            raise FormatError(
                "SOVA-PRIVACY-DEFAULTS",
                "reference privacy defaults must remain local, account-free, and opt-in",
            )


class EphemeralSecretStore:
    """In-memory byte buffers addressed only by opaque references."""

    def __init__(self) -> None:
        self._values: dict[str, bytearray] = {}
        self._lock = threading.Lock()
        self._closed = False

    def put(self, value: str | bytes) -> str:
        if self._closed:
            raise FormatError("SOVA-SECRET-CLOSED", "secret store is closed")
        encoded = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        reference = "sova-secret:" + secrets.token_urlsafe(24)
        with self._lock:
            self._values[reference] = bytearray(encoded)
        return reference

    def resolve(self, reference: str) -> str:
        with self._lock:
            value = self._values.get(reference)
            if value is None:
                raise FormatError("SOVA-SECRET-MISSING", "secret reference is unknown or expired")
            return bytes(value).decode("utf-8")

    def delete(self, reference: str) -> None:
        with self._lock:
            value = self._values.pop(reference, None)
        if value is not None:
            value[:] = b"\x00" * len(value)

    def close(self) -> None:
        with self._lock:
            references = tuple(self._values)
        for reference in references:
            self.delete(reference)
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class ContributionConsent:
    approved_items: frozenset[str]
    reviewed_at: datetime
    approved_by: str

    def __post_init__(self) -> None:
        if self.reviewed_at.tzinfo is None or not self.approved_by:
            raise FormatError("SOVA-CONSENT", "consent requires an identified, timestamped review")

    def permits(self, item_digest: str) -> bool:
        return item_digest in self.approved_items


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    name: str
    expires_at: datetime | None
    auto_delete: bool
    export_allowed: bool

    def expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        if self.expires_at.tzinfo is None:
            raise FormatError("SOVA-RETENTION-TIMEZONE", "retention time needs a timezone")
        return (now or datetime.now(UTC)) >= self.expires_at


class RetentionController:
    """Delete individual local artifacts only inside one explicit root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not self.root.is_dir():
            raise FormatError("SOVA-RETENTION-ROOT", "retention root must exist")

    def delete_file(self, path: Path) -> bool:
        resolved = path.resolve()
        if resolved == self.root or self.root not in resolved.parents:
            raise FormatError("SOVA-RETENTION-SCOPE", "deletion target escaped retention root")
        if not resolved.exists():
            return False
        if not resolved.is_file() or resolved.is_symlink():
            raise FormatError(
                "SOVA-RETENTION-TARGET",
                "reference retention deletion accepts ordinary files only",
            )
        resolved.unlink()
        return True


__all__ = [
    "ContributionConsent",
    "EphemeralSecretStore",
    "PrivacyDefaults",
    "RetentionController",
    "RetentionPolicy",
]
