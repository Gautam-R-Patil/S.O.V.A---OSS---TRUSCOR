# SPDX-License-Identifier: Apache-2.0
"""Opaque identities, durable browser profiles, and coordinated session leases."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_SESSION_TTL_SECONDS = 3600
_PROFILE_HANDLE_LENGTH = 40


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    """A pre-provisioned authorized test identity with opaque secret references."""

    id: str
    target: str
    secret_refs: tuple[str, ...]
    max_concurrency: int = 1
    shared_state_allowed: bool = False

    def __post_init__(self) -> None:
        if not self.id or not self.target or self.max_concurrency < 1:
            raise FormatError("SOVA-SESSION-IDENTITY", "invalid session identity")
        if not self.secret_refs or not all(
            reference.startswith("sova-secret:") for reference in self.secret_refs
        ):
            raise FormatError(
                "SOVA-SESSION-SECRET-REF",
                "session identities require opaque sova-secret references",
            )


@dataclass(frozen=True, slots=True)
class SessionLease:
    """A short-lived handle; it contains no password, cookie, or token value."""

    id: str
    identity_id: str
    agent_id: str
    target: str
    scope: tuple[str, ...]
    profile_handle: str
    expires_monotonic_ns: int
    shared: bool

    def trace_mapping(self) -> dict[str, object]:
        return {
            "leaseId": self.id,
            "identityId": self.identity_id,
            "agentId": self.agent_id,
            "target": self.target,
            "scope": list(self.scope),
            "shared": self.shared,
            "secretValuesPresent": False,
            "profileHandleExposed": False,
            "profileMaterialPresent": False,
            "profilePersistence": "executor-managed",
        }


class SessionBroker:
    """Lease identities without disclosing authentication material to agents."""

    def __init__(self, identities: tuple[SessionIdentity, ...]) -> None:
        if len({identity.id for identity in identities}) != len(identities):
            raise FormatError("SOVA-SESSION-DUPLICATE", "session identity IDs must be unique")
        self._identities = {identity.id: identity for identity in identities}
        self._leases: dict[str, SessionLease] = {}
        self._by_identity: dict[str, set[str]] = {identity.id: set() for identity in identities}
        self._profile_handles = {
            identity.id: f"profile:{secrets.token_hex(16)}" for identity in identities
        }
        self._lock = threading.Lock()

    def lease(
        self,
        identity_id: str,
        *,
        agent_id: str,
        scope: tuple[str, ...],
        ttl_seconds: int = 300,
        shared: bool = False,
    ) -> SessionLease:
        if not agent_id or not scope or not 1 <= ttl_seconds <= _MAX_SESSION_TTL_SECONDS:
            raise FormatError("SOVA-SESSION-LEASE", "invalid session lease request")
        identity = self._identities.get(identity_id)
        if identity is None:
            raise FormatError("SOVA-SESSION-IDENTITY", "unknown session identity")
        if shared and not identity.shared_state_allowed:
            raise FormatError(
                "SOVA-SESSION-SHARING-DENIED",
                "identity does not authorize shared mutable session state",
            )
        with self._lock:
            self._expire_locked(time.monotonic_ns())
            active = self._by_identity[identity_id]
            if len(active) >= identity.max_concurrency:
                raise FormatError(
                    "SOVA-SESSION-BUSY",
                    "all authorized leases for the identity are in use",
                )
            lease = SessionLease(
                id=f"session-lease:{secrets.token_hex(16)}",
                identity_id=identity_id,
                agent_id=agent_id,
                target=identity.target,
                scope=tuple(sorted(set(scope))),
                profile_handle=self._profile_handles[identity_id],
                expires_monotonic_ns=time.monotonic_ns() + ttl_seconds * 1_000_000_000,
                shared=shared,
            )
            self._leases[lease.id] = lease
            active.add(lease.id)
            return lease

    def secret_refs_for_executor(self, lease_id: str) -> tuple[str, ...]:
        """Return opaque references only at the trusted executor boundary."""
        with self._lock:
            self._expire_locked(time.monotonic_ns())
            lease = self._leases.get(lease_id)
            if lease is None:
                raise FormatError("SOVA-SESSION-EXPIRED", "session lease is absent or expired")
            return self._identities[lease.identity_id].secret_refs

    def release(self, lease_id: str) -> None:
        with self._lock:
            lease = self._leases.pop(lease_id, None)
            if lease is not None:
                self._by_identity[lease.identity_id].discard(lease_id)

    def release_agent(self, agent_id: str) -> int:
        with self._lock:
            selected = [
                lease_id for lease_id, lease in self._leases.items() if lease.agent_id == agent_id
            ]
            for lease_id in selected:
                lease = self._leases.pop(lease_id)
                self._by_identity[lease.identity_id].discard(lease_id)
            return len(selected)

    def _expire_locked(self, now_ns: int) -> None:
        expired = [
            lease_id
            for lease_id, lease in self._leases.items()
            if lease.expires_monotonic_ns <= now_ns
        ]
        for lease_id in expired:
            lease = self._leases.pop(lease_id)
            self._by_identity[lease.identity_id].discard(lease_id)


@dataclass(frozen=True, slots=True)
class BrowserProfileRecord:
    """Non-secret metadata for one executor-owned browser profile."""

    handle: str
    identity_id: str
    target: str
    created_unix_ms: int

    def trace_mapping(self) -> dict[str, object]:
        return {
            "handleDigest": sha256_digest(self.handle.encode("utf-8")),
            "identityId": self.identity_id,
            "target": self.target,
            "profilePathPresent": False,
            "profileMaterialPresent": False,
            "secretValuesPresent": False,
            "persistence": "executor-managed",
        }


class BrowserProfileVault:
    """Map opaque handles to workspace-contained profile directories.

    The path is available only at the trusted executor boundary. Profile
    contents can include authentication material and must never be copied into
    traces, capsules, reports, or model prompts.
    """

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        if self._root.is_symlink() or not self._root.is_dir():
            raise FormatError("SOVA-PROFILE-ROOT", "browser profile root must be a real directory")
        self._lock = threading.Lock()

    @staticmethod
    def _validate_handle(handle: str) -> None:
        if not handle.startswith("profile:") or len(handle) != _PROFILE_HANDLE_LENGTH:
            raise FormatError("SOVA-PROFILE-HANDLE", "browser profile handle is malformed")
        suffix = handle.removeprefix("profile:")
        if any(character not in "0123456789abcdef" for character in suffix):
            raise FormatError("SOVA-PROFILE-HANDLE", "browser profile handle is malformed")

    def _directory(self, handle: str) -> Path:
        self._validate_handle(handle)
        digest = sha256_digest(handle.encode("utf-8")).removeprefix("sha256:")
        path = (self._root / digest).resolve()
        try:
            path.relative_to(self._root)
        except ValueError as error:  # pragma: no cover - digest paths cannot escape
            raise FormatError(
                "SOVA-PROFILE-PATH", "browser profile path escaped its vault"
            ) from error
        return path

    def provision(
        self,
        handle: str,
        *,
        identity_id: str,
        target: str,
    ) -> BrowserProfileRecord:
        if not identity_id or not target:
            raise FormatError("SOVA-PROFILE-IDENTITY", "profile identity and target are required")
        path = self._directory(handle)
        metadata = path / "sova-profile.json"
        with self._lock:
            path.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise FormatError("SOVA-PROFILE-PATH", "browser profile directory is a symlink")
            if metadata.exists():
                record = self._read_record(metadata)
                if (
                    record.handle != handle
                    or record.identity_id != identity_id
                    or record.target != target
                ):
                    raise FormatError(
                        "SOVA-PROFILE-SUBSTITUTION",
                        "profile handle is already bound to a different identity or target",
                    )
                return record
            record = BrowserProfileRecord(handle, identity_id, target, time.time_ns() // 1_000_000)
            document = {
                "schemaVersion": "0.1.0",
                "handle": record.handle,
                "identityId": record.identity_id,
                "target": record.target,
                "createdUnixMs": record.created_unix_ms,
                "containsAuthenticationMaterial": "possible-never-export",
            }
            metadata.write_bytes(canonical_json_bytes(document) + b"\n")
            return record

    @staticmethod
    def _read_record(path: Path) -> BrowserProfileRecord:
        value = strict_json_loads(path.read_bytes(), max_bytes=64 * 1024)
        if not isinstance(value, dict):
            raise FormatError("SOVA-PROFILE-METADATA", "profile metadata is malformed")
        handle = value.get("handle")
        identity_id = value.get("identityId")
        target = value.get("target")
        created = value.get("createdUnixMs")
        if (
            value.get("schemaVersion") != "0.1.0"
            or not isinstance(handle, str)
            or not isinstance(identity_id, str)
            or not isinstance(target, str)
            or not isinstance(created, int)
        ):
            raise FormatError("SOVA-PROFILE-METADATA", "profile metadata is malformed")
        return BrowserProfileRecord(handle, identity_id, target, created)

    def path_for_executor(self, handle: str) -> Path:
        """Resolve a provisioned profile only for a trusted executor launch."""
        path = self._directory(handle)
        metadata = path / "sova-profile.json"
        if not path.is_dir() or path.is_symlink() or not metadata.is_file():
            raise FormatError("SOVA-PROFILE-ABSENT", "browser profile was not provisioned")
        self._read_record(metadata)
        return path

    def inspect(self, handle: str) -> dict[str, object]:
        """Return trace-safe metadata without enumerating profile contents."""
        path = self.path_for_executor(handle)
        return self._read_record(path / "sova-profile.json").trace_mapping()


__all__ = [
    "BrowserProfileRecord",
    "BrowserProfileVault",
    "SessionBroker",
    "SessionIdentity",
    "SessionLease",
]
