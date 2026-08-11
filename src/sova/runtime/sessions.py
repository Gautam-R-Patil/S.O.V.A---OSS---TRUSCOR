# SPDX-License-Identifier: Apache-2.0
"""Opaque identities, durable browser profiles, and coordinated session leases."""

from __future__ import annotations

import ctypes
import os
import secrets
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self, TypedDict

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_SESSION_TTL_SECONDS = 3600
_PROFILE_HANDLE_LENGTH = 40
_PROFILE_LEASE_FILENAME = "sova-profile.lease.json"


def _windows_pid_is_alive(pid: int) -> bool:
    """Query a Windows process without sending a signal or mutating it."""
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return True
    kernel32: Any = win_dll("kernel32", use_last_error=True)
    process_query_limited_information = 0x1000
    error_invalid_parameter = 87
    still_active = 259
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    inherit_handle = wintypes.BOOL()
    handle = kernel32.OpenProcess(process_query_limited_information, inherit_handle, pid)
    if not handle:
        # Only ERROR_INVALID_PARAMETER proves the PID does not exist. Access
        # denial and unknown failures remain live so lease recovery fails closed.
        get_last_error = getattr(ctypes, "get_last_error", None)
        if get_last_error is None:
            return True
        return bool(get_last_error() != error_invalid_parameter)
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


class _ProfileLeaseMetadata(TypedDict):
    schemaVersion: str
    leaseId: str
    ownerId: str
    processId: int
    acquiredUnixMs: int
    expiresUnixMs: int


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


@dataclass(slots=True)
class BrowserProfileLease:
    """Exclusive, short-lived access to profile material at the executor boundary.

    The raw directory is deliberately available only through
    :meth:`path_for_executor`.  Trace-safe serialization exposes a digest of the
    opaque handle and lease metadata, never the handle, path, cookies, tokens,
    or other browser state.
    """

    id: str
    handle: str
    identity_id: str
    target: str
    owner_id: str
    acquired_unix_ms: int
    expires_unix_ms: int
    _profile_path: Path
    _lease_path: Path
    _released: bool = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()

    def path_for_executor(self) -> Path:
        """Return profile material only to the trusted launch boundary."""
        if self._released:
            raise FormatError("SOVA-PROFILE-LEASE-RELEASED", "browser profile lease was released")
        return self._profile_path

    def require_target(self, expected_target: str) -> None:
        """Refuse cross-target profile reuse at the trusted workflow boundary."""
        if self.target != expected_target:
            raise FormatError(
                "SOVA-PROFILE-TARGET-MISMATCH",
                "browser profile is bound to a different target",
            )

    def root_for_executor(self) -> Path:
        """Return the admitted vault root only to the trusted launch boundary."""
        if self._released:
            raise FormatError("SOVA-PROFILE-LEASE-RELEASED", "browser profile lease was released")
        return self._profile_path.parent

    def trace_mapping(self) -> dict[str, object]:
        return {
            "leaseId": self.id,
            "handleDigest": sha256_digest(self.handle.encode("utf-8")),
            "identityId": self.identity_id,
            "target": self.target,
            "ownerId": self.owner_id,
            "acquiredUnixMs": self.acquired_unix_ms,
            "expiresUnixMs": self.expires_unix_ms,
            "exclusive": True,
            "profileHandleExposed": False,
            "profilePathPresent": False,
            "profileMaterialPresent": False,
            "secretValuesPresent": False,
        }

    def release(self) -> None:
        """Release this lease without removing the durable browser profile."""
        if self._released:
            return
        try:
            value = strict_json_loads(self._lease_path.read_bytes(), max_bytes=64 * 1024)
        except FileNotFoundError:
            self._released = True
            return
        if not isinstance(value, dict) or value.get("leaseId") != self.id:
            raise FormatError(
                "SOVA-PROFILE-LEASE-SUBSTITUTION",
                "browser profile lease was replaced before release",
            )
        self._lease_path.unlink()
        self._released = True


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
        if os.name != "nt":
            self._root.chmod(0o700)
        self._lock = threading.Lock()

    def create(self, *, identity_id: str, target: str) -> BrowserProfileRecord:
        """Provision a new random opaque profile handle."""
        return self.provision(
            f"profile:{secrets.token_hex(16)}",
            identity_id=identity_id,
            target=target,
        )

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
            if os.name != "nt":
                metadata.chmod(0o600)
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

    @staticmethod
    def _pid_is_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        if os.name == "nt":
            return _windows_pid_is_alive(pid)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except (OSError, PermissionError):
            # Denied process inspection is treated as live: fail closed rather
            # than breaking another browser's profile lock.
            return True
        return True

    @staticmethod
    def _read_lease(path: Path) -> _ProfileLeaseMetadata:
        try:
            value = strict_json_loads(path.read_bytes(), max_bytes=64 * 1024)
        except FileNotFoundError as error:
            raise FormatError(
                "SOVA-PROFILE-LEASE-RACE", "browser profile lease changed during acquisition"
            ) from error
        if not isinstance(value, dict):
            raise FormatError("SOVA-PROFILE-LEASE-METADATA", "profile lease is malformed")
        lease_id = value.get("leaseId")
        owner_id = value.get("ownerId")
        process_id = value.get("processId")
        acquired = value.get("acquiredUnixMs")
        expires = value.get("expiresUnixMs")
        if (
            value.get("schemaVersion") != "0.1.0"
            or not isinstance(lease_id, str)
            or not isinstance(owner_id, str)
            or not isinstance(process_id, int)
            or not isinstance(acquired, int)
            or not isinstance(expires, int)
        ):
            raise FormatError("SOVA-PROFILE-LEASE-METADATA", "profile lease is malformed")
        return {
            "schemaVersion": "0.1.0",
            "leaseId": lease_id,
            "ownerId": owner_id,
            "processId": process_id,
            "acquiredUnixMs": acquired,
            "expiresUnixMs": expires,
        }

    def acquire(
        self,
        handle: str,
        *,
        owner_id: str,
        ttl_seconds: int = 900,
        recover_stale: bool = True,
    ) -> BrowserProfileLease:
        """Acquire a cross-process exclusive lease for a provisioned profile.

        Recovery removes a lease only after its deadline has passed *and* its
        recorded process is no longer observable.  A live or uninspectable PID
        always wins, so SOVA may refuse a usable profile but never knowingly
        opens it concurrently.
        """
        if not owner_id or not 1 <= ttl_seconds <= _MAX_SESSION_TTL_SECONDS:
            raise FormatError("SOVA-PROFILE-LEASE", "invalid browser profile lease request")
        profile_path = self.path_for_executor(handle)
        record = self._read_record(profile_path / "sova-profile.json")
        lease_path = profile_path / _PROFILE_LEASE_FILENAME
        now_ms = time.time_ns() // 1_000_000
        lease_id = f"profile-lease:{secrets.token_hex(16)}"
        document = {
            "schemaVersion": "0.1.0",
            "leaseId": lease_id,
            "ownerId": owner_id,
            "processId": os.getpid(),
            "acquiredUnixMs": now_ms,
            "expiresUnixMs": now_ms + ttl_seconds * 1000,
        }
        payload = canonical_json_bytes(document) + b"\n"
        with self._lock:
            for attempt in range(2):
                try:
                    with lease_path.open("xb") as stream:
                        stream.write(payload)
                    if os.name != "nt":
                        lease_path.chmod(0o600)
                    return BrowserProfileLease(
                        lease_id,
                        handle,
                        record.identity_id,
                        record.target,
                        owner_id,
                        now_ms,
                        now_ms + ttl_seconds * 1000,
                        profile_path,
                        lease_path,
                    )
                except FileExistsError as error:
                    existing = self._read_lease(lease_path)
                    expired = existing["expiresUnixMs"] <= now_ms
                    live = self._pid_is_alive(existing["processId"])
                    if not recover_stale or not expired or live or attempt:
                        raise FormatError(
                            "SOVA-PROFILE-BUSY",
                            "browser profile already has an active or unrecoverable lease",
                        ) from error
                    # Re-read before unlinking so a concurrent recovery cannot
                    # make us delete a newly acquired lease.
                    if self._read_lease(lease_path).get("leaseId") != existing.get("leaseId"):
                        raise FormatError(
                            "SOVA-PROFILE-LEASE-RACE",
                            "browser profile lease changed during recovery",
                        ) from error
                    lease_path.unlink()
        raise AssertionError


__all__ = [
    "BrowserProfileLease",
    "BrowserProfileRecord",
    "BrowserProfileVault",
    "SessionBroker",
    "SessionIdentity",
    "SessionLease",
]
