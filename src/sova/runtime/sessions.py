# SPDX-License-Identifier: Apache-2.0
"""In-memory identity and session leases for coordinated agent swarms."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from sova.formats.errors import FormatError

_MAX_SESSION_TTL_SECONDS = 3600


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
            "profileMaterialPersisted": False,
        }


class SessionBroker:
    """Lease identities without disclosing authentication material to agents."""

    def __init__(self, identities: tuple[SessionIdentity, ...]) -> None:
        if len({identity.id for identity in identities}) != len(identities):
            raise FormatError("SOVA-SESSION-DUPLICATE", "session identity IDs must be unique")
        self._identities = {identity.id: identity for identity in identities}
        self._leases: dict[str, SessionLease] = {}
        self._by_identity: dict[str, set[str]] = {identity.id: set() for identity in identities}
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
                profile_handle=f"profile:{secrets.token_hex(16)}",
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


__all__ = ["SessionBroker", "SessionIdentity", "SessionLease"]
