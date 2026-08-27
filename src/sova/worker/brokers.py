# SPDX-License-Identifier: Apache-2.0
"""Fail-closed network and secret capability brokers for hostile guests."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.worker.contracts import NetworkRule, SecretGrant, WorkerJobManifest

IP = IPv4Address | IPv6Address


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise FormatError("SOVA-WORKER-BROKER-TIME", "broker clock must be timezone-aware")
    return value.astimezone(UTC)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _admissible_destination(value: str, *, allow_private: bool) -> IP:
    try:
        address = ip_address(value)
    except ValueError as error:
        raise FormatError("SOVA-WORKER-NETWORK-IP", "resolved destination is invalid") from error
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or (address.is_private and not allow_private)
        or (not address.is_global and not (allow_private and address.is_private))
    ):
        raise FormatError(
            "SOVA-WORKER-NETWORK-PRIVATE",
            (
                "loopback, private, link-local, metadata, multicast, and reserved "
                "destinations are denied"
            ),
        )
    return address


@dataclass(frozen=True, slots=True)
class NetworkFlowReceipt:
    job_id: str
    sequence: int
    observed_at: str
    hostname: str
    port: int
    protocol: str
    pinned_addresses: tuple[str, ...]
    resolved_addresses: tuple[str, ...]
    selected_address: str | None
    requested_bytes: int
    decision: str
    reason: str

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-network-receipt",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "sequence": self.sequence,
            "observedAt": self.observed_at,
            "endpoint": {
                "hostname": self.hostname,
                "port": self.port,
                "protocol": self.protocol,
            },
            "pinnedAddresses": list(self.pinned_addresses),
            "resolvedAddresses": list(self.resolved_addresses),
            "selectedAddress": self.selected_address,
            "requestedBytes": self.requested_bytes,
            "decision": self.decision,
            "reason": self.reason,
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


@dataclass(slots=True)
class NetworkBroker:
    """Authorize exact flows and emit receipts without granting ambient guest egress."""

    manifest: WorkerJobManifest
    _connection_count: int = 0
    _byte_count: int = 0
    _sequence: int = 0
    receipts: list[NetworkFlowReceipt] = field(default_factory=list)

    def _find_rule(self, hostname: str, port: int, protocol: str) -> NetworkRule | None:
        normalized = hostname.rstrip(".").lower()
        return next(
            (
                rule
                for rule in self.manifest.network_rules
                if (rule.hostname, rule.port, rule.protocol) == (normalized, port, protocol)
            ),
            None,
        )

    def authorize(  # noqa: PLR0913 - endpoint and observation bindings remain explicit
        self,
        *,
        hostname: str,
        port: int,
        protocol: str,
        resolved_addresses: tuple[str, ...],
        selected_address: str,
        requested_bytes: int,
        now: datetime,
    ) -> NetworkFlowReceipt:
        """Admit a single connection only if pins, destination, time, and budgets hold."""
        self._sequence += 1
        rule = self._find_rule(hostname, port, protocol)
        decision, reason = "denied", "endpoint-not-authorized"
        pins: tuple[str, ...] = () if rule is None else rule.initial_addresses
        instant = _utc(now)
        if requested_bytes < 0:
            reason = "negative-byte-request"
        elif rule is not None:
            try:
                parsed = tuple(
                    str(_admissible_destination(value, allow_private=rule.allow_private))
                    for value in resolved_addresses
                )
                selected = str(
                    _admissible_destination(selected_address, allow_private=rule.allow_private)
                )
                if not parsed or len(parsed) != len(set(parsed)):
                    reason = "dns-answer-invalid"
                elif set(parsed) != set(pins) or selected not in parsed:
                    reason = "dns-pin-mismatch"
                elif instant < _parse_time(self.manifest.issued_at):
                    reason = "job-not-yet-valid"
                elif instant >= self._deadline():
                    reason = "job-time-budget-exhausted"
                elif self._connection_count >= self.manifest.limits.network_connection_limit:
                    reason = "connection-budget-exhausted"
                elif self._byte_count + requested_bytes > self.manifest.limits.network_bytes:
                    reason = "byte-budget-exhausted"
                else:
                    decision, reason = "allowed", "policy-and-budgets-satisfied"
                    self._connection_count += 1
                    self._byte_count += requested_bytes
            except FormatError as error:
                reason = error.issue.code
        receipt = NetworkFlowReceipt(
            job_id=self.manifest.job_id,
            sequence=self._sequence,
            observed_at=instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
            hostname=hostname.rstrip(".").lower(),
            port=port,
            protocol=protocol,
            pinned_addresses=pins,
            resolved_addresses=resolved_addresses,
            selected_address=selected_address,
            requested_bytes=requested_bytes,
            decision=decision,
            reason=reason,
        )
        self.receipts.append(receipt)
        return receipt

    def _deadline(self) -> datetime:
        authority_end = _parse_time(self.manifest.expires_at)
        budget_end = _parse_time(self.manifest.issued_at) + timedelta(
            seconds=self.manifest.limits.timeout_seconds
        )
        return min(authority_end, budget_end)

    @property
    def consumed_connections(self) -> int:
        return self._connection_count

    @property
    def consumed_bytes(self) -> int:
        return self._byte_count


@dataclass(frozen=True, slots=True)
class SecretUseReceipt:
    job_id: str
    grant_name: str
    audience: str
    kind: str
    observed_at: str
    use_number: int
    secret_digest: str
    decision: str
    reason: str

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-secret-receipt",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "grantName": self.grant_name,
            "audience": self.audience,
            "kind": self.kind,
            "observedAt": self.observed_at,
            "useNumber": self.use_number,
            "secretDigest": self.secret_digest,
            "decision": self.decision,
            "reason": self.reason,
            "claims": {
                "secretValueEmbedded": False,
                "capabilityTokenEmbedded": False,
                "hostPathOrSocketGranted": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


@dataclass(slots=True, repr=False)
class _SecretCapability:
    token: str
    grant: SecretGrant
    value: bytearray
    digest: str
    uses: int = 0
    revoked: bool = False


@dataclass(slots=True)
class SecretBroker:
    """Deliver scalar values through opaque, audience-bound, one-job capabilities."""

    manifest: WorkerJobManifest
    _capabilities: dict[str, _SecretCapability] = field(default_factory=dict, repr=False)
    receipts: list[SecretUseReceipt] = field(default_factory=list)

    def provision(self, grant_name: str, value: bytes, *, now: datetime) -> str:
        """Provision a declared secret in broker memory and return an unlogged opaque token."""
        instant = _utc(now)
        grant = next(
            (item for item in self.manifest.secret_grants if item.name == grant_name),
            None,
        )
        if grant is None:
            raise FormatError("SOVA-WORKER-SECRET-GRANT", "secret grant is not declared")
        if not value or len(value) > 64 * 1024:
            raise FormatError("SOVA-WORKER-SECRET-SIZE", "secret value is empty or exceeds policy")
        if instant >= _parse_time(grant.expires_at) or instant >= _parse_time(
            self.manifest.expires_at
        ):
            raise FormatError("SOVA-WORKER-SECRET-EXPIRED", "secret grant has expired")
        token = secrets.token_urlsafe(32)
        digest = sha256_digest(value)
        self._capabilities[token] = _SecretCapability(token, grant, bytearray(value), digest)
        return token

    def redeem(
        self, token: str, *, audience: str, now: datetime
    ) -> tuple[bytes | None, SecretUseReceipt]:
        """Redeem once within grant policy; receipts never contain token or secret bytes."""
        instant = _utc(now)
        capability = self._capabilities.get(token)
        if capability is None:
            receipt = self._receipt(
                None,
                audience=audience,
                instant=instant,
                decision="denied",
                reason="unknown-capability",
            )
            return None, receipt
        grant = capability.grant
        decision, reason = "denied", "capability-revoked"
        value: bytes | None = None
        if not capability.revoked:
            if audience != grant.audience:
                reason = "audience-mismatch"
            elif instant >= _parse_time(grant.expires_at) or instant >= _parse_time(
                self.manifest.expires_at
            ):
                reason = "secret-grant-expired"
            elif capability.uses >= grant.maximum_uses:
                reason = "use-budget-exhausted"
            else:
                capability.uses += 1
                decision, reason = "allowed", "capability-policy-satisfied"
                value = bytes(capability.value)
                if capability.uses >= grant.maximum_uses:
                    capability.revoked = True
                    _zero(capability.value)
        receipt = self._receipt(
            capability,
            audience=audience,
            instant=instant,
            decision=decision,
            reason=reason,
        )
        return value, receipt

    def revoke_all(self) -> None:
        for capability in self._capabilities.values():
            capability.revoked = True
            _zero(capability.value)

    def _receipt(
        self,
        capability: _SecretCapability | None,
        *,
        audience: str,
        instant: datetime,
        decision: str,
        reason: str,
    ) -> SecretUseReceipt:
        receipt = SecretUseReceipt(
            job_id=self.manifest.job_id,
            grant_name="unknown" if capability is None else capability.grant.name,
            audience=audience,
            kind="unknown" if capability is None else capability.grant.kind.value,
            observed_at=instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
            use_number=0 if capability is None else capability.uses,
            secret_digest=("sha256:" + "0" * 64 if capability is None else capability.digest),
            decision=decision,
            reason=reason,
        )
        self.receipts.append(receipt)
        return receipt


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


__all__ = [
    "NetworkBroker",
    "NetworkFlowReceipt",
    "SecretBroker",
    "SecretUseReceipt",
]
