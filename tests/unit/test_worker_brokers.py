# SPDX-License-Identifier: Apache-2.0
"""P5 network and secret broker denial-path tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from sova.formats import validate_document
from sova.formats.errors import FormatError
from sova.worker.brokers import NetworkBroker, SecretBroker
from sova.worker.contracts import NetworkRule
from tests.support.worker import guest_keypair, worker_manifest

NOW = datetime(2026, 8, 27, 10, 1, tzinfo=UTC)


def test_network_broker_allows_exact_pin_and_records_budget() -> None:
    broker = NetworkBroker(worker_manifest(guest_keypair()))
    receipt = broker.authorize(
        hostname="example.com.",
        port=443,
        protocol="tcp",
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=1024,
        now=NOW,
    )
    assert receipt.decision == "allowed"
    assert broker.consumed_connections == 1
    assert broker.consumed_bytes == 1024
    validate_document(receipt.to_mapping())


def test_network_broker_denies_dns_rebinding_and_metadata_service() -> None:
    broker = NetworkBroker(worker_manifest(guest_keypair()))
    rebound = broker.authorize(
        hostname="example.com",
        port=443,
        protocol="tcp",
        resolved_addresses=("1.1.1.1", "8.8.8.8"),
        selected_address="8.8.8.8",
        requested_bytes=10,
        now=NOW,
    )
    metadata = broker.authorize(
        hostname="example.com",
        port=443,
        protocol="tcp",
        resolved_addresses=("169.254.169.254",),
        selected_address="169.254.169.254",
        requested_bytes=10,
        now=NOW,
    )
    assert rebound.reason == "dns-pin-mismatch"
    assert metadata.reason == "SOVA-WORKER-NETWORK-PRIVATE"
    assert broker.consumed_connections == 0


def test_private_target_requires_explicit_rule_and_never_enables_metadata() -> None:
    base = worker_manifest(guest_keypair())
    denied = NetworkBroker(
        replace(
            base,
            network_rules=(NetworkRule("internal.example", 443, "tcp", ("10.10.0.5",)),),
        )
    )
    allowed = NetworkBroker(
        replace(
            base,
            network_rules=(
                NetworkRule("internal.example", 443, "tcp", ("10.10.0.5",), allow_private=True),
            ),
        )
    )
    denied_receipt = denied.authorize(
        hostname="internal.example",
        port=443,
        protocol="tcp",
        resolved_addresses=("10.10.0.5",),
        selected_address="10.10.0.5",
        requested_bytes=1,
        now=NOW,
    )
    allowed_receipt = allowed.authorize(
        hostname="internal.example",
        port=443,
        protocol="tcp",
        resolved_addresses=("10.10.0.5",),
        selected_address="10.10.0.5",
        requested_bytes=1,
        now=NOW,
    )
    assert denied_receipt.decision == "denied"
    assert allowed_receipt.decision == "allowed"


def test_network_broker_enforces_connection_byte_and_time_budgets() -> None:
    broker = NetworkBroker(
        worker_manifest(guest_keypair(), network_bytes=100, network_connections=1)
    )
    allowed = broker.authorize(
        hostname="example.com",
        port=443,
        protocol="tcp",
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=100,
        now=NOW,
    )
    exhausted = broker.authorize(
        hostname="example.com",
        port=443,
        protocol="tcp",
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=1,
        now=NOW,
    )
    late = broker.authorize(
        hostname="example.com",
        port=443,
        protocol="tcp",
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=0,
        now=datetime(2026, 8, 27, 10, 11, tzinfo=UTC),
    )
    assert allowed.decision == "allowed"
    assert exhausted.reason == "connection-budget-exhausted"
    assert late.reason == "job-time-budget-exhausted"


def test_secret_broker_binds_job_audience_expiry_and_use_count() -> None:
    broker = SecretBroker(worker_manifest(guest_keypair()))
    token = broker.provision("target-api", b"fixture-secret", now=NOW)
    wrong_value, wrong_receipt = broker.redeem(token, audience="wrong", now=NOW)
    value, receipt = broker.redeem(token, audience="https://example.com", now=NOW)
    replay, replay_receipt = broker.redeem(token, audience="https://example.com", now=NOW)
    assert wrong_value is None and wrong_receipt.reason == "audience-mismatch"
    assert value == b"fixture-secret" and receipt.decision == "allowed"
    assert replay is None and replay_receipt.reason == "capability-revoked"
    serialized = str(receipt.to_mapping())
    assert token not in serialized
    assert "fixture-secret" not in serialized
    validate_document(receipt.to_mapping())


def test_secret_broker_revokes_and_zeroes_all_capabilities() -> None:
    broker = SecretBroker(worker_manifest(guest_keypair()))
    token = broker.provision("target-api", b"fixture-secret", now=NOW)
    broker.revoke_all()
    value, receipt = broker.redeem(token, audience="https://example.com", now=NOW)
    assert value is None
    assert receipt.reason == "capability-revoked"


def test_network_broker_denies_unknown_negative_duplicate_early_and_byte_budget() -> None:
    broker = NetworkBroker(worker_manifest(guest_keypair(), network_bytes=10))
    common = {
        "port": 443,
        "protocol": "tcp",
        "selected_address": "1.1.1.1",
        "now": NOW,
    }
    unknown = broker.authorize(
        hostname="other.example",
        resolved_addresses=("1.1.1.1",),
        requested_bytes=1,
        **common,  # type: ignore[arg-type]
    )
    negative = broker.authorize(
        hostname="example.com",
        resolved_addresses=("1.1.1.1",),
        requested_bytes=-1,
        **common,  # type: ignore[arg-type]
    )
    duplicate = broker.authorize(
        hostname="example.com",
        resolved_addresses=("1.1.1.1", "1.1.1.1"),
        requested_bytes=1,
        **common,  # type: ignore[arg-type]
    )
    early = broker.authorize(
        hostname="example.com",
        resolved_addresses=("1.1.1.1",),
        requested_bytes=1,
        port=443,
        protocol="tcp",
        selected_address="1.1.1.1",
        now=datetime(2026, 8, 27, 9, 59, tzinfo=UTC),
    )
    over_bytes = broker.authorize(
        hostname="example.com",
        resolved_addresses=("1.1.1.1",),
        requested_bytes=11,
        **common,  # type: ignore[arg-type]
    )
    assert [item.reason for item in (unknown, negative, duplicate, early, over_bytes)] == [
        "endpoint-not-authorized",
        "negative-byte-request",
        "dns-answer-invalid",
        "job-not-yet-valid",
        "byte-budget-exhausted",
    ]


def test_secret_broker_rejects_unknown_empty_oversized_and_expired_provision() -> None:
    broker = SecretBroker(worker_manifest(guest_keypair()))
    with pytest.raises(FormatError, match="not declared"):
        broker.provision("unknown", b"x", now=NOW)
    with pytest.raises(FormatError, match="empty"):
        broker.provision("target-api", b"", now=NOW)
    with pytest.raises(FormatError, match="exceeds"):
        broker.provision("target-api", b"x" * (64 * 1024 + 1), now=NOW)
    with pytest.raises(FormatError, match="expired"):
        broker.provision("target-api", b"x", now=datetime(2026, 8, 27, 10, 11, tzinfo=UTC))


def test_secret_broker_unknown_capability_and_expiry_emit_denied_receipts() -> None:
    broker = SecretBroker(worker_manifest(guest_keypair()))
    value, unknown = broker.redeem("unknown", audience="target", now=NOW)
    token = broker.provision("target-api", b"secret", now=NOW)
    expired_value, expired = broker.redeem(
        token,
        audience="https://example.com",
        now=datetime(2026, 8, 27, 10, 11, tzinfo=UTC),
    )
    assert value is None and unknown.reason == "unknown-capability"
    assert expired_value is None and expired.reason == "secret-grant-expired"


def test_broker_clocks_must_be_timezone_aware() -> None:
    manifest = worker_manifest(guest_keypair())
    with pytest.raises(FormatError, match="timezone-aware"):
        SecretBroker(manifest).provision("target-api", b"secret", now=NOW.replace(tzinfo=None))
