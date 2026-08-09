# SPDX-License-Identifier: Apache-2.0
"""Containment, privacy, retention, and responsible-disclosure contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from sova.formats.errors import FormatError
from sova.safety import (
    BackendDescriptor,
    ContainmentGate,
    ContainmentRequirements,
    ContributionConsent,
    DisclosureGate,
    DisclosureRequest,
    EphemeralSecretStore,
    IsolationKind,
    NetworkMode,
    PrivacyDefaults,
    RetentionController,
    RetentionPolicy,
    VulnerabilityState,
    known_backend_descriptors,
)

if TYPE_CHECKING:
    from pathlib import Path


def _backend(identifier: str) -> BackendDescriptor:
    return next(item for item in known_backend_descriptors() if item.id == identifier)


def test_synthetic_simulation_is_admitted_without_mislabeling_it_a_sandbox() -> None:
    decision = ContainmentGate().assess(
        _backend("sova:backend:synthetic"),
        ContainmentRequirements(minimum_isolation=IsolationKind.MICROVM),
    )
    assert decision.allowed
    assert any("not an operating-system sandbox" in item for item in decision.limitations)


def test_host_process_and_live_network_fail_closed() -> None:
    decision = ContainmentGate().assess(
        _backend("sova:backend:restricted-local"),
        ContainmentRequirements(
            minimum_isolation=IsolationKind.CONTAINER,
            maximum_network_mode=NetworkMode.SINK_ONLY,
        ),
    )
    assert not decision.allowed
    assert "isolation-below-requirement" in decision.reasons
    assert "network-more-permissive-than-requirement" in decision.reasons


def test_backend_inventory_never_infers_readiness_from_a_target_architecture() -> None:
    backends = {backend.id: backend for backend in known_backend_descriptors()}
    assert backends["sova:backend:synthetic"].readiness == "ready"
    assert backends["sova:backend:restricted-local"].network_mode == NetworkMode.LIVE
    assert "Client presence does not prove" in backends["sova:backend:docker"].limitations[0]
    assert backends["sova:backend:docker-desktop-oci"].readiness != "ready"
    assert backends["sova:backend:docker-sandbox"].readiness != "ready"
    assert backends["sova:backend:gvisor"].readiness != "ready"


def test_reference_privacy_defaults_cannot_be_silently_enabled() -> None:
    assert PrivacyDefaults() == PrivacyDefaults(
        telemetry_enabled=False,
        account_required=False,
        raw_environment_capture=False,
        contribution_enabled=False,
    )
    with pytest.raises(FormatError, match="opt-in"):
        PrivacyDefaults(telemetry_enabled=True)


def test_ephemeral_secret_store_uses_opaque_refs_and_expires_values() -> None:
    store = EphemeralSecretStore()
    reference = store.put("not-a-real-provider-secret")
    assert "not-a-real" not in reference
    assert store.resolve(reference) == "not-a-real-provider-secret"
    store.delete(reference)
    with pytest.raises(FormatError, match="unknown or expired"):
        store.resolve(reference)
    store.close()
    with pytest.raises(FormatError, match="closed"):
        store.put("another")


def test_retention_only_deletes_ordinary_files_inside_exact_root(tmp_path: Path) -> None:
    root = tmp_path / "retention"
    root.mkdir()
    artifact = root / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    controller = RetentionController(root)
    assert controller.delete_file(artifact)
    assert not controller.delete_file(artifact)
    with pytest.raises(FormatError, match="escaped"):
        controller.delete_file(tmp_path / "outside.json")
    with pytest.raises(FormatError, match="escaped"):
        controller.delete_file(root)


def test_contribution_consent_and_retention_are_item_specific() -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)
    consent = ContributionConsent(frozenset({"sha256:approved"}), now, "Gautam")
    assert consent.permits("sha256:approved")
    assert not consent.permits("sha256:other")
    policy = RetentionPolicy(
        name="short",
        expires_at=now + timedelta(days=1),
        auto_delete=True,
        export_allowed=False,
    )
    assert not policy.expired(now)
    assert policy.expired(now + timedelta(days=2))


def test_disclosure_gate_blocks_victim_ranking_and_live_payloads() -> None:
    unsafe = DisclosureRequest(
        target_kind="organization",
        vulnerability_state=VulnerabilityState.REPORTED,
        contains_working_payload=True,
        authorization_redacted=False,
        secrets_scan_clean=False,
        human_reviewed=False,
        limitations_present=False,
    )
    decision = DisclosureGate().assess(unsafe)
    assert not decision.allowed
    assert "organizations-and-victims-must-not-be-ranked" in decision.reasons
    assert "working-unpatched-payload-cannot-be-published" in decision.reasons
    assert "human-export-review-required" in decision.reasons


def test_disclosure_gate_allows_reviewed_synthetic_or_patched_component_records() -> None:
    safe = DisclosureRequest(
        target_kind="synthetic",
        vulnerability_state=VulnerabilityState.PUBLIC,
        contains_working_payload=True,
        authorization_redacted=True,
        secrets_scan_clean=True,
        human_reviewed=True,
        limitations_present=True,
    )
    assert DisclosureGate().assess(safe).allowed
