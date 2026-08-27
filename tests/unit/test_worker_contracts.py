# SPDX-License-Identifier: Apache-2.0
"""P5 worker contract and backend-claim tests."""

from __future__ import annotations

import pytest

from sova.formats import FormatError, validate_document
from sova.worker.alternative_backends import (
    KataAdmissionEvidence,
    assess_gvisor_backend,
    assess_kata_backend,
)
from sova.worker.attestation import approved_firecracker_version
from sova.worker.contracts import (
    FIRECRACKER_VERSION,
    NetworkRule,
    WorkerReadiness,
    assess_worker_attestation,
)
from sova.worker.malicious import MaliciousGuestCase, malicious_guest_matrix
from tests.support.worker import digest, guest_keypair, worker_attestation, worker_manifest


def test_worker_manifest_and_attestation_validate_against_bundled_schemas() -> None:
    guest = guest_keypair()
    manifest = worker_manifest(guest)
    attestation = worker_attestation(reviewed=True)

    validate_document(manifest.to_mapping())
    validate_document(attestation.to_mapping())
    assert manifest.to_mapping()["claims"]["hostMountsAllowed"] is False
    assert manifest.to_mapping()["bindings"]["guestOutputKeyDigest"].startswith("sha256:")


def test_worker_admission_separates_development_implementation_and_production() -> None:
    expectations = (
        (worker_attestation(dedicated=False, wsl=True), WorkerReadiness.DEVELOPER_ONLY),
        (worker_attestation(), WorkerReadiness.IMPLEMENTATION_READY),
        (worker_attestation(reviewed=True), WorkerReadiness.PRODUCTION_READY),
    )
    for attestation, expected in expectations:
        admission = assess_worker_attestation(
            attestation,
            expected_policy_digest=digest("policy"),
            expected_guest_kernel_digest=digest("kernel"),
            expected_root_filesystem_digest=digest("rootfs"),
        )
        assert admission.readiness == expected


def test_worker_admission_fails_closed_on_missing_kvm_or_pin_mismatch() -> None:
    admission = assess_worker_attestation(
        worker_attestation(kvm=False),
        expected_policy_digest=digest("different-policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )
    assert admission.readiness == WorkerReadiness.UNAVAILABLE
    assert set(admission.reasons) >= {"kvm-unavailable", "worker-policy-pin-mismatch"}


def test_network_rule_rejects_non_ip_pin() -> None:
    with pytest.raises(FormatError, match="invalid IP"):
        NetworkRule("example.com", 443, "tcp", ("not-an-ip",))


def test_firecracker_version_is_an_exact_deployment_pin() -> None:
    assert approved_firecracker_version(FIRECRACKER_VERSION)
    assert not approved_firecracker_version("1.16.0")


def test_kata_stays_disabled_with_any_open_hardening_gate() -> None:
    admission = assess_kata_backend(
        KataAdmissionEvidence(
            installed_version="3.20.0",
            approved_version="3.20.0",
            runtime_digest_pinned=True,
            advisory_snapshot_current=True,
            unresolved_escape_advisories=("GHSA-fixture",),
            untrusted_annotations_disabled=True,
            host_mounts_disabled=True,
            configuration_paths_root_owned=True,
        )
    )
    assert admission.status == "disabled"
    assert "kata-unresolved-escape-advisory" in admission.reasons


def test_optional_backends_never_claim_firecracker_equivalence() -> None:
    kata = assess_kata_backend(
        KataAdmissionEvidence(
            installed_version="3.20.0",
            approved_version="3.20.0",
            runtime_digest_pinned=True,
            advisory_snapshot_current=True,
            unresolved_escape_advisories=(),
            untrusted_annotations_disabled=True,
            host_mounts_disabled=True,
            configuration_paths_root_owned=True,
        )
    )
    gvisor = assess_gvisor_backend(installed=True, conformance_passed=True)
    assert kata.status == "compatibility-only"
    assert gvisor.status == "lower-assurance-compatibility"
    assert not kata.to_mapping()["claims"]["equivalentToFirecracker"]
    assert not gvisor.to_mapping()["claims"]["arbitraryHostileCodeProductionReady"]


def test_malicious_guest_matrix_covers_every_p5_case_without_live_overclaim() -> None:
    matrix = malicious_guest_matrix()
    assert {item.case for item in matrix} == set(MaliciousGuestCase)
    assert all(item.local_adverse_test for item in matrix)
    assert any(item.exact_host_test_required for item in matrix)
