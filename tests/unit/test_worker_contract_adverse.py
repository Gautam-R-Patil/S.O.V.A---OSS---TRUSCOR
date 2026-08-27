# SPDX-License-Identifier: Apache-2.0
"""Adverse validation paths for hostile controller/worker contract input."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import FormatError
from sova.worker.contracts import (
    ContentReference,
    NetworkRule,
    ResourceLimits,
    SecretGrant,
    WorkerBackend,
    WorkerReadiness,
    assess_worker_attestation,
)
from tests.support.worker import digest, guest_keypair, worker_attestation, worker_manifest

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (
            lambda: ContentReference("BAD NAME", digest("x"), 1, "application/octet-stream"),
            "identifier",
        ),
        (
            lambda: ContentReference("name", "sha256:BAD", 1, "application/octet-stream"),
            "SHA-256",
        ),
        (
            lambda: ContentReference("name", digest("x"), -1, "application/octet-stream"),
            "size",
        ),
        (lambda: ContentReference("name", digest("x"), 1, "invalid"), "media type"),
        (lambda: ResourceLimits(vcpu_count=0), "limit"),
        (lambda: ResourceLimits(open_file_limit=1), "limit"),
        (lambda: NetworkRule("BAD HOST", 443, "tcp", ("1.1.1.1",)), "hostname"),
        (lambda: NetworkRule("example.com", 0, "tcp", ("1.1.1.1",)), "endpoint"),
        (lambda: NetworkRule("example.com", 443, "icmp", ("1.1.1.1",)), "endpoint"),
        (lambda: NetworkRule("example.com", 443, "tcp", ()), "pin set"),
        (
            lambda: NetworkRule("example.com", 443, "tcp", ("1.1.1.1", "1.1.1.1")),
            "unique",
        ),
        (lambda: SecretGrant("name", "audience", "not-time"), "second-precision"),
        (
            lambda: SecretGrant("name", "audience", "2026-08-27T10:00:00Z", maximum_uses=0),
            "uses",
        ),
    ],
)
def test_primitives_reject_malformed_values(factory: Callable[[], object], message: str) -> None:
    with pytest.raises(FormatError, match=message):
        factory()


def test_job_manifest_rejects_time_digest_backend_and_empty_output() -> None:
    manifest = worker_manifest(guest_keypair())
    mutations: tuple[tuple[dict[str, Any], str], ...] = (
        ({"expires_at": manifest.issued_at}, "expiry"),
        ({"expires_at": "2026-08-29T10:00:00Z"}, "24 hours"),
        ({"target_profile_digest": "bad"}, "SHA-256"),
        ({"output_schema_ids": ()}, "at least one output"),
        ({"backend": WorkerBackend.GVISOR}, "Firecracker"),
    )
    for changes, message in mutations:
        with pytest.raises(FormatError, match=message):
            replace(manifest, **changes)


def test_job_manifest_rejects_duplicate_names_endpoints_grants_and_schemas() -> None:
    manifest = worker_manifest(guest_keypair())
    duplicate_input = ContentReference(
        manifest.guest_kernel.name, digest("other"), 1, "application/octet-stream"
    )
    duplicate_rule = NetworkRule("example.com", 443, "tcp", ("8.8.8.8",))
    grant = manifest.secret_grants[0]
    mutations: tuple[tuple[dict[str, Any], str], ...] = (
        ({"inputs": (duplicate_input,)}, "content names"),
        ({"network_rules": (*manifest.network_rules, duplicate_rule)}, "network endpoints"),
        ({"secret_grants": (grant, grant)}, "secret grants"),
        ({"output_schema_ids": ("sova.evidence", "sova.evidence")}, "unique"),
        ({"output_schema_ids": ("BAD SCHEMA",)}, "identifier"),
    )
    for changes, message in mutations:
        with pytest.raises(FormatError, match=message):
            replace(manifest, **changes)


def test_attestation_rejects_bad_identity_time_digests_and_review_receipt() -> None:
    attestation = worker_attestation()
    mutations: tuple[tuple[dict[str, Any], str], ...] = (
        ({"worker_id": "BAD WORKER"}, "identifier"),
        ({"measured_at": "not-time"}, "second-precision"),
        ({"firecracker_digest": "bad"}, "SHA-256"),
        ({"independent_review_receipt": "bad"}, "SHA-256"),
    )
    for changes, message in mutations:
        with pytest.raises(FormatError, match=message):
            replace(attestation, **changes)


def test_attestation_admission_lists_every_failed_host_and_pin_control() -> None:
    attestation = replace(
        worker_attestation(),
        backend=WorkerBackend.GVISOR,
        firecracker_version="0.0.0",
        kvm_available=False,
        cgroup_v2=False,
        swap_disabled=False,
        default_seccomp=False,
        unique_uid_gid_per_job=False,
        host_paths_root_owned=False,
        guest_kernel_digest=digest("wrong-kernel"),
        root_filesystem_digest=digest("wrong-rootfs"),
        policy_digest=digest("wrong-policy"),
    )
    admission = assess_worker_attestation(
        attestation,
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )
    assert admission.readiness == WorkerReadiness.UNAVAILABLE
    assert set(admission.reasons) == {
        "firecracker-backend-required",
        "firecracker-version-not-approved",
        "kvm-unavailable",
        "cgroup-v2-unavailable",
        "swap-enabled",
        "default-seccomp-not-enforced",
        "unique-job-identity-not-enforced",
        "trusted-host-path-ownership-unverified",
        "worker-policy-pin-mismatch",
        "guest-kernel-pin-mismatch",
        "root-filesystem-pin-mismatch",
    }


def test_admission_mapping_never_grants_production_for_implementation_ready() -> None:
    attestation = worker_attestation()
    admission = assess_worker_attestation(
        attestation,
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )
    assert admission.to_mapping()["productionIsolationClaimAllowed"] is False
