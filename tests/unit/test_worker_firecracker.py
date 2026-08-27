# SPDX-License-Identifier: Apache-2.0
"""Pinned Firecracker plan and cleanup-contract tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from sova.formats import FormatError, validate_document
from sova.worker import firecracker as firecracker_module
from sova.worker.contracts import WorkerAdmission, WorkerReadiness, assess_worker_attestation
from sova.worker.firecracker import (
    FirecrackerHostPolicy,
    WorkerCleanupReceipt,
    build_firecracker_launch_plan,
    validate_cleanup_receipt,
)
from tests.support.worker import digest, guest_keypair, worker_attestation, worker_manifest


def _policy() -> FirecrackerHostPolicy:
    return FirecrackerHostPolicy(
        firecracker_binary=Path("C:/sova-worker/bin/firecracker"),
        jailer_binary=Path("C:/sova-worker/bin/jailer"),
        chroot_base=Path("C:/sova-worker/jailer"),
        network_namespace_base=Path("C:/sova-worker/netns"),
        content_store=Path("C:/sova-worker/cas"),
        approved_firecracker_digest=digest("firecracker"),
        approved_jailer_digest=digest("jailer"),
    )


def _admission() -> WorkerAdmission:
    return assess_worker_attestation(
        worker_attestation(),
        expected_policy_digest=digest("policy"),
        expected_guest_kernel_digest=digest("kernel"),
        expected_root_filesystem_digest=digest("rootfs"),
    )


def test_launch_plan_enforces_jailer_mmio_cgroups_and_disposable_storage() -> None:
    manifest = worker_manifest(guest_keypair())
    plan = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=17)
    mapping = plan.to_mapping()
    assert mapping["firecrackerVersion"] == "1.16.1"
    assert "--no-seccomp" not in plan.jailer_command
    assert mapping["jailer"]["seccompLevel"] == 2
    assert mapping["invariants"]["pciEnabled"] is False
    assert mapping["invariants"]["hostMountsAllowed"] is False
    assert {item[0] for item in plan.cgroup_values} == {"cpu.max", "memory.max", "pids.max"}
    assert {item[2] for item in plan.staged_content} == {
        "copy-read-only",
        "copy-disposable-writable",
    }
    validate_document(mapping)


def test_launch_plan_uses_exclusive_host_allocated_identity_slots() -> None:
    manifest = worker_manifest(guest_keypair())
    first = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=1)
    second = build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=2)
    assert (first.uid, first.gid) != (second.uid, second.gid)


def test_launch_plan_refuses_unavailable_attestation() -> None:
    admission = WorkerAdmission(WorkerReadiness.UNAVAILABLE, ("kvm-unavailable",), digest("a"))
    with pytest.raises(FormatError, match="not admitted"):
        build_firecracker_launch_plan(
            worker_manifest(guest_keypair()), admission, _policy(), identity_slot=1
        )


def test_cleanup_receipt_must_bind_exact_job_and_every_cleanup_check() -> None:
    plan = build_firecracker_launch_plan(
        worker_manifest(guest_keypair()), _admission(), _policy(), identity_slot=1
    )
    complete = WorkerCleanupReceipt(
        job_id=plan.job_id,
        vm_id=plan.vm_id,
        completed_at="2026-08-27T10:12:00Z",
        process_terminated=True,
        api_socket_removed=True,
        cgroup_removed=True,
        network_namespace_removed=True,
        chroot_removed=True,
        writable_layer_removed=True,
        secret_broker_revoked=True,
    )
    validate_cleanup_receipt(complete, plan)
    validate_document(complete.to_mapping())
    incomplete = WorkerCleanupReceipt(
        job_id=plan.job_id,
        vm_id=plan.vm_id,
        completed_at="2026-08-27T10:12:00Z",
        process_terminated=True,
        api_socket_removed=True,
        cgroup_removed=False,
        network_namespace_removed=True,
        chroot_removed=True,
        writable_layer_removed=True,
        secret_broker_revoked=True,
    )
    with pytest.raises(FormatError, match="incomplete"):
        validate_cleanup_receipt(incomplete, plan)
    with pytest.raises(FormatError, match="another job"):
        validate_cleanup_receipt(
            replace(complete, job_id="job:other"),
            plan,
        )


def test_host_policy_rejects_relative_paths_identity_ranges_and_seccomp_override() -> None:
    base = _policy()
    mutations = (
        {"firecracker_binary": Path("relative")},
        {"uid_base": 1},
        {"gid_base": 1},
        {"seccomp_level": 0},
    )
    for changes in mutations:
        with pytest.raises(FormatError):
            replace(base, **changes)


def test_launch_plan_rejects_invalid_identity_slot_and_cas_digest() -> None:
    manifest = worker_manifest(guest_keypair())
    with pytest.raises(FormatError, match="negative"):
        build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=-1)
    with pytest.raises(FormatError, match="exceeds"):
        build_firecracker_launch_plan(manifest, _admission(), _policy(), identity_slot=600_001)
    with pytest.raises(FormatError, match="approved CAS key"):
        firecracker_module._cas_path(Path("C:/cas"), "bad")
