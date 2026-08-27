# SPDX-License-Identifier: Apache-2.0
"""Pinned Firecracker jailer launch plans and controller-verifiable cleanup receipts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.worker.contracts import (
    FIRECRACKER_VERSION,
    WorkerAdmission,
    WorkerJobManifest,
    WorkerReadiness,
)

MINIMUM_JOB_IDENTITY = 100_000
MAXIMUM_JOB_IDENTITY = 600_000
DEFAULT_SECCOMP_LEVEL = 2
SHA256_HEX_LENGTH = 64


@dataclass(frozen=True, slots=True)
class FirecrackerHostPolicy:
    """Root-controlled host pins; manifest content can never supply host paths."""

    firecracker_binary: Path
    jailer_binary: Path
    chroot_base: Path
    network_namespace_base: Path
    content_store: Path
    approved_firecracker_digest: str
    approved_jailer_digest: str
    uid_base: int = MINIMUM_JOB_IDENTITY
    gid_base: int = MINIMUM_JOB_IDENTITY
    seccomp_level: int = DEFAULT_SECCOMP_LEVEL

    def __post_init__(self) -> None:
        for role, value in (
            ("Firecracker", self.firecracker_binary),
            ("jailer", self.jailer_binary),
            ("chroot base", self.chroot_base),
            ("network namespace base", self.network_namespace_base),
            ("content store", self.content_store),
        ):
            if not value.is_absolute():
                raise FormatError("SOVA-WORKER-HOST-PATH", f"{role} path must be absolute")
            if ".." in value.parts:
                raise FormatError("SOVA-WORKER-HOST-PATH", f"{role} path cannot traverse")
        if not MINIMUM_JOB_IDENTITY <= self.uid_base <= MAXIMUM_JOB_IDENTITY:
            raise FormatError("SOVA-WORKER-IDENTITY", "UID base is outside the isolated range")
        if not MINIMUM_JOB_IDENTITY <= self.gid_base <= MAXIMUM_JOB_IDENTITY:
            raise FormatError("SOVA-WORKER-IDENTITY", "GID base is outside the isolated range")
        if self.seccomp_level != DEFAULT_SECCOMP_LEVEL:
            raise FormatError(
                "SOVA-WORKER-SECCOMP", "default Firecracker seccomp level is required"
            )


@dataclass(frozen=True, slots=True)
class FirecrackerLaunchPlan:
    job_id: str
    vm_id: str
    uid: int
    gid: int
    jailer_command: tuple[str, ...]
    chroot_directory: str
    network_namespace: str
    api_socket: str
    pid_file: str
    staged_content: tuple[tuple[str, str, str], ...]
    cgroup_values: tuple[tuple[str, str], ...]
    firecracker_api_requests: tuple[tuple[str, dict[str, Any]], ...]
    watchdog_seconds: int
    maximum_log_bytes: int
    manifest_digest: str
    identity_slot: int
    firecracker_version: str = FIRECRACKER_VERSION

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.firecracker-launch-plan",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "vmId": self.vm_id,
            "manifestDigest": self.manifest_digest,
            "firecrackerVersion": self.firecracker_version,
            "identity": {"uid": self.uid, "gid": self.gid, "uniquePerJob": True},
            "identitySlot": self.identity_slot,
            "jailer": {
                "argv": list(self.jailer_command),
                "chrootDirectory": self.chroot_directory,
                "networkNamespace": self.network_namespace,
                "apiSocket": self.api_socket,
                "pidFile": self.pid_file,
                "seccompLevel": 2,
            },
            "stagedContent": [
                {"source": source, "destination": destination, "mode": mode}
                for source, destination, mode in self.staged_content
            ],
            "cgroupValues": [{"key": key, "value": value} for key, value in self.cgroup_values],
            "apiRequests": [
                {"path": path, "payload": payload}
                for path, payload in self.firecracker_api_requests
            ],
            "watchdogSeconds": self.watchdog_seconds,
            "maximumLogBytes": self.maximum_log_bytes,
            "invariants": {
                "oneVmPerJob": True,
                "hostMountsAllowed": False,
                "rootFilesystemReadOnly": True,
                "writableLayerDisposable": True,
                "ambientNetworkAllowed": False,
                "pciEnabled": False,
                "serialConsoleEnabled": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


@dataclass(frozen=True, slots=True)
class WorkerCleanupReceipt:
    job_id: str
    vm_id: str
    completed_at: str
    process_terminated: bool
    api_socket_removed: bool
    cgroup_removed: bool
    network_namespace_removed: bool
    chroot_removed: bool
    writable_layer_removed: bool
    secret_broker_revoked: bool

    @property
    def complete(self) -> bool:
        return all(
            (
                self.process_terminated,
                self.api_socket_removed,
                self.cgroup_removed,
                self.network_namespace_removed,
                self.chroot_removed,
                self.writable_layer_removed,
                self.secret_broker_revoked,
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-cleanup-receipt",
            "schemaVersion": "0.1.0",
            "jobId": self.job_id,
            "vmId": self.vm_id,
            "completedAt": self.completed_at,
            "checks": {
                "processTerminated": self.process_terminated,
                "apiSocketRemoved": self.api_socket_removed,
                "cgroupRemoved": self.cgroup_removed,
                "networkNamespaceRemoved": self.network_namespace_removed,
                "chrootRemoved": self.chroot_removed,
                "writableLayerRemoved": self.writable_layer_removed,
                "secretBrokerRevoked": self.secret_broker_revoked,
            },
            "status": "complete" if self.complete else "cleanup-failed",
            "claims": {"futureEscapeImpossible": False},
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


def _cas_path(store: Path, digest: str) -> str:
    try:
        algorithm, value = digest.split(":", maxsplit=1)
    except ValueError as exc:
        raise FormatError("SOVA-WORKER-CAS", "content digest is not an approved CAS key") from exc
    if algorithm != "sha256" or len(value) != SHA256_HEX_LENGTH:
        raise FormatError("SOVA-WORKER-CAS", "content digest is not an approved CAS key")
    return str(store / algorithm / value[:2] / value)


def build_firecracker_launch_plan(
    manifest: WorkerJobManifest,
    admission: WorkerAdmission,
    policy: FirecrackerHostPolicy,
    *,
    identity_slot: int,
) -> FirecrackerLaunchPlan:
    """Compile immutable authority into a jailer-only, MMIO-only microVM plan."""
    if admission.attestation_digest == "" or admission.readiness == WorkerReadiness.UNAVAILABLE:
        raise FormatError("SOVA-WORKER-ADMISSION", "worker attestation was not admitted")
    if identity_slot < 0:
        raise FormatError("SOVA-WORKER-IDENTITY", "identity slot cannot be negative")
    uid = policy.uid_base + identity_slot
    gid = policy.gid_base + identity_slot
    if uid > MAXIMUM_JOB_IDENTITY or gid > MAXIMUM_JOB_IDENTITY:
        raise FormatError("SOVA-WORKER-IDENTITY", "identity slot exceeds the isolated range")
    safe_job_id = re.sub(r"[^a-zA-Z0-9_-]", "-", manifest.job_id)[:48]
    vm_id = f"sova-{safe_job_id}-{manifest.digest[7:19]}"
    chroot = policy.chroot_base / vm_id
    netns = policy.network_namespace_base / vm_id
    api_socket = PurePosixPath("/run") / f"{vm_id}.socket"
    pid_file = PurePosixPath("/run") / f"{vm_id}.pid"
    jailer_command = (
        str(policy.jailer_binary),
        "--id",
        vm_id,
        "--exec-file",
        str(policy.firecracker_binary),
        "--uid",
        str(uid),
        "--gid",
        str(gid),
        "--chroot-base-dir",
        str(policy.chroot_base),
        "--netns",
        str(netns),
        "--cgroup-version",
        "2",
        "--resource-limit",
        f"no-file={manifest.limits.open_file_limit}",
        "--resource-limit",
        f"fsize={manifest.limits.output_bytes}",
        "--daemonize",
        "--",
        "--api-sock",
        str(api_socket),
        "--id",
        vm_id,
        "--pid-file",
        str(pid_file),
    )
    cgroups = (
        ("cpu.max", f"{manifest.limits.vcpu_count * 100000} 100000"),
        ("memory.max", str(manifest.limits.memory_mib * 1024 * 1024)),
        ("pids.max", str(manifest.limits.process_limit)),
    )
    staged_content = (
        (
            _cas_path(policy.content_store, manifest.guest_kernel.digest),
            str(chroot / "root" / "kernel"),
            "copy-read-only",
        ),
        (
            _cas_path(policy.content_store, manifest.root_filesystem.digest),
            str(chroot / "root" / "rootfs.ext4"),
            "copy-read-only",
        ),
        (
            _cas_path(policy.content_store, manifest.writable_layer_seed.digest),
            str(chroot / "root" / "writable.ext4"),
            "copy-disposable-writable",
        ),
    )
    requests: tuple[tuple[str, dict[str, Any]], ...] = (
        (
            "/boot-source",
            {
                "kernel_image_path": "/kernel",
                "boot_args": (
                    "reboot=k panic=1 pci=off 8250.nr_uarts=0 random.trust_cpu=on "
                    "ipv6.disable=1 module.sig_enforce=1"
                ),
            },
        ),
        (
            "/machine-config",
            {
                "vcpu_count": manifest.limits.vcpu_count,
                "mem_size_mib": manifest.limits.memory_mib,
                "smt": False,
                "track_dirty_pages": False,
            },
        ),
        (
            "/drives/rootfs",
            {
                "drive_id": "rootfs",
                "path_on_host": "/rootfs.ext4",
                "is_root_device": True,
                "is_read_only": True,
                "io_engine": "Sync",
            },
        ),
        (
            "/drives/writable",
            {
                "drive_id": "writable",
                "path_on_host": "/writable.ext4",
                "is_root_device": False,
                "is_read_only": False,
                "io_engine": "Sync",
            },
        ),
        (
            "/network-interfaces/eth0",
            {
                "iface_id": "eth0",
                "guest_mac": "06:00:00:00:00:01",
                "host_dev_name": f"tap-{manifest.digest[7:18]}",
                "rx_rate_limiter": {
                    "bandwidth": {
                        "size": manifest.limits.network_bytes,
                        "refill_time": manifest.limits.timeout_seconds * 1000,
                    }
                },
                "tx_rate_limiter": {
                    "bandwidth": {
                        "size": manifest.limits.network_bytes,
                        "refill_time": manifest.limits.timeout_seconds * 1000,
                    }
                },
            },
        ),
        ("/actions", {"action_type": "InstanceStart"}),
    )
    return FirecrackerLaunchPlan(
        job_id=manifest.job_id,
        vm_id=vm_id,
        uid=uid,
        gid=gid,
        jailer_command=jailer_command,
        chroot_directory=str(chroot),
        network_namespace=str(netns),
        api_socket=str(api_socket),
        pid_file=str(pid_file),
        staged_content=staged_content,
        cgroup_values=cgroups,
        firecracker_api_requests=requests,
        watchdog_seconds=manifest.limits.timeout_seconds + 15,
        maximum_log_bytes=manifest.limits.output_bytes,
        manifest_digest=manifest.digest,
        identity_slot=identity_slot,
    )


def validate_cleanup_receipt(receipt: WorkerCleanupReceipt, plan: FirecrackerLaunchPlan) -> None:
    """Refuse completion if any exact-job cleanup assertion is missing."""
    if (receipt.job_id, receipt.vm_id) != (plan.job_id, plan.vm_id):
        raise FormatError("SOVA-WORKER-CLEANUP-BINDING", "cleanup receipt binds another job")
    if not receipt.complete:
        raise FormatError("SOVA-WORKER-CLEANUP-INCOMPLETE", "worker cleanup is incomplete")


__all__ = [
    "FirecrackerHostPolicy",
    "FirecrackerLaunchPlan",
    "WorkerCleanupReceipt",
    "build_firecracker_launch_plan",
    "validate_cleanup_receipt",
]
