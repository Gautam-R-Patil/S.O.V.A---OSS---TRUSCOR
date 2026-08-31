# SPDX-License-Identifier: Apache-2.0
"""Exact-file worker measurements; self-attestation never substitutes for review."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.worker.contracts import FIRECRACKER_VERSION, WorkerAttestation, WorkerBackend

if TYPE_CHECKING:
    from sova.worker.firecracker import FirecrackerHostPolicy

_VERSION = re.compile(r"\bFirecracker\s+v?([0-9]+\.[0-9]+\.[0-9]+)\b", re.IGNORECASE)


def _digest_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise FormatError("SOVA-WORKER-ATTEST-FILE", "measured path must be a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _root_owned(path: Path) -> bool:
    if not path.is_absolute() or ".." in path.parts:
        return False
    current = path
    while True:
        try:
            stat_result = current.lstat()
        except OSError:
            return False
        if current.is_symlink() or stat_result.st_uid != 0 or stat_result.st_mode & 0o022:
            return False
        if current.parent == current:
            return True
        current = current.parent


def _firecracker_version(binary: Path) -> str:
    try:
        process = subprocess.run(  # noqa: S603 - root-owned, digest-pinned executable
            [str(binary), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FormatError(
            "SOVA-WORKER-ATTEST-VERSION", "Firecracker version could not be measured"
        ) from error
    match = _VERSION.search(process.stdout + process.stderr)
    if match is None:
        raise FormatError("SOVA-WORKER-ATTEST-VERSION", "Firecracker version is unparseable")
    return match.group(1)


def _swap_disabled() -> bool:
    try:
        lines = Path("/proc/swaps").read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    return len([line for line in lines[1:] if line.strip()]) == 0


def collect_worker_attestation(  # noqa: PLR0913 - exact measurements stay explicit
    *,
    worker_id: str,
    measured_at: str,
    policy: FirecrackerHostPolicy,
    host_kernel_image: Path,
    microcode_image: Path,
    guest_kernel_image: Path,
    root_filesystem_image: Path,
    worker_policy_bytes: bytes,
    advisory_snapshot_bytes: bytes,
    dedicated_linux_host: bool = False,
    default_seccomp_enforced: bool = False,
    unique_uid_gid_enforced: bool = False,
    independent_review_receipt: str | None = None,
) -> WorkerAttestation:
    """Measure exact files and host controls without promoting a self-issued trust claim."""
    if platform.system() != "Linux":
        raise FormatError("SOVA-WORKER-ATTEST-HOST", "worker attestation requires Linux")
    release = platform.release().lower()
    try:
        proc_version = Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        proc_version = ""
    wsl_environment = "microsoft" in release or "microsoft" in proc_version or "wsl" in release
    firecracker_digest = _digest_file(policy.firecracker_binary)
    jailer_digest = _digest_file(policy.jailer_binary)
    if firecracker_digest != policy.approved_firecracker_digest:
        raise FormatError(
            "SOVA-WORKER-ATTEST-PIN", "Firecracker binary digest does not match policy"
        )
    if jailer_digest != policy.approved_jailer_digest:
        raise FormatError("SOVA-WORKER-ATTEST-PIN", "jailer binary digest does not match policy")
    trusted_paths = (
        policy.firecracker_binary,
        policy.jailer_binary,
        policy.chroot_base,
        policy.network_namespace_base,
        policy.content_store,
        policy.cgroup_base,
        host_kernel_image,
        microcode_image,
        guest_kernel_image,
        root_filesystem_image,
    )
    return WorkerAttestation(
        worker_id=worker_id,
        measured_at=measured_at,
        backend=WorkerBackend.FIRECRACKER,
        dedicated_linux_host=dedicated_linux_host,
        wsl_environment=wsl_environment,
        kvm_available=os.access("/dev/kvm", os.R_OK | os.W_OK),
        cgroup_v2=(policy.cgroup_base / "cgroup.controllers").is_file(),
        swap_disabled=_swap_disabled(),
        default_seccomp=default_seccomp_enforced,
        unique_uid_gid_per_job=unique_uid_gid_enforced,
        host_paths_root_owned=all(_root_owned(path) for path in trusted_paths),
        firecracker_version=_firecracker_version(policy.firecracker_binary),
        firecracker_digest=firecracker_digest,
        jailer_digest=jailer_digest,
        host_kernel_digest=_digest_file(host_kernel_image),
        microcode_digest=_digest_file(microcode_image),
        guest_kernel_digest=_digest_file(guest_kernel_image),
        root_filesystem_digest=_digest_file(root_filesystem_image),
        policy_digest=sha256_digest(worker_policy_bytes),
        advisory_snapshot_digest=sha256_digest(advisory_snapshot_bytes),
        independent_review_receipt=independent_review_receipt,
    )


def approved_firecracker_version(version: str) -> bool:
    """Expose the exact protocol pin for deployment checks and test fixtures."""
    return version == FIRECRACKER_VERSION


__all__ = ["approved_firecracker_version", "collect_worker_attestation"]
