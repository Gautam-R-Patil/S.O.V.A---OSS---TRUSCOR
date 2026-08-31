# SPDX-License-Identifier: Apache-2.0
"""Self-measured dedicated-host preflight before any live containment claim."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.worker.contracts import FIRECRACKER_VERSION
from sova.worker.firecracker import MAXIMUM_JOB_IDENTITY
from sova.worker.network_plane import MAXIMUM_NETWORK_IDENTITY_SLOT

if TYPE_CHECKING:
    from sova.worker.contracts import WorkerAttestation
    from sova.worker.firecracker import FirecrackerHostPolicy
    from sova.worker.network_plane import NetworkPlaneHostPolicy

_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_VULNERABLE = re.compile(r"\bvulnerable\b", re.IGNORECASE)
_CPU_VULNERABILITY_DIRECTORY = Path("/sys/devices/system/cpu/vulnerabilities")
_PASSWD_MIN_FIELDS = 4
_GROUP_MIN_FIELDS = 3
_NETWORK_STATE_MODE = 0o711
_IDENTITY_LEASE_MODE = 0o700


def _digest_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise FormatError("SOVA-WORKER-PREFLIGHT-FILE", "measured binary is not a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _root_controlled(path: Path) -> bool:
    if not path.is_absolute() or ".." in path.parts:
        return False
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if (
            current.is_symlink()
            or metadata.st_uid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            return False
        if current.parent == current:
            return True
        current = current.parent


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


@dataclass(frozen=True, slots=True)
class HostPreflightCheck:
    name: str
    required: bool
    passed: bool
    evidence: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "required": self.required,
            "passed": self.passed,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class WorkerHostPreflightReceipt:
    release_commit: str
    worker_id: str
    measured_at: str
    attestation_digest: str
    checks: tuple[HostPreflightCheck, ...]

    def __post_init__(self) -> None:
        if _COMMIT.fullmatch(self.release_commit) is None:
            raise FormatError("SOVA-WORKER-PREFLIGHT-COMMIT", "release commit is invalid")
        if _RFC3339.fullmatch(self.measured_at) is None:
            raise FormatError("SOVA-WORKER-PREFLIGHT-TIME", "measurement time is invalid")
        if not self.checks or len({item.name for item in self.checks}) != len(self.checks):
            raise FormatError("SOVA-WORKER-PREFLIGHT-CHECK", "preflight checks must be unique")

    @property
    def ready_for_live_matrix(self) -> bool:
        return all(item.passed for item in self.checks if item.required)

    def to_mapping(self) -> dict[str, Any]:
        failed = [item.name for item in self.checks if item.required and not item.passed]
        body: dict[str, Any] = {
            "artifactType": "sova.worker-host-preflight-receipt",
            "schemaVersion": "0.1.0",
            "releaseCommit": self.release_commit,
            "workerId": self.worker_id,
            "measuredAt": self.measured_at,
            "attestationDigest": self.attestation_digest,
            "checks": [item.to_mapping() for item in self.checks],
            "failedRequiredChecks": failed,
            "status": "ready-for-live-matrix" if self.ready_for_live_matrix else "blocked",
            "claims": {
                "selfMeasured": True,
                "liveFirecrackerExecuted": False,
                "exactHostMatrixPassed": False,
                "independentlyReviewed": False,
                "productionIsolationClaimAllowed": False,
                "escapeImpossible": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


def _check(name: str, evidence: str, *, required: bool, passed: bool) -> HostPreflightCheck:
    return HostPreflightCheck(name, required, passed, evidence[:512])


def _swap_disabled() -> tuple[bool, str]:
    value = _read_text(Path("/proc/swaps"))
    if value is None:
        return False, "unreadable"
    rows = [line for line in value.splitlines()[1:] if line.strip()]
    return not rows, f"active-devices={len(rows)}"


def _kvm_available() -> bool:
    path = Path("/dev/kvm")
    try:
        return stat.S_ISCHR(path.stat().st_mode) and os.access(path, os.R_OK | os.W_OK)
    except OSError:
        return False


def _egress_interface_exists(name: str) -> bool:
    return (Path("/sys/class/net") / name).is_dir()


def _permission_bits(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _identity_ranges_unallocated(
    uid_start: int,
    uid_end: int,
    gid_start: int,
    gid_end: int,
) -> bool:
    passwd = _read_text(Path("/etc/passwd"))
    groups = _read_text(Path("/etc/group"))
    if passwd is None or groups is None:
        return False
    user_collision = any(
        len(fields := row.split(":")) >= _PASSWD_MIN_FIELDS
        and fields[2].isdigit()
        and fields[3].isdigit()
        and (uid_start <= int(fields[2]) <= uid_end or gid_start <= int(fields[3]) <= gid_end)
        for row in passwd.splitlines()
    )
    group_collision = any(
        len(fields := row.split(":")) >= _GROUP_MIN_FIELDS
        and fields[2].isdigit()
        and gid_start <= int(fields[2]) <= gid_end
        for row in groups.splitlines()
    )
    return not user_collision and not group_collision


def _cpu_vulnerability_state() -> tuple[bool, str]:
    try:
        entries = sorted(item for item in _CPU_VULNERABILITY_DIRECTORY.iterdir() if item.is_file())
    except OSError:
        return False, "unavailable"
    if not entries:
        return False, "no-vulnerability-status-files"
    unsafe: list[str] = []
    for entry in entries:
        value = _read_text(entry)
        if value is None or _VULNERABLE.search(value):
            unsafe.append(entry.name)
    return not unsafe, "unsafe=" + (",".join(unsafe) if unsafe else "none")


def collect_worker_host_preflight(  # noqa: PLR0913 - exact host bindings stay explicit
    *,
    release_commit: str,
    measured_at: str,
    attestation: WorkerAttestation,
    firecracker_policy: FirecrackerHostPolicy,
    network_policy: NetworkPlaneHostPolicy,
    identity_lease_directory: Path,
) -> WorkerHostPreflightReceipt:
    """Measure launch prerequisites; this receipt authorizes only the live matrix."""
    release = platform.release().lower()
    proc_version = (_read_text(Path("/proc/version")) or "").lower()
    linux = platform.system() == "Linux"
    root = getattr(os, "geteuid", lambda: -1)() == 0
    wsl = "microsoft" in release or "microsoft" in proc_version or "wsl" in release
    kvm_access = _kvm_available()
    swap_ok, swap_evidence = _swap_disabled()
    ip_forward = _read_text(Path("/proc/sys/net/ipv4/ip_forward"))
    cgroup_controllers = firecracker_policy.cgroup_base / "cgroup.controllers"
    paths = (
        firecracker_policy.firecracker_binary,
        firecracker_policy.jailer_binary,
        firecracker_policy.chroot_base,
        firecracker_policy.network_namespace_base,
        firecracker_policy.content_store,
        firecracker_policy.cgroup_base,
        network_policy.ip_binary,
        network_policy.nft_binary,
        network_policy.setpriv_binary,
        network_policy.mediator_binary,
        network_policy.state_directory,
        identity_lease_directory,
    )
    root_paths = all(_root_controlled(path) for path in paths)
    binary_pins = (
        (firecracker_policy.firecracker_binary, firecracker_policy.approved_firecracker_digest),
        (firecracker_policy.jailer_binary, firecracker_policy.approved_jailer_digest),
        (network_policy.ip_binary, network_policy.approved_ip_digest),
        (network_policy.nft_binary, network_policy.approved_nft_digest),
        (network_policy.setpriv_binary, network_policy.approved_setpriv_digest),
        (network_policy.mediator_binary, network_policy.approved_mediator_digest),
    )
    try:
        pins_match = all(_digest_file(path) == expected for path, expected in binary_pins)
    except (FormatError, OSError):
        pins_match = False
    egress_exists = _egress_interface_exists(network_policy.egress_interface)
    job_identity_range = _identity_ranges_unallocated(
        firecracker_policy.uid_base,
        MAXIMUM_JOB_IDENTITY,
        firecracker_policy.gid_base,
        MAXIMUM_JOB_IDENTITY,
    )
    mediator_identity_range = _identity_ranges_unallocated(
        network_policy.mediator_uid_base,
        network_policy.mediator_uid_base + MAXIMUM_NETWORK_IDENTITY_SLOT,
        network_policy.mediator_gid_base,
        network_policy.mediator_gid_base + MAXIMUM_NETWORK_IDENTITY_SLOT,
    )
    network_state_mode = _permission_bits(network_policy.state_directory)
    identity_lease_mode = _permission_bits(identity_lease_directory)
    cpu_safe, cpu_evidence = _cpu_vulnerability_state()
    smt = _read_text(Path("/sys/devices/system/cpu/smt/active"))
    unprivileged_bpf = _read_text(Path("/proc/sys/kernel/unprivileged_bpf_disabled"))
    checks = (
        _check("linux-host", platform.system(), required=True, passed=linux),
        _check(
            "root-execution",
            f"effective-uid={getattr(os, 'geteuid', lambda: -1)()}",
            required=True,
            passed=root,
        ),
        _check("not-wsl", f"release={platform.release()}", required=True, passed=not wsl),
        _check(
            "dedicated-host-operator-assertion",
            "self-asserted; independent review still required",
            required=True,
            passed=attestation.dedicated_linux_host,
        ),
        _check(
            "kvm-character-device-access",
            "read-write /dev/kvm",
            required=True,
            passed=kvm_access,
        ),
        _check(
            "cgroup-v2",
            str(cgroup_controllers),
            required=True,
            passed=cgroup_controllers.is_file(),
        ),
        _check("swap-disabled", swap_evidence, required=True, passed=swap_ok),
        _check(
            "root-controlled-host-paths",
            f"path-count={len(paths)}",
            required=True,
            passed=root_paths,
        ),
        _check(
            "binary-digests-pinned",
            f"binary-count={len(binary_pins)}",
            required=True,
            passed=pins_match,
        ),
        _check(
            "firecracker-version-pinned",
            f"observed={attestation.firecracker_version};required={FIRECRACKER_VERSION}",
            required=True,
            passed=attestation.firecracker_version == FIRECRACKER_VERSION,
        ),
        _check(
            "ipv4-forwarding-enabled",
            f"observed={ip_forward}",
            required=True,
            passed=ip_forward == "1",
        ),
        _check(
            "egress-interface-present",
            f"interface={network_policy.egress_interface}",
            required=True,
            passed=egress_exists,
        ),
        _check(
            "job-identity-range-unallocated",
            (
                f"uid={firecracker_policy.uid_base}-{MAXIMUM_JOB_IDENTITY};"
                f"gid={firecracker_policy.gid_base}-{MAXIMUM_JOB_IDENTITY}"
            ),
            required=True,
            passed=job_identity_range,
        ),
        _check(
            "mediator-identity-range-unallocated",
            (
                f"uid={network_policy.mediator_uid_base}-"
                f"{network_policy.mediator_uid_base + MAXIMUM_NETWORK_IDENTITY_SLOT};"
                f"gid={network_policy.mediator_gid_base}-"
                f"{network_policy.mediator_gid_base + MAXIMUM_NETWORK_IDENTITY_SLOT}"
            ),
            required=True,
            passed=mediator_identity_range,
        ),
        _check(
            "network-state-directory-mode",
            f"observed={network_state_mode};required={_NETWORK_STATE_MODE}",
            required=True,
            passed=network_state_mode == _NETWORK_STATE_MODE,
        ),
        _check(
            "identity-lease-directory-mode",
            f"observed={identity_lease_mode};required={_IDENTITY_LEASE_MODE}",
            required=True,
            passed=identity_lease_mode == _IDENTITY_LEASE_MODE,
        ),
        _check(
            "attestation-host-controls-consistent",
            "attestation compared with fresh measurements",
            required=True,
            passed=all(
                (
                    attestation.kvm_available == kvm_access,
                    attestation.cgroup_v2 == cgroup_controllers.is_file(),
                    attestation.swap_disabled == swap_ok,
                    attestation.host_paths_root_owned,
                    root_paths,
                    attestation.wsl_environment == wsl,
                )
            ),
        ),
        _check(
            "cpu-vulnerabilities-not-unmitigated",
            cpu_evidence,
            required=False,
            passed=cpu_safe,
        ),
        _check(
            "simultaneous-multithreading-disabled",
            f"observed={smt}",
            required=False,
            passed=smt == "0",
        ),
        _check(
            "unprivileged-bpf-disabled",
            f"observed={unprivileged_bpf}",
            required=False,
            passed=unprivileged_bpf == "2",
        ),
    )
    return WorkerHostPreflightReceipt(
        release_commit=release_commit,
        worker_id=attestation.worker_id,
        measured_at=measured_at,
        attestation_digest=attestation.digest,
        checks=checks,
    )


__all__ = [
    "HostPreflightCheck",
    "WorkerHostPreflightReceipt",
    "collect_worker_host_preflight",
]
