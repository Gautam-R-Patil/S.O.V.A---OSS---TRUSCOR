# SPDX-License-Identifier: Apache-2.0
"""Strict dedicated-worker deployment policy loader."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sova.formats import sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.worker.firecracker import FirecrackerHostPolicy
from sova.worker.network_plane import NetworkPlaneHostPolicy

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _object(value: Any, role: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-WORKER-DEPLOY-TYPE", f"{role} must be an object")
    return value


def _string(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value:
        raise FormatError("SOVA-WORKER-DEPLOY-TYPE", f"{role} must be a non-empty string")
    return value


def _integer(value: Any, role: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError("SOVA-WORKER-DEPLOY-TYPE", f"{role} must be an integer")
    return value


def _exact(value: dict[str, Any], expected: set[str], role: str) -> None:
    if set(value) != expected:
        raise FormatError("SOVA-WORKER-DEPLOY-FIELDS", f"{role} fields must be exact")


@dataclass(frozen=True, slots=True)
class DeploymentPins:
    host_kernel_digest: str
    microcode_digest: str
    guest_kernel_digest: str
    root_filesystem_digest: str
    advisory_snapshot_digest: str

    def __post_init__(self) -> None:
        if any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.host_kernel_digest,
                self.microcode_digest,
                self.guest_kernel_digest,
                self.root_filesystem_digest,
                self.advisory_snapshot_digest,
            )
        ):
            raise FormatError("SOVA-WORKER-DEPLOY-PIN", "deployment digest pin is invalid")


@dataclass(frozen=True, slots=True)
class WorkerDeploymentPolicy:
    worker_id: str
    source_digest: str
    firecracker: FirecrackerHostPolicy
    network: NetworkPlaneHostPolicy
    identity_lease_directory: Path
    host_kernel_image: Path
    microcode_image: Path
    guest_kernel_image: Path
    root_filesystem_image: Path
    advisory_snapshot: Path
    pins: DeploymentPins

    def __post_init__(self) -> None:
        for path in (
            self.identity_lease_directory,
            self.host_kernel_image,
            self.microcode_image,
            self.guest_kernel_image,
            self.root_filesystem_image,
            self.advisory_snapshot,
        ):
            if not path.is_absolute() or ".." in path.parts:
                raise FormatError(
                    "SOVA-WORKER-DEPLOY-PATH", "deployment path must be absolute and normalized"
                )


def read_worker_deployment_policy(raw: bytes) -> WorkerDeploymentPolicy:
    """Load one fully configured policy; templates and unknown fields fail closed."""
    document = _object(strict_json_loads(raw), "deployment policy")
    _exact(
        document,
        {
            "artifactType",
            "schemaVersion",
            "status",
            "workerId",
            "firecrackerVersion",
            "hostPaths",
            "network",
            "pins",
            "requiredControls",
        },
        "deployment policy",
    )
    if (
        document["artifactType"] != "sova.worker-deployment-policy"
        or document["schemaVersion"] != "0.2.0"
        or document["status"] != "configured-not-attested"
        or document["firecrackerVersion"] != "1.16.1"
    ):
        raise FormatError(
            "SOVA-WORKER-DEPLOY-STATUS", "policy is a template, unsupported, or unconfigured"
        )
    paths = _object(document["hostPaths"], "host paths")
    _exact(
        paths,
        {
            "firecrackerBinary",
            "jailerBinary",
            "chrootBase",
            "networkNamespaceBase",
            "contentStore",
            "cgroupBase",
            "ipBinary",
            "nftBinary",
            "setprivBinary",
            "networkMediatorBinary",
            "networkStateDirectory",
            "identityLeaseDirectory",
            "hostKernelImage",
            "microcodeImage",
            "guestKernelImage",
            "rootFilesystemImage",
            "advisorySnapshot",
        },
        "host paths",
    )
    pins = _object(document["pins"], "pins")
    _exact(
        pins,
        {
            "firecrackerDigest",
            "jailerDigest",
            "ipDigest",
            "nftDigest",
            "setprivDigest",
            "networkMediatorDigest",
            "hostKernelDigest",
            "microcodeDigest",
            "guestKernelDigest",
            "rootFilesystemDigest",
            "advisorySnapshotDigest",
        },
        "pins",
    )
    network = _object(document["network"], "network")
    _exact(
        network,
        {"egressInterface", "mediatorUidBase", "mediatorGidBase", "proxyPort"},
        "network",
    )
    controls = _object(document["requiredControls"], "required controls")
    expected_controls = {
        "dedicatedLinuxHost",
        "kvm",
        "cgroupV2",
        "swapDisabled",
        "defaultSeccomp",
        "uniqueUidGidPerJob",
        "rootOwnedPaths",
        "hostMountsAllowed",
        "pciEnabled",
        "ambientGuestNetwork",
        "mediatorOnlyEgress",
        "independentReviewRequired",
    }
    _exact(controls, expected_controls, "required controls")
    required_true = expected_controls - {
        "hostMountsAllowed",
        "pciEnabled",
        "ambientGuestNetwork",
    }
    if any(controls.get(key) is not True for key in required_true) or any(
        controls.get(key) is not False
        for key in ("hostMountsAllowed", "pciEnabled", "ambientGuestNetwork")
    ):
        raise FormatError("SOVA-WORKER-DEPLOY-CONTROL", "required controls are weakened")

    def configured_path(name: str) -> Path:
        return Path(_string(paths[name], name))

    deployment_pins = DeploymentPins(
        host_kernel_digest=_string(pins["hostKernelDigest"], "host kernel digest"),
        microcode_digest=_string(pins["microcodeDigest"], "microcode digest"),
        guest_kernel_digest=_string(pins["guestKernelDigest"], "guest kernel digest"),
        root_filesystem_digest=_string(pins["rootFilesystemDigest"], "root filesystem digest"),
        advisory_snapshot_digest=_string(
            pins["advisorySnapshotDigest"], "advisory snapshot digest"
        ),
    )
    firecracker = FirecrackerHostPolicy(
        firecracker_binary=configured_path("firecrackerBinary"),
        jailer_binary=configured_path("jailerBinary"),
        chroot_base=configured_path("chrootBase"),
        network_namespace_base=configured_path("networkNamespaceBase"),
        content_store=configured_path("contentStore"),
        cgroup_base=configured_path("cgroupBase"),
        approved_firecracker_digest=_string(pins["firecrackerDigest"], "Firecracker digest"),
        approved_jailer_digest=_string(pins["jailerDigest"], "jailer digest"),
    )
    network_policy = NetworkPlaneHostPolicy(
        ip_binary=configured_path("ipBinary"),
        nft_binary=configured_path("nftBinary"),
        setpriv_binary=configured_path("setprivBinary"),
        mediator_binary=configured_path("networkMediatorBinary"),
        state_directory=configured_path("networkStateDirectory"),
        approved_ip_digest=_string(pins["ipDigest"], "ip digest"),
        approved_nft_digest=_string(pins["nftDigest"], "nft digest"),
        approved_setpriv_digest=_string(pins["setprivDigest"], "setpriv digest"),
        approved_mediator_digest=_string(pins["networkMediatorDigest"], "network mediator digest"),
        egress_interface=_string(network["egressInterface"], "egress interface"),
        mediator_uid_base=_integer(network["mediatorUidBase"], "mediator UID base"),
        mediator_gid_base=_integer(network["mediatorGidBase"], "mediator GID base"),
        proxy_port=_integer(network["proxyPort"], "proxy port"),
    )
    return WorkerDeploymentPolicy(
        worker_id=_string(document["workerId"], "worker identifier"),
        source_digest=sha256_digest(raw),
        firecracker=firecracker,
        network=network_policy,
        identity_lease_directory=configured_path("identityLeaseDirectory"),
        host_kernel_image=configured_path("hostKernelImage"),
        microcode_image=configured_path("microcodeImage"),
        guest_kernel_image=configured_path("guestKernelImage"),
        root_filesystem_image=configured_path("rootFilesystemImage"),
        advisory_snapshot=configured_path("advisorySnapshot"),
        pins=deployment_pins,
    )


__all__ = ["DeploymentPins", "WorkerDeploymentPolicy", "read_worker_deployment_policy"]
