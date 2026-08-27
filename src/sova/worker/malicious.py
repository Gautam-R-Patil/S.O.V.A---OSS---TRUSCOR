# SPDX-License-Identifier: Apache-2.0
"""Declared malicious-guest matrix separating local policy tests from live escape tests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class MaliciousGuestCase(StrEnum):
    RESOURCE_EXHAUSTION = "resource-exhaustion"
    OUTPUT_BOMB = "output-bomb"
    SYMLINK_PATH_ABUSE = "symlink-path-abuse"
    DEVICE_MOUNT_ACCESS = "device-mount-access"
    METADATA_SERVICE_ACCESS = "metadata-service-access"
    DNS_REBINDING = "dns-rebinding"
    SECRET_THEFT = "secret-theft"  # noqa: S105 - attack class, not a credential
    DAEMON_SOCKET_ACCESS = "daemon-socket-access"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"


@dataclass(frozen=True, slots=True)
class MaliciousGuestControl:
    case: MaliciousGuestCase
    policy_enforcement: tuple[str, ...]
    local_adverse_test: str
    exact_host_test_required: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "case": self.case.value,
            "policyEnforcement": list(self.policy_enforcement),
            "localAdverseTest": self.local_adverse_test,
            "localPolicyTested": True,
            "exactHostTestRequired": self.exact_host_test_required,
        }


def malicious_guest_matrix() -> tuple[MaliciousGuestControl, ...]:
    """Return every P5-09 case without conflating simulation with host containment."""
    return (
        MaliciousGuestControl(
            MaliciousGuestCase.RESOURCE_EXHAUSTION,
            ("cgroup cpu/memory/pids", "file/output/network/time limits", "watchdog"),
            "test_network_broker_enforces_connection_byte_and_time_budgets",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.OUTPUT_BOMB,
            ("compressed and expanded byte limits", "compression-ratio limit"),
            "test_controller_rejects_path_traversal_symlink_and_output_bomb",
            exact_host_test_required=False,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.SYMLINK_PATH_ABUSE,
            ("in-memory extraction", "normalized paths", "special-file rejection"),
            "test_controller_rejects_path_traversal_symlink_and_output_bomb",
            exact_host_test_required=False,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.DEVICE_MOUNT_ACCESS,
            ("no host mounts", "MMIO-only devices", "PCI disabled"),
            "test_launch_plan_enforces_jailer_mmio_cgroups_and_disposable_storage",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.METADATA_SERVICE_ACCESS,
            ("non-global IP denial", "host-side broker-only egress"),
            "test_network_broker_denies_dns_rebinding_and_metadata_service",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.DNS_REBINDING,
            ("initial pin", "exact revalidation", "selected-address binding"),
            "test_network_broker_denies_dns_rebinding_and_metadata_service",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.SECRET_THEFT,
            ("opaque capabilities", "audience/expiry/use limits", "redaction scan"),
            "test_secret_broker_binds_job_audience_expiry_and_use_count",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.DAEMON_SOCKET_ACCESS,
            ("no host mounts", "no path or socket secret grants"),
            "test_optional_backends_never_claim_firecracker_equivalence",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.PERSISTENCE,
            ("one disposable writable layer per job", "no reusable guest state"),
            "test_cleanup_receipt_must_bind_exact_job_and_every_cleanup_check",
            exact_host_test_required=True,
        ),
        MaliciousGuestControl(
            MaliciousGuestCase.CLEANUP,
            ("seven cleanup checks", "fail-closed cleanup status"),
            "test_cleanup_receipt_must_bind_exact_job_and_every_cleanup_check",
            exact_host_test_required=True,
        ),
    )


__all__ = ["MaliciousGuestCase", "MaliciousGuestControl", "malicious_guest_matrix"]
