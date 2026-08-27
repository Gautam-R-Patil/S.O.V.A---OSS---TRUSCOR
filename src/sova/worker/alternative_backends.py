# SPDX-License-Identifier: Apache-2.0
"""Claim-limited admission for optional Kata and gVisor compatibility lanes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest


@dataclass(frozen=True, slots=True)
class AlternativeBackendAdmission:
    backend: str
    status: str
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "backend": self.backend,
            "status": self.status,
            "reasons": list(self.reasons),
            "limitations": list(self.limitations),
            "claims": {
                "equivalentToFirecracker": False,
                "arbitraryHostileCodeProductionReady": False,
            },
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


@dataclass(frozen=True, slots=True)
class KataAdmissionEvidence:
    installed_version: str | None
    approved_version: str
    runtime_digest_pinned: bool
    advisory_snapshot_current: bool
    unresolved_escape_advisories: tuple[str, ...]
    untrusted_annotations_disabled: bool
    host_mounts_disabled: bool
    configuration_paths_root_owned: bool


def assess_kata_backend(evidence: KataAdmissionEvidence) -> AlternativeBackendAdmission:
    """Keep Kata disabled until every version, advisory, annotation, and mount gate holds."""
    reasons: list[str] = []
    for condition, reason in (
        (
            evidence.installed_version == evidence.approved_version,
            "kata-version-not-approved",
        ),
        (evidence.runtime_digest_pinned, "kata-runtime-digest-unpinned"),
        (evidence.advisory_snapshot_current, "kata-advisory-snapshot-stale"),
        (
            not evidence.unresolved_escape_advisories,
            "kata-unresolved-escape-advisory",
        ),
        (evidence.untrusted_annotations_disabled, "kata-untrusted-annotations-enabled"),
        (evidence.host_mounts_disabled, "kata-host-mounts-enabled"),
        (evidence.configuration_paths_root_owned, "kata-configuration-paths-untrusted"),
    ):
        if not condition:
            reasons.append(reason)
    return AlternativeBackendAdmission(
        backend="kata",
        status="compatibility-only" if not reasons else "disabled",
        reasons=tuple(reasons),
        limitations=(
            "Optional OCI compatibility lane only.",
            "Admission does not establish escape immunity or Firecracker equivalence.",
        ),
    )


def assess_gvisor_backend(
    *, installed: bool, conformance_passed: bool
) -> AlternativeBackendAdmission:
    """Never upgrade the user-space-kernel lane to the hostile-code microVM claim."""
    reasons: list[str] = []
    if not installed:
        reasons.append("gvisor-not-installed")
    if not conformance_passed:
        reasons.append("gvisor-conformance-not-passed")
    return AlternativeBackendAdmission(
        backend="gvisor",
        status="lower-assurance-compatibility" if not reasons else "disabled",
        reasons=tuple(reasons),
        limitations=(
            "gVisor is a user-space kernel sandbox, not a VM boundary.",
            "Hardware side channels and higher-layer runtime errors remain outside its boundary.",
        ),
    )


__all__ = [
    "AlternativeBackendAdmission",
    "KataAdmissionEvidence",
    "assess_gvisor_backend",
    "assess_kata_backend",
]
