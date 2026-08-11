# SPDX-License-Identifier: Apache-2.0
"""Portable desktop-executor conformance workflow and receipt material."""

from __future__ import annotations

import platform as host_platform
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    Executor,
    OutcomeStatus,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_DIGEST_LENGTH = 71


@dataclass(frozen=True, slots=True)
class DesktopConformancePlan:
    platform: str
    fixture_id: str
    fixture_digest: str
    driver_attestation_digest: str
    click_inputs: dict[str, Any]
    type_inputs: dict[str, Any]

    def __post_init__(self) -> None:
        if self.platform not in {"windows", "macos", "linux"} or not self.fixture_id:
            raise FormatError("SOVA-DESKTOP-CONFORMANCE", "platform or fixture id is invalid")
        digests = (self.fixture_digest, self.driver_attestation_digest)
        if any(not item.startswith("sha256:") or len(item) != _DIGEST_LENGTH for item in digests):
            raise FormatError("SOVA-DESKTOP-CONFORMANCE", "fixture and driver digests are required")


def run_desktop_conformance(
    plan: DesktopConformancePlan,
    executor: Executor,
    workspace: Path,
) -> dict[str, Any]:
    """Run snapshot, click, and type through one application-bound real adapter."""
    capabilities = {item.identifier for item in executor.capabilities()}
    required = {
        "computer.snapshot/0.1",
        "computer.click/0.1",
        "computer.type/0.1",
    }
    if not required <= capabilities:
        raise FormatError("SOVA-DESKTOP-CONFORMANCE", "desktop capabilities are incomplete")
    context = ExecutionContext(
        workspace,
        {"decision": "allowed", "scope": "self-owned-native-conformance-fixture"},
    )
    rows = (
        ActionRequest("snapshot", "computer.snapshot", {}, 20),
        ActionRequest("click", "computer.click", plan.click_inputs, 20),
        ActionRequest("type", "computer.type", plan.type_inputs, 20),
    )
    results = tuple(executor.execute(row, context, CancellationToken()) for row in rows)
    checks = [
        {
            "requestId": result.request_id,
            "status": result.status.value,
            "verification": result.verification,
            "evidenceCount": len(result.evidence),
            "postObservationCaptured": result.output.get("postObservationCaptured") is True,
            "limitations": list(result.limitations),
        }
        for result in results
    ]
    accepted = all(
        result.status == OutcomeStatus.SUCCEEDED
        and result.evidence
        and result.verification != "not-performed"
        and result.output.get("postObservationCaptured") is True
        for result in results
    )
    report = {
        "artifactType": "sova.desktop-conformance-report",
        "schemaVersion": "0.1.0",
        "status": "pass" if accepted else "fail",
        "accepted": accepted,
        "platform": plan.platform,
        "executor": executor.name,
        "fixtureId": plan.fixture_id,
        "fixtureDigest": plan.fixture_digest,
        "driverAttestationDigest": plan.driver_attestation_digest,
        "environmentId": sha256_digest(
            canonical_json_bytes(
                {
                    "platform": host_platform.platform(),
                    "python": host_platform.python_version(),
                    "executor": executor.name,
                    "driver": plan.driver_attestation_digest,
                }
            )
        ),
        "capabilities": sorted(capabilities),
        "checks": checks,
        "claims": {
            "applicationBound": True,
            "postActionObserved": accepted,
            "hostIsSecuritySandbox": False,
            "arbitraryDesktopCompatibility": False,
            "independentValidation": False,
        },
        "limitations": [
            "Result applies only to the exact fixture, driver, host, and action set.",
            "Accessibility providers can omit custom, elevated, secure, or GPU-drawn UI.",
        ],
    }
    report["digest"] = sha256_digest(canonical_json_bytes(report))
    return report


__all__ = ["DesktopConformancePlan", "run_desktop_conformance"]
