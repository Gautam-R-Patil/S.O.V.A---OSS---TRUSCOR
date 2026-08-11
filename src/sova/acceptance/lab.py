# SPDX-License-Identifier: Apache-2.0
"""Safe offline acceptance lab and stable-readiness evaluation."""

from __future__ import annotations

import platform
import secrets
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sova.acceptance.model import (
    AcceptanceReceipt,
    default_release_gates,
    evaluate_release_readiness,
)
from sova.detonation import (
    CaptureMode,
    CoverageRequirement,
    OrderingGuarantee,
    SensorCoverageLedger,
    SensorCoveragePolicy,
    SensorDeclaration,
    SensorKind,
    SensorSurface,
    run_sleeper_demo,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.replay import verify_artifact

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class AcceptanceLabArtifacts:
    root: Path
    report: Path
    sensor_coverage: Path
    readiness: Path
    core_capsule: Path
    core_trace: Path
    status: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "root": str(self.root),
            "report": str(self.report),
            "sensorCoverage": str(self.sensor_coverage),
            "readiness": str(self.readiness),
            "coreCapsule": str(self.core_capsule),
            "coreTrace": str(self.core_trace),
        }


def _synthetic_coverage() -> dict[str, Any]:
    declarations = (
        SensorDeclaration(
            "sova-authorization",
            SensorKind.AUTHORIZATION,
            SensorSurface.SOVA,
            "healthy",
            "sova.authorization-kernel/0.1",
            CaptureMode.DIRECT,
            "sova-trace-sequence",
            OrderingGuarantee.LOCAL_TOTAL,
            emitted_events=1,
        ),
        SensorDeclaration(
            "sova-containment",
            SensorKind.SAFETY,
            SensorSurface.SOVA,
            "healthy",
            "sova.synthetic-world/0.1",
            CaptureMode.DIRECT,
            "sova-trace-sequence",
            OrderingGuarantee.LOCAL_TOTAL,
            emitted_events=1,
        ),
        SensorDeclaration(
            "synthetic-filesystem",
            SensorKind.FILESYSTEM,
            SensorSurface.HOST,
            "healthy",
            "sova.synthetic-filesystem/0.1",
            CaptureMode.DIRECT,
            "sova-world-sequence",
            OrderingGuarantee.PARTIAL,
            emitted_events=1,
            blind_spots=("simulated filesystem only; no native host activity",),
        ),
        SensorDeclaration(
            "synthetic-network",
            SensorKind.NETWORK,
            SensorSurface.EXTERNAL,
            "healthy",
            "sova.sink-only-network/0.1",
            CaptureMode.DIRECT,
            "sova-world-sequence",
            OrderingGuarantee.PARTIAL,
            emitted_events=1,
            blind_spots=("sink-only simulation; no packet or third-party service observation",),
        ),
    )
    policy = SensorCoveragePolicy(
        "sova:coverage:synthetic-sleeper/0.1",
        "declared synthetic authorization, safety, filesystem, and sink-only network effects",
        tuple(
            CoverageRequirement(declaration.surface, declaration.kind)
            for declaration in declarations
        ),
    )
    return SensorCoverageLedger(declarations).evaluate(policy).to_mapping()


def run_offline_acceptance_lab(
    destination: Path,
    *,
    receipts: tuple[AcceptanceReceipt, ...] = (),
) -> AcceptanceLabArtifacts:
    """Run credential-free core evidence tests and evaluate external stable gates."""
    root = destination.resolve()
    if root.exists():
        raise FormatError("SOVA-ACCEPTANCE-EXISTS", "acceptance destination must not exist")
    temporary = root.with_name(f".{root.name}.partial-{secrets.token_hex(8)}")
    temporary.mkdir(parents=True)
    try:
        core = temporary / "core-workflow"
        demo = run_sleeper_demo(core)
        capsule_verification = verify_artifact(demo.capsule).to_mapping()
        trace_verification = verify_artifact(demo.trace).to_mapping()
        core_pass = bool(
            capsule_verification["state"] in {"verified", "partial"}
            and trace_verification["state"] == "verified"
            and demo.oracle_status == "pass"
            and demo.evidence_closure == "sufficient"
            and demo.cleanup_verified
        )
        coverage = _synthetic_coverage()
        coverage_path = temporary / "sensor-coverage.json"
        coverage_path.write_bytes(canonical_json_bytes(coverage) + b"\n")
        readiness = evaluate_release_readiness(receipts).to_mapping()
        readiness_path = temporary / "stable-readiness.json"
        readiness_path.write_bytes(canonical_json_bytes(readiness) + b"\n")
        status = "pass" if core_pass and coverage["accepted"] else "fail"
        report = {
            "artifactType": "sova.acceptance-lab-report",
            "schemaVersion": "0.1.0",
            "status": status,
            "coreAcceptancePassed": core_pass,
            "stable1Ready": readiness["readyForStable1"],
            "environment": {
                "platform": platform.system().casefold(),
                "machine": platform.machine().casefold(),
                "python": platform.python_version(),
            },
            "artifacts": {
                "capsuleDigest": sha256_digest(demo.capsule.read_bytes()),
                "traceDigest": sha256_digest(demo.trace.read_bytes()),
                "sensorCoverageDigest": sha256_digest(coverage_path.read_bytes()),
                "readinessDigest": sha256_digest(readiness_path.read_bytes()),
            },
            "verification": {
                "capsule": capsule_verification,
                "trace": trace_verification,
                "oracleStatus": demo.oracle_status,
                "evidenceClosure": demo.evidence_closure,
                "cleanupVerified": demo.cleanup_verified,
            },
            "scope": {
                "networkUsed": False,
                "credentialsUsed": False,
                "nativeTargetCodeExecuted": False,
                "externalEvidenceGenerated": False,
            },
            "limitations": [
                "Core acceptance uses SOVA's deterministic synthetic fixture.",
                "The lab does not convert self-generated evidence into external validation.",
                "Stable 1.0 remains blocked until every separate stable gate passes.",
            ],
        }
        report["digest"] = sha256_digest(canonical_json_bytes(report))
        report_path = temporary / "report.json"
        report_path.write_bytes(canonical_json_bytes(report) + b"\n")
        temporary.rename(root)
        return AcceptanceLabArtifacts(
            root,
            root / report_path.name,
            root / coverage_path.name,
            root / readiness_path.name,
            root / "core-workflow" / demo.capsule.name,
            root / "core-workflow" / demo.trace.name,
            status,
        )
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def acceptance_receipt_template(gate_id: str) -> dict[str, Any]:
    gate = next((item for item in default_release_gates() if item.id == gate_id), None)
    if gate is None:
        raise FormatError("SOVA-ACCEPTANCE-GATE", "unknown stable-release gate")
    labels = {name: values[0] for name, values in gate.required_labels if values}
    return {
        "artifactType": "sova.acceptance-receipt",
        "schemaVersion": "0.1.0",
        "gateId": gate.id,
        "evidenceType": gate.evidence_type,
        "runId": "replace-with-stable-run-id",
        "result": "inconclusive",
        "producer": "replace-with-runner-or-reviewer",
        "organization": "replace-with-legal-organization",
        "environmentId": "replace-with-environment-fingerprint",
        "labels": labels,
        "artifactDigests": ["sha256:" + "0" * 64],
        "independentOfSovaTeam": False,
        "observedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "limitations": [
            "Template only; replace every placeholder with verified evidence.",
            "A receipt signature does not prove reviewer identity or independence.",
        ],
    }


__all__ = [
    "AcceptanceLabArtifacts",
    "acceptance_receipt_template",
    "run_offline_acceptance_lab",
]
