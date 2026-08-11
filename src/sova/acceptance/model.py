# SPDX-License-Identifier: Apache-2.0
"""Evidence-driven final-mile and stable-release gates."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_SHA256_TEXT_LENGTH = 71


class GateClass(StrEnum):
    ENGINEERING = "engineering"
    EXTERNAL = "external-evidence"


@dataclass(frozen=True, slots=True)
class AcceptanceReceipt:
    gate_id: str
    evidence_type: str
    run_id: str
    result: str
    producer: str
    organization: str
    environment_id: str
    labels: tuple[tuple[str, str], ...]
    artifact_digests: tuple[str, ...]
    independent_of_sova_team: bool
    observed_at: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        values = (
            self.gate_id,
            self.evidence_type,
            self.run_id,
            self.producer,
            self.organization,
            self.environment_id,
            self.observed_at,
        )
        if any(not value for value in values):
            raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt identity fields are required")
        if self.result not in {"pass", "fail", "inconclusive"}:
            raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt result is unsupported")
        if not self.observed_at.endswith("Z"):
            raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt timestamp must be UTC")
        if len(dict(self.labels)) != len(self.labels):
            raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt labels must be unique")
        if any(not key or not value for key, value in self.labels):
            raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt labels cannot be empty")
        if any(
            not digest.startswith("sha256:") or len(digest) != _SHA256_TEXT_LENGTH
            for digest in self.artifact_digests
        ):
            raise FormatError("SOVA-ACCEPTANCE-DIGEST", "artifact digests must be SHA-256")

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping(include_digest=False)))

    def to_mapping(self, *, include_digest: bool = True) -> dict[str, Any]:
        material = {
            "artifactType": "sova.acceptance-receipt",
            "schemaVersion": "0.1.0",
            "gateId": self.gate_id,
            "evidenceType": self.evidence_type,
            "runId": self.run_id,
            "result": self.result,
            "producer": self.producer,
            "organization": self.organization,
            "environmentId": self.environment_id,
            "labels": dict(sorted(self.labels)),
            "artifactDigests": list(self.artifact_digests),
            "independentOfSovaTeam": self.independent_of_sova_team,
            "observedAt": self.observed_at,
            "limitations": list(self.limitations),
        }
        if include_digest:
            material["digest"] = self.digest
        return material


@dataclass(frozen=True, slots=True)
class AcceptanceGate:
    id: str
    title: str
    evidence_type: str
    gate_class: GateClass
    minimum_passes: int = 1
    minimum_environments: int = 1
    minimum_independent_organizations: int = 0
    required_labels: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.title or not self.evidence_type:
            raise FormatError("SOVA-ACCEPTANCE-GATE", "gate identity fields are required")
        if self.minimum_passes < 1 or self.minimum_environments < 1:
            raise FormatError("SOVA-ACCEPTANCE-GATE", "gate minimums must be positive")
        if self.minimum_independent_organizations < 0:
            raise FormatError("SOVA-ACCEPTANCE-GATE", "independence minimum cannot be negative")


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    status: str
    accepted_receipts: tuple[str, ...]
    failed_receipts: tuple[str, ...]
    reasons: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "gateId": self.gate_id,
            "status": self.status,
            "acceptedReceipts": list(self.accepted_receipts),
            "failedReceipts": list(self.failed_receipts),
            "reasons": list(self.reasons),
        }


def evaluate_gate(gate: AcceptanceGate, receipts: tuple[AcceptanceReceipt, ...]) -> GateResult:
    candidates = tuple(
        receipt
        for receipt in receipts
        if receipt.gate_id == gate.id and receipt.evidence_type == gate.evidence_type
    )
    passing = tuple(receipt for receipt in candidates if receipt.result == "pass")
    reasons: list[str] = []
    if len(passing) < gate.minimum_passes:
        reasons.append(f"requires-{gate.minimum_passes}-passing-receipts")
    environments = {receipt.environment_id for receipt in passing}
    if len(environments) < gate.minimum_environments:
        reasons.append(f"requires-{gate.minimum_environments}-distinct-environments")
    independent_organizations = {
        receipt.organization for receipt in passing if receipt.independent_of_sova_team
    }
    if len(independent_organizations) < gate.minimum_independent_organizations:
        reasons.append(
            f"requires-{gate.minimum_independent_organizations}-independent-organizations"
        )
    for label, required in gate.required_labels:
        observed = {dict(receipt.labels).get(label) for receipt in passing}
        missing = sorted(set(required) - observed)
        if missing:
            reasons.append(f"missing-{label}:" + ",".join(missing))
    return GateResult(
        gate.id,
        "pass" if not reasons else "blocked",
        tuple(receipt.digest for receipt in passing),
        tuple(receipt.digest for receipt in candidates if receipt.result == "fail"),
        tuple(reasons),
    )


def default_release_gates() -> tuple[AcceptanceGate, ...]:
    """Return stable-1.0 gates; external facts remain external gates."""
    return (
        AcceptanceGate(
            "universal-authorized-web",
            "Authorized website workflow across held-out applications",
            "sova.web-held-out-study",
            GateClass.EXTERNAL,
            minimum_passes=6,
            minimum_environments=3,
            minimum_independent_organizations=1,
            required_labels=(("applicationClass", ("static", "spa", "authenticated")),),
        ),
        AcceptanceGate(
            "cross-platform-desktop",
            "Fixture-owned desktop UI workflows on supported operating systems",
            "sova.desktop-conformance",
            GateClass.ENGINEERING,
            minimum_passes=3,
            minimum_environments=3,
            required_labels=(("platform", ("windows", "macos", "linux")),),
        ),
        AcceptanceGate(
            "hostile-agent-isolation",
            "User-kernel or per-workload VM isolation conformance",
            "sova.isolation-conformance",
            GateClass.ENGINEERING,
            minimum_passes=1,
            required_labels=(("isolationClass", ("user-kernel-or-microvm",)),),
        ),
        AcceptanceGate(
            "declared-sensor-coverage",
            "Claim-conditioned sensor coverage with drop and blind-spot accounting",
            "sova.sensor-coverage-study",
            GateClass.ENGINEERING,
            minimum_passes=4,
            required_labels=(("surface", ("host", "browser", "model", "external")),),
        ),
        AcceptanceGate(
            "independent-causal-validation",
            "Blinded causal-attribution validation on real-agent ground truth",
            "sova.blinded-causal-study",
            GateClass.EXTERNAL,
            minimum_passes=1,
            minimum_independent_organizations=1,
        ),
        AcceptanceGate(
            "cross-provider-experiment",
            "Predeclared cross-provider and cross-model behavioral experiment",
            "sova.provider-comparison-study",
            GateClass.EXTERNAL,
            minimum_passes=4,
            minimum_environments=4,
            required_labels=(("providerClass", ("provider-a", "provider-b")),),
        ),
        AcceptanceGate(
            "hosted-community",
            "Production registry, community, leaderboard, and corpus deployment",
            "sova.production-community-attestation",
            GateClass.EXTERNAL,
            minimum_passes=1,
            minimum_independent_organizations=1,
        ),
        AcceptanceGate(
            "managed-monitoring",
            "Supervised continuous monitoring and acknowledged alert integration",
            "sova.monitoring-service-attestation",
            GateClass.EXTERNAL,
            minimum_passes=2,
            minimum_environments=2,
            required_labels=(("alertPath", ("webhook", "operator-channel")),),
        ),
        AcceptanceGate(
            "independent-implementations",
            "Independent .sova reader, verifier, and migration interoperability",
            "sova.independent-implementation",
            GateClass.EXTERNAL,
            minimum_passes=2,
            minimum_independent_organizations=1,
            required_labels=(("implementationRole", ("reader", "verifier", "migration")),),
        ),
        AcceptanceGate(
            "stable-format-and-signed-release",
            "Compatibility rehearsal and signed public stable release",
            "sova.stable-release-attestation",
            GateClass.EXTERNAL,
            minimum_passes=2,
            minimum_environments=2,
            minimum_independent_organizations=1,
        ),
        AcceptanceGate(
            "benchmark-advantage",
            "Predeclared benchmark advantage over named strongest baselines",
            "sova.comparative-benchmark",
            GateClass.EXTERNAL,
            minimum_passes=2,
            minimum_environments=2,
            minimum_independent_organizations=1,
        ),
        AcceptanceGate(
            "external-user-workflows",
            "Complete workflow reproduced by external users outside SOVA fixtures",
            "sova.external-user-study",
            GateClass.EXTERNAL,
            minimum_passes=3,
            minimum_environments=3,
            minimum_independent_organizations=2,
        ),
    )


@dataclass(frozen=True, slots=True)
class ReleaseReadinessReport:
    results: tuple[GateResult, ...]

    @property
    def ready_for_stable_1(self) -> bool:
        return all(result.passed for result in self.results)

    def to_mapping(self) -> dict[str, Any]:
        material = {
            "artifactType": "sova.release-readiness-report",
            "schemaVersion": "0.1.0",
            "status": "pass" if self.ready_for_stable_1 else "blocked",
            "readyForStable1": self.ready_for_stable_1,
            "passedGateCount": sum(result.passed for result in self.results),
            "totalGateCount": len(self.results),
            "results": [result.to_mapping() for result in self.results],
            "claims": {
                "externalEvidenceSelfGenerated": False,
                "independenceInferredFromSignature": False,
                "adoptionInferredFromDownloads": False,
            },
        }
        material["digest"] = sha256_digest(canonical_json_bytes(material))
        return material


def evaluate_release_readiness(
    receipts: tuple[AcceptanceReceipt, ...],
    gates: tuple[AcceptanceGate, ...] | None = None,
) -> ReleaseReadinessReport:
    selected = gates or default_release_gates()
    if len({gate.id for gate in selected}) != len(selected):
        raise FormatError("SOVA-ACCEPTANCE-GATE", "gate ids must be unique")
    return ReleaseReadinessReport(tuple(evaluate_gate(gate, receipts) for gate in selected))


__all__ = [
    "AcceptanceGate",
    "AcceptanceReceipt",
    "GateClass",
    "GateResult",
    "ReleaseReadinessReport",
    "default_release_gates",
    "evaluate_gate",
    "evaluate_release_readiness",
]
