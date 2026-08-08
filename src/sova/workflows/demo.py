# SPDX-License-Identifier: Apache-2.0
"""Complete zero-Atlas map, search, evidence, and reproduction demonstration."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.detonation import DemoArtifacts, run_sleeper_demo
from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.mapping import build_capability_map, write_capability_map
from sova.reproduction import compare_observable_outcomes
from sova.runtime import ModelRouter, OrchestrationRuntime, RoleKind, RunProfile
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

    from sova.runtime.orchestration import ModelResponse


@dataclass(frozen=True, slots=True)
class CompleteDemoArtifacts:
    capsule: Path
    trace: Path
    reproduction_trace: Path
    orchestration_trace: Path
    map_report: Path
    report: Path
    summary: Path
    oracle_status: str
    evidence_closure: str
    cleanup_verified: bool
    reproduced: bool


@dataclass(frozen=True, slots=True)
class _RuleResponse:
    response_text: str
    structured: dict[str, Any] | None
    tool_calls: tuple[dict[str, Any], ...] = ()
    token_count: int | None = None
    monetary_cost: str | None = None


class _RuleRoleModel:
    """Deterministic no-network role used only by the bundled proof."""

    def __init__(self, role: RoleKind) -> None:
        self.role = role
        self.model_id = f"sova-rule-role/{role.value}/0.1"

    def respond(self, prompt: str) -> ModelResponse:
        document = json.loads(prompt)
        if document.get("role") != self.role.value:
            raise FormatError("SOVA-DEMO-ROLE", "role prompt was routed incorrectly")
        structured: dict[str, Any]
        if self.role == RoleKind.RECON:
            structured = {"surface": "synthetic-owned-target", "network": "sink-only"}
        elif self.role == RoleKind.EXPLORER:
            structured = {"dimensions": ["message", "SOVA_MODE"]}
        elif self.role == RoleKind.STRATEGIST:
            structured = {"method": "bounded-grid", "attemptBudget": 4}
        elif self.role == RoleKind.ATTACKER:
            structured = {"candidate": "sova:target:sleeper", "effects": "inert-only"}
        elif self.role == RoleKind.JUDGE:
            atoms = document["visibleInputs"]["evidenceAtoms"]
            oracle = next(item for item in atoms if item["kind"] == "oracle.completed")
            structured = {
                "status": "confirmed",
                "propositions": [
                    {
                        "id": "demo-oracle",
                        "text": "The deterministic oracle observed the planted inert effect.",
                        "evidenceIds": [oracle["id"]],
                    }
                ],
                "limitations": ["Synthetic measurement-system fixture only."],
            }
        else:  # pragma: no cover - the bundled demo binds only these roles
            structured = {"status": "unused"}
        return _RuleResponse("deterministic structured response", structured)


def _router() -> ModelRouter:
    roles = (
        RoleKind.RECON,
        RoleKind.EXPLORER,
        RoleKind.STRATEGIST,
        RoleKind.ATTACKER,
        RoleKind.JUDGE,
    )
    return ModelRouter({role: (_RuleRoleModel(role),) for role in roles})


def _safe_workspace(destination: Path) -> tuple[Path, Path]:
    workspace = destination / "synthetic-target"
    workspace.mkdir()
    inventory = workspace / "inventory.json"
    inventory.write_bytes(
        canonical_json_bytes(
            {
                "nodes": [
                    {
                        "key": "target",
                        "kind": "runtime",
                        "name": "synthetic planted sleeper",
                        "attributes": {
                            "owned": True,
                            "nativeCode": False,
                            "network": "sink-only",
                            "consequence": "none",
                        },
                    },
                    {
                        "key": "gate",
                        "kind": "approval-gate",
                        "name": "synthetic fixture authority",
                    },
                ],
                "edges": [
                    {"source": "workspace", "target": "gate", "kind": "protected-by"},
                    {"source": "workspace", "target": "target", "kind": "reaches"},
                ],
            }
        )
        + b"\n"
    )
    return workspace, inventory


def run_complete_demo(destination: Path, *, profile: RunProfile) -> CompleteDemoArtifacts:
    """Run discovery and a fresh reproduction with no Atlas or external model."""
    started_ns = time.perf_counter_ns()
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-DEMO-EXISTS", "demo output directory is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    workspace, inventory = _safe_workspace(destination)
    map_document = build_capability_map(workspace, inventories=(inventory,))
    map_path = destination / "target.sova-map.json"
    write_capability_map(map_path, map_document)

    discovered: DemoArtifacts | None = None

    def execute(_candidate: dict[str, Any], attempt: int) -> Path:
        nonlocal discovered
        if attempt != 0:
            raise FormatError("SOVA-DEMO-ATTEMPT", "bundled proof expects one orchestrated attempt")
        discovered = run_sleeper_demo(destination / "discovery")
        return discovered.trace

    runtime = OrchestrationRuntime(_router())
    orchestration = runtime.run(
        map_report=map_document.to_mapping(),
        profile=profile,
        orchestration_trace=destination / "orchestration.sova-trace",
        execute=execute,
    )
    if discovered is None:  # pragma: no cover - runtime contract
        raise FormatError("SOVA-DEMO-MISSING", "discovery artifacts were not created")
    reproduced = run_sleeper_demo(destination / "reproduction")
    comparison = compare_observable_outcomes(
        discovered.trace,
        reproduced.trace,
        kinds=("oracle.completed", "network.egress-attempt", "filesystem.read"),
    )
    discovery_verify = TraceReader(discovered.trace).verify(require_signature=True)
    reproduction_verify = TraceReader(reproduced.trace).verify(require_signature=True)
    summary = json.loads(discovered.summary.read_text(encoding="utf-8"))
    report_path = destination / "demo-report.json"
    report = {
        "artifactType": "sova.demo-report",
        "schemaVersion": "0.1.0",
        "target": "sova:target:sleeper",
        "profile": profile.to_mapping(),
        "conditions": {
            "ownedSyntheticTarget": True,
            "nativeTargetCodeExecuted": False,
            "network": "sink-only",
            "credentials": "synthetic-canary-only",
        },
        "baselines": summary["baselines"],
        "search": summary["search"],
        "result": {
            "status": orchestration.verdict.status.value,
            "source": orchestration.verdict.source,
            "attempts": len(summary["search"]["attempts"]),
            "durationMs": max(1, (time.perf_counter_ns() - started_ns + 999_999) // 1_000_000),
            "coverage": map_document.to_mapping()["coverage"],
            "detectionFloor": (
                "Only the bundled two-dimensional deterministic search space was exercised."
            ),
            "safeOrCleanClaim": False,
            "nextStep": (
                "Use `sova hunt owned-web-fixture` for real-browser bounded trigger search, "
                "or author an authorized target kit for an owned website."
            ),
        },
        "verification": {
            "discoverySignatureValid": discovery_verify.signature_valid,
            "reproductionSignatureValid": reproduction_verify.signature_valid,
            "includedKeyIdentityClaim": False,
            "offline": True,
            "independentCommand": (
                "python scripts/sova_independent_verify.py --require-signature <trace>"
            ),
        },
        "reproduction": {
            "equivalent": comparison.equivalent,
            "method": comparison.method,
            "status": comparison.status,
            "freshRun": True,
        },
        "artifacts": {
            "capsule": str(discovered.capsule.relative_to(destination)),
            "trace": str(discovered.trace.relative_to(destination)),
            "reproductionTrace": str(reproduced.trace.relative_to(destination)),
            "orchestrationTrace": str(orchestration.orchestration_trace.relative_to(destination)),
            "map": map_path.name,
        },
        "limitations": [
            "This is a deterministic synthetic measurement-system demonstration.",
            "It does not establish detection performance on real agents or unknown targets.",
            "An included ephemeral signing key proves integrity, not external signer identity.",
            "SOVA evidence is self-assessment material, not TRUSCOR attestation.",
        ],
    }
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return CompleteDemoArtifacts(
        discovered.capsule,
        discovered.trace,
        reproduced.trace,
        orchestration.orchestration_trace,
        map_path,
        report_path,
        discovered.summary,
        discovered.oracle_status,
        discovered.evidence_closure,
        discovered.cleanup_verified and reproduced.cleanup_verified,
        comparison.equivalent,
    )


__all__ = ["CompleteDemoArtifacts", "run_complete_demo"]
