# SPDX-License-Identifier: Apache-2.0
"""Capsule-to-trace-to-forensics-to-evidence composition integration proof."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.composition import (
    CompositionBudget,
    CompositionSearchEngine,
    CompositionStrategy,
    PlantedCompositionEvaluator,
    composition_to_scenario_fragment,
    planted_composition_graph,
)
from sova.evidence import build_evidence_bundle
from sova.forensics import (
    CausalLayer,
    CounterfactualTrial,
    assess_counterfactuals,
    reconstruct_trace,
)
from sova.formats import sha256_digest, validate_document
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from pathlib import Path


def test_portable_composition_failure_becomes_bounded_shareable_evidence(tmp_path: Path) -> None:
    graph = planted_composition_graph()
    composition_report = CompositionSearchEngine(
        graph,
        CompositionBudget(max_attempts=50, max_candidates=50, max_path_nodes=4),
    ).search(CompositionStrategy.TRIGGER_AWARE, PlantedCompositionEvaluator())
    assert composition_report.minimized is not None
    assert composition_report.composition_only_confirmed

    scenario = scenario_template(
        title="Synthetic composition-only behavior",
        purpose="Reproduce one safe deterministic memory-to-agent-to-sink interaction.",
    )
    scenario["extensions"]["x-sova-composition"] = composition_to_scenario_fragment(
        graph,
        composition_report.minimized,
        report=composition_report,
    )
    manifest = capsule_manifest_template(
        title="Synthetic composition-only behavior",
        summary="Portable deterministic Topic 17 ground-truth fixture.",
        author="SOVA OSS test fixture",
    )
    capsule_path = tmp_path / "composition.sova"
    build_capsule(capsule_path, manifest, scenario=scenario)

    trace_path = tmp_path / "composition.sova-trace"
    writer = TraceWriter(trace_path)
    start = writer.append("run.started", {"capsule": "composition.sova"})
    memory = writer.append(
        "memory.read",
        {"resource": "fixture-memory", "value": "fixture-marker"},
        parents=[start] if start else [],
    )
    handoff = writer.append(
        "inter-agent.message",
        {"from": "memory", "to": "agent", "content": "fixture-marker"},
        parents=[memory] if memory else [],
    )
    writer.append(
        "tool.completed",
        {"tool": "fixture.sink.write", "effect": "fixture-effect-observed"},
        parents=[handoff] if handoff else [],
    )
    writer.finalize()

    reconstruction = reconstruct_trace(trace_path)
    assert len(reconstruction.entries) == 4
    assert any(entry.decision_point for entry in reconstruction.entries)
    validate_document(reconstruction.to_mapping(), "sova.forensic-reconstruction")

    trials = tuple(
        CounterfactualTrial(
            trial_id=f"permission-{index}",
            layer=CausalLayer.AUTHORIZATION,
            changed_layers=(CausalLayer.AUTHORIZATION,),
            baseline_outcome=True,
            intervention_outcome=False,
            context_equivalent=True,
            evidence_complete=True,
            original_trace=str(trace_path),
            counterfactual_trace=f"fixture:without-permission:{index}",
        )
        for index in range(4)
    )
    attribution = assess_counterfactuals(str(trace_path), trials)
    assert attribution.assessments[0].layer == CausalLayer.AUTHORIZATION

    evidence = build_evidence_bundle(
        {
            "finding": {
                "id": "SOVA-COMPOSITION-FIXTURE-001",
                "title": "Synthetic composition-only sink effect",
                "summary": "The ordered three-component fixture emitted the planted effect.",
                "affected": {
                    "component": "sova-composition-fixture",
                    "version": "0.1.0",
                    "identifiers": [],
                },
                "technicalSeverity": "informational",
                "harmCategory": "synthetic-ground-truth",
            },
            "evidence": [
                {
                    "role": "capsule",
                    "uri": capsule_path.name,
                    "digest": sha256_digest(capsule_path.read_bytes()),
                    "mediaType": "application/vnd.sova.capsule+zip",
                    "verified": True,
                },
                {
                    "role": "trace",
                    "uri": trace_path.name,
                    "digest": sha256_digest(trace_path.read_bytes()),
                    "mediaType": "application/vnd.sova.trace+zip",
                    "verified": True,
                },
            ],
            "conditionsTested": ["planted three-component order"],
            "coverage": {
                "testedCount": 4,
                "denominator": 4,
                "detectionFloor": "one deterministic synthetic composition-only chain",
            },
            "reproduction": {"successful": 4, "eligible": 4, "rate": "1"},
            "taxonomyMappings": [],
            "methodology": {
                "composition": "trigger-aware-sequence/0.1.0",
                "attribution": "paired-intervention-wilson/0.1.0",
            },
            "suggestedMitigations": ["Remove the synthetic sink permission."],
            "regressionEvidence": [],
            "attachments": [],
            "limitations": ["Deterministic synthetic fixture; field validity is untested."],
            "lifecycle": {"state": "draft", "supersedes": None},
        }
    )
    validate_document(evidence.to_mapping(), "sova.evidence")
    assert evidence.to_mapping()["assuranceBoundary"]["independentAttestation"] is False
