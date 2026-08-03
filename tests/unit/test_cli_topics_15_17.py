# SPDX-License-Identifier: Apache-2.0
"""Public CLI contracts for Topics 15 through 17."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sova.cli import main
from sova.composition import (
    CompositionBudget,
    CompositionSearchEngine,
    CompositionStrategy,
    PlantedCompositionEvaluator,
    planted_composition_graph,
)

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _evidence_specification() -> dict[str, Any]:
    digest = "sha256:" + "a" * 64
    return {
        "finding": {
            "id": "FIXTURE-1",
            "title": "Fixture behavior",
            "summary": "Synthetic behavior for CLI tests.",
            "affected": {"component": "fixture", "version": "1", "identifiers": []},
            "technicalSeverity": "low",
            "harmCategory": "fixture",
        },
        "evidence": [
            {
                "role": role,
                "uri": f"fixture.{suffix}",
                "digest": digest,
                "mediaType": media_type,
                "verified": True,
            }
            for role, suffix, media_type in (
                ("capsule", "sova", "application/vnd.sova.capsule+zip"),
                ("trace", "sova-trace", "application/vnd.sova.trace+zip"),
            )
        ],
        "conditionsTested": ["fixture"],
        "coverage": {"testedCount": 1, "denominator": 1, "detectionFloor": "fixture"},
        "reproduction": {"successful": 1, "eligible": 1, "rate": "1"},
        "taxonomyMappings": [],
        "methodology": {"oracle": "fixture/1"},
        "suggestedMitigations": [],
        "regressionEvidence": [],
        "attachments": [],
        "limitations": ["Synthetic only."],
        "lifecycle": {"state": "draft"},
    }


def _finding() -> dict[str, str]:
    return {
        "scanner": "fixture-scanner",
        "scannerVersion": "1",
        "ruleId": "R1",
        "targetId": "fixture",
        "location": "fixture:1",
        "message": "possible issue",
        "evidenceReference": "scanner:evidence",
        "mechanism": "static-pattern",
    }


def test_forensics_reconstruct_and_attribute_cli(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    events_path = tmp_path / "events.json"
    _write(
        events_path,
        {
            "sourceType": "external.fixture",
            "sourceId": "case",
            "events": [
                {
                    "id": "e0",
                    "sequence": 0,
                    "kind": "prompt.sent",
                    "phase": "test",
                    "actor": {"name": "operator"},
                    "target": {"name": "model"},
                    "parents": [],
                }
            ],
        },
    )
    assert main(["forensics", "reconstruct", str(events_path)]) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["artifactType"] == "sova.forensic-reconstruction"

    study_path = tmp_path / "attribution.json"
    trials = [
        {
            "trialId": f"trial-{index}",
            "layer": "tool-description-or-implementation",
            "changedLayers": ["tool-description-or-implementation"],
            "baselineOutcome": True,
            "interventionOutcome": False,
            "contextEquivalent": True,
            "evidenceComplete": True,
            "originalTrace": "trace:original",
            "counterfactualTrace": f"trace:{index}",
        }
        for index in range(4)
    ]
    _write(study_path, {"originalTrace": "trace:original", "trials": trials})
    assert main(["forensics", "attribute", str(study_path)]) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["assessments"][0]["state"] == "supported-under-declared-interventions"
    assert main(["forensics", "benchmark"]) == 0
    benchmark = json.loads(capfd.readouterr().out)
    assert benchmark["evaluatedCases"] == 5
    assert benchmark["decisionAccuracy"] == "1"


def test_evidence_adjudicate_and_disclose_cli(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    evidence_path = tmp_path / "evidence.json"
    _write(evidence_path, _evidence_specification())
    assert main(["evidence", str(evidence_path), "--format", "json"]) == 0
    assert json.loads(capfd.readouterr().out)["assuranceBoundary"]["selfGenerated"] is True
    assert main(["evidence", str(evidence_path), "--format", "sarif"]) == 0
    assert json.loads(capfd.readouterr().out)["version"] == "2.1.0"

    finding = _finding()
    claim_key = "\x1f".join((finding["targetId"], finding["ruleId"], finding["location"]))
    adjudication_path = tmp_path / "adjudication.json"
    _write(
        adjudication_path,
        {
            "findings": [finding],
            "targetOwnedOrAuthorized": True,
            "allowedActionFamilies": ["fixture.read"],
            "observations": [
                {
                    "claimKey": claim_key,
                    "state": "confirmed",
                    "traceReference": "trace:fixture",
                    "oracleMethod": "fixture/1",
                    "evidenceComplete": True,
                    "safeAndAuthorized": True,
                    "limitations": [],
                }
            ],
        },
    )
    assert main(["adjudicate", "plan", str(adjudication_path)]) == 0
    assert json.loads(capfd.readouterr().out)["executionMode"] == "inert-plan-only"
    assert main(["adjudicate", "evaluate", str(adjudication_path)]) == 0
    assert json.loads(capfd.readouterr().out)["claims"][0]["state"] == "confirmed-positive"

    disclose_path = tmp_path / "disclose.json"
    _write(
        disclose_path,
        {
            "evidence": _evidence_specification(),
            "request": {
                "targetKind": "synthetic",
                "vulnerabilityState": "patched",
                "containsWorkingPayload": False,
                "authorizationRedacted": True,
                "secretsScanClean": True,
                "humanReviewed": True,
                "limitationsPresent": True,
            },
            "contacts": [{"address": "security@example.invalid", "source": "fixture"}],
            "clock": {"embargoState": "reviewed"},
        },
    )
    assert main(["disclose", str(disclose_path)]) == 0
    package = json.loads(capfd.readouterr().out)
    assert package["externalMessageSent"] is False
    assert package["published"] is False


def test_compose_plan_and_offline_observation_evaluation_cli(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    graph = planted_composition_graph()
    graph_path = tmp_path / "graph.json"
    _write(graph_path, graph.to_mapping())
    assert main(["compose", "plan", str(graph_path), "--strategy", "trigger-aware-sequence"]) == 0
    plan = json.loads(capfd.readouterr().out)
    assert plan["executesActions"] is False

    engine = CompositionSearchEngine(
        graph, CompositionBudget(max_attempts=50, max_candidates=50, max_path_nodes=4)
    )
    oracle = PlantedCompositionEvaluator()
    observation_rows = []
    for candidate in engine.candidates(CompositionStrategy.TRIGGER_AWARE):
        observation = oracle(candidate).to_mapping()
        observation["candidateDigest"] = candidate.digest
        observation_rows.append(observation)
    study_path = tmp_path / "compose-study.json"
    _write(
        study_path,
        {
            "graph": graph.to_mapping(),
            "budget": {
                "maxAttempts": 50,
                "maxDurationMs": 30000,
                "maxT": 3,
                "maxPathNodes": 4,
                "maxCandidates": 50,
            },
            "observations": observation_rows,
        },
    )
    assert main(["compose", "evaluate", str(study_path)]) == 0
    report = json.loads(capfd.readouterr().out)
    assert report["successfulCandidate"] is not None
    assert report["compositionOnlyConfirmed"] is True


def test_topics_cli_rejects_truthy_strings_and_coerced_budgets(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    attribution = tmp_path / "bad-attribution.json"
    _write(
        attribution,
        {
            "originalTrace": "trace",
            "trials": [
                {
                    "trialId": "bad",
                    "layer": "base-model",
                    "changedLayers": ["base-model"],
                    "baselineOutcome": "true",
                    "interventionOutcome": False,
                    "contextEquivalent": True,
                    "evidenceComplete": True,
                }
            ],
        },
    )
    assert main(["forensics", "attribute", str(attribution)]) == 2
    assert "boolean or null" in capfd.readouterr().err

    composition = tmp_path / "bad-composition.json"
    _write(
        composition,
        {
            "graph": planted_composition_graph().to_mapping(),
            "budget": {"maxAttempts": "10"},
            "observations": [],
        },
    )
    assert main(["compose", "evaluate", str(composition)]) == 2
    assert "must be an integer" in capfd.readouterr().err


def test_disclose_cli_discovers_local_contact_and_defaults_clock(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "SECURITY.md").write_text(
        "Report privately to security@example.invalid.", encoding="utf-8"
    )
    study = tmp_path / "discovery-disclosure.json"
    _write(
        study,
        {
            "evidence": _evidence_specification(),
            "request": {
                "targetKind": "synthetic",
                "vulnerabilityState": "patched",
                "containsWorkingPayload": False,
                "authorizationRedacted": True,
                "secretsScanClean": True,
                "humanReviewed": True,
                "limitationsPresent": True,
            },
            "contactRoot": str(project),
            "reportedAt": "2026-08-03T00:00:00+00:00",
        },
    )
    assert main(["disclose", str(study)]) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["contacts"][0]["address"] == "security@example.invalid"
    assert output["clock"]["defaultPeriodDays"] == 90
