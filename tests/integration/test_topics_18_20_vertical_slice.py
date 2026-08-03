# SPDX-License-Identifier: Apache-2.0
"""End-to-end proof for safe rehearsal, regression gating, and offline sharing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.monitoring import build_behavior_snapshot, compare_behavior_snapshots, evaluate_ci
from sova.registry import (
    RegistryEntry,
    VerificationTier,
    build_registry,
    prepare_contribution,
    sync_registry,
    verify_registry,
)
from sova.rehearsal import (
    RehearsalAction,
    RehearsalActionKind,
    RehearsalSpecification,
    export_approved_changes,
    prepare_rehearsal_environment,
    run_rehearsal,
)
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path


def test_rehearsal_to_signed_capsule_to_ci_to_offline_registry(tmp_path: Path) -> None:
    production_fixture = tmp_path / "owned-fixture"
    production_fixture.mkdir()
    (production_fixture / "app.txt").write_text("version one\n", encoding="utf-8")
    (production_fixture / ".env").write_text("TOKEN=fixture-only-secret", encoding="utf-8")
    production_digest = sha256_digest((production_fixture / "app.txt").read_bytes())

    workspace = tmp_path / "rehearsal"
    preparation = prepare_rehearsal_environment(production_fixture, workspace)
    trace_path = tmp_path / "task.sova-trace"
    report = run_rehearsal(
        RehearsalSpecification(
            task="Update a fixture and emit an inert API call.",
            agent_id="scripted-agent",
            actions=(
                RehearsalAction(
                    "write-app",
                    "scripted-agent",
                    RehearsalActionKind.FILE_WRITE,
                    "app.txt",
                    "replace",
                    {"content": "version two\n"},
                    material_step=True,
                ),
                RehearsalAction(
                    "call-api",
                    "scripted-agent",
                    RehearsalActionKind.API,
                    "fixture-api",
                    "post",
                    {"body": {"value": "safe"}},
                ),
            ),
            authorization_confirmed=True,
            with_attack=True,
            attack_profile="synthetic-boundary-probe",
        ),
        workspace,
        trace_path,
    )
    assert TraceReader(trace_path).verify().signature_valid
    assert sha256_digest((production_fixture / "app.txt").read_bytes()) == production_digest
    assert not (workspace / ".env").exists()
    assert preparation.omitted[0]["reason"] == "credential-shaped-file-omitted"

    report_document = report.to_mapping()
    approved = next(row["id"] for row in report_document["changes"] if row["kind"] == "file.write")
    staged_patch = tmp_path / "reviewed-export"
    export_approved_changes(report_document, workspace, staged_patch, frozenset({approved}))
    assert (staged_patch / "app.txt").read_text(encoding="utf-8") == "version two\n"
    assert (production_fixture / "app.txt").read_text(encoding="utf-8") == "version one\n"

    manifest = capsule_manifest_template(
        title="Safe rehearsal behavior",
        summary="A deterministic substitute-only integration fixture.",
        author="SOVA OSS test fixture",
    )
    scenario = scenario_template(
        title="Rehearse one local write and one substituted API call",
        purpose="Verify selective promotion and offline evidence sharing.",
    )
    scenario["extensions"]["x-sova-rehearsal"] = {
        "sourceFingerprint": preparation.source_fingerprint,
        "productionEffects": False,
        "approvedChangeIds": [approved],
    }
    capsule = tmp_path / "rehearsal.sova"
    build_capsule(
        capsule,
        manifest,
        scenario=scenario,
        attachments={"rehearsal-report.json": canonical_json_bytes(report_document)},
        traces=[trace_path],
    )
    PackageReader(capsule).verify("sova.capsule")

    baseline = build_behavior_snapshot(
        {
            "id": "baseline",
            "target": {"capsule": sha256_digest(capsule.read_bytes())},
            "environment": {"source": preparation.source_fingerprint},
            "observedEffects": ["file-write", "substitute-api"],
            "methodology": {"rehearsal": "0.1.0"},
        }
    )
    regression = build_behavior_snapshot(
        {
            "id": "regression",
            "target": {"capsule": sha256_digest(capsule.read_bytes())},
            "environment": {"source": preparation.source_fingerprint},
            "observedEffects": ["unexpected-production-effect"],
            "methodology": {"rehearsal": "0.1.0"},
        }
    )
    ci = evaluate_ci(
        compare_behavior_snapshots(baseline, regression),
        {
            "maxBehaviorChanges": 0,
            "maxEnvironmentChanges": 0,
            "allowedFlakyReproductions": 0,
            "observedFlakyReproductions": 0,
        },
    )
    assert ci["status"] == "failed" and ci["exitCode"] == 1

    digest = sha256_digest(capsule.read_bytes())
    registry_entry = RegistryEntry(
        "safe-rehearsal",
        "0.1.0",
        f"objects/sha256/{digest[7:]}",
        digest,
        capsule.stat().st_size,
        "sova-fixture",
        "0.1.0",
        ("rehearsal", "safe-fixture"),
        "public",
        {"state": "ci-reproduced", "trace": trace_path.name},
        {"source": "integration-fixture"},
        "Apache-2.0",
        VerificationTier.CI_REPRODUCED,
    )
    registry = tmp_path / "registry"
    build_registry(
        registry,
        registry_version="0.1.0",
        taxonomy_version="0.1.0",
        taxonomy_bytes=b"# Safe fixture taxonomy\n",
        artifacts=((capsule, registry_entry),),
    )
    assert verify_registry(registry)["verifiedObjectCount"] == 1
    cache = tmp_path / "offline-cache"
    sync = sync_registry((registry,), cache)
    assert sync["offlineCachedOperationAvailable"] is True

    contribution = prepare_contribution(
        {
            "items": [str(capsule)],
            "contributor": {"name": "Fixture", "identity": "fixture@example.invalid"},
            "license": "Apache-2.0",
            "gates": {
                "humanReviewed": True,
                "publicDisclosureAllowed": True,
                "authorizationRedacted": True,
                "provenanceComplete": True,
                "separateCorpusReuseConsent": False,
            },
        },
        tmp_path / "contribution",
        confirmed=True,
    )
    assert contribution["submitted"] is False
    assert contribution["privateCorpusReuse"] is False
