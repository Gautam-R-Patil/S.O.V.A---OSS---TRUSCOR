# SPDX-License-Identifier: Apache-2.0
"""Safety, integrity, and interoperability contracts for Topics 18 through 20."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

import sova.rehearsal.environment as environment_module
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.monitoring import (
    build_behavior_snapshot,
    build_integrity_manifest,
    compare_behavior_snapshots,
    evaluate_ci,
    record_local_process,
    run_sentinel,
    verify_integrity_manifest,
)
from sova.registry import (
    RegistryEntry,
    VerificationTier,
    build_registry,
    import_benchmark_scenario,
    import_passive_trace,
    map_external_taxonomy,
    prepare_contribution,
    preview_contribution,
    sync_registry,
    verify_registry,
)
from sova.rehearsal import (
    FilesystemSubstituteBackend,
    RehearsalAction,
    RehearsalActionKind,
    RehearsalSpecification,
    ScriptedRehearsalAgent,
    export_approved_changes,
    prepare_rehearsal_environment,
    prepare_with_backend,
    run_agent_rehearsal,
    run_rehearsal,
    specification_from_mapping,
)
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.monkeypatch import MonkeyPatch


def _snapshot(identifier: str, **overrides: Any) -> Any:
    value: dict[str, Any] = {
        "id": identifier,
        "target": {"name": "fixture", "version": "1"},
        "model": {"name": "scripted", "version": "1"},
        "toolSchemas": {"digest": "one"},
        "permissions": ["fixture.read"],
        "dependencies": {"fixture": "1"},
        "environment": {"os": "fixture"},
        "registrySnapshot": {"digest": "registry-one"},
        "approvalSurface": {"required": True},
        "observedEffects": ["safe-output"],
        "reproductionRates": {"successful": 4, "eligible": 4},
        "findings": [],
        "methodology": {"oracle": "exact/1"},
        "captureProfile": "standard",
        "taxonomy": {"version": "0.1"},
        "traceReference": f"trace:{identifier}",
    }
    value.update(overrides)
    return build_behavior_snapshot(value)


def _registry_entry(
    path: Path,
    *,
    tier: VerificationTier = VerificationTier.VALIDATED,
) -> RegistryEntry:
    data = path.read_bytes()
    digest = sha256_digest(data)
    return RegistryEntry(
        "fixture-behavior",
        "0.1.0",
        f"objects/sha256/{digest[7:]}"
        if tier not in {VerificationTier.EMBARGOED, VerificationTier.WITHDRAWN}
        else None,
        (digest if tier not in {VerificationTier.EMBARGOED, VerificationTier.WITHDRAWN} else None),
        (len(data) if tier not in {VerificationTier.EMBARGOED, VerificationTier.WITHDRAWN} else 0),
        "fixture-agent",
        "1",
        ("safe-fixture",),
        "public",
        {"state": "not-run"},
        {"source": "unit-test"},
        "Apache-2.0",
        tier,
    )


def test_rehearsal_strips_credentials_and_never_mutates_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.txt").write_text(
        'token = "real-token-value"\nname = "safe"\n', encoding="utf-8"
    )
    (source / ".env").write_text("PASSWORD=never-copy", encoding="utf-8")
    (source / "binary.bin").write_bytes(b"\xff\x00")
    (source / "delete.txt").write_text("remove in rehearsal", encoding="utf-8")
    original = {path.name: path.read_bytes() for path in source.iterdir()}

    workspace = tmp_path / "workspace"
    preparation = prepare_rehearsal_environment(source, workspace)
    assert preparation.cloned_file_count == 2
    assert preparation.sanitized_file_count == 1
    assert "<SOVA-REDACTED:TOKEN>" in (workspace / "config.txt").read_text(encoding="utf-8")
    assert not (workspace / ".env").exists()
    assert not (workspace / "binary.bin").exists()
    substitute_contract = json.loads(
        (workspace / ".sova-rehearsal/substitutes.json").read_text(encoding="utf-8")
    )
    assert substitute_contract["serviceDescriptors"][0]["productionFallback"] is False

    specification = RehearsalSpecification(
        task="Make a safe local change and exercise inert services.",
        agent_id="fixture-agent",
        actions=(
            RehearsalAction(
                "write-one",
                "fixture-agent",
                RehearsalActionKind.FILE_WRITE,
                "result.txt",
                "write",
                {"content": "safe result\n"},
            ),
            RehearsalAction(
                "delete-one",
                "fixture-agent",
                RehearsalActionKind.FILE_DELETE,
                "delete.txt",
                "delete",
                {},
            ),
            RehearsalAction(
                "api-one",
                "fixture-agent",
                RehearsalActionKind.API,
                "fixture-api",
                "post",
                {"authorization": "sova-secret:fixture-token"},
            ),
            RehearsalAction(
                "browser-one",
                "fixture-agent",
                RehearsalActionKind.BROWSER,
                "fixture-page",
                "open <safe>",
                {},
                material_step=True,
            ),
        ),
        authorization_confirmed=True,
        with_attack=True,
        attack_profile="safe-planted-prompt",
    )
    trace = tmp_path / "rehearsal.sova-trace"
    report = run_rehearsal(specification, workspace, trace)
    verified = TraceReader(trace).verify()
    assert verified.signature_valid
    assert report.completed and report.with_attack
    assert report.capability_reach == ("api", "browser", "file.delete", "file.write")
    assert report.material_captures == (".sova-rehearsal/screenshots/browser-one.svg",)
    assert (workspace / ".sova-rehearsal/effects/api-one.json").is_file()
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "safe result\n"
    assert {path.name: path.read_bytes() for path in source.iterdir()} == original

    mapped = report.to_mapping()
    approved = frozenset(
        row["id"] for row in mapped["changes"] if row["kind"] in {"file.write", "file.delete"}
    )
    export = tmp_path / "export"
    result = export_approved_changes(mapped, workspace, export, approved)
    assert (export / "result.txt").read_text(encoding="utf-8") == "safe result\n"
    assert (export / "sova-deletions.json").is_file()
    assert result["productionPatched"] is False


def test_rehearsal_refuses_unsafe_input_and_review_drift(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.txt").write_text("safe", encoding="utf-8")
    with pytest.raises(FormatError, match="inside the source"):
        prepare_rehearsal_environment(source, source / "nested")
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FormatError, match="must not already exist"):
        prepare_rehearsal_environment(source, existing)
    with pytest.raises(FormatError, match="Credential fields"):
        RehearsalAction(
            "bad",
            "agent",
            RehearsalActionKind.API,
            "api",
            "call",
            {"password": "plaintext"},
        )
    with pytest.raises(FormatError, match="private-key"):
        RehearsalAction(
            "bad-key",
            "agent",
            RehearsalActionKind.API,
            "api",
            "call",
            {"value": "-----BEGIN " + "PRIVATE KEY-----"},
        )
    with pytest.raises(FormatError, match="credential-shaped material"):
        RehearsalAction(
            "bad-content",
            "agent",
            RehearsalActionKind.FILE_WRITE,
            "config.txt",
            "write",
            {"content": "token=plaintext-secret-value"},
        )
    with pytest.raises(FormatError, match="explicit attack profile"):
        RehearsalSpecification(
            "task",
            "agent",
            (),
            authorization_confirmed=True,
            with_attack=True,
        )

    workspace = tmp_path / "workspace"
    prepare_rehearsal_environment(source, workspace)
    action = RehearsalAction(
        "write",
        "agent",
        RehearsalActionKind.FILE_WRITE,
        "result.txt",
        "write",
        {"content": "reviewed"},
    )
    report = run_rehearsal(
        RehearsalSpecification(
            "task",
            "agent",
            (action,),
            authorization_confirmed=True,
        ),
        workspace,
        tmp_path / "trace.sova-trace",
    ).to_mapping()
    (workspace / "result.txt").write_text("changed after review", encoding="utf-8")
    with pytest.raises(FormatError, match="changed after review"):
        export_approved_changes(
            report,
            workspace,
            tmp_path / "export",
            frozenset({report["changes"][0]["id"]}),
        )
    with pytest.raises(FormatError, match="unknown change"):
        export_approved_changes(report, workspace, tmp_path / "other", frozenset({"unknown"}))


def test_rehearsal_backend_boundary_and_failure_trace(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.txt").write_text("safe", encoding="utf-8")
    workspace = tmp_path / "workspace"
    backend = FilesystemSubstituteBackend()
    preparation = prepare_with_backend(
        backend,
        source,
        workspace,
        substitutes=("api",),
    )
    assert preparation.substitutes == ("api",)
    assert "not-a-security-sandbox" in backend.isolation_claim

    trace = tmp_path / "failed.sova-trace"
    action = RehearsalAction(
        "escape",
        "agent",
        RehearsalActionKind.FILE_WRITE,
        "../escape.txt",
        "write",
        {"content": "safe"},
    )
    with pytest.raises(FormatError, match="normalized relative"):
        run_rehearsal(
            RehearsalSpecification(
                "failure fixture",
                "agent",
                (action,),
                authorization_confirmed=True,
            ),
            workspace,
            trace,
        )
    verification = TraceReader(trace).verify()
    assert verification.completion == "failed"
    assert any(event["kind"] == "error.recorded" for event in TraceReader(trace).events())
    browser = RehearsalAction(
        "browser",
        "agent",
        RehearsalActionKind.BROWSER,
        "page",
        "open",
        {},
    )
    with pytest.raises(FormatError, match="no prepared inert substitute"):
        run_rehearsal(
            RehearsalSpecification(
                "fixture",
                "agent",
                (browser,),
                authorization_confirmed=True,
            ),
            workspace,
            tmp_path / "missing-substitute.sova-trace",
        )


def test_scripted_user_agent_drives_rehearsal_without_credentials(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    workspace = tmp_path / "workspace"
    prepare_rehearsal_environment(source, workspace)
    driver = ScriptedRehearsalAgent(
        "user-agent",
        (
            RehearsalAction(
                "write",
                "user-agent",
                RehearsalActionKind.FILE_WRITE,
                "result.txt",
                "write",
                {"content": "agent result"},
            ),
        ),
    )
    report = run_agent_rehearsal(
        driver,
        "perform fixture task",
        workspace,
        tmp_path / "agent.sova-trace",
        authorization_confirmed=True,
    )
    assert report.agent_id == "user-agent"
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "agent result"
    with pytest.raises(FormatError, match="credential-free"):
        driver.propose("task", {"productionCredentialsImported": True})


def test_rehearsal_mapping_validation_and_limits(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    valid = {
        "task": "safe task",
        "agentId": "agent",
        "authorizationConfirmed": True,
        "actions": [],
        "substitutes": ["api", "api"],
    }
    assert specification_from_mapping(valid).substitutes == ("api",)
    with pytest.raises(FormatError, match="actions must"):
        specification_from_mapping({**valid, "actions": "bad"})
    with pytest.raises(FormatError, match="must belong"):
        specification_from_mapping(
            {
                **valid,
                "actions": [
                    {
                        "id": "x",
                        "actorId": "other",
                        "kind": "api",
                        "target": "x",
                        "operation": "get",
                    }
                ],
            }
        )
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.txt").write_text("one", encoding="utf-8")
    monkeypatch.setattr(environment_module, "_MAX_FILES", 0)
    with pytest.raises(FormatError, match="file limit"):
        prepare_rehearsal_environment(source, tmp_path / "workspace")


def test_behavior_drift_sentinel_and_ci_are_separated_and_local(tmp_path: Path) -> None:
    baseline = _snapshot("baseline")
    environment = _snapshot("environment", dependencies={"fixture": "2"})
    behavior = _snapshot("behavior", observedEffects=["different-output"])
    methodology = _snapshot("method", methodology={"oracle": "semantic/2"})
    assert compare_behavior_snapshots(baseline, environment).environment_drift
    assert not compare_behavior_snapshots(baseline, environment).behavioral_drift
    assert compare_behavior_snapshots(baseline, behavior).behavioral_drift
    method_diff = compare_behavior_snapshots(baseline, methodology)
    assert method_diff.methodology_drift and not method_diff.comparable

    history = tmp_path / "history.jsonl"
    sentinel = run_sentinel(
        baseline,
        behavior,
        policy={
            "maxEnvironmentChanges": 0,
            "maxBehaviorChanges": 0,
            "maxMethodologyChanges": 0,
        },
        history_path=history,
    )
    assert sentinel["status"] == "failed"
    assert sentinel["notification"]["silentUpload"] is False
    assert len(history.read_text(encoding="utf-8").splitlines()) == 1

    ci = evaluate_ci(
        compare_behavior_snapshots(baseline, behavior),
        {
            "maxEnvironmentChanges": 0,
            "maxBehaviorChanges": 0,
            "allowedFlakyReproductions": 0,
            "observedFlakyReproductions": 1,
        },
    )
    assert ci["exitCode"] == 1
    assert set(ci["reasons"]) == {"behavioral-drift-policy", "flakiness-policy"}
    assert ci["sarif"]["version"] == "2.1.0"
    assert ci["automaticPatching"] is False and ci["uploadPerformed"] is False


def test_snapshot_rejects_secrets_unknown_axes_and_bad_policy(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="credential-shaped"):
        build_behavior_snapshot({"id": "bad", "environment": {"api_key": "secret"}})
    with pytest.raises(FormatError, match="unsupported axes"):
        build_behavior_snapshot({"id": "bad", "unknownAxis": {}})
    with pytest.raises(FormatError, match="non-negative integer"):
        run_sentinel(
            _snapshot("a"),
            _snapshot("b"),
            policy={"maxEnvironmentChanges": -1},
            history_path=tmp_path / "history",
        )


def test_sova_self_check_detects_change_and_manifest_substitution(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "component.txt"
    target.write_text("version-one", encoding="utf-8")
    manifest = build_integrity_manifest(root, ("component.txt",))
    assert verify_integrity_manifest(root, manifest)["status"] == "passed"
    target.write_text("version-two", encoding="utf-8")
    report = verify_integrity_manifest(root, manifest)
    assert report["status"] == "failed"
    assert report["changes"][0]["state"] == "changed"
    tampered = dict(manifest)
    tampered["files"] = []
    with pytest.raises(FormatError, match="manifest is malformed"):
        verify_integrity_manifest(root, tampered)
    with pytest.raises(FormatError, match="normalized relative"):
        build_integrity_manifest(root, ("../escape",))


def test_allowlisted_process_is_signed_and_shell_free(tmp_path: Path) -> None:
    specification: dict[str, Any] = {
        "argv": [sys.executable, "-c", "print('safe fixture')"],
        "workingDirectory": str(tmp_path),
        "timeoutSeconds": 10,
        "captureProfile": "standard",
        "authorizationConfirmed": True,
        "executableAllowlist": [sys.executable],
        "observedEvents": [{"kind": "model.response", "payload": {"observable": "fixture"}}],
    }
    trace = tmp_path / "process.sova-trace"
    report = record_local_process(specification, trace)
    assert report["processStatus"] == "succeeded"
    assert report["trustPolicy"] == "included-key-integrity-only"
    assert report["recordingElapsedNs"] >= report["processElapsedNs"]
    assert report["instrumentationElapsedNs"] >= 0
    verified = TraceReader(trace).verify()
    assert verified.signature_valid
    assert any(row["kind"] == "model.response" for row in TraceReader(trace).events())

    with pytest.raises(FormatError, match="explicit authorization"):
        record_local_process({**specification, "authorizationConfirmed": False}, tmp_path / "no")
    with pytest.raises(FormatError, match="exact allowlist"):
        record_local_process(
            {**specification, "executableAllowlist": []},
            tmp_path / "disallowed.sova-trace",
        )


def test_registry_build_verify_tamper_and_atomic_offline_sync(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"safe":true}\n', encoding="utf-8")
    entry = _registry_entry(artifact)
    registry = tmp_path / "registry"
    report = build_registry(
        registry,
        registry_version="0.1.0",
        taxonomy_version="0.1.0",
        taxonomy_bytes=b"# SOVA taxonomy 0.1.0\n",
        artifacts=((artifact, entry),),
    )
    assert report["accepted"] and report["identityTrusted"] is False
    trusted = verify_registry(registry, trusted_key_ids=frozenset({report["keyId"]}))
    assert trusted["identityTrusted"] and trusted["trustPolicy"] == "explicit-trusted-key"

    cache = tmp_path / "cache"
    first = sync_registry((registry,), cache)
    second = sync_registry((registry,), cache)
    assert first["snapshotReused"] is False
    assert second["snapshotReused"] is True
    assert second["offlineCachedOperationAvailable"] is True

    object_path = registry / str(entry.object_path)
    object_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(FormatError, match="digest or size mismatch"):
        verify_registry(registry)
    with pytest.raises(FormatError, match="no supplied local mirror"):
        sync_registry((registry,), tmp_path / "bad-cache")


def test_registry_lifecycle_and_index_rejections(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    embargoed = _registry_entry(artifact, tier=VerificationTier.EMBARGOED)
    registry = tmp_path / "registry"
    report = build_registry(
        registry,
        registry_version="0.1.0",
        taxonomy_version="0.1.0",
        taxonomy_bytes=b"fixture",
        artifacts=((artifact, embargoed),),
    )
    assert report["verifiedObjectCount"] == 0
    assert not (registry / "objects/sha256" / sha256_digest(artifact.read_bytes())[7:]).exists()
    with pytest.raises(FormatError, match="unsafe"):
        build_registry(
            tmp_path / "bad-registry",
            registry_version="../unsafe",
            taxonomy_version="0.1.0",
            taxonomy_bytes=b"fixture",
            artifacts=(),
        )
    with pytest.raises(FormatError, match="cannot expose"):
        RegistryEntry(
            "bad",
            "1",
            "objects/sha256/" + "a" * 64,
            "sha256:" + "a" * 64,
            1,
            "component",
            "1",
            (),
            "embargoed",
            {},
            {},
            "Apache-2.0",
            VerificationTier.EMBARGOED,
        )


def test_contribution_requires_review_confirmation_and_clean_items(tmp_path: Path) -> None:
    item = tmp_path / "finding.json"
    item.write_text('{"finding":"safe fixture"}', encoding="utf-8")
    specification: dict[str, Any] = {
        "items": [str(item)],
        "contributor": {"name": "Fixture", "identity": "fixture@example.invalid"},
        "license": "CC-BY-4.0",
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": False,
        },
    }
    preview = preview_contribution(specification)
    assert preview["acceptedForLocalStaging"] is True
    assert preview["privateCorpusReuse"] is False and preview["uploadPerformed"] is False
    with pytest.raises(FormatError, match="explicit per-item confirmation"):
        prepare_contribution(specification, tmp_path / "unconfirmed", confirmed=False)
    staged = prepare_contribution(specification, tmp_path / "staged", confirmed=True)
    assert staged["submitted"] is False and staged["pullRequestCreated"] is False

    secret = tmp_path / "secret.json"
    secret.write_text('{"api_key":"this-is-a-real-looking-secret"}', encoding="utf-8")
    with pytest.raises(FormatError, match="credential-shaped"):
        preview_contribution({**specification, "items": [str(secret)]})
    executable = tmp_path / "binary.json"
    executable.write_bytes(b"MZ" + b"0" * 20)
    with pytest.raises(FormatError, match="executable payload"):
        preview_contribution({**specification, "items": [str(executable)]})
    with pytest.raises(FormatError, match="gates did not pass"):
        prepare_contribution(
            {
                **specification,
                "gates": {**specification["gates"], "humanReviewed": False},
            },
            tmp_path / "failed",
            confirmed=True,
        )


def test_external_adapters_preserve_provenance_without_upgrading_evidence() -> None:
    passive = import_passive_trace(
        [{"kind": "tool.completed", "payload": {"status": "ok"}}],
        source_format="fixture-jsonl",
        source_uri="fixture://trace",
        integrity_state="unsigned",
    )
    assert passive["provenancePreserved"] is True and passive["evidenceUpgraded"] is False
    benchmark = import_benchmark_scenario(
        {"prompt": "safe fixture"},
        source_name="fixture",
        source_version="1",
        source_uri="fixture://scenario",
        license_expression="CC-BY-4.0",
    )
    assert benchmark["executorMechanicsIncluded"] is False
    taxonomy = map_external_taxonomy(
        ["known", "unknown"], {"known": "sova:safe"}, mapping_version="1"
    )
    assert taxonomy["results"][1]["state"] == "unmapped"
    with pytest.raises(FormatError, match="provenance"):
        import_passive_trace([], source_format="", source_uri="", integrity_state="")
    with pytest.raises(FormatError, match="benchmark provenance"):
        import_benchmark_scenario(
            {}, source_name="", source_version="", source_uri="", license_expression=""
        )


def test_registry_index_signature_substitution_is_detected(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    registry = tmp_path / "registry"
    build_registry(
        registry,
        registry_version="0.1.0",
        taxonomy_version="0.1.0",
        taxonomy_bytes=b"fixture",
        artifacts=((artifact, _registry_entry(artifact)),),
    )
    index_path = registry / "index.json"
    document = json.loads(index_path.read_text(encoding="utf-8"))
    document["index"]["registryVersion"] = "0.1.1"
    index_path.write_bytes(canonical_json_bytes(document) + b"\n")
    with pytest.raises(FormatError, match="signed payload and index differ"):
        verify_registry(registry)
