# SPDX-License-Identifier: Apache-2.0
"""Hostile and malformed-input coverage for Topics 18 through 20."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

import sova.monitoring.integrity as integrity_module
import sova.registry.contribution as contribution_module
import sova.registry.sync as sync_module
import sova.rehearsal.environment as environment_module
import sova.rehearsal.model as rehearsal_model
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
    RegistryIndex,
    VerificationTier,
    build_registry,
    import_passive_trace,
    map_external_taxonomy,
    prepare_contribution,
    preview_contribution,
    sync_registry,
    verify_registry,
)
from sova.registry.model import entry_from_mapping
from sova.rehearsal import (
    FilesystemSubstituteBackend,
    RehearsalAction,
    RehearsalActionKind,
    RehearsalSpecification,
    export_approved_changes,
    prepare_rehearsal_environment,
    prepare_with_backend,
    run_rehearsal,
    specification_from_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from _pytest.monkeypatch import MonkeyPatch


def _snapshot(identifier: str, **values: Any) -> Any:
    return build_behavior_snapshot({"id": identifier, **values})


def _entry(path: Path) -> RegistryEntry:
    data = path.read_bytes()
    digest = sha256_digest(data)
    return RegistryEntry(
        "fixture",
        "1",
        f"objects/sha256/{digest[7:]}",
        digest,
        len(data),
        "component",
        "1",
        (),
        "public",
        {},
        {},
        "Apache-2.0",
        VerificationTier.SUBMITTED,
    )


def _contribution(path: Path) -> dict[str, Any]:
    return {
        "items": [str(path)],
        "contributor": {"name": "Fixture", "identity": "fixture@example.invalid"},
        "license": "Apache-2.0",
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": False,
        },
    }


def test_snapshot_structural_edges_and_all_sentinel_triggers(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="keys must be strings"):
        build_behavior_snapshot({"id": "bad", "environment": {1: "bad"}})
    with pytest.raises(FormatError, match="snapshot id"):
        build_behavior_snapshot({})
    with pytest.raises(FormatError, match=r"traceReference"):
        build_behavior_snapshot({"id": "bad", "traceReference": 1})

    baseline = _snapshot(
        "left",
        environment={"v": 1},
        methodology={"v": 1},
        approvalSurface={"v": 1},
    )
    current = _snapshot(
        "right",
        environment={"v": 2},
        methodology={"v": 2},
        approvalSurface={"v": 2},
    )
    report = run_sentinel(
        baseline,
        current,
        policy={
            "maxEnvironmentChanges": 0,
            "maxBehaviorChanges": 0,
            "maxMethodologyChanges": 0,
        },
        history_path=tmp_path / "nested/history.jsonl",
    )
    assert set(report["triggers"]) == {
        "environment-drift-threshold",
        "methodology-drift-threshold",
        "approval-surface-changed",
    }
    passed = run_sentinel(
        baseline,
        baseline,
        policy={},
        history_path=tmp_path / "nested/history.jsonl",
    )
    assert passed["status"] == "passed"
    ci = evaluate_ci(compare_behavior_snapshots(baseline, current), {})
    assert set(ci["reasons"]) == {"environment-drift-policy", "methodology-not-comparable"}


def test_integrity_manifest_input_and_missing_file_edges(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "one.txt"
    target.write_text("one", encoding="utf-8")
    with pytest.raises(FormatError, match="at least one"):
        build_integrity_manifest(root, ())
    with pytest.raises(FormatError, match="duplicates"):
        build_integrity_manifest(root, ("one.txt", "one.txt"))
    with pytest.raises(FormatError, match="missing or unsafe"):
        build_integrity_manifest(root, ("missing.txt",))
    with pytest.raises(FormatError, match="normalized relative"):
        build_integrity_manifest(root, ("bad\\path",))
    monkeypatch.setattr(integrity_module, "_MAX_TOTAL_BYTES", 0)
    with pytest.raises(FormatError, match="byte limit"):
        build_integrity_manifest(root, ("one.txt",))
    monkeypatch.setattr(integrity_module, "_MAX_TOTAL_BYTES", 100)
    manifest = build_integrity_manifest(root, ("one.txt",))
    target.unlink()
    assert verify_integrity_manifest(root, manifest)["changes"][0]["state"] == "missing"
    malformed = dict(manifest)
    malformed["files"] = ["bad"]
    unsigned = dict(malformed)
    unsigned.pop("manifestDigest")
    malformed["manifestDigest"] = sha256_digest(canonical_json_bytes(unsigned))
    with pytest.raises(FormatError, match="file entries"):
        verify_integrity_manifest(root, malformed)
    malformed["files"] = [{"path": "one.txt", "size": True, "digest": "bad"}]
    unsigned = dict(malformed)
    unsigned.pop("manifestDigest")
    malformed["manifestDigest"] = sha256_digest(canonical_json_bytes(unsigned))
    with pytest.raises(FormatError, match="file entry is malformed"):
        verify_integrity_manifest(root, malformed)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ({"argv": []}, "argv"),
        ({"workingDirectory": ""}, "workingDirectory"),
        ({"timeoutSeconds": True}, "numeric"),
        ({"timeoutSeconds": 0}, "outside"),
        ({"captureProfile": "unknown"}, "unsupported"),
        ({"executableAllowlist": "bad"}, "must contain paths"),
        ({"observedEvents": "bad"}, "observedEvents"),
    ],
)
def test_process_recorder_rejects_malformed_contract(
    tmp_path: Path,
    replacement: dict[str, Any],
    message: str,
) -> None:
    specification: dict[str, Any] = {
        "argv": [sys.executable, "-c", "print('safe')"],
        "workingDirectory": str(tmp_path),
        "authorizationConfirmed": True,
        "executableAllowlist": [sys.executable],
    }
    specification.update(replacement)
    with pytest.raises(FormatError, match=message):
        record_local_process(specification, tmp_path / "bad.sova-trace")


def test_process_recorder_timeout_missing_cwd_and_bad_observed_event(tmp_path: Path) -> None:
    base: dict[str, Any] = {
        "argv": [sys.executable, "-c", "import time; time.sleep(1)"],
        "workingDirectory": str(tmp_path),
        "authorizationConfirmed": True,
        "executableAllowlist": [sys.executable],
        "timeoutSeconds": 0.05,
    }
    report = record_local_process(base, tmp_path / "timeout.sova-trace")
    assert report["processStatus"] == "timeout"
    with pytest.raises(FormatError, match="must exist"):
        record_local_process(
            {**base, "workingDirectory": str(tmp_path / "missing")},
            tmp_path / "missing.sova-trace",
        )
    with pytest.raises(FormatError, match="requires kind"):
        record_local_process(
            {**base, "observedEvents": [{"kind": 1}]},
            tmp_path / "event.sova-trace",
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(items=[]), "items"),
        (lambda value: value.update(contributor="bad"), "contributor"),
        (lambda value: value["contributor"].update(name=1), "name and identity"),
        (lambda value: value.update(gates="bad"), "gates"),
        (lambda value: value["gates"].update(humanReviewed="yes"), "must be boolean"),
    ],
)
def test_contribution_metadata_edges(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    item = tmp_path / "item.json"
    item.write_text("{}", encoding="utf-8")
    specification = _contribution(item)
    mutate(specification)
    with pytest.raises(FormatError, match=message):
        preview_contribution(specification)


def test_contribution_type_size_and_destination_edges(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    unsupported = tmp_path / "item.exe"
    unsupported.write_bytes(b"safe")
    with pytest.raises(FormatError, match="type is not allowed"):
        preview_contribution(_contribution(unsupported))
    item = tmp_path / "item.json"
    item.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(contribution_module, "_MAX_ITEM_BYTES", 0)
    with pytest.raises(FormatError, match="size limit"):
        preview_contribution(_contribution(item))
    monkeypatch.setattr(contribution_module, "_MAX_ITEM_BYTES", 1024)
    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(FormatError, match="must not exist"):
        prepare_contribution(_contribution(item), destination, confirmed=True)


def test_external_adapter_and_taxonomy_edges() -> None:
    with pytest.raises(FormatError, match="requires a kind"):
        import_passive_trace([{}], source_format="fixture", source_uri="x", integrity_state="x")
    with pytest.raises(FormatError, match="mapping version"):
        map_external_taxonomy([], {}, mapping_version="")


def test_registry_model_and_entry_mapping_edges() -> None:
    digest = "sha256:" + "a" * 64
    with pytest.raises(FormatError, match="identity fields"):
        RegistryEntry(
            "",
            "1",
            f"objects/sha256/{digest[7:]}",
            digest,
            1,
            "component",
            "1",
            (),
            "public",
            {},
            {},
            "Apache-2.0",
            VerificationTier.SUBMITTED,
        )
    with pytest.raises(FormatError, match="cannot be negative"):
        RegistryEntry(
            "id",
            "1",
            f"objects/sha256/{digest[7:]}",
            digest,
            -1,
            "component",
            "1",
            (),
            "public",
            {},
            {},
            "Apache-2.0",
            VerificationTier.SUBMITTED,
        )
    with pytest.raises(FormatError, match="derived"):
        RegistryEntry(
            "id",
            "1",
            "wrong",
            digest,
            1,
            "component",
            "1",
            (),
            "public",
            {},
            {},
            "Apache-2.0",
            VerificationTier.SUBMITTED,
        )
    with pytest.raises(FormatError, match="taxonomy digest"):
        RegistryIndex("1", "1", "bad", ())
    with pytest.raises(FormatError, match="taxonomy version"):
        RegistryIndex("1", "../bad", digest, ())
    valid = {
        "id": "id",
        "version": "1",
        "objectPath": f"objects/sha256/{digest[7:]}",
        "digest": digest,
        "size": 1,
        "component": {"name": "component", "version": "1"},
        "taxonomy": [],
        "disclosureState": "public",
        "reproduction": {},
        "provenance": {},
        "license": "Apache-2.0",
        "verificationTier": "submitted",
        "supersedes": None,
    }
    assert entry_from_mapping(valid).entry_id == "id"
    for field, replacement in (
        ("component", "bad"),
        ("taxonomy", "bad"),
        ("size", True),
        ("verificationTier", "bad"),
        ("objectPath", 1),
        ("digest", 1),
        ("supersedes", 1),
    ):
        malformed = dict(valid)
        malformed[field] = replacement
        with pytest.raises(FormatError):
            entry_from_mapping(malformed)
    malformed = dict(valid)
    malformed["reproduction"] = "bad"
    with pytest.raises(FormatError, match="reproduction and provenance"):
        entry_from_mapping(malformed)
    malformed = dict(valid)
    malformed["id"] = ""
    with pytest.raises(FormatError, match="non-empty string"):
        entry_from_mapping(malformed)
    entry = entry_from_mapping(valid)
    with pytest.raises(FormatError, match="pairs must be unique"):
        RegistryIndex("1", "1", digest, (entry, entry))


def test_registry_build_and_signature_failure_edges(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    registry = tmp_path / "registry"
    build_registry(
        registry,
        registry_version="1",
        taxonomy_version="1",
        taxonomy_bytes=b"taxonomy",
        artifacts=((artifact, _entry(artifact)),),
    )
    with pytest.raises(FormatError, match="must not exist"):
        build_registry(
            registry,
            registry_version="1",
            taxonomy_version="1",
            taxonomy_bytes=b"taxonomy",
            artifacts=(),
        )
    index_path = registry / "index.json"
    original = json.loads(index_path.read_text(encoding="utf-8"))
    malformed = dict(original)
    malformed["publicKey"] = dict(original["publicKey"])
    malformed["publicKey"]["raw"] = "%%%"
    index_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
    with pytest.raises(FormatError, match="invalid base64"):
        verify_registry(registry)
    malformed = json.loads(canonical_json_bytes(original))
    malformed["envelope"]["payload"] = 1
    index_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
    with pytest.raises(FormatError, match="must be a string"):
        verify_registry(registry)
    malformed = {"artifactType": "bad"}
    index_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
    with pytest.raises(FormatError, match="signed index is malformed"):
        verify_registry(registry)
    index_path.write_bytes(b"[]\n")
    with pytest.raises(FormatError, match="must be an object"):
        verify_registry(registry)
    malformed = json.loads(canonical_json_bytes(original))
    malformed["envelope"]["signatures"][0]["sig"] = "AAAA"
    index_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
    with pytest.raises(FormatError, match="verification failed"):
        verify_registry(registry)
    index_path.write_bytes(canonical_json_bytes(original) + b"\n")
    (registry / "taxonomy/1.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(FormatError, match="taxonomy snapshot"):
        verify_registry(registry)


def test_registry_digest_and_sync_limit_edges(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    bad = _entry(artifact)
    bad_source = tmp_path / "changed.json"
    bad_source.write_text("changed", encoding="utf-8")
    with pytest.raises(FormatError, match="does not match"):
        build_registry(
            tmp_path / "bad-registry",
            registry_version="1",
            taxonomy_version="1",
            taxonomy_bytes=b"taxonomy",
            artifacts=((bad_source, bad),),
        )
    registry = tmp_path / "registry"
    build_registry(
        registry,
        registry_version="1",
        taxonomy_version="1",
        taxonomy_bytes=b"taxonomy",
        artifacts=((artifact, _entry(artifact)),),
    )
    monkeypatch.setattr(sync_module, "_MAX_FILES", 0)
    with pytest.raises(FormatError, match="file-count"):
        sync_registry((registry,), tmp_path / "cache")
    with pytest.raises(FormatError, match="at least one"):
        sync_registry((), tmp_path / "empty")


def test_rehearsal_environment_and_backend_edges(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    with pytest.raises(FormatError, match="existing directory"):
        prepare_rehearsal_environment(tmp_path / "missing", tmp_path / "workspace")
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.txt").write_text("1234", encoding="utf-8")
    monkeypatch.setattr(environment_module, "_MAX_FILE_BYTES", 0)
    report = prepare_rehearsal_environment(source, tmp_path / "size-workspace")
    assert report.omitted[0]["reason"] == "file-size-limit"

    with pytest.raises(FormatError, match="must declare"):
        prepare_with_backend(
            FilesystemSubstituteBackend(name=""),
            source,
            tmp_path / "other-workspace",
            substitutes=(),
        )


def test_rehearsal_mapping_and_export_edges(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    base: dict[str, Any] = {
        "task": "task",
        "agentId": "agent",
        "authorizationConfirmed": True,
        "actions": [],
    }
    mutations = (
        {"actions": ["bad"]},
        {
            "actions": [
                {"id": "a", "actorId": "agent", "kind": "bad", "target": "x", "operation": "x"}
            ]
        },
        {
            "actions": [
                {
                    "id": "a",
                    "actorId": "agent",
                    "kind": "api",
                    "target": "x",
                    "operation": "x",
                    "parameters": "bad",
                }
            ]
        },
        {
            "actions": [
                {
                    "id": "a",
                    "actorId": "agent",
                    "kind": "api",
                    "target": "x",
                    "operation": "x",
                    "materialStep": "yes",
                }
            ]
        },
        {"authorizationConfirmed": "yes"},
        {"substitutes": "bad"},
        {"attackProfile": 1},
    )
    for mutation in mutations:
        with pytest.raises(FormatError):
            specification_from_mapping({**base, **mutation})
    with pytest.raises(FormatError, match="keys must be strings"):
        RehearsalAction(
            "one",
            "agent",
            RehearsalActionKind.API,
            "api",
            "get",
            {1: "bad"},  # type: ignore[dict-item]
        )
    with pytest.raises(FormatError, match="action id"):
        RehearsalAction("bad/id", "agent", RehearsalActionKind.API, "api", "get", {})
    with pytest.raises(FormatError, match="actor id"):
        RehearsalAction("one", "bad/id", RehearsalActionKind.API, "api", "get", {})
    with pytest.raises(FormatError, match="target and operation"):
        RehearsalAction("one", "agent", RehearsalActionKind.API, "", "get", {})
    monkeypatch.setattr(rehearsal_model, "_MAX_ACTIONS", 0)
    with pytest.raises(FormatError, match="action limit"):
        RehearsalSpecification(
            "task",
            "agent",
            (RehearsalAction("one", "agent", RehearsalActionKind.API, "api", "get", {}),),
            authorization_confirmed=True,
        )
    monkeypatch.setattr(rehearsal_model, "_MAX_ACTIONS", 4096)
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.txt").write_text("safe", encoding="utf-8")
    workspace = tmp_path / "workspace"
    prepare_rehearsal_environment(source, workspace)
    (workspace / "directory").mkdir()
    with pytest.raises(FormatError, match="explicit human"):
        run_rehearsal(
            RehearsalSpecification("task", "agent", (), authorization_confirmed=False),
            workspace,
            tmp_path / "unauthorized.sova-trace",
        )
    report = run_rehearsal(
        RehearsalSpecification(
            "task",
            "agent",
            (RehearsalAction("api", "agent", RehearsalActionKind.API, "api", "get", {}),),
            authorization_confirmed=True,
        ),
        workspace,
        tmp_path / "trace.sova-trace",
    ).to_mapping()
    with pytest.raises(FormatError, match="only reviewed file changes"):
        export_approved_changes(
            report,
            workspace,
            tmp_path / "export",
            frozenset({report["changes"][0]["id"]}),
        )
    with pytest.raises(FormatError, match="changes must be an array"):
        export_approved_changes({}, workspace, tmp_path / "missing", frozenset())
    with pytest.raises(FormatError, match="new directory"):
        export_approved_changes(report, workspace, workspace, frozenset())
    with pytest.raises(FormatError, match="change entries"):
        export_approved_changes({"changes": ["bad"]}, workspace, tmp_path / "bad-row", frozenset())


def test_rehearsal_runner_path_content_and_missing_export_edges(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "directory").mkdir()
    workspace = tmp_path / "workspace"
    prepare_rehearsal_environment(source, workspace)
    (workspace / "directory").mkdir()
    for target in ("/absolute", ".sova-rehearsal/control"):
        action = RehearsalAction(
            "bad", "agent", RehearsalActionKind.FILE_WRITE, target, "write", {"content": "x"}
        )
        with pytest.raises(FormatError):
            run_rehearsal(
                RehearsalSpecification("task", "agent", (action,), authorization_confirmed=True),
                workspace,
                tmp_path / f"{sha256_digest(target.encode())[7:15]}.sova-trace",
            )
    missing_content = RehearsalAction(
        "missing-content", "agent", RehearsalActionKind.FILE_WRITE, "x", "write", {}
    )
    with pytest.raises(FormatError, match="requires string content"):
        run_rehearsal(
            RehearsalSpecification(
                "task", "agent", (missing_content,), authorization_confirmed=True
            ),
            workspace,
            tmp_path / "content.sova-trace",
        )
    delete_directory = RehearsalAction(
        "delete-dir", "agent", RehearsalActionKind.FILE_DELETE, "directory", "delete", {}
    )
    with pytest.raises(FormatError, match="ordinary files"):
        run_rehearsal(
            RehearsalSpecification(
                "task", "agent", (delete_directory,), authorization_confirmed=True
            ),
            workspace,
            tmp_path / "delete.sova-trace",
        )
    with pytest.raises(FormatError, match="not prepared"):
        run_rehearsal(
            RehearsalSpecification("task", "agent", (), authorization_confirmed=True),
            tmp_path / "unprepared",
            tmp_path / "unprepared.sova-trace",
        )
    report = {
        "changes": [
            {
                "id": "missing",
                "kind": "file.write",
                "target": "missing.txt",
                "afterDigest": "sha256:" + "a" * 64,
            }
        ]
    }
    with pytest.raises(FormatError, match="missing or unsafe"):
        export_approved_changes(
            report, workspace, tmp_path / "missing-export", frozenset({"missing"})
        )
