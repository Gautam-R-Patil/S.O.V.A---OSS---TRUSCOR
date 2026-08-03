# SPDX-License-Identifier: Apache-2.0
"""CLI contracts for rehearsal, monitoring, registry, and contribution commands."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from sova.cli import main
from sova.formats import sha256_digest
from sova.registry import RegistryEntry, VerificationTier, build_registry

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _snapshot(identifier: str, effect: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "target": {"name": "fixture", "version": "1"},
        "model": {"name": "scripted", "version": "1"},
        "toolSchemas": {},
        "permissions": [],
        "dependencies": {},
        "environment": {},
        "registrySnapshot": {},
        "approvalSurface": {"required": True},
        "observedEffects": [effect],
        "reproductionRates": {"successful": 1, "eligible": 1},
        "findings": [],
        "methodology": {"oracle": "exact/1"},
        "captureProfile": "standard",
        "taxonomy": {"version": "0.1"},
    }


def test_rehearse_trace_diff_sentinel_and_ci_cli(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "input.txt").write_text("input", encoding="utf-8")
    workspace = tmp_path / "workspace"
    assert main(["rehearse", "prepare", str(source), str(workspace)]) == 0
    preparation = json.loads(capfd.readouterr().out)
    assert preparation["productionCredentialsImported"] is False

    specification = tmp_path / "rehearse.json"
    _write(
        specification,
        {
            "task": "write one safe file",
            "agentId": "fixture-agent",
            "authorizationConfirmed": True,
            "actions": [
                {
                    "id": "write-one",
                    "actorId": "fixture-agent",
                    "kind": "file.write",
                    "target": "output.txt",
                    "operation": "write",
                    "parameters": {"content": "safe output"},
                    "materialStep": False,
                }
            ],
        },
    )
    trace = tmp_path / "rehearsal.sova-trace"
    report_path = tmp_path / "report.json"
    assert (
        main(
            [
                "rehearse",
                "run",
                str(specification),
                str(workspace),
                str(trace),
                str(report_path),
            ]
        )
        == 0
    )
    report = json.loads(capfd.readouterr().out)
    export = tmp_path / "export"
    assert (
        main(
            [
                "rehearse",
                "export",
                str(report_path),
                str(workspace),
                str(export),
                "--approve",
                report["changes"][0]["id"],
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["productionPatched"] is False

    process_spec = tmp_path / "process.json"
    _write(
        process_spec,
        {
            "argv": [sys.executable, "-c", "print('safe')"],
            "workingDirectory": str(tmp_path),
            "authorizationConfirmed": True,
            "executableAllowlist": [sys.executable],
        },
    )
    assert main(["trace", "run", str(process_spec), str(tmp_path / "process.sova-trace")]) == 0
    assert json.loads(capfd.readouterr().out)["processStatus"] == "succeeded"

    baseline_spec = tmp_path / "baseline.json"
    current_spec = tmp_path / "current.json"
    baseline = tmp_path / "baseline.snapshot.json"
    current = tmp_path / "current.snapshot.json"
    _write(baseline_spec, _snapshot("baseline", "safe"))
    _write(current_spec, _snapshot("current", "changed"))
    assert main(["trace", "snapshot", str(baseline_spec), "--output", str(baseline)]) == 0
    capfd.readouterr()
    assert main(["trace", "snapshot", str(current_spec), "--output", str(current)]) == 0
    capfd.readouterr()
    assert main(["diff", str(baseline), str(current)]) == 1
    assert json.loads(capfd.readouterr().out)["behavioralDrift"] is True
    history = tmp_path / "history.jsonl"
    assert main(["sentinel", str(baseline), str(current), str(history)]) == 1
    assert json.loads(capfd.readouterr().out)["status"] == "failed"
    sarif = tmp_path / "results.sarif"
    assert main(["ci", str(baseline), str(current), "--sarif", str(sarif)]) == 1
    assert json.loads(capfd.readouterr().out)["uploadPerformed"] is False
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_registry_sync_contribution_and_errors_cli(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text('{"safe":true}', encoding="utf-8")
    digest = sha256_digest(artifact.read_bytes())
    entry = RegistryEntry(
        "fixture",
        "1",
        f"objects/sha256/{digest[7:]}",
        digest,
        artifact.stat().st_size,
        "fixture",
        "1",
        ("safe",),
        "public",
        {},
        {"source": "fixture"},
        "Apache-2.0",
        VerificationTier.VALIDATED,
    )
    registry = tmp_path / "registry"
    built = build_registry(
        registry,
        registry_version="0.1.0",
        taxonomy_version="0.1.0",
        taxonomy_bytes=b"fixture",
        artifacts=((artifact, entry),),
    )
    assert main(["registry", "verify", str(registry)]) == 0
    assert json.loads(capfd.readouterr().out)["identityTrusted"] is False
    assert (
        main(
            [
                "registry",
                "verify",
                str(registry),
                "--trusted-key-id",
                built["keyId"],
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["identityTrusted"] is True
    cache = tmp_path / "cache"
    assert main(["sync", str(registry), "--cache", str(cache)]) == 0
    assert json.loads(capfd.readouterr().out)["uploadPerformed"] is False

    contribution = tmp_path / "contribution.json"
    _write(
        contribution,
        {
            "items": [str(artifact)],
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
    )
    assert main(["contribute", str(contribution), str(tmp_path / "no-confirm")]) == 2
    assert "SOVA-CONTRIBUTE-CONFIRM" in capfd.readouterr().err
    assert main(["contribute", str(contribution), str(tmp_path / "staged"), "--confirm"]) == 0
    assert json.loads(capfd.readouterr().out)["submitted"] is False


def test_self_check_cli(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "component.txt"
    target.write_text("one", encoding="utf-8")
    manifest = tmp_path / "integrity.json"
    assert (
        main(
            [
                "self-check",
                "create",
                str(root),
                str(manifest),
                "--include",
                "component.txt",
            ]
        )
        == 0
    )
    capfd.readouterr()
    assert main(["self-check", "verify", str(root), str(manifest)]) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "passed"
    target.write_text("two", encoding="utf-8")
    assert main(["self-check", "verify", str(root), str(manifest)]) == 1
    assert json.loads(capfd.readouterr().out)["status"] == "failed"
