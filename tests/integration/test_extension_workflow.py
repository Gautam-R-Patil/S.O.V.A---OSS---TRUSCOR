# SPDX-License-Identifier: Apache-2.0
"""End-to-end operator workflow tests for digest-pinned subprocess extensions."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sova.extensions import (
    EXTENSION_API_VERSION,
    ExtensionKind,
    ExtensionLaunch,
    ExtensionManifest,
    PinnedArgumentFile,
    extension_launch_from_mapping,
    run_extension_workflow,
)
from sova.formats import sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import TraceReader

if TYPE_CHECKING:
    from sova.extensions import ExtensionApproval


def _manifest() -> ExtensionManifest:
    return ExtensionManifest(
        "example.operator-oracle",
        "1.0.0",
        EXTENSION_API_VERSION,
        ExtensionKind.ORACLE,
        ("oracle.fixture",),
        ("reads.request",),
    )


def _script(tmp_path: Path) -> Path:
    source = Path(__file__).parents[1] / "fixtures/external_extension.py"
    script = tmp_path / "extension.py"
    shutil.copyfile(source, script)
    return script


def _launch(
    manifest: ExtensionManifest,
    script: Path,
    working_directory: Path,
    *,
    operation: str = "conform",
    payload: dict[str, Any] | None = None,
) -> ExtensionLaunch:
    executable = Path(sys.executable).resolve()
    return ExtensionLaunch(
        manifest.digest,
        operation,
        (str(executable), str(script.resolve())),
        sha256_digest(executable.read_bytes()),
        (PinnedArgumentFile(1, sha256_digest(script.read_bytes())),),
        working_directory,
        10,
        payload or {},
    )


def _approve(challenge: ExtensionApproval) -> str:
    assert challenge.summary["extensionAuthorityInherited"] is False
    assert "not make it a security sandbox" in challenge.summary["warning"]
    return challenge.exact_phrase


def test_extension_conformance_workflow_emits_signed_evidence(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    launch = _launch(manifest, script, tmp_path)
    parsed = extension_launch_from_mapping(launch.to_mapping())
    assert parsed == launch

    artifacts = run_extension_workflow(
        manifest,
        parsed,
        tmp_path / "output",
        approval_prompt=_approve,
    )
    assert artifacts.status == "pass"
    assert artifacts.to_mapping()["trace"] == str(artifacts.trace)
    TraceReader(artifacts.trace).verify(require_signature=True)
    report = strict_json_loads(artifacts.report.read_bytes())
    assert [row["operation"] for row in report["results"]] == ["describe", "self-test"]
    assert report["claims"] == {
        "allExistingFileArgumentsPinned": True,
        "exactExecutableDigestVerified": True,
        "extensionAuthorityInherited": False,
        "humanApproval": True,
        "sanitizedEnvironment": True,
        "securitySandbox": False,
        "shellUsed": False,
    }


def test_extension_invoke_uses_reviewed_payload_without_authority_inheritance(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    artifacts = run_extension_workflow(
        manifest,
        _launch(
            manifest,
            script,
            tmp_path,
            operation="invoke",
            payload={"fixture": "safe"},
        ),
        tmp_path / "output",
        approval_prompt=_approve,
    )
    report = strict_json_loads(artifacts.report.read_bytes())
    assert report["results"][0]["operation"] == "invoke"
    assert report["results"][0]["response"]["accepted"] is True


def test_extension_exact_approval_precedes_process_and_output_creation(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)

    def deny(_challenge: ExtensionApproval) -> str:
        return "denied"

    destination = tmp_path / "output"
    with pytest.raises(FormatError, match="approval was not granted"):
        run_extension_workflow(
            manifest,
            _launch(manifest, script, tmp_path),
            destination,
            approval_prompt=deny,
        )
    assert not destination.exists()


def test_extension_argument_drift_after_approval_fails_before_process(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)

    def approve_then_modify(challenge: ExtensionApproval) -> str:
        script.write_text("raise SystemExit('must not run')\n", encoding="utf-8")
        return challenge.exact_phrase

    with pytest.raises(FormatError, match="argument file digest changed"):
        run_extension_workflow(
            manifest,
            _launch(manifest, script, tmp_path),
            tmp_path / "output",
            approval_prompt=approve_then_modify,
        )
    assert not (tmp_path / "output").exists()


def test_extension_payload_drift_after_approval_fails_before_process(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    launch = _launch(
        manifest,
        script,
        tmp_path,
        operation="invoke",
        payload={"fixture": "reviewed"},
    )

    def approve_then_modify(challenge: ExtensionApproval) -> str:
        launch.payload["fixture"] = "changed"
        return challenge.exact_phrase

    with pytest.raises(FormatError, match="launch scope changed"):
        run_extension_workflow(
            manifest,
            launch,
            tmp_path / "output",
            approval_prompt=approve_then_modify,
        )
    assert not (tmp_path / "output").exists()


def test_extension_response_secrets_are_redacted_before_evidence(tmp_path: Path) -> None:
    manifest = _manifest()
    script = tmp_path / "secret-response.py"
    script.write_text(
        "import json, sys\n"
        "r=json.loads(sys.stdin.buffer.readline())\n"
        "print(json.dumps({'protocol':'sova.extension-jsonl/0.1',"
        "'manifestDigest':r['manifestDigest'],'operation':r['operation'],"
        "'accepted':True,'note':'Bearer abcdefghijklmnopqrstuvwxyz'}))\n",
        encoding="utf-8",
    )
    artifacts = run_extension_workflow(
        manifest,
        _launch(manifest, script, tmp_path, operation="describe"),
        tmp_path / "output",
        approval_prompt=_approve,
    )
    raw_report = artifacts.report.read_text(encoding="utf-8")
    assert "abcdefghijklmnopqrstuvwxyz" not in raw_report
    report = strict_json_loads(raw_report.encode("utf-8"))
    assert report["results"][0]["captureTimeRedactions"] == 1
    assert "$redacted" in report["results"][0]["response"]["note"]
