# SPDX-License-Identifier: Apache-2.0
"""Real subprocess acceptance for the bounded owned-software workflow."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.live import run_owned_software_vertical_slice
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader
from sova.workflows import build_case_workspace

if TYPE_CHECKING:
    from pathlib import Path

    from sova.safety import ActionIntent, ApprovalBatchChallenge


def _approve(
    challenge: ApprovalBatchChallenge,
    _intents: tuple[ActionIntent, ...],
) -> str:
    return str(challenge.exact_phrase)


def test_owned_software_runs_real_process_reproduces_and_builds_case(tmp_path: Path) -> None:
    unrelated = tmp_path / ".software-assessment.sova"
    unrelated.write_bytes(b"unrelated-user-file")
    artifacts = run_owned_software_vertical_slice(
        tmp_path / "software-assessment",
        approval_prompt=_approve,
    )
    assert artifacts.status == "pass"
    assert unrelated.read_bytes() == b"unrelated-user-file"
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["liveTargetExecuted"] is True
    assert report["originalWorkspaceMutated"] is False
    assert report["credentialStrippedCopies"] is True
    assert report["semanticOutcomeEquivalent"] is True
    assert report["containment"] == {
        "backend": "restricted-host-process",
        "executableDigest": report["executableDigest"],
        "filesystemIsolation": False,
        "networkIsolation": False,
        "originalWorkspaceMutationAllowed": False,
        "securitySandbox": False,
        "workspace": "credential-stripped-disposable-copy",
    }
    for trace in (artifacts.trace, artifacts.reproduction_trace):
        assert verify_artifact(trace, require_signature=True).state == VerificationState.VERIFIED
        outcome = next(TraceReader(trace).query(kind_prefix="tool.completed"))["payload"]["outcome"]
        assert outcome["output"]["workspaceDelta"]["complete"] is True
        assert outcome["output"]["workspaceDelta"]["created"][0]["path"] == "state.json"
        assert "unexpected-action" in outcome["output"]["stdout"]
    assert verify_artifact(artifacts.evidence_capsule).state == VerificationState.VERIFIED

    case = build_case_workspace(
        artifacts.trace,
        artifacts.evidence_capsule,
        tmp_path / "software-case",
        title="Owned local software behavior",
        component="SOVA inert software fixture",
        component_version="0.1.0",
    )
    case_index = json.loads(case.index.read_text(encoding="utf-8"))
    assert case_index["operations"]["targetExecuted"] is False
    assert case_index["source"]["traceDigest"] == sha256_digest(artifacts.trace.read_bytes())


def test_owned_software_refuses_wrong_human_phrase_and_cleans_output(tmp_path: Path) -> None:
    destination = tmp_path / "refused"
    with pytest.raises(FormatError, match="approval phrase"):
        run_owned_software_vertical_slice(
            destination,
            approval_prompt=_reject,
        )
    assert not destination.exists()


def _reject(
    _challenge: ApprovalBatchChallenge,
    _intents: tuple[ActionIntent, ...],
) -> str:
    return "not-the-phrase"
