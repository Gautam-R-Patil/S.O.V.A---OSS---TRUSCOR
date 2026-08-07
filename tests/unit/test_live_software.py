# SPDX-License-Identifier: Apache-2.0
"""Security and failure-path tests for bounded local-software execution."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.live import software
from sova.safety import ControlProof, ControlProofMethod, validate_control_proof
from sova.targets import TargetKind, TargetManifest

if TYPE_CHECKING:
    from collections.abc import Callable


def _target(
    *,
    kind: TargetKind = TargetKind.LOCAL_PROCESS,
    capabilities: tuple[str, ...] = ("process.invoke", "process.observe"),
    basis: str = "self",
    reference: str = "owned-test-program",
) -> TargetManifest:
    return TargetManifest(
        "sova:target:owned-software-test",
        kind,
        "1.0.0",
        capabilities,
        "owned test program",
        {
            "interface": "argv-and-files",
            "authorityBasis": basis,
            "authorityReference": reference,
        },
    )


def _scenario(executable: Path, **inputs: Any) -> dict[str, Any]:
    value = scenario_template(title="Software test", purpose="Exercise a local test process")
    value["procedure"]["steps"] = [
        {
            "id": "software-step",
            "action": "process.exec",
            "inputs": {"argv": [str(executable), "app.py"], **inputs},
            "onFailure": "inconclusive",
            "requires": ["process.exec/0.1"],
        }
    ]
    value["oracles"] = [{"kind": "field-contains", "path": "$.stdout", "contains": "ok"}]
    return value


def _capsule(path: Path, scenario: dict[str, Any]) -> None:
    build_capsule(
        path,
        capsule_manifest_template(
            title="Software capsule",
            summary="Local software unit fixture.",
            author="SOVA tests",
        ),
        scenario=scenario,
    )


def test_local_possession_control_proof_is_narrow_and_explicit() -> None:
    now = datetime(2026, 8, 8, tzinfo=UTC)
    target = "sova:local-software:fixture"
    digest = "sha256:" + "a" * 64
    proof = ControlProof(
        ControlProofMethod.LOCAL_POSSESSION,
        target,
        "challenge",
        {
            "challenge": "challenge",
            "operatorAssertion": True,
            "executableDigest": digest,
            "workspaceFingerprint": digest,
            "targetDigest": digest,
        },
        now,
        now + timedelta(minutes=1),
        "test",
    )
    assert validate_control_proof(proof, target=target, now=now)[0]
    for changed in (
        replace(proof, subject="other"),
        replace(proof, evidence={**proof.evidence, "challenge": "wrong"}),
        replace(proof, evidence={**proof.evidence, "operatorAssertion": False}),
        replace(proof, evidence={**proof.evidence, "targetDigest": "not-a-digest"}),
    ):
        accepted, reasons = validate_control_proof(changed, target=target, now=now)
        assert not accepted and reasons


@pytest.mark.parametrize(
    ("target", "message"),
    [
        (_target(kind=TargetKind.BROWSER_AGENT), "local-process"),
        (_target(capabilities=()), "not conformant"),
        (_target(basis="replace-me"), "authorityBasis"),
        (_target(reference=""), "authorityBasis"),
    ],
)
def test_software_target_admission_fails_closed(target: TargetManifest, message: str) -> None:
    with pytest.raises(FormatError, match=message):
        software._assert_target(target)


def test_scenario_admission_accepts_exact_process_and_rejects_unsafe_variants(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve()
    accepted = _scenario(executable)
    assert software._validate_scenario(accepted, executable)[0]["action"] == "process.exec"

    mutations: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (lambda value: value["procedure"]["steps"].clear(), "1..32"),
        (
            lambda value: value["procedure"]["steps"][0].update(action="browser.navigate"),
            "process.exec only",
        ),
        (
            lambda value: value["procedure"]["steps"][0]["inputs"].update(argv=[]),
            "requires string argv",
        ),
        (
            lambda value: value["procedure"]["steps"][0]["inputs"].update(
                argv=[str(tmp_path / "other.exe")]
            ),
            "exact admitted",
        ),
        (
            lambda value: value["procedure"]["steps"][0]["inputs"].update(
                secretEnv={"TOKEN": "sova-secret:fixture"}
            ),
            "does not admit secret",
        ),
        (
            lambda value: value["procedure"]["steps"][0]["inputs"].update(offensive=True),
            "not admitted",
        ),
    )
    for mutate, message in mutations:
        value = _scenario(executable)
        mutate(value)
        with pytest.raises(FormatError, match=message):
            software._validate_scenario(value, executable)


def test_workspace_snapshot_reports_delta_symlinks_and_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.txt"
    first.write_text("before", encoding="utf-8")
    before = software._snapshot_workspace(workspace)
    first.write_text("after", encoding="utf-8")
    (workspace / "created.txt").write_text("new", encoding="utf-8")
    after = software._snapshot_workspace(workspace)
    delta = software._workspace_delta(before, after)
    assert delta["complete"] is True
    assert delta["created"][0]["path"] == "created.txt"
    assert delta["modified"][0]["path"] == "first.txt"

    link = workspace / "link.txt"
    try:
        link.symlink_to(first)
    except OSError:
        pass
    else:
        assert software._snapshot_workspace(workspace).complete is False
    monkeypatch.setattr(software, "_MAX_SNAPSHOT_FILES", 0)
    limited = software._snapshot_workspace(workspace)
    assert not limited.complete and "budget" in limited.limitations[0]


def test_observed_executor_converts_incomplete_sensor_to_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = iter(
        (
            software._WorkspaceSnapshot(files={}, complete=True, limitations=()),
            software._WorkspaceSnapshot(
                files={}, complete=False, limitations=("sensor unavailable",)
            ),
        )
    )
    monkeypatch.setattr(software, "_snapshot_workspace", lambda _workspace: next(snapshots))
    executor = software._ObservedLocalExecutor(Path(sys.executable))
    monkeypatch.setattr(
        executor._delegate,
        "execute",
        lambda *_args: ActionOutcome(
            "request",
            OutcomeStatus.SUCCEEDED,
            SideEffect.MUTATE,
            {"returncode": 0},
        ),
    )
    outcome = executor.execute(
        ActionRequest("request", "process.exec", {"argv": [sys.executable]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.PARTIAL
    assert outcome.error_code == "SOVA-SOFTWARE-SENSOR-PARTIAL"
    executor._delegate.close()


def test_live_assessment_rejects_unsafe_paths_and_scenarios(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('ok')", encoding="utf-8")
    capsule = tmp_path / "source.sova"
    _capsule(capsule, _scenario(executable))

    def approve(challenge: Any, _intents: Any) -> str:
        return str(challenge.exact_phrase)

    with pytest.raises(FormatError, match="destination must be outside"):
        software.run_live_software_assessment(
            _target(),
            capsule,
            workspace,
            workspace / "evidence",
            executable=executable,
            approval_prompt=approve,
        )
    inside = workspace / "tool.py"
    inside.write_text("print('ok')", encoding="utf-8")
    with pytest.raises(FormatError, match="installed outside"):
        software.run_live_software_assessment(
            _target(),
            capsule,
            workspace,
            tmp_path / "outside",
            executable=inside,
            approval_prompt=approve,
        )
    wrong = tmp_path / "wrong.sova"
    _capsule(wrong, _scenario(executable, offensive=True))
    with pytest.raises(FormatError, match="not admitted"):
        software.run_live_software_assessment(
            _target(),
            wrong,
            workspace,
            tmp_path / "wrong-output",
            executable=executable,
            approval_prompt=approve,
        )


def test_file_and_workspace_guards_reject_missing_symlinks_and_broad_roots(
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError, match="regular"):
        software._safe_file(tmp_path / "missing", code="TEST", role="fixture")
    with pytest.raises(FormatError, match="user home"):
        software._safe_source_workspace(Path.home())
    if hasattr(Path, "symlink_to"):
        source = tmp_path / "source"
        source.mkdir()
        link = tmp_path / "source-link"
        try:
            link.symlink_to(source, target_is_directory=True)
        except OSError:
            return
        with pytest.raises(FormatError, match="regular directory"):
            software._safe_source_workspace(link)
