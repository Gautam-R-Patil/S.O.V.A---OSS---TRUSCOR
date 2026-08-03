# SPDX-License-Identifier: Apache-2.0
"""Topic 12 replay-mode, verification, uncertainty, and UX contracts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.cli import main
from sova.executors import OutcomeStatus, ScriptedAction, ScriptedExecutor, SideEffect, run_capsule
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.replay import (
    ReplayMode,
    ReproductionClass,
    VerificationState,
    calibrate_judge,
    controlled_reexecute,
    render_timeline_html,
    semantic_reproduction_study,
    verify_artifact,
    wilson_interval,
)
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path


def _fingerprints() -> dict[str, dict[str, str | None]]:
    return {
        name: {
            "value": None,
            "status": "not-applicable",
            "method": "test-fixture",
            "source": "test-fixture",
            "version": "0.1.0",
        }
        for name in ("environment", "target", "code", "dependencies", "registry", "model")
    }


def _oracle_trace(path: Path, label: str, *, signed: bool = True) -> None:
    writer = TraceWriter(
        path,
        signing_key=generate_ed25519_keypair() if signed else None,
        fingerprints=_fingerprints(),
    )
    writer.append(
        "oracle.completed",
        {"status": "pass", "results": [{"status": "pass", "expected": label}]},
    )
    writer.finalize()


def test_offline_verifier_reports_verified_partial_invalid_and_unsupported(
    tmp_path: Path,
) -> None:
    signed = tmp_path / "signed.sova-trace"
    unsigned = tmp_path / "unsigned.sova-trace"
    _oracle_trace(signed, "TRIGGERED")
    _oracle_trace(unsigned, "TRIGGERED", signed=False)

    assert verify_artifact(signed).state == VerificationState.VERIFIED
    assert verify_artifact(unsigned).state == VerificationState.PARTIAL
    assert verify_artifact(tmp_path / "unknown.bin").state == VerificationState.UNSUPPORTED
    damaged = tmp_path / "damaged.sova-trace"
    damaged.write_bytes(signed.read_bytes()[:-9])
    invalid = verify_artifact(damaged)
    assert invalid.state == VerificationState.INVALID
    assert invalid.error_code is not None


def test_semantic_study_reports_counts_wilson_uncertainty_and_sensitivity(
    tmp_path: Path,
) -> None:
    reference = tmp_path / "reference.sova-trace"
    _oracle_trace(reference, "TRIGGERED")
    matching = []
    for index in range(3):
        path = tmp_path / f"matching-{index}.sova-trace"
        _oracle_trace(path, "TRIGGERED")
        matching.append(path)
    report = semantic_reproduction_study(
        reference,
        matching,
        conditions=("model-a", "model-a", "model-a"),
    )
    assert report.mode == ReplayMode.SEMANTIC_REPRODUCTION
    assert report.classification == ReproductionClass.STRUCTURAL
    assert report.reproduced == report.eligible == report.total == 3
    assert 0 < report.interval_low < report.interval_high <= 1
    assert report.sensitivity[0].condition == "model-a"

    divergent = tmp_path / "divergent.sova-trace"
    _oracle_trace(divergent, "BASELINE")
    flaky = semantic_reproduction_study(reference, (matching[0], divergent))
    assert flaky.classification == ReproductionClass.FLAKY
    assert flaky.reproduced == 1
    assert flaky.eligible == 2


def test_wilson_and_judge_calibration_validate_inputs() -> None:
    assert wilson_interval(0, 0) == (0.0, 1.0)
    calibration = calibrate_judge((True, False, True), (True, True, None))
    assert calibration.total == 3
    assert calibration.correct == 1
    assert calibration.false_positive == 1
    with pytest.raises(FormatError):
        wilson_interval(2, 1)
    with pytest.raises(FormatError):
        calibrate_judge((), ())


def test_visual_timeline_is_inert_scrubbable_filtered_and_xss_safe(tmp_path: Path) -> None:
    trace = tmp_path / "hostile.sova-trace"
    writer = TraceWriter(trace)
    writer.append("model.response", {"text": "</script><script>alert(1)</script>"})
    writer.append("tool.completed", {"state": "observed"})
    writer.finalize()
    html_path = tmp_path / "replay.html"
    render_timeline_html(
        trace,
        html_path,
        comparison=trace,
        counterfactual="sova:trace:counterfactual",
    )
    rendered = html_path.read_text(encoding="utf-8")
    assert 'type="range"' in rendered
    assert "drawFilters" in rendered
    assert "Inert playback only" in rendered
    assert "primaryPayload" in rendered
    assert "comparisonPayload" in rendered
    assert "</script><script>alert(1)" not in rendered
    assert "\\u003c/script\\u003e" in rendered
    with pytest.raises(FormatError):
        render_timeline_html(trace, trace)


def _scenario(digest: str) -> dict[str, Any]:
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": "sova:scenario:019fc000-0000-7000-8000-000000000012",
        "version": "0.1.0",
        "title": "Controlled replay fixture",
        "purpose": "Re-read an inert capsule attachment.",
        "parameters": {},
        "preconditions": [],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "read",
                    "action": "artifact.read",
                    "inputs": {"digest": digest, "mediaType": "text/plain"},
                    "onFailure": "stop",
                    "requires": ["artifact.read/0.1"],
                }
            ]
        },
        "triggers": [],
        "mutations": [],
        "expectedEffects": [],
        "oracles": [{"kind": "field-contains", "path": "$.text", "contains": "fixture"}],
        "evidenceRequirements": ["action.outcome"],
        "safety": {
            "budgets": {"maxSteps": 1, "maxStepSeconds": 5},
            "forbiddenEffects": ["network.egress"],
            "stopConditions": [],
        },
        "cleanup": [],
        "limitations": ["Inert fixture only."],
        "extensions": {},
    }


def _scripted(data: bytes) -> ScriptedExecutor:
    digest = sha256_digest(data)
    return ScriptedExecutor(
        [
            ScriptedAction(
                action="artifact.read",
                expected_inputs={"digest": digest, "mediaType": "text/plain"},
                status=OutcomeStatus.SUCCEEDED,
                side_effect=SideEffect.READ,
                output={
                    "digest": digest,
                    "size": len(data),
                    "mediaType": "text/plain",
                    "text": data.decode(),
                },
                verification="digest-and-size-checked",
            )
        ]
    )


def test_controlled_reexecution_never_overwrites_and_links_condition_drift(
    tmp_path: Path,
) -> None:
    data = b"portable fixture"
    digest = sha256_digest(data)
    manifest = capsule_manifest_template(
        title="Controlled replay", summary="Inert replay fixture.", author="Tests"
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "fixture.sova"
    build_capsule(capsule, manifest, scenario=_scenario(digest), attachments={"fixture": data})
    authorization = {"decision": "allowed", "scopeDigest": None, "decidedBy": "test"}
    source = tmp_path / "source.sova-trace"
    run_capsule(
        capsule,
        source,
        executor=_scripted(data),
        workspace=tmp_path,
        authorization=authorization,
    )
    destination = tmp_path / "fresh.sova-trace"
    report = controlled_reexecute(
        capsule,
        source,
        destination,
        executor=_scripted(data),
        workspace=tmp_path,
        authorization=authorization,
    )
    assert report.mode == ReplayMode.CONTROLLED_REEXECUTION
    assert report.completion == "completed"
    assert report.outcome_status == "equivalent"
    started = next(TraceReader(destination).query(kind_prefix="run.started"))
    assert started["payload"]["sourceTraceDigest"] == sha256_digest(source.read_bytes())
    assert started["payload"]["replayMode"] == "controlled-reexecution"
    assert started["payload"]["conditionDrift"]
    with pytest.raises(FormatError):
        controlled_reexecute(
            capsule,
            source,
            source,
            executor=_scripted(data),
            workspace=tmp_path,
            authorization=authorization,
        )


def test_cli_outputs_precise_verify_and_replay_states(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trace = tmp_path / "run.sova-trace"
    _oracle_trace(trace, "TRIGGERED")
    assert main(["verify", str(trace)]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "verified"
    assert main(["replay", "modes"]) == 0
    assert json.loads(capsys.readouterr().out)["bitForBitHostedInferenceClaim"] is False
    assert main(["replay", "study", str(trace), str(trace), str(trace), str(trace)]) == 0
    assert json.loads(capsys.readouterr().out)["classification"].startswith("structural")
    html_path = tmp_path / "cli-replay.html"
    assert (
        main(
            [
                "replay",
                "timeline",
                str(trace),
                str(html_path),
                "--comparison",
                str(trace),
                "--counterfactual",
                "remove-trigger",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == str(html_path)
    assert "comparisonPayload" in html_path.read_text(encoding="utf-8")
    unsupported = tmp_path / "unsupported.bin"
    assert main(["verify", str(unsupported)]) == 4
    assert json.loads(capsys.readouterr().out)["state"] == "unsupported"
