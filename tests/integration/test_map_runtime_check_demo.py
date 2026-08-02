# SPDX-License-Identifier: Apache-2.0
"""Topics 09-11 acceptance: map -> orchestration -> signed reproducible proof."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sova.cli import main
from sova.formats import PackageReader
from sova.runtime import ProfileKind, RunProfile, standard_profile
from sova.trace import TraceReader
from sova.workflows import run_complete_demo


@pytest.mark.integration
def test_complete_demo_is_repeatable_signed_and_independently_verifiable(
    tmp_path: Path,
) -> None:
    runs = [
        run_complete_demo(tmp_path / f"run-{index}", profile=standard_profile())
        for index in range(3)
    ]
    for artifacts in runs:
        assert artifacts.oracle_status == "pass"
        assert artifacts.evidence_closure == "sufficient"
        assert artifacts.cleanup_verified
        assert artifacts.reproduced
        assert PackageReader(artifacts.capsule).verify("sova.capsule")
        for trace in (artifacts.trace, artifacts.reproduction_trace):
            verification = TraceReader(trace).verify(require_signature=True)
            assert verification.signature_valid is True
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/sova_independent_verify.py",
                    "--require-signature",
                    str(trace),
                ],
                cwd=Path.cwd(),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert completed.returncode == 0, completed.stderr

        report = json.loads(artifacts.report.read_text(encoding="utf-8"))
        assert report["result"]["safeOrCleanClaim"] is False
        assert report["result"]["attempts"] == 4
        assert report["result"]["durationMs"] >= 1
        assert report["search"]["dimensions"] == ["message", "SOVA_MODE"]
        assert report["reproduction"]["freshRun"] is True
        assert all(not value["detected"] for value in report["baselines"].values())
        assert all(value["reason"] for value in report["baselines"].values())


@pytest.mark.integration
def test_check_exit_codes_profiles_and_unsupported_target_are_honest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    confirmed = tmp_path / "confirmed"
    assert main(["check", "synthetic-sleeper", str(confirmed)]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "confirmed-behavior"
    assert output["safeOrCleanClaim"] is False
    report = json.loads(Path(output["report"]).read_text(encoding="utf-8"))
    assert report["profile"]["kind"] == "standard"
    assert report["profile"]["sharedComparisonEligible"] is True

    custom_path = tmp_path / "custom.json"
    custom_path.write_text('{"attacks":["fixture-only"]}', encoding="utf-8")
    custom = tmp_path / "custom-run"
    assert (
        main(
            [
                "check",
                "synthetic-sleeper",
                str(custom),
                "--custom-profile",
                str(custom_path),
            ]
        )
        == 1
    )
    custom_output = json.loads(capsys.readouterr().out)
    custom_report = json.loads(Path(custom_output["report"]).read_text(encoding="utf-8"))
    assert custom_report["profile"]["kind"] == ProfileKind.CUSTOM.value
    assert custom_report["profile"]["sharedComparisonEligible"] is False
    assert custom_report["profile"]["watermark"] == "CUSTOM / NON-STANDARD"

    unsupported_target = tmp_path / "ordinary-component"
    unsupported_target.mkdir()
    unsupported = tmp_path / "unsupported"
    assert main(["check", str(unsupported_target), str(unsupported)]) == 3
    unsupported_output = json.loads(capsys.readouterr().out)
    assert unsupported_output["status"] == "inconclusive"
    unsupported_report = json.loads(Path(unsupported_output["report"]).read_text(encoding="utf-8"))
    assert unsupported_report["conditions"]["nativeCodeExecuted"] is False
    assert unsupported_report["safeOrCleanClaim"] is False
    assert (
        TraceReader(Path(unsupported_output["trace"]))
        .verify(require_signature=True)
        .signature_valid
    )


@pytest.mark.integration
def test_explicit_custom_profile_constructor_remains_non_comparable() -> None:
    profile = RunProfile(
        ProfileKind.CUSTOM,
        "0.1.0",
        customization_digest="sha256:" + "a" * 64,
    )
    assert profile.to_mapping()["sharedComparisonEligible"] is False


@pytest.mark.integration
def test_check_refuses_invalid_target_and_nonempty_destination(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["check", str(tmp_path / "missing"), str(tmp_path / "out")]) == 2
    assert "SOVA-CHECK-TARGET" in capsys.readouterr().err
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "preserve.txt").write_text("user data", encoding="utf-8")
    assert main(["check", "synthetic-sleeper", str(nonempty)]) == 2
    assert "SOVA-CHECK-EXISTS" in capsys.readouterr().err
    assert (nonempty / "preserve.txt").read_text(encoding="utf-8") == "user data"
