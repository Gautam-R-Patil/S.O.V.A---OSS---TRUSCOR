# SPDX-License-Identifier: Apache-2.0
"""Offline final-mile acceptance lab integration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.acceptance import acceptance_receipt_template, run_offline_acceptance_lab
from sova.cli import main
from sova.formats.errors import FormatError
from sova.replay import verify_artifact

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.integration
def test_offline_acceptance_lab_produces_verified_core_and_blocked_stable_report(
    tmp_path: Path,
) -> None:
    artifacts = run_offline_acceptance_lab(tmp_path / "acceptance")
    assert artifacts.status == "pass"
    assert verify_artifact(artifacts.core_capsule).accepted
    assert verify_artifact(artifacts.core_trace).accepted
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["coreAcceptancePassed"] is True
    assert report["stable1Ready"] is False
    assert report["scope"] == {
        "networkUsed": False,
        "credentialsUsed": False,
        "nativeTargetCodeExecuted": False,
        "externalEvidenceGenerated": False,
    }
    coverage = json.loads(artifacts.sensor_coverage.read_text(encoding="utf-8"))
    assert coverage["accepted"] is True
    assert coverage["claims"]["totalSensorCoverage"] is False
    readiness = json.loads(artifacts.readiness.read_text(encoding="utf-8"))
    assert readiness["readyForStable1"] is False
    assert readiness["totalGateCount"] == 12


def test_acceptance_lab_is_atomic_and_templates_do_not_claim_pass(tmp_path: Path) -> None:
    destination = tmp_path / "acceptance"
    destination.mkdir()
    with pytest.raises(FormatError, match="must not exist"):
        run_offline_acceptance_lab(destination)
    template = acceptance_receipt_template("external-user-workflows")
    assert template["result"] == "inconclusive"
    assert template["independentOfSovaTeam"] is False
    assert "replace" in template["runId"]
    with pytest.raises(FormatError, match="unknown"):
        acceptance_receipt_template("missing")


def test_acceptance_cli_runs_templates_and_reports_blocked_stable_gate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    template = tmp_path / "receipts" / "external-user.json"
    assert main(["acceptance", "template", "external-user-workflows", str(template)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "template-only"
    document = json.loads(template.read_text(encoding="utf-8"))
    assert document["result"] == "inconclusive"

    assert main(["acceptance", "evaluate", str(template.parent)]) == 3
    readiness = json.loads(capsys.readouterr().out)
    assert readiness["readyForStable1"] is False

    output = tmp_path / "acceptance"
    assert main(["acceptance", "run", str(output)]) == 0
    run = json.loads(capsys.readouterr().out)
    assert run["status"] == "pass"
    assert (output / "stable-readiness.json").is_file()
