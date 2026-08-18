# SPDX-License-Identifier: Apache-2.0
"""Authorized-target planning and deterministic website/software pipeline tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.assessment import (
    build_assessment_plan,
    create_browser_test_kit,
    run_reference_assessment,
    target_template,
)
from sova.cli import main
from sova.formats.errors import FormatError
from sova.live import browser_campaign_from_mapping
from sova.replay import verify_artifact
from sova.targets import TargetKind, target_manifest_from_mapping

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["website", "software"])
def test_reference_target_pipeline_is_reproducible_and_offline(tmp_path: Path, kind: str) -> None:
    artifacts = run_reference_assessment(kind, tmp_path / kind)
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert report["liveTargetExecuted"] is False
    assert report["semanticOutcomeEquivalent"] is True
    assert verify_artifact(artifacts.trace).state.value == "partial"
    assert verify_artifact(artifacts.capsule).state.value in {"partial", "verified"}


def test_target_template_and_plan_are_portable_and_inert() -> None:
    mapping = target_template(TargetKind.BROWSER_AGENT)
    target = target_manifest_from_mapping(mapping)
    plan = build_assessment_plan(target)
    assert plan["executionPerformed"] is False
    assert plan["authorization"]["requiredBeforeExecution"] is True
    assert plan["adapterCandidates"][0] == "microsoft-playwright-mcp"
    assert "argv" not in json.dumps(plan)


def test_target_manifest_rejects_nested_secret_material() -> None:
    mapping = target_template(TargetKind.REST_API)
    mapping["configuration"]["nested"] = {"apiKey": "do-not-store"}
    with pytest.raises(FormatError, match="secret"):
        target_manifest_from_mapping(mapping)


def test_target_manifest_rejects_unknown_fields_and_missing_capability() -> None:
    mapping = target_template(TargetKind.BROWSER_AGENT)
    mapping["unexpected"] = True
    with pytest.raises(FormatError, match="missing or unknown"):
        target_manifest_from_mapping(mapping)

    mapping = target_template(TargetKind.BROWSER_AGENT)
    mapping["capabilities"] = []
    target = target_manifest_from_mapping(mapping)
    plan_error = "required portable capability"
    with pytest.raises(FormatError, match=plan_error):
        build_assessment_plan(target)


def test_target_contract_rejects_invalid_kinds_types_and_fixture_destinations(
    tmp_path: Path,
) -> None:
    mapping = target_template(TargetKind.BROWSER_AGENT)
    mapping["kind"] = "unknown"
    with pytest.raises(FormatError, match="unsupported"):
        target_manifest_from_mapping(mapping)

    mapping = target_template(TargetKind.BROWSER_AGENT)
    mapping["capabilities"] = "browser.observe"
    with pytest.raises(FormatError, match="string array"):
        target_manifest_from_mapping(mapping)

    mapping = target_template(TargetKind.BROWSER_AGENT)
    mapping["configuration"] = []
    with pytest.raises(FormatError, match="must be an object"):
        target_manifest_from_mapping(mapping)

    with pytest.raises(FormatError, match="website or software"):
        run_reference_assessment("unknown", tmp_path / "unknown")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("keep", encoding="utf-8")
    with pytest.raises(FormatError, match="not empty"):
        run_reference_assessment("website", occupied)


def test_target_cli_template_plan_and_fixture(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "target.json"
    plan = tmp_path / "plan.json"
    assert main(["target", "template", "browser-agent", str(manifest)]) == 0
    capsys.readouterr()
    assert main(["target", "validate", str(manifest)]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] is True
    assert main(["target", "plan", str(manifest), str(plan)]) == 0
    capsys.readouterr()
    assert json.loads(plan.read_text(encoding="utf-8"))["executionPerformed"] is False
    assert main(["target", "fixture", "website", str(tmp_path / "fixture")]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "pass"


def test_browser_kit_is_inert_complete_and_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "kit"
    assert main(["target", "browser-kit", "https://owned.example", str(destination)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["networkUsed"] is False
    assert report["authorizationEstablished"] is False
    assert report["readyForExecution"] is False
    assert sorted(path.name for path in destination.iterdir()) == sorted(report["files"])
    target = target_manifest_from_mapping(
        json.loads((destination / "target.json").read_text(encoding="utf-8"))
    )
    campaign = browser_campaign_from_mapping(
        json.loads((destination / "campaign.json").read_text(encoding="utf-8"))
    )
    assert target.configuration["allowedOrigins"] == ["https://owned.example"]
    assert campaign.entry_url == "https://owned.example/"
    assert campaign.total_actions == 26
    assert "does not prove ownership" in (destination / "README.md").read_text(encoding="utf-8")

    with pytest.raises(FormatError, match="require HTTPS"):
        create_browser_test_kit("http://third-party.example", tmp_path / "unsafe")
    with pytest.raises(FormatError, match="bare HTTP"):
        create_browser_test_kit("https://owned.example/path", tmp_path / "path")
    with pytest.raises(FormatError, match="not empty"):
        create_browser_test_kit("https://owned.example", destination)
