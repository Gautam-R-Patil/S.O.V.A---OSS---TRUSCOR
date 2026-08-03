# SPDX-License-Identifier: Apache-2.0
"""Reusable workflow annotation rendering tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from scripts.emit_ci_annotations import main, render_annotations

if TYPE_CHECKING:
    from pathlib import Path


def _report() -> dict[str, object]:
    return {
        "artifactType": "sova.ci-report",
        "annotations": [
            {"title": "SOVA% drift", "message": "behavior\nchanged", "level": "failure"},
            {"title": "Environment", "message": "stable", "level": "notice"},
        ],
    }


def test_annotations_are_bounded_and_command_escaped() -> None:
    assert render_annotations(_report()) == [
        "::error title=SOVA%25 drift::behavior%0Achanged",
        "::notice title=Environment::stable",
    ]
    with pytest.raises(ValueError, match="not a SOVA"):
        render_annotations({})
    with pytest.raises(ValueError, match="must be an object"):
        render_annotations({"artifactType": "sova.ci-report", "annotations": ["bad"]})


def test_annotation_cli(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report()), encoding="utf-8")
    assert main([str(report)]) == 0
    assert "::error" in capfd.readouterr().out
    assert main([]) == 2
    assert "usage" in capfd.readouterr().err
    report.write_text("not-json", encoding="utf-8")
    assert main([str(report)]) == 2
    assert "SOVA-CI-ANNOTATIONS" in capfd.readouterr().err
