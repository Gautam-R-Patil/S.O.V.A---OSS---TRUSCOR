# SPDX-License-Identifier: Apache-2.0
"""Mandatory no-network capsule-to-trace reproduction vertical slice."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.reproduction import compare_observable_outcomes, reproduce_with_scripted_model
from sova.trace import TraceReader

ROOT = Path(__file__).resolve().parents[2]


def _capsule(tmp_path: Path) -> Path:
    scenario = json.loads(
        (ROOT / "examples" / "scenarios" / "conditional-trigger.json").read_text(encoding="utf-8")
    )
    manifest = capsule_manifest_template(
        title=scenario["title"],
        summary=scenario["purpose"],
        author="SOVA OSS synthetic fixture authors",
    )
    path = tmp_path / "conditional.sova"
    build_capsule(path, manifest, scenario=scenario)
    return path


def _model() -> ScriptedModel:
    return ScriptedModel(
        [
            ScriptedTurn("Return the fixture status.", "BASELINE", {"label": "BASELINE"}),
            ScriptedTurn(
                "blue owl",
                "TRIGGERED",
                {"label": "TRIGGERED"},
            ),
        ]
    )


@pytest.mark.integration
def test_no_network_reproduction_is_verifiable_and_repeatable(tmp_path: Path) -> None:
    capsule = _capsule(tmp_path)
    auth = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + "4" * 64,
        "decidedBy": "synthetic-test",
    }
    first = reproduce_with_scripted_model(
        capsule,
        tmp_path / "first.sova-trace",
        model=_model(),
        authorization=auth,
    )
    second = reproduce_with_scripted_model(
        capsule,
        tmp_path / "second.sova-trace",
        model=_model(),
        authorization=auth,
    )

    assert first.completion == second.completion == "completed"
    assert TraceReader(first.trace_path).verify().event_count == 7
    comparison = compare_observable_outcomes(first.trace_path, second.trace_path)
    assert comparison.equivalent
    oracle = next(TraceReader(first.trace_path).query(kind_prefix="oracle.completed"))
    assert oracle["payload"]["status"] == "pass"
    assert any(
        event["payload"].get("structured", {}).get("label") == "TRIGGERED"
        for event in TraceReader(first.trace_path).query(kind_prefix="model.")
    )


@pytest.mark.integration
def test_reproduction_fails_closed_without_fresh_authorization(tmp_path: Path) -> None:
    with pytest.raises(FormatError) as error:
        reproduce_with_scripted_model(
            _capsule(tmp_path),
            tmp_path / "blocked.sova-trace",
            model=_model(),
            authorization={
                "decision": "unknown",
                "scopeDigest": None,
                "decidedBy": "not-recorded",
            },
        )
    assert error.value.issue.code == "SOVA-REPRODUCE-AUTHORIZATION"
