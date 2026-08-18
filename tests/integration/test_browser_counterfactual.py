# SPDX-License-Identifier: Apache-2.0
"""Evidence-producing browser counterfactual workflow tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sova.cli import main
from sova.forensics import (
    BrowserCounterfactualStudy,
    CausalLayer,
    browser_counterfactual_from_mapping,
    run_browser_counterfactual_study,
)
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import BrowserCampaign, BrowserCampaignArtifacts, owned_web_target
from sova.replay import VerificationState, verify_artifact
from sova.runtime import standard_profile
from sova.trace import TraceWriter, generate_ed25519_keypair


def _baseline(origin: str = "http://127.0.0.1:8765/") -> BrowserCampaign:
    return BrowserCampaign(
        "sova:browser-cf:baseline",
        "Owned fixture exact baseline",
        origin,
        "#message",
        "#send",
        (("enable research mode", "blue owl"),),
        "SOVA_FIXTURE_TRIGGERED",
        1,
        120,
    )


def _trace(path: Path) -> None:
    writer = TraceWriter(path, signing_key=generate_ed25519_keypair())
    writer.append("run.started", {"fixture": True})
    writer.append("oracle.completed", {"status": "pass"})
    writer.append("run.completed", {"completion": "completed"})
    writer.finalize()


def test_browser_counterfactual_runs_four_independent_evidence_pairs(
    tmp_path: Path,
) -> None:
    study = BrowserCounterfactualStudy(
        "owned-sequence-removal",
        "Owned sequence removal study",
        _baseline(),
        CausalLayer.ORCHESTRATION,
        0,
        4,
    )
    calls: list[tuple[tuple[tuple[str, ...], ...], Path]] = []

    def runner(
        _target: object,
        campaign: BrowserCampaign,
        destination: Path,
        **kwargs: Any,
    ) -> BrowserCampaignArtifacts:
        calls.append((campaign.candidates, kwargs["package_cache"]))
        destination.mkdir(parents=True)
        intervention = destination / "intervention.sova-trace"
        baseline = destination / "baseline.sova-trace"
        reproduction = destination / "reproduction.sova-trace"
        for path in (intervention, baseline, reproduction):
            _trace(path)
        report = destination / "report.json"
        report.write_bytes(
            canonical_json_bytes(
                {
                    "artifactType": "sova.live-browser-campaign-report",
                    "schemaVersion": "0.1.0",
                    "status": "pass",
                    "attempts": [
                        {"triggered": False, "trace": intervention.name},
                        {"triggered": True, "trace": baseline.name},
                    ],
                    "reproduction": {"attempted": True, "equivalent": True},
                }
            )
            + b"\n"
        )
        return BrowserCampaignArtifacts(
            destination / "target.json",
            destination / "campaign.json",
            (intervention, baseline),
            reproduction,
            None,
            report,
            "pass",
        )

    artifacts = run_browser_counterfactual_study(
        owned_web_target("http://127.0.0.1:8765"),
        study,
        tmp_path / "counterfactual",
        profile=standard_profile(),
        package_runner=Path("unused-npx"),
        browser_executable=Path("unused-browser"),
        approval_prompt=lambda _challenge, _intents: "unused",
        runner=runner,
    )

    assert len(calls) == 4
    assert all(
        candidates == (("blue owl",), ("enable research mode", "blue owl"))
        for candidates, _cache in calls
    )
    assert len({cache for _candidates, cache in calls}) == 1
    assert len(artifacts.traces) == 12
    assert artifacts.status == "supported-under-declared-interventions"
    assert verify_artifact(artifacts.capsule).state == VerificationState.VERIFIED
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assessment = report["attribution"]["assessments"][0]
    assert assessment["eligibleTrials"] == 4
    assert assessment["prevented"] == 4
    assert report["claims"]["causalCertainty"] is False


def test_browser_counterfactual_parser_and_campaign_reject_unsafe_inputs() -> None:
    value = BrowserCounterfactualStudy(
        "safe-study",
        "Safe study",
        _baseline(),
        CausalLayer.ORCHESTRATION,
        0,
        4,
    ).to_mapping()
    assert browser_counterfactual_from_mapping(value).intervention_sequence == ("blue owl",)
    example = strict_json_loads(
        Path("examples/topics-15-17/browser-counterfactual-study.json").read_bytes()
    )
    assert isinstance(example, dict)
    parsed_example = browser_counterfactual_from_mapping(example)
    assert parsed_example.repetitions == 4
    assert parsed_example.baseline.total_actions == 10
    with pytest.raises(FormatError, match="fields are invalid"):
        browser_counterfactual_from_mapping({**value, "unknown": True})
    with pytest.raises(FormatError, match="between four and ten"):
        browser_counterfactual_from_mapping({**value, "repetitions": 3})
    with pytest.raises(FormatError, match="credential-shaped"):
        BrowserCampaign(
            "sensitive",
            "Sensitive",
            "http://127.0.0.1:8765/",
            "#message",
            "#send",
            (("Bearer abcdefghijklmnopqrstuvwxyz", "blue owl"),),
            "SOVA_FIXTURE_TRIGGERED",
            1,
            120,
        )


def test_browser_counterfactual_cli_requires_terminal_before_input_read(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "forensics",
                "browser-counterfactual",
                str(tmp_path / "missing-target.json"),
                str(tmp_path / "missing-study.json"),
                str(tmp_path / "output"),
            ]
        )
        == 2
    )
    assert "SOVA-LIVE-INTERACTIVE-APPROVAL" in capfd.readouterr().err
