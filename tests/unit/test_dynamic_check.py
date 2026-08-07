# SPDX-License-Identifier: Apache-2.0
"""Dynamic check status, evidence, and fail-closed boundary tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import sova.workflows.check as check_module
from sova.capsule import build_capsule, capsule_manifest_template
from sova.cli import main
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import BrowserCampaignArtifacts, owned_web_campaign, owned_web_target
from sova.runtime import standard_profile
from sova.trace import TraceWriter, generate_ed25519_keypair
from sova.workflows import run_browser_check


def _signed_trace(path: Path) -> None:
    writer = TraceWriter(path, signing_key=generate_ed25519_keypair())
    writer.append("run.started", {"fixture": True})
    writer.append("run.completed", {"completion": "completed"})
    writer.finalize()


def _runner(
    status: str,
    stop_reason: str,
    *,
    reproduction: bool = False,
) -> Any:
    def run(
        _target: object,
        _campaign: object,
        destination: Path,
        **_kwargs: object,
    ) -> BrowserCampaignArtifacts:
        destination.mkdir(parents=True, exist_ok=True)
        trace = destination / "attempt.sova-trace"
        _signed_trace(trace)
        reproduction_trace = destination / "reproduction.sova-trace" if reproduction else None
        if reproduction_trace is not None:
            _signed_trace(reproduction_trace)
        report = destination / "report.json"
        report.write_bytes(
            canonical_json_bytes(
                {
                    "artifactType": "sova.live-browser-campaign-report",
                    "schemaVersion": "0.1.0",
                    "status": status,
                    "search": {
                        "attempts": 1,
                        "coverage": ["browser-state:READY"],
                        "stopReason": stop_reason,
                    },
                }
            )
            + b"\n"
        )
        return BrowserCampaignArtifacts(
            destination / "target.json",
            destination / "campaign.json",
            (trace,),
            reproduction_trace,
            None,
            report,
            status,
        )

    return run


def test_browser_check_reports_exhaustive_not_observed_without_clean_claim(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "check"
    result = run_browser_check(
        owned_web_target("http://127.0.0.1:8765"),
        owned_web_campaign("http://127.0.0.1:8765/"),
        destination,
        profile=standard_profile(),
        package_runner=Path("unused-npx"),
        browser_executable=Path("unused-browser"),
        approval_prompt=lambda _challenge, _intents: "unused",
        runner=_runner("not-confirmed", "candidate-source-exhausted"),
    )

    assert result.status == "not-observed" and result.exit_code == 0
    report = strict_json_loads(result.report.read_bytes())
    assert isinstance(report, dict)
    assert report["safeOrCleanClaim"] is False
    assert report["conditions"]["realBrowserExecuted"] is True
    assert report["stopReason"] == "candidate-source-exhausted"


def test_browser_check_refuses_offensive_campaign_before_runner(tmp_path: Path) -> None:
    campaign = replace(
        owned_web_campaign("http://127.0.0.1:8765/"),
        offensive=True,
    )
    with pytest.raises(FormatError, match="refuses offensive"):
        run_browser_check(
            owned_web_target("http://127.0.0.1:8765"),
            campaign,
            tmp_path / "offensive",
            profile=standard_profile(),
            package_runner=Path("unused-npx"),
            browser_executable=Path("unused-browser"),
            approval_prompt=lambda _challenge, _intents: "unused",
            runner=lambda *_args, **_kwargs: pytest.fail("runner must not execute"),
        )


def test_browser_check_confirmation_requires_reproduction_evidence(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="lacks reproduction evidence"):
        run_browser_check(
            owned_web_target("http://127.0.0.1:8765"),
            owned_web_campaign("http://127.0.0.1:8765/"),
            tmp_path / "missing-reproduction",
            profile=standard_profile(),
            package_runner=Path("unused-npx"),
            browser_executable=Path("unused-browser"),
            approval_prompt=lambda _challenge, _intents: "unused",
            runner=_runner("pass", "confirmed-trigger"),
        )


def test_browser_check_cli_requires_terminal_before_reading_inputs(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "check",
                str(tmp_path / "missing-target.json"),
                str(tmp_path / "output"),
                "--browser-campaign",
                str(tmp_path / "missing-campaign.json"),
            ]
        )
        == 2
    )
    assert "SOVA-LIVE-INTERACTIVE-APPROVAL" in capfd.readouterr().err


def test_browser_options_cannot_be_silently_ignored(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "check",
                "synthetic-sleeper",
                str(tmp_path / "output"),
                "--browser-executable",
                "browser.exe",
            ]
        )
        == 2
    )
    assert "SOVA-CHECK-BROWSER-ARGS" in capfd.readouterr().err


def test_browser_check_artifact_guards_reject_missing_invalid_and_malformed_inputs(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(FormatError, match="report is invalid"):
        check_module._campaign_report(report)

    empty = BrowserCampaignArtifacts(
        tmp_path / "target.json",
        tmp_path / "campaign.json",
        (),
        None,
        None,
        report,
        "not-confirmed",
    )
    with pytest.raises(FormatError, match="no trace"):
        check_module._verify_browser_check_artifacts(empty)

    failed_trace = tmp_path / "failed.sova-trace"
    writer = TraceWriter(failed_trace, signing_key=generate_ed25519_keypair())
    writer.append("run.failed", {"status": "failed"})
    writer.finalize(completion="failed")
    failed = replace(empty, traces=(failed_trace,))
    with pytest.raises(FormatError, match="failed signed"):
        check_module._verify_browser_check_artifacts(failed)

    valid_trace = tmp_path / "valid.sova-trace"
    _signed_trace(valid_trace)
    failed_reproduction = replace(
        empty,
        traces=(valid_trace,),
        reproduction_trace=failed_trace,
    )
    with pytest.raises(FormatError, match="reproduction failed"):
        check_module._verify_browser_check_artifacts(failed_reproduction)


def test_browser_check_verifies_capsule_and_returns_confirmed_or_inconclusive(
    tmp_path: Path,
) -> None:
    def runner(status: str, stop_reason: str, *, include_search: bool = True) -> Any:
        def run(
            _target: object,
            _campaign: object,
            destination: Path,
            **_kwargs: object,
        ) -> BrowserCampaignArtifacts:
            destination.mkdir(parents=True, exist_ok=True)
            trace = destination / "attempt.sova-trace"
            reproduction = destination / "reproduction.sova-trace"
            _signed_trace(trace)
            _signed_trace(reproduction)
            capsule = destination / "evidence.sova"
            manifest = capsule_manifest_template(
                title="Dynamic check evidence",
                summary="Owned deterministic fixture evidence.",
                author="SOVA tests",
            )
            build_capsule(capsule, manifest, traces=[trace, reproduction])
            report = destination / "report.json"
            document: dict[str, Any] = {
                "artifactType": "sova.live-browser-campaign-report",
                "status": status,
            }
            if include_search:
                document["search"] = {
                    "attempts": 1,
                    "coverage": [],
                    "stopReason": stop_reason,
                }
            report.write_bytes(canonical_json_bytes(document) + b"\n")
            return BrowserCampaignArtifacts(
                destination / "target.json",
                destination / "campaign.json",
                (trace,),
                reproduction,
                capsule,
                report,
                status,
            )

        return run

    target = owned_web_target("http://127.0.0.1:8765")
    campaign = owned_web_campaign("http://127.0.0.1:8765/")
    confirmed = run_browser_check(
        target,
        campaign,
        tmp_path / "confirmed",
        profile=standard_profile(),
        package_runner=Path("unused-npx"),
        browser_executable=Path("unused-browser"),
        approval_prompt=lambda _challenge, _intents: "unused",
        runner=runner("pass", "confirmed-trigger"),
    )
    assert confirmed.status == "confirmed-behavior"
    assert confirmed.to_mapping()["reproductionTrace"] is not None
    assert confirmed.to_mapping()["capsule"] is not None

    inconclusive = run_browser_check(
        target,
        campaign,
        tmp_path / "inconclusive",
        profile=standard_profile(),
        package_runner=Path("unused-npx"),
        browser_executable=Path("unused-browser"),
        approval_prompt=lambda _challenge, _intents: "unused",
        runner=runner("not-confirmed", "duration-budget"),
    )
    assert inconclusive.status == "inconclusive" and inconclusive.exit_code == 3

    with pytest.raises(FormatError, match="search report is missing"):
        run_browser_check(
            target,
            campaign,
            tmp_path / "missing-search",
            profile=standard_profile(),
            package_runner=Path("unused-npx"),
            browser_executable=Path("unused-browser"),
            approval_prompt=lambda _challenge, _intents: "unused",
            runner=runner("not-confirmed", "ignored", include_search=False),
        )
