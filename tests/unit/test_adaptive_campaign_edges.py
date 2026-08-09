# SPDX-License-Identifier: Apache-2.0
"""Failure and stop-condition coverage for adaptive browser coordination."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Any

import pytest

import sova.live.adaptive_campaign as adaptive
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import (
    AdaptiveBrowserPolicy,
    adaptive_browser_policy_from_mapping,
    owned_web_campaign,
    owned_web_target,
    run_adaptive_agent_browser_campaign,
)
from sova.live.agent_campaign import AgentBrowserCampaignArtifacts
from sova.live.campaign import BrowserCampaignArtifacts
from sova.models import ScriptedModel
from sova.runtime import ModelRouter, RoleKind
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _router() -> ModelRouter:
    return ModelRouter({RoleKind.RECON: (ScriptedModel([]),)})


def _run(
    tmp_path: Path,
    policy: AdaptiveBrowserPolicy,
    *,
    max_model_turns: int,
    max_total_tokens: int | None = None,
) -> Any:
    return run_adaptive_agent_browser_campaign(
        owned_web_target("http://127.0.0.1:9187"),
        owned_web_campaign("http://127.0.0.1:9187/"),
        policy,
        tmp_path / "adaptive",
        router=_router(),
        max_model_turns=max_model_turns,
        max_total_tokens=max_total_tokens,
        package_runner=tmp_path / "npx.exe",
        browser_executable=tmp_path / "browser.exe",
        approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
    )


def _fake_round(  # noqa: PLR0913 - edge fixture controls independent corruption axes
    destination: Path,
    *,
    digest: str = "sha256:" + "1" * 64,
    status: str = "not-confirmed",
    token_count: int | None = 1,
    candidate_count: int = 1,
    malformed: str | None = None,
) -> AgentBrowserCampaignArtifacts:
    browser_dir = destination / "browser"
    browser_dir.mkdir(parents=True)
    target = browser_dir / "target.json"
    campaign = browser_dir / "campaign.json"
    browser_report = browser_dir / "report.json"
    orchestration = destination / "agent-orchestration.sova-trace"
    report = destination / "report.json"
    target.write_bytes(b"{}\n")
    campaign.write_bytes(
        canonical_json_bytes(
            {"candidates": [[f"candidate-{index}"] for index in range(candidate_count)]}
        )
        + b"\n"
    )
    attempts: Any = [
        {
            "candidateDigest": digest,
            "sequence": ["candidate"],
            "triggered": False,
            "score": "0.25",
            "coverage": ["baseline"],
        }
    ]
    if malformed == "attempts":
        attempts = ["bad", {"sequence": "bad", "coverage": "bad"}]
    browser_report.write_bytes(
        canonical_json_bytes(
            {
                "status": status,
                "attempts": attempts,
                "search": {"stopReason": "candidate-source-exhausted"},
            }
        )
        + b"\n"
    )
    orchestration.write_bytes(b"synthetic round trace")
    roles: Any = [{"usage": {"tokenCount": token_count}}]
    if malformed == "roles":
        roles = ["bad"]
    report.write_bytes(
        canonical_json_bytes({"browserReport": "browser/report.json", "roles": roles}) + b"\n"
    )
    browser = BrowserCampaignArtifacts(
        target,
        campaign,
        (),
        None,
        None,
        browser_report,
        status,
    )
    return AgentBrowserCampaignArtifacts(browser, orchestration, report, status)


@pytest.mark.parametrize(
    ("policy", "code"),
    (
        (("", 1, 1, 1, 1), "SOVA-ADAPTIVE-POLICY-ID"),
        (("x", 1, 0, 1, 1), "SOVA-ADAPTIVE-POLICY-CANDIDATES"),
        (("x", 1, 1, 0, 1), "SOVA-ADAPTIVE-POLICY-DURATION"),
    ),
)
def test_adaptive_policy_constructor_rejects_invalid_boundaries(
    policy: tuple[str, int, int, int, int],
    code: str,
) -> None:
    with pytest.raises(FormatError) as captured:
        AdaptiveBrowserPolicy(*policy)
    assert captured.value.issue.code == code


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (
            lambda value: value.update({"artifactType": "wrong"}),
            "SOVA-ADAPTIVE-POLICY",
        ),
        (lambda value: value.update({"id": 7}), "SOVA-ADAPTIVE-POLICY-ID"),
        (lambda value: value.update({"budgets": []}), "SOVA-ADAPTIVE-POLICY"),
    ),
)
def test_adaptive_policy_parser_rejects_wrong_types(
    mutation: Callable[[dict[str, Any]], None],
    code: str,
) -> None:
    value = deepcopy(AdaptiveBrowserPolicy("x", 1, 1, 1, 1).to_mapping())
    mutation(value)
    with pytest.raises(FormatError) as captured:
        adaptive_browser_policy_from_mapping(value)
    assert captured.value.issue.code == code


def test_adaptive_helpers_fail_closed_on_malformed_round_artifacts(tmp_path: Path) -> None:
    artifacts = _fake_round(tmp_path / "one")
    artifacts.report.write_bytes(b"[]\n")
    with pytest.raises(FormatError, match="agent round report"):
        adaptive._browser_report(artifacts)

    artifacts = _fake_round(tmp_path / "two")
    artifacts.browser.campaign.write_bytes(b"{}\n")
    with pytest.raises(FormatError, match="campaign record"):
        adaptive._campaign_candidate_count(artifacts)

    artifacts = _fake_round(tmp_path / "three", malformed="roles")
    with pytest.raises(FormatError, match="usage record"):
        adaptive._round_token_count(artifacts)

    artifacts = _fake_round(tmp_path / "four", token_count=-1)
    with pytest.raises(FormatError, match="token count"):
        adaptive._round_token_count(artifacts)

    artifacts = _fake_round(tmp_path / "five", token_count=None)
    assert adaptive._round_token_count(artifacts) is None


def test_safe_round_context_omits_malformed_and_raw_target_content() -> None:
    context = adaptive._safe_round_context(
        1,
        {
            "status": "not-confirmed",
            "attempts": ["bad", {"sequence": "bad", "coverage": "bad"}],
            "search": "bad",
            "rawResponse": "must-not-propagate",
        },
    )
    assert context == {
        "round": 1,
        "status": "not-confirmed",
        "stopReason": None,
        "attempts": [
            {
                "candidateDigest": None,
                "sequence": [],
                "triggered": False,
                "score": "unknown",
                "coverage": [],
            }
        ],
        "targetContentCaptured": False,
    }
    assert adaptive._safe_round_context(2, {"attempts": "bad"})["attempts"] == []


def test_adaptive_runner_rejects_insufficient_budget_and_nonempty_destination(
    tmp_path: Path,
) -> None:
    policy = AdaptiveBrowserPolicy("x", 2, 2, 10, 1)
    with pytest.raises(FormatError) as turns:
        _run(tmp_path, policy, max_model_turns=9)
    assert turns.value.issue.code == "SOVA-ADAPTIVE-MODEL-BUDGET"

    destination = tmp_path / "adaptive"
    destination.mkdir()
    (destination / "occupied").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError) as occupied:
        _run(tmp_path, policy, max_model_turns=10)
    assert occupied.value.issue.code == "SOVA-LIVE-EXISTS"


def test_adaptive_runner_stops_on_stagnation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def runner(*args: Any, **_kwargs: Any) -> AgentBrowserCampaignArtifacts:
        nonlocal calls
        calls += 1
        return _fake_round(args[2], digest="sha256:" + "2" * 64)

    monkeypatch.setattr(adaptive, "run_agent_browser_campaign", runner)
    artifacts = _run(
        tmp_path,
        AdaptiveBrowserPolicy("x", 3, 3, 60, 1),
        max_model_turns=15,
    )
    assert calls == 2
    assert artifacts.status == "not-confirmed"
    report = strict_json_loads(artifacts.report.read_bytes())
    assert report["stopReason"] == "stagnation"
    assert TraceReader(artifacts.coordinator_trace).verify(require_signature=True).signature_valid


def test_adaptive_runner_distinguishes_duration_candidate_and_token_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 2.0, 2.0))
    monkeypatch.setattr("sova.live.adaptive_campaign.time.monotonic", lambda: next(ticks))
    duration = _run(
        tmp_path / "duration",
        AdaptiveBrowserPolicy("duration", 1, 1, 1, 1),
        max_model_turns=5,
    )
    duration_report = strict_json_loads(duration.report.read_bytes())
    assert duration_report["stopReason"] == "duration-budget"

    monkeypatch.setattr("sova.live.adaptive_campaign.time.monotonic", lambda: 0.0)
    monkeypatch.setattr(
        adaptive,
        "run_agent_browser_campaign",
        lambda *args, **_kwargs: _fake_round(args[2]),
    )
    candidates = _run(
        tmp_path / "candidates",
        AdaptiveBrowserPolicy("candidates", 2, 1, 60, 2),
        max_model_turns=10,
    )
    candidate_report = strict_json_loads(candidates.report.read_bytes())
    assert candidate_report["stopReason"] == "candidate-budget"

    tokens = _run(
        tmp_path / "tokens",
        AdaptiveBrowserPolicy("tokens", 1, 1, 60, 1),
        max_model_turns=5,
        max_total_tokens=0,
    )
    assert strict_json_loads(tokens.report.read_bytes())["stopReason"] == "token-budget"


def test_adaptive_runner_records_failed_trace_on_missing_token_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        adaptive,
        "run_agent_browser_campaign",
        lambda *args, **_kwargs: _fake_round(args[2], token_count=None),
    )
    with pytest.raises(FormatError, match="provider-reported usage"):
        _run(
            tmp_path,
            AdaptiveBrowserPolicy("tokens", 1, 1, 60, 1),
            max_model_turns=5,
            max_total_tokens=10,
        )
    failed_trace = tmp_path / "adaptive" / "adaptive-coordinator.sova-trace"
    assert TraceReader(failed_trace).verify(require_signature=True).signature_valid
    assert TraceReader(failed_trace).manifest()["completion"] == "failed"
