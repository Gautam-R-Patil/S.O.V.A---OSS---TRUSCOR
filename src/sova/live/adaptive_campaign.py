# SPDX-License-Identifier: Apache-2.0
"""Bounded observe-plan-review-execute loops for authorized browser research."""

from __future__ import annotations

import time
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Never

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.agent_campaign import AgentBrowserCampaignArtifacts, run_agent_browser_campaign
from sova.live.campaign import BrowserCampaign
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.live.agent_campaign import AgentCampaignEventObserver
    from sova.live.browser import ApprovalPrompt
    from sova.runtime import ModelRouter
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_MAX_ROUNDS = 8
_MAX_TOTAL_CANDIDATES = 64
_MAX_DURATION_SECONDS = 3600
_TURNS_PER_ROUND = 5
_MAX_IDENTIFIER_CHARS = 160


@dataclass(frozen=True, slots=True)
class AdaptiveBrowserPolicy:
    """Operator-declared hard ceilings for one adaptive campaign."""

    identifier: str
    max_rounds: int
    max_total_candidates: int
    max_duration_seconds: int
    max_stagnant_rounds: int = 1

    def __post_init__(self) -> None:
        if not self.identifier or len(self.identifier) > _MAX_IDENTIFIER_CHARS:
            raise FormatError("SOVA-ADAPTIVE-POLICY-ID", "adaptive policy id is invalid")
        if not 1 <= self.max_rounds <= _MAX_ROUNDS:
            raise FormatError("SOVA-ADAPTIVE-POLICY-ROUNDS", "maxRounds is out of bounds")
        if not 1 <= self.max_total_candidates <= _MAX_TOTAL_CANDIDATES:
            raise FormatError(
                "SOVA-ADAPTIVE-POLICY-CANDIDATES",
                "maxTotalCandidates is out of bounds",
            )
        if not 1 <= self.max_duration_seconds <= _MAX_DURATION_SECONDS:
            raise FormatError(
                "SOVA-ADAPTIVE-POLICY-DURATION",
                "maxDurationSeconds is out of bounds",
            )
        if not 1 <= self.max_stagnant_rounds <= self.max_rounds:
            raise FormatError(
                "SOVA-ADAPTIVE-POLICY-STAGNATION",
                "maxStagnantRounds must fit maxRounds",
            )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.adaptive-browser-policy",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "budgets": {
                "maxRounds": self.max_rounds,
                "maxTotalCandidates": self.max_total_candidates,
                "maxDurationSeconds": self.max_duration_seconds,
                "maxStagnantRounds": self.max_stagnant_rounds,
            },
        }


@dataclass(frozen=True, slots=True)
class AdaptiveBrowserCampaignArtifacts:
    """Files produced by the adaptive coordinator."""

    rounds: tuple[AgentBrowserCampaignArtifacts, ...]
    coordinator_trace: Path
    report: Path
    discovery_capsule: Path | None
    status: str


def adaptive_browser_policy_from_mapping(value: dict[str, Any]) -> AdaptiveBrowserPolicy:
    """Parse a strict adaptive policy document."""
    expected = {"artifactType", "schemaVersion", "id", "budgets"}
    if set(value) != expected:
        raise FormatError("SOVA-ADAPTIVE-POLICY", "adaptive policy fields are invalid")
    if value.get("artifactType") != "sova.adaptive-browser-policy":
        raise FormatError("SOVA-ADAPTIVE-POLICY", "adaptive policy artifactType is invalid")
    if value.get("schemaVersion") != "0.1.0":
        raise FormatError("SOVA-ADAPTIVE-POLICY", "adaptive policy version is unsupported")
    budgets = value.get("budgets")
    if not isinstance(budgets, dict) or set(budgets) != {
        "maxRounds",
        "maxTotalCandidates",
        "maxDurationSeconds",
        "maxStagnantRounds",
    }:
        raise FormatError("SOVA-ADAPTIVE-POLICY", "adaptive policy budgets are invalid")
    identifier = value.get("id")
    if not isinstance(identifier, str):
        raise FormatError("SOVA-ADAPTIVE-POLICY-ID", "adaptive policy id must be a string")
    integer_fields = (
        "maxRounds",
        "maxTotalCandidates",
        "maxDurationSeconds",
        "maxStagnantRounds",
    )
    if any(type(budgets.get(field)) is not int for field in integer_fields):
        raise FormatError("SOVA-ADAPTIVE-POLICY", "adaptive policy budgets must be integers")
    return AdaptiveBrowserPolicy(
        identifier,
        budgets["maxRounds"],
        budgets["maxTotalCandidates"],
        budgets["maxDurationSeconds"],
        budgets["maxStagnantRounds"],
    )


def _round_campaign(
    base: BrowserCampaign,
    *,
    round_index: int,
    candidate_budget: int,
    duration_budget: int,
) -> BrowserCampaign:
    count = min(base.max_attempts, candidate_budget)
    declared = base.candidates[:count]
    return BrowserCampaign(
        f"{base.identifier}:adaptive-round-{round_index}",
        f"{base.title} (adaptive round {round_index})",
        base.entry_url,
        base.input_target,
        base.submit_target,
        declared,
        base.oracle_contains,
        count,
        min(base.max_duration_seconds, duration_budget),
        base.offensive,
    )


def _browser_report(artifacts: AgentBrowserCampaignArtifacts) -> dict[str, Any]:
    agent = strict_json_loads(artifacts.report.read_bytes())
    if not isinstance(agent, dict) or not isinstance(agent.get("browserReport"), str):
        raise FormatError("SOVA-ADAPTIVE-REPORT", "agent round report is invalid")
    browser_path = artifacts.report.parent / agent["browserReport"]
    browser = strict_json_loads(browser_path.read_bytes())
    if not isinstance(browser, dict):
        raise FormatError("SOVA-ADAPTIVE-REPORT", "browser round report is invalid")
    return browser


def _campaign_candidate_count(artifacts: AgentBrowserCampaignArtifacts) -> int:
    campaign_path = artifacts.report.parent / "browser" / "campaign.json"
    campaign = strict_json_loads(campaign_path.read_bytes())
    if not isinstance(campaign, dict) or not isinstance(campaign.get("candidates"), list):
        raise FormatError("SOVA-ADAPTIVE-REPORT", "round campaign record is invalid")
    return len(campaign["candidates"])


def _safe_round_context(index: int, browser: dict[str, Any]) -> dict[str, Any]:
    attempts = browser.get("attempts")
    safe_attempts: list[dict[str, Any]] = []
    if isinstance(attempts, list):
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            sequence = attempt.get("sequence")
            safe_sequence = (
                sequence
                if isinstance(sequence, list)
                and all(isinstance(message, str) for message in sequence)
                else []
            )
            coverage = attempt.get("coverage")
            safe_attempts.append(
                {
                    "candidateDigest": attempt.get("candidateDigest"),
                    "sequence": safe_sequence,
                    "triggered": attempt.get("triggered") is True,
                    "score": str(attempt.get("score", "unknown")),
                    "coverage": (
                        coverage
                        if isinstance(coverage, list)
                        and all(isinstance(item, str) for item in coverage)
                        else []
                    ),
                }
            )
    search = browser.get("search")
    return {
        "round": index,
        "status": browser.get("status"),
        "stopReason": search.get("stopReason") if isinstance(search, dict) else None,
        "attempts": safe_attempts,
        "targetContentCaptured": False,
    }


def _round_token_count(artifacts: AgentBrowserCampaignArtifacts) -> int | None:
    report = strict_json_loads(artifacts.report.read_bytes())
    if not isinstance(report, dict) or not isinstance(report.get("roles"), list):
        raise FormatError("SOVA-ADAPTIVE-REPORT", "agent role audit is invalid")
    total = 0
    for role in report["roles"]:
        if not isinstance(role, dict) or not isinstance(role.get("usage"), dict):
            raise FormatError("SOVA-ADAPTIVE-REPORT", "agent usage record is invalid")
        count = role["usage"].get("tokenCount")
        if count is None:
            return None
        if type(count) is not int or count < 0:
            raise FormatError("SOVA-ADAPTIVE-REPORT", "agent token count is invalid")
        total += count
    return total


def _budget_error(message: str) -> Never:
    raise FormatError("SOVA-ADAPTIVE-MODEL-BUDGET", message)


def _round_observer(
    observer: AgentCampaignEventObserver | None,
    index: int,
) -> AgentCampaignEventObserver | None:
    if observer is None:
        return None

    def emit(channel: str, event: dict[str, Any]) -> None:
        observer(f"round-{index:03d}/{channel}", event)

    return emit


def _coordinator_observer(
    observer: AgentCampaignEventObserver | None,
) -> Callable[[dict[str, Any]], None] | None:
    if observer is None:
        return None

    def emit(event: dict[str, Any]) -> None:
        observer("adaptive-coordinator", event)

    return emit


def run_adaptive_agent_browser_campaign(  # noqa: PLR0913, PLR0915
    target: TargetManifest,
    base_campaign: BrowserCampaign,
    policy: AdaptiveBrowserPolicy,
    destination: Path,
    *,
    router: ModelRouter,
    max_model_turns: int,
    max_total_tokens: int | None,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    control_proof: ControlProof | None = None,
    event_observer: AgentCampaignEventObserver | None = None,
) -> AdaptiveBrowserCampaignArtifacts:
    """Iterate over reviewed batches while preserving exact scope and hard budgets."""
    required_turns = policy.max_rounds * _TURNS_PER_ROUND
    if max_model_turns < required_turns:
        raise FormatError(
            "SOVA-ADAPTIVE-MODEL-BUDGET",
            "model-turn budget cannot cover the declared maximum rounds",
            details={"required": required_turns, "available": max_model_turns},
        )
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-LIVE-EXISTS", "adaptive campaign destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    rounds_dir = destination / "rounds"
    rounds_dir.mkdir()
    coordinator_trace = destination / "adaptive-coordinator.sova-trace"
    report_path = destination / "report.json"
    writer = TraceWriter(
        coordinator_trace,
        authorization={
            "decision": "not-required",
            "scopeDigest": target.digest,
            "decidedBy": "sova.adaptive-browser-coordinator/0.1.0",
        },
        signing_key=generate_ed25519_keypair(),
        event_observer=_coordinator_observer(event_observer),
    )
    writer.append(
        "run.started",
        {
            "runtime": "sova.adaptive-browser-coordinator/0.1.0",
            "targetDigest": target.digest,
            "baseCampaignDigest": base_campaign.digest,
            "policyDigest": policy.digest,
            "roundApprovalMode": "fresh-exact-batch",
            "targetContentPassedBetweenRounds": False,
        },
    )
    started = time.monotonic()
    rounds: list[AgentBrowserCampaignArtifacts] = []
    prior_rounds: list[dict[str, Any]] = []
    round_rows: list[dict[str, Any]] = []
    seen_candidates: set[str] = set()
    generated_candidates = 0
    consumed_tokens = 0
    stagnant_rounds = 0
    stop_reason = "max-rounds"
    discovery_capsule: Path | None = None
    status = "not-confirmed"
    try:
        for round_index in range(1, policy.max_rounds + 1):
            elapsed = int(time.monotonic() - started)
            remaining_seconds = policy.max_duration_seconds - elapsed
            remaining_candidates = policy.max_total_candidates - generated_candidates
            if remaining_seconds <= 0:
                stop_reason = "duration-budget"
                break
            if remaining_candidates <= 0:
                stop_reason = "candidate-budget"
                break
            round_campaign = _round_campaign(
                base_campaign,
                round_index=round_index,
                candidate_budget=remaining_candidates,
                duration_budget=remaining_seconds,
            )
            remaining_tokens = (
                None if max_total_tokens is None else max_total_tokens - consumed_tokens
            )
            if remaining_tokens is not None and remaining_tokens <= 0:
                stop_reason = "token-budget"
                break
            artifacts = run_agent_browser_campaign(
                target,
                round_campaign,
                rounds_dir / f"round-{round_index:03d}",
                router=router,
                max_model_turns=_TURNS_PER_ROUND,
                max_total_tokens=remaining_tokens,
                package_runner=package_runner,
                browser_executable=browser_executable,
                approval_prompt=approval_prompt,
                control_proof=control_proof,
                event_observer=_round_observer(event_observer, round_index),
                prior_rounds=tuple(prior_rounds),
            )
            rounds.append(artifacts)
            candidate_count = _campaign_candidate_count(artifacts)
            generated_candidates += candidate_count
            round_tokens = _round_token_count(artifacts)
            if max_total_tokens is not None:
                if round_tokens is None:
                    _budget_error("global token budget requires provider-reported usage")
                consumed_tokens += round_tokens
                if consumed_tokens > max_total_tokens:
                    _budget_error("global token budget was exceeded")
            browser = _browser_report(artifacts)
            context = _safe_round_context(round_index, browser)
            prior_rounds.append(context)
            digests = {
                str(attempt["candidateDigest"])
                for attempt in context["attempts"]
                if isinstance(attempt, dict) and isinstance(attempt.get("candidateDigest"), str)
            }
            novel = digests - seen_candidates
            seen_candidates.update(digests)
            stagnant_rounds = 0 if novel else stagnant_rounds + 1
            row = {
                "round": round_index,
                "status": artifacts.status,
                "generatedCandidates": candidate_count,
                "executedCandidateDigests": sorted(digests),
                "novelExecutedCandidateDigests": sorted(novel),
                "agentReportDigest": sha256_digest(artifacts.report.read_bytes()),
                "orchestrationTraceDigest": sha256_digest(
                    artifacts.orchestration_trace.read_bytes()
                ),
                "browserReportDigest": sha256_digest(
                    (artifacts.report.parent / "browser" / "report.json").read_bytes()
                ),
                "tokenCount": round_tokens,
                "freshExactBatchApproval": True,
            }
            round_rows.append(row)
            writer.append("attempt.completed", row, phase=f"round-{round_index:03d}")
            if artifacts.status == "pass":
                status = "pass"
                stop_reason = "confirmed-and-reproduced"
                discovery_capsule = artifacts.browser.discovery_capsule
                break
            if stagnant_rounds >= policy.max_stagnant_rounds:
                stop_reason = "stagnation"
                break
        writer.append(
            "run.completed",
            {
                "completion": "completed",
                "status": status,
                "stopReason": stop_reason,
                "rounds": len(rounds),
                "generatedCandidates": generated_candidates,
                "tokenCount": consumed_tokens if max_total_tokens is not None else None,
            },
        )
        writer.finalize()
    except Exception:
        with suppress(Exception):
            writer.append("run.failed", {"completion": "failed", "stopReason": "error"})
            writer.finalize(completion="failed")
        raise

    TraceReader(coordinator_trace).verify(require_signature=True)
    report = {
        "artifactType": "sova.adaptive-browser-campaign-report",
        "schemaVersion": "0.1.0",
        "status": status,
        "stopReason": stop_reason,
        "targetDigest": target.digest,
        "baseCampaignDigest": base_campaign.digest,
        "policy": policy.to_mapping(),
        "coordinatorTrace": coordinator_trace.name,
        "rounds": round_rows,
        "budgets": {
            "modelTurnsUsed": len(rounds) * _TURNS_PER_ROUND,
            "modelTurnsMaximum": max_model_turns,
            "generatedCandidates": generated_candidates,
            "candidateMaximum": policy.max_total_candidates,
            "tokenCount": consumed_tokens if max_total_tokens is not None else None,
            "tokenMaximum": max_total_tokens,
            "elapsedMilliseconds": int((time.monotonic() - started) * 1000),
            "durationMaximumSeconds": policy.max_duration_seconds,
        },
        "authorization": {
            "freshExactBatchApprovalEachRound": True,
            "scopeWidening": False,
            "accountCreationAutomated": False,
            "captchaBypassAutomated": False,
            "credentialMaterialAcceptedInCampaign": False,
        },
        "adaptation": {
            "priorCandidateSequencesAvailableToPlanner": True,
            "deterministicScoresAndCoverageAvailableToPlanner": True,
            "rawTargetContentAvailableToPlanner": False,
            "providerOutputIsExecutionEvidence": False,
        },
        "discoveryCapsule": (
            None
            if discovery_capsule is None
            else discovery_capsule.relative_to(destination).as_posix()
        ),
        "limitations": [
            "The coordinator adapts candidate batches, not arbitrary browser actions.",
            "Each round reruns candidates in an ephemeral browser context.",
            "A miss does not establish that no trigger exists outside the bounded search.",
            (
                "Provider output is untrusted planning data and cannot override "
                "deterministic evidence."
            ),
        ],
    }
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return AdaptiveBrowserCampaignArtifacts(
        tuple(rounds),
        coordinator_trace,
        report_path,
        discovery_capsule,
        status,
    )


__all__ = [
    "AdaptiveBrowserCampaignArtifacts",
    "AdaptiveBrowserPolicy",
    "adaptive_browser_policy_from_mapping",
    "run_adaptive_agent_browser_campaign",
]
