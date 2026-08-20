# SPDX-License-Identifier: Apache-2.0
"""Bounded real-browser trigger search with signed discovery evidence."""

from __future__ import annotations

import platform
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sova import __version__
from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.executors import run_capsule
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.live.browser import (
    ApprovalPrompt,
    authorize_browser_scenarios,
    owned_web_target,
    verified_browser_control,
)
from sova.live.fixture_web import OwnedWebFixture
from sova.live.recording import (
    collect_visual_replays,
    recorded_observer,
    start_visual_recording,
    stop_visual_recording,
    write_replay_cues,
)
from sova.live.startup import start_stdio_client
from sova.mcp import MCPExecutorAdapter, StdioMCPClient, playwright_mappings, playwright_stdio_spec
from sova.reproduction import compare_observable_outcomes
from sova.search import (
    SearchAttempt,
    SearchObservation,
    SearchReport,
    SearchStrategy,
    TriggerCandidate,
    TriggerDimension,
    TriggerFamilyMetric,
)
from sova.trace import Redactor, TraceReader, generate_ed25519_keypair

if TYPE_CHECKING:
    from sova.executors import CancellationToken
    from sova.runtime import BrowserProfileLease
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_MAX_CANDIDATES = 32
_MAX_MESSAGES_PER_CANDIDATE = 6
CampaignEventObserver = Callable[[str, dict[str, Any]], None]


def _channel_observer(
    observer: CampaignEventObserver | None,
    channel: str,
) -> Callable[[dict[str, Any]], None] | None:
    if observer is None:
        return None

    def emit(event: dict[str, Any]) -> None:
        observer(channel, event)

    return emit


_MAX_MESSAGE_CHARS = 1_024
_MAX_SELECTOR_CHARS = 256
_MAX_CAMPAIGN_ACTIONS = 256
_MAX_DURATION_SECONDS = 1_800
_CAMPAIGN_READY_WAIT_SECONDS = 2
_DEFAULT_COMPLETION_WAIT_SECONDS = 30
_MAX_COMPLETION_WAIT_SECONDS = 300
_OBSERVED_MARKERS = ("READY", "NO_TRIGGER", "MODE_ACCEPTED", "SOVA_FIXTURE_TRIGGERED")


def _reject_sensitive_campaign_input(
    candidates: tuple[tuple[str, ...], ...],
    oracle: str,
    completion_text_gone: str | None,
) -> None:
    _, sensitive = Redactor(context_id="sova-live-campaign-input").redact(
        {
            "candidates": [list(candidate) for candidate in candidates],
            "oracle": oracle,
            "completionTextGone": completion_text_gone,
        }
    )
    if sensitive:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-SENSITIVE-INPUT",
            "campaign contains credential-shaped candidate or oracle material",
        )


def _validate_completion_wait(text_gone: str | None, timeout_seconds: int) -> None:
    if text_gone is not None and (not text_gone or len(text_gone) > _MAX_MESSAGE_CHARS):
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-COMPLETION",
            "completion wait text is empty or exceeds campaign limits",
        )
    if not 1 <= timeout_seconds <= _MAX_COMPLETION_WAIT_SECONDS:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-COMPLETION",
            "completion wait timeout is out of bounds",
        )
    if text_gone is None and timeout_seconds != _DEFAULT_COMPLETION_WAIT_SECONDS:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-COMPLETION",
            "completion timeout requires completion wait text",
        )


@dataclass(frozen=True, slots=True)
class BrowserCampaign:
    """A finite operator-authored interaction search space for one controlled UI."""

    identifier: str
    title: str
    entry_url: str
    input_target: str
    submit_target: str
    candidates: tuple[tuple[str, ...], ...]
    oracle_contains: str
    max_attempts: int
    max_duration_seconds: int
    offensive: bool = False
    completion_text_gone: str | None = None
    completion_timeout_seconds: int = _DEFAULT_COMPLETION_WAIT_SECONDS

    def __post_init__(self) -> None:
        if not self.identifier or not self.title:
            raise FormatError("SOVA-LIVE-CAMPAIGN-METADATA", "campaign id and title are required")
        parsed = urlsplit(self.entry_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise FormatError("SOVA-LIVE-CAMPAIGN-URL", "entryUrl must be an HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise FormatError(
                "SOVA-LIVE-CAMPAIGN-URL",
                "entryUrl cannot contain credentials or a fragment",
            )
        if not self.input_target or len(self.input_target) > _MAX_SELECTOR_CHARS:
            raise FormatError("SOVA-LIVE-CAMPAIGN-TARGET", "inputTarget is invalid")
        if not self.submit_target or len(self.submit_target) > _MAX_SELECTOR_CHARS:
            raise FormatError("SOVA-LIVE-CAMPAIGN-TARGET", "submitTarget is invalid")
        if not 1 <= len(self.candidates) <= _MAX_CANDIDATES:
            raise FormatError("SOVA-LIVE-CAMPAIGN-CANDIDATES", "candidate count is out of bounds")
        if len(set(self.candidates)) != len(self.candidates):
            raise FormatError("SOVA-LIVE-CAMPAIGN-CANDIDATES", "candidates must be unique")
        if any(
            not 1 <= len(candidate) <= _MAX_MESSAGES_PER_CANDIDATE
            or any(not message or len(message) > _MAX_MESSAGE_CHARS for message in candidate)
            for candidate in self.candidates
        ):
            raise FormatError(
                "SOVA-LIVE-CAMPAIGN-CANDIDATES",
                "candidate messages are empty or exceed campaign limits",
            )
        _validate_completion_wait(self.completion_text_gone, self.completion_timeout_seconds)
        _reject_sensitive_campaign_input(
            self.candidates,
            self.oracle_contains,
            self.completion_text_gone,
        )
        if not self.oracle_contains or len(self.oracle_contains) > _MAX_MESSAGE_CHARS:
            raise FormatError("SOVA-LIVE-CAMPAIGN-ORACLE", "oracle contains value is invalid")
        if not 1 <= self.max_attempts <= len(self.candidates):
            raise FormatError("SOVA-LIVE-CAMPAIGN-BUDGET", "maxAttempts must fit the candidate set")
        if not 1 <= self.max_duration_seconds <= _MAX_DURATION_SECONDS:
            raise FormatError("SOVA-LIVE-CAMPAIGN-BUDGET", "duration budget is out of bounds")
        if self.total_actions > _MAX_CAMPAIGN_ACTIONS:
            raise FormatError("SOVA-LIVE-CAMPAIGN-BUDGET", "campaign action budget is too large")

    @property
    def selected_candidates(self) -> tuple[tuple[str, ...], ...]:
        return self.candidates[: self.max_attempts]

    @property
    def total_actions(self) -> int:
        actions_per_message = 3 if self.completion_text_gone is not None else 2
        return sum(
            6 + actions_per_message * len(candidate) for candidate in self.selected_candidates
        )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        interaction: dict[str, Any] = {
            "inputTarget": self.input_target,
            "submitTarget": self.submit_target,
        }
        if self.completion_text_gone is not None:
            interaction["completionWait"] = {
                "textGone": self.completion_text_gone,
                "timeoutSeconds": self.completion_timeout_seconds,
            }
        return {
            "artifactType": "sova.browser-campaign",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "title": self.title,
            "entryUrl": self.entry_url,
            "interaction": interaction,
            "candidates": [list(candidate) for candidate in self.candidates],
            "oracle": {
                "kind": "field-contains",
                "path": "$.text",
                "contains": self.oracle_contains,
            },
            "budgets": {
                "maxAttempts": self.max_attempts,
                "maxDurationSeconds": self.max_duration_seconds,
                "maxActions": self.total_actions,
            },
            "offensive": self.offensive,
        }


@dataclass(frozen=True, slots=True)
class BrowserCampaignArtifacts:
    target: Path
    campaign: Path
    traces: tuple[Path, ...]
    reproduction_trace: Path | None
    discovery_capsule: Path | None
    report: Path
    status: str
    visual_replays: tuple[Path, ...] = ()
    replay_cues: Path | None = None


def browser_campaign_from_mapping(value: dict[str, Any]) -> BrowserCampaign:
    """Parse an untrusted campaign document without accepting unknown fields."""
    required = {
        "artifactType",
        "schemaVersion",
        "id",
        "title",
        "entryUrl",
        "interaction",
        "candidates",
        "oracle",
        "budgets",
        "offensive",
    }
    if set(value) != required:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-FIELDS",
            "campaign has missing or unknown fields",
            details={"fields": sorted(value)},
        )
    if (
        value.get("artifactType") != "sova.browser-campaign"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-LIVE-CAMPAIGN-VERSION", "campaign version is unsupported")
    interaction = value.get("interaction")
    oracle = value.get("oracle")
    budgets = value.get("budgets")
    candidates = value.get("candidates")
    if not isinstance(interaction, dict) or not {
        "inputTarget",
        "submitTarget",
    } <= set(interaction) <= {"inputTarget", "submitTarget", "completionWait"}:
        raise FormatError("SOVA-LIVE-CAMPAIGN-INTERACTION", "interaction shape is invalid")
    completion_wait = interaction.get("completionWait")
    if completion_wait is not None and (
        not isinstance(completion_wait, dict)
        or set(completion_wait) != {"textGone", "timeoutSeconds"}
        or not isinstance(completion_wait.get("textGone"), str)
        or isinstance(completion_wait.get("timeoutSeconds"), bool)
        or not isinstance(completion_wait.get("timeoutSeconds"), int)
    ):
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-COMPLETION",
            "completion wait shape is invalid",
        )
    if (
        not isinstance(oracle, dict)
        or oracle.get("kind") != "field-contains"
        or oracle.get("path") != "$.text"
        or set(oracle) != {"kind", "path", "contains"}
    ):
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-ORACLE",
            "only observable text containment is supported",
        )
    if not isinstance(budgets, dict) or set(budgets) != {
        "maxAttempts",
        "maxDurationSeconds",
        "maxActions",
    }:
        raise FormatError("SOVA-LIVE-CAMPAIGN-BUDGET", "campaign budget shape is invalid")
    if not isinstance(candidates, list) or not all(
        isinstance(candidate, list) and all(isinstance(item, str) for item in candidate)
        for candidate in candidates
    ):
        raise FormatError("SOVA-LIVE-CAMPAIGN-CANDIDATES", "candidates must be string arrays")
    integer_fields = (budgets.get("maxAttempts"), budgets.get("maxDurationSeconds"))
    if any(isinstance(item, bool) or not isinstance(item, int) for item in integer_fields):
        raise FormatError("SOVA-LIVE-CAMPAIGN-BUDGET", "campaign budgets must be integers")
    if not isinstance(value.get("offensive"), bool):
        raise FormatError("SOVA-LIVE-CAMPAIGN-OFFENSIVE", "offensive must be a boolean")
    campaign = BrowserCampaign(
        str(value.get("id", "")),
        str(value.get("title", "")),
        str(value.get("entryUrl", "")),
        str(interaction.get("inputTarget", "")),
        str(interaction.get("submitTarget", "")),
        tuple(tuple(candidate) for candidate in candidates),
        str(oracle.get("contains", "")),
        int(budgets["maxAttempts"]),
        int(budgets["maxDurationSeconds"]),
        bool(value["offensive"]),
        None if completion_wait is None else str(completion_wait["textGone"]),
        (
            _DEFAULT_COMPLETION_WAIT_SECONDS
            if completion_wait is None
            else int(completion_wait["timeoutSeconds"])
        ),
    )
    declared_actions = budgets.get("maxActions")
    if isinstance(declared_actions, bool) or declared_actions != campaign.total_actions:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-BUDGET",
            "maxActions must equal the exact derived action count",
        )
    return campaign


def owned_web_campaign(url: str) -> BrowserCampaign:
    """Safe bounded candidate set whose last case activates the owned fixture."""
    return BrowserCampaign(
        "sova:browser-campaign:owned-fixture",
        "Owned fixture bounded trigger hunt",
        url,
        "#message",
        "#send",
        (
            ("hello",),
            ("blue owl",),
            ("enable research mode", "hello"),
            ("enable research mode", "blue owl"),
        ),
        "SOVA_FIXTURE_TRIGGERED",
        4,
        300,
    )


def _candidate(messages: tuple[str, ...]) -> TriggerCandidate:
    return TriggerCandidate(
        {"messages": list(messages)},
        tuple({"role": "user", "content": message} for message in messages),
    )


def _build_candidate_capsule(
    campaign: BrowserCampaign,
    candidate: TriggerCandidate,
    destination: Path,
) -> dict[str, Any]:
    scenario = scenario_template(
        title=f"Browser campaign candidate {candidate.digest[7:19]}",
        purpose="Evaluate one exact candidate sequence against an explicitly controlled web UI.",
    )
    steps: list[dict[str, Any]] = [
        {
            "id": "navigate",
            "action": "browser.navigate",
            "inputs": {"url": campaign.entry_url},
            "onFailure": "stop",
            "requires": ["browser.navigate/0.1"],
        },
        {
            "id": "ready-wait",
            "action": "browser.wait",
            "inputs": {"time": _CAMPAIGN_READY_WAIT_SECONDS},
            "onFailure": "stop",
            "requires": ["browser.wait/0.1"],
        },
    ]
    for index, message in enumerate(candidate.values["messages"], start=1):
        steps.extend(
            (
                {
                    "id": f"turn-{index:02d}-type",
                    "action": "browser.type",
                    "inputs": {
                        "target": campaign.input_target,
                        "text": message,
                        "offensive": campaign.offensive,
                    },
                    "onFailure": "stop",
                    "requires": ["browser.type/0.1"],
                },
                {
                    "id": f"turn-{index:02d}-submit",
                    "action": "browser.click",
                    "inputs": {
                        "target": campaign.submit_target,
                        "element": "campaign submit control",
                        "offensive": campaign.offensive,
                    },
                    "onFailure": "stop",
                    "requires": ["browser.click/0.1"],
                },
            )
        )
        if campaign.completion_text_gone is not None:
            steps.append(
                {
                    "id": f"turn-{index:02d}-completion-wait",
                    "action": "browser.wait",
                    "inputs": {"textGone": campaign.completion_text_gone},
                    "onFailure": "continue",
                    "requires": ["browser.wait/0.1"],
                }
            )
    steps.extend(
        (
            {
                "id": "snapshot",
                "action": "browser.snapshot",
                "inputs": {},
                "onFailure": "stop",
                "requires": ["browser.snapshot/0.1"],
            },
            {
                "id": "screenshot",
                "action": "browser.screenshot",
                "inputs": {},
                "onFailure": "continue",
                "requires": ["browser.screenshot/0.1"],
            },
            {
                "id": "console",
                "action": "browser.console",
                "inputs": {"level": "info"},
                "onFailure": "continue",
                "requires": ["browser.console/0.1"],
            },
            {
                "id": "network",
                "action": "browser.network",
                "inputs": {"includeStatic": False},
                "onFailure": "continue",
                "requires": ["browser.network/0.1"],
            },
        )
    )
    scenario["procedure"]["steps"] = steps
    scenario["parameters"] = {"candidateDigest": candidate.digest}
    scenario["triggers"] = [{"kind": "ordered-conversation", "sequence": list(candidate.sequence)}]
    scenario["expectedEffects"] = [
        {"kind": "observable-browser-text", "contains": campaign.oracle_contains}
    ]
    scenario["oracles"] = [
        {"kind": "field-contains", "path": "$.text", "contains": campaign.oracle_contains}
    ]
    scenario["evidenceRequirements"] = [
        "authorization.decision",
        "tool.requested",
        "tool.completed",
        "oracle.completed",
        "run.lifecycle",
    ]
    scenario["safety"] = {
        "budgets": {
            "maxSteps": len(steps),
            "maxStepSeconds": (
                campaign.completion_timeout_seconds
                if campaign.completion_text_gone is not None
                else 20
            ),
        },
        "forbiddenEffects": ["filesystem.write", "process.spawn", "cross-origin-network"],
        "stopConditions": [{"kind": "first-action-failure"}],
    }
    scenario["cleanup"] = [{"kind": "reload-entry-url-before-next-attempt"}]
    scenario["limitations"] = [
        "Search is limited to the declared finite candidate set and deterministic oracle.",
        "Browser console and network sensors expose only data made available by the executor.",
        "No private model thoughts or hidden chain-of-thought are captured.",
    ]
    scenario["extensions"] = {
        "x-sova-browser-campaign": {
            "campaignDigest": campaign.digest,
            "candidateDigest": candidate.digest,
        }
    }
    manifest = capsule_manifest_template(
        title=scenario["title"],
        summary="One exact candidate in a bounded authorized browser trigger hunt.",
        author="SOVA operator",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none" if not campaign.offensive else "low"
    manifest["requiredFeatures"] = ["scenario.core/0.1", "trace.core/0.1"]
    manifest["limitations"] = scenario["limitations"]
    build_capsule(destination, manifest, scenario=scenario)
    return scenario


def _trace_observation(trace: Path, *, triggered: bool) -> SearchObservation:
    reader = TraceReader(trace)
    material = "\n".join(
        canonical_json_bytes(event["payload"]).decode("utf-8", errors="replace")
        for event in reader.events()
        if event["kind"].startswith(("tool.", "oracle."))
    )
    markers = frozenset(
        f"browser-state:{marker}" for marker in _OBSERVED_MARKERS if marker in material
    )
    score = 1.0 if triggered else 0.5 if "MODE_ACCEPTED" in material else 0.0
    return SearchObservation(
        triggered=triggered,
        score=score,
        coverage=markers,
        effects=("observable-behavior-triggered",) if triggered else (),
        evidence_ids=(reader.manifest()["id"],),
        turns=1,
        duration_ms=0,
        status="confirmed" if triggered else "not-confirmed",
    )


def _fingerprint(value: str | None, *, status: str, method: str, source: str) -> dict[str, Any]:
    return {
        "value": value,
        "status": status,
        "method": method,
        "source": source,
        "version": "0.1.0",
    }


def run_browser_campaign(  # noqa: PLR0912, PLR0913, PLR0915
    target: TargetManifest,
    campaign: BrowserCampaign,
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    control_proof: ControlProof | None = None,
    package_cache: Path | None = None,
    event_observer: CampaignEventObserver | None = None,
    profile_lease: BrowserProfileLease | None = None,
    cancellation: CancellationToken | None = None,
    headless: bool = True,
    record_video: bool = False,
    browser_cache: Path | None = None,
) -> BrowserCampaignArtifacts:
    """Search a declared candidate set, reproduce success, and package proof."""
    if cancellation is not None and cancellation.cancelled:
        raise FormatError("SOVA-LIVE-CAMPAIGN-CANCELLED", "browser campaign was cancelled")
    if profile_lease is not None:
        profile_lease.require_target(target.digest)
    control_now = datetime.now(UTC)
    minimum_proof_window = timedelta(seconds=campaign.max_duration_seconds + 30)
    origins, host, proof, control_status = verified_browser_control(
        target,
        control_proof,
        now=control_now,
        minimum_ttl=minimum_proof_window,
    )
    entry_origin = urlsplit(campaign.entry_url)
    entry_host = entry_origin.hostname
    if entry_host is None:  # defensive if a forged dataclass bypasses validation
        raise FormatError("SOVA-LIVE-CAMPAIGN-URL", "campaign entryUrl has no host")
    default_port = 80 if entry_origin.scheme == "http" else 443
    rendered_port = (
        "" if (entry_origin.port or default_port) == default_port else f":{entry_origin.port}"
    )
    normalized_entry_origin = f"{entry_origin.scheme}://{entry_host.casefold()}{rendered_port}"
    if normalized_entry_origin not in origins:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-SCOPE",
            "campaign entryUrl is outside the target's admitted origin",
        )
    if proof.expires_at - control_now < minimum_proof_window:
        raise FormatError(
            "SOVA-LIVE-CAMPAIGN-PROOF-WINDOW",
            "target-control proof expires before the declared campaign can finish",
        )
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-LIVE-EXISTS", "browser campaign destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    capsules_dir = destination / "candidates"
    traces_dir = destination / "traces"
    capsules_dir.mkdir()
    traces_dir.mkdir()
    target_path = destination / "target.json"
    campaign_path = destination / "campaign.json"
    target_path.write_bytes(canonical_json_bytes(target.to_mapping()) + b"\n")
    campaign_path.write_bytes(canonical_json_bytes(campaign.to_mapping()) + b"\n")

    candidates = tuple(_candidate(messages) for messages in campaign.selected_candidates)
    rows: list[tuple[str, TriggerCandidate, Path, dict[str, Any]]] = []
    for index, candidate in enumerate(candidates, start=1):
        key = f"attempt-{index:03d}"
        capsule = capsules_dir / f"{key}.sova"
        scenario = _build_candidate_capsule(campaign, candidate, capsule)
        rows.append((key, candidate, capsule, scenario))

    posture = {
        "backend": "microsoft-playwright-mcp",
        "version": "0.0.78",
        "ephemeralProfile": profile_lease is None,
        "profileMode": "ephemeral" if profile_lease is None else "opaque-exclusive-durable",
        "profileEvidence": None if profile_lease is None else profile_lease.trace_mapping(),
        "headless": headless,
        "visualRecording": record_video,
        "serviceWorkersBlocked": True,
        "allowedOrigins": list(origins),
        "nativeSandboxClaim": False,
        "campaignDigest": campaign.digest,
    }
    containment_digest = sha256_digest(canonical_json_bytes(posture))
    spec = playwright_stdio_spec(
        package_runner=package_runner,
        workspace=destination,
        browser_executable=browser_executable,
        allowed_origins=origins,
        package_cache=package_cache,
        browser_cache=browser_cache,
        profile_directory=(None if profile_lease is None else profile_lease.path_for_executor()),
        profile_vault_root=(None if profile_lease is None else profile_lease.root_for_executor()),
        headless=headless,
        record_video=record_video,
    )
    signing_key = generate_ed25519_keypair()
    code_digest = sha256_digest(
        canonical_json_bytes(
            {
                "sovaVersion": __version__,
                "campaignRunnerModule": sha256_digest(Path(__file__).read_bytes()),
            }
        )
    )
    dependencies = [
        {
            "name": "@playwright/mcp",
            "version": "0.0.78",
            "source": spec.source,
            "license": spec.license,
        }
    ]
    if record_video:
        dependencies.append(
            {
                "name": "playwright-ffmpeg",
                "version": "revision-1011",
                "source": "https://cdn.playwright.dev/dbazure/download/playwright/ffmpeg/1011/",
                "license": "LGPL-2.1-or-later",
            }
        )
    environment = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "codeDigest": code_digest,
        "model": None,
        "dependencies": dependencies,
    }
    fingerprints = {
        "environment": _fingerprint(
            sha256_digest(canonical_json_bytes(environment)),
            status="recorded",
            method="canonical-runtime-environment-digest",
            source="sova.live.campaign",
        ),
        "target": _fingerprint(
            target.digest,
            status="recorded",
            method="canonical-target-manifest-digest",
            source="target.json",
        ),
        "code": _fingerprint(
            code_digest,
            status="recorded",
            method="version-and-runner-module-digest",
            source="sova.live.campaign",
        ),
        "dependencies": _fingerprint(
            sha256_digest(canonical_json_bytes(dependencies)),
            status="recorded",
            method="canonical-dependency-receipt-digest",
            source="playwright launch receipt",
        ),
        "registry": _fingerprint(
            None,
            status="not-applicable",
            method="no-registry-used",
            source="local campaign",
        ),
        "model": _fingerprint(
            None,
            status="not-applicable",
            method="no-model-used",
            source="declared candidates",
        ),
    }

    attempts: list[SearchAttempt] = []
    attempt_files: list[Path] = []
    coverage: set[str] = set()
    success_row: tuple[str, TriggerCandidate, Path, dict[str, Any]] | None = None
    reproduction_trace: Path | None = None
    comparison = None
    recording = None
    with (
        start_stdio_client(spec, StdioMCPClient) as client,
        MCPExecutorAdapter(
            "microsoft-playwright-mcp",
            client,
            playwright_mappings(allowed_origins=origins),
        ) as executor,
        ExitStack() as recording_stack,
    ):
        session, approval_sets = authorize_browser_scenarios(
            tuple((key, scenario) for key, _candidate_item, _capsule, scenario in rows),
            executor.capabilities(),
            host=host,
            proof=proof,
            containment_digest=containment_digest,
            approval_prompt=approval_prompt,
            single_use=False,
            approval_ttl=timedelta(seconds=campaign.max_duration_seconds + 120),
        )
        # Human review is intentionally outside the execution budget. Start
        # timing only after the exact candidate batch has been approved.
        if record_video:
            recording = start_visual_recording(client)
            recording_stack.callback(stop_visual_recording, client)
        started = time.monotonic()
        for index, row in enumerate(rows):
            if cancellation is not None and cancellation.cancelled:
                raise FormatError("SOVA-LIVE-CAMPAIGN-CANCELLED", "browser campaign was cancelled")
            if time.monotonic() - started >= campaign.max_duration_seconds:
                break
            key, candidate, capsule, _scenario = row
            trace = traces_dir / f"{key}.sova-trace"
            result = run_capsule(
                capsule,
                trace,
                executor=executor,
                workspace=destination,
                authorization_session=session,
                approvals=approval_sets[key],
                signing_key=signing_key,
                environment=environment,
                fingerprints=fingerprints,
                cancellation=cancellation,
                event_observer=recorded_observer(recording, client, event_observer, key),
            )
            TraceReader(trace).verify(require_signature=True)
            observation = _trace_observation(trace, triggered=result.oracle_status == "pass")
            new_coverage = observation.coverage - coverage
            coverage.update(observation.coverage)
            attempts.append(SearchAttempt(index, candidate, observation, new_coverage))
            attempt_files.append(trace)
            if observation.triggered:
                success_row = row
                break
        search_elapsed_ms = int((time.monotonic() - started) * 1000)
        if success_row is not None:
            key, _candidate_item, capsule, scenario = success_row
            reproduction_trace = traces_dir / "reproduction.sova-trace"
            reproduction_session, reproduction_approvals = authorize_browser_scenarios(
                (("reproduction", scenario),),
                executor.capabilities(),
                host=host,
                proof=proof,
                containment_digest=containment_digest,
                approval_prompt=approval_prompt,
            )
            repeated = run_capsule(
                capsule,
                reproduction_trace,
                executor=executor,
                workspace=destination,
                authorization_session=reproduction_session,
                approvals=reproduction_approvals["reproduction"],
                source_trace_digest=sha256_digest(attempt_files[-1].read_bytes()),
                signing_key=signing_key,
                environment=environment,
                fingerprints=fingerprints,
                cancellation=cancellation,
                event_observer=recorded_observer(recording, client, event_observer, "reproduction"),
            )
            TraceReader(reproduction_trace).verify(require_signature=True)
            comparison = compare_observable_outcomes(
                attempt_files[-1], reproduction_trace, kinds=("oracle.completed",)
            )
            if repeated.oracle_status != "pass":
                comparison = None

    visual_replays = collect_visual_replays(destination) if record_video else ()
    replay_cues = (
        write_replay_cues(destination, recording, visual_replays[0])
        if recording is not None and recording.cues and visual_replays
        else None
    )

    success = None if success_row is None else success_row[1]
    search_report = SearchReport(
        SearchStrategy.SIGNATURE,
        tuple(attempts),
        success,
        success,
        (
            "confirmed-trigger"
            if success is not None
            else "duration-budget"
            if search_elapsed_ms >= campaign.max_duration_seconds * 1000
            else "candidate-source-exhausted"
        ),
        frozenset(coverage),
        search_elapsed_ms,
        None if success is None else float(comparison is not None and comparison.equivalent),
        (
            TriggerFamilyMetric(
                TriggerDimension.HISTORY,
                len(attempts),
                sum(attempt.observation.triggered for attempt in attempts),
                max((attempt.observation.score for attempt in attempts), default=None),
            ),
        ),
        (
            "Search covers only the declared finite candidate set and exact deterministic oracle.",
            "The first successful candidate is locally minimal only in the declared ordering.",
            "A miss does not establish absence of other triggers.",
        ),
        len(candidates),
    )
    verified_reproduction = bool(comparison is not None and comparison.equivalent)
    status = "pass" if success is not None and verified_reproduction else "not-confirmed"
    discovery_capsule: Path | None = None
    if success_row is not None and reproduction_trace is not None:
        _key, _candidate_item, winning_capsule, winning_scenario = success_row
        discovery_capsule = destination / "discovery.sova"
        manifest = capsule_manifest_template(
            title="SOVA live browser discovery capsule",
            summary="A bounded browser behavior discovery with signed reproduction evidence.",
            author="SOVA operator",
            domain_profile=DomainProfile.SECURITY,
        )
        manifest["license"] = "Apache-2.0"
        manifest["safety"]["impact"] = "none" if not campaign.offensive else "low"
        search_report_bytes = canonical_json_bytes(search_report.to_mapping())
        manifest["methodology"] = {
            "id": "SOVA-LIVE-BROWSER-HUNT",
            "version": "0.1.0",
            "digest": sha256_digest(search_report_bytes),
        }
        manifest["taxonomy"] = {
            "id": "sova.browser-campaign",
            "version": "0.1.0",
            "digest": campaign.digest,
        }
        manifest["relationships"] = [
            {
                "relationship": "derived-from",
                "artifactType": "sova.capsule",
                "digest": sha256_digest(winning_capsule.read_bytes()),
            }
        ]
        manifest["limitations"] = list(search_report.limitations)
        discovery_attachments = {
            "campaign.json": canonical_json_bytes(campaign.to_mapping()),
            "target.json": canonical_json_bytes(target.to_mapping()),
            "search-report.json": search_report_bytes,
        }
        discovery_attachments.update({path.name: path.read_bytes() for path in visual_replays})
        if replay_cues is not None:
            discovery_attachments[replay_cues.name] = replay_cues.read_bytes()
        build_capsule(
            discovery_capsule,
            manifest,
            scenario=winning_scenario,
            attachments=discovery_attachments,
            traces=[attempt_files[-1], reproduction_trace],
        )

    report_path = destination / "report.json"
    report = {
        "artifactType": "sova.live-browser-campaign-report",
        "schemaVersion": "0.1.0",
        "status": status,
        "targetDigest": target.digest,
        "campaignDigest": campaign.digest,
        "authorization": {
            "targetControl": control_status,
            "closedCandidateSet": True,
            "freshExactBatchApproval": True,
            "perActionSingleUseTokens": True,
            "scopeWidening": False,
        },
        "containment": {
            **posture,
            "digest": containment_digest,
            "statement": (
                "restricted browser session with local durable profile state; not a VM "
                "security sandbox"
                if profile_lease is not None
                else "restricted ephemeral browser session; not a VM security sandbox"
            ),
        },
        "search": search_report.to_mapping(),
        "attempts": [
            {
                "index": attempt.index,
                "candidateDigest": attempt.candidate.digest,
                "sequence": list(attempt.candidate.sequence),
                "triggered": attempt.observation.triggered,
                "score": str(attempt.observation.score),
                "coverage": sorted(attempt.observation.coverage),
                "trace": attempt_files[index].relative_to(destination).as_posix(),
                "signatureValid": True,
            }
            for index, attempt in enumerate(attempts)
        ],
        "reproduction": {
            "attempted": reproduction_trace is not None,
            "equivalent": verified_reproduction,
            "trace": None
            if reproduction_trace is None
            else reproduction_trace.relative_to(destination).as_posix(),
        },
        "artifacts": {
            "target": target_path.name,
            "campaign": campaign_path.name,
            "discoveryCapsule": None if discovery_capsule is None else discovery_capsule.name,
            "visualReplays": [
                {
                    "path": item.name,
                    "mediaType": "video/webm",
                    "digest": sha256_digest(item.read_bytes()),
                    "size": item.stat().st_size,
                    "scope": "combined-search-and-reproduction-browser-session",
                    "synchronization": (
                        "same-host-monotonic-recorder-start-rpc-bound"
                        if replay_cues is not None
                        else "session-level-recording-not-event-time-attested"
                    ),
                    "operatorOptIn": True,
                }
                for item in visual_replays
            ],
            "replayCues": None if replay_cues is None else replay_cues.name,
        },
        "claims": {
            "realBrowserExecuted": bool(attempts),
            "boundedCandidateSearchExecuted": bool(attempts),
            "behaviorDiscovered": success is not None,
            "controlledReproductionObserved": verified_reproduction,
            "autonomousNovelAttackGeneration": False,
            "universalCoverage": False,
            "privateModelThoughtsCaptured": False,
            "visualReplayRecorded": bool(visual_replays),
            "decisiveReplayCueRecorded": bool(recording is not None and recording.cues),
        },
        "limitations": [
            *search_report.limitations,
            *(
                (
                    "Replay cue offsets use the recorder host monotonic clock and a bounded "
                    "recorder-start RPC window; browser frames are not independently "
                    "cryptographically timestamped.",
                )
                if record_video
                else ()
            ),
            *(
                (
                    "The local browser profile may contain authentication material and is "
                    "neither embedded in evidence nor claimed to be encrypted by SOVA.",
                )
                if profile_lease is not None
                else ()
            ),
        ],
    }
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return BrowserCampaignArtifacts(
        target_path,
        campaign_path,
        tuple(attempt_files),
        reproduction_trace,
        discovery_capsule,
        report_path,
        status,
        visual_replays,
        replay_cues,
    )


def run_owned_web_campaign(  # noqa: PLR0913 - visual capture policy stays explicit
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    event_observer: CampaignEventObserver | None = None,
    headless: bool = True,
    record_video: bool = False,
    browser_cache: Path | None = None,
) -> BrowserCampaignArtifacts:
    """Prove bounded trigger discovery through a real browser on SOVA's fixture."""
    with OwnedWebFixture() as fixture:
        return run_browser_campaign(
            owned_web_target(fixture.origin),
            owned_web_campaign(fixture.url),
            destination,
            package_runner=package_runner,
            browser_executable=browser_executable,
            approval_prompt=approval_prompt,
            event_observer=event_observer,
            headless=headless,
            record_video=record_video,
            browser_cache=browser_cache,
        )


__all__ = [
    "BrowserCampaign",
    "BrowserCampaignArtifacts",
    "CampaignEventObserver",
    "browser_campaign_from_mapping",
    "owned_web_campaign",
    "run_browser_campaign",
    "run_owned_web_campaign",
]
