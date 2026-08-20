# SPDX-License-Identifier: Apache-2.0
"""Signed Playwright execution for policy-confined semantic browser missions."""

from __future__ import annotations

import contextlib
import math
import platform
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova import __version__
from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    FailureCause,
    OutcomeStatus,
    SideEffect,
    run_capsule,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.live.browser import (
    ApprovalPrompt,
    authorize_browser_scenarios,
    verified_browser_control,
)
from sova.live.recording import (
    add_visual_chapter,
    collect_visual_replays,
    recorded_observer,
    start_visual_recording,
    stop_visual_recording,
    write_replay_cues,
)
from sova.live.semantic_workflow import (
    SemanticBrowserAction,
    SemanticBrowserDriver,
    SemanticBrowserMission,
    SemanticBrowserObservation,
    SemanticExecutionBatch,
    SemanticWorkflowResult,
    run_semantic_browser_workflow,
)
from sova.live.startup import start_stdio_client
from sova.mcp import MCPExecutorAdapter, StdioMCPClient, playwright_mappings, playwright_stdio_spec
from sova.reproduction import compare_observable_outcomes
from sova.trace import Redactor, TraceReader, generate_ed25519_keypair

if TYPE_CHECKING:
    from sova.executors import CancellationToken
    from sova.runtime import BrowserProfileLease, ModelRouter
    from sova.safety import ControlProof
    from sova.targets import TargetManifest
    from sova.trace.integrity import Ed25519Keypair

SemanticBrowserEventObserver = Callable[[str, dict[str, Any]], None]
_PAGE_URL = re.compile(r"(?m)^- Page URL:\s*(\S+)\s*$")
_PAGE_TITLE = re.compile(r"(?m)^- Page Title:\s*(.*?)\s*$")
_MAX_DISCLOSED_SNAPSHOT_CHARS = 64_000
# A fresh, owned AI test fixture may have to rebuild a local vector index during
# reset/setup.  Keep the per-step window bounded, but large enough for that
# deterministic initialization to finish on CPU-only release-test hosts.
_MAX_STEP_SECONDS = 120


@dataclass(frozen=True, slots=True)
class SemanticBrowserWorkflowArtifacts:
    """Durable files and verified states from one semantic browser mission."""

    target: Path
    mission: Path
    report: Path
    discovery_capsule: Path | None
    traces: tuple[Path, ...]
    reproduction_trace: Path | None
    status: str
    visual_replays: tuple[Path, ...] = ()
    replay_cues: Path | None = None


def _fingerprint(
    value: str | None,
    *,
    status: str,
    method: str,
    source: str,
) -> dict[str, Any]:
    return {
        "value": value,
        "status": status,
        "method": method,
        "source": source,
        "version": "0.1.0",
    }


def _step(
    identifier: str,
    action: SemanticBrowserAction | tuple[str, dict[str, Any]],
    *,
    offensive: bool,
) -> dict[str, Any]:
    name, raw_arguments = (
        (action.action, action.arguments) if isinstance(action, SemanticBrowserAction) else action
    )
    arguments = dict(raw_arguments)
    if offensive and name not in {"browser.snapshot", "browser.wait", "browser.hover"}:
        arguments["offensive"] = True
    return {
        "id": identifier,
        "action": name,
        "inputs": arguments,
        "onFailure": "stop",
        "requires": [f"{name}/0.1"],
    }


def _scenario(
    mission: SemanticBrowserMission,
    actions: tuple[SemanticBrowserAction, ...],
    *,
    key: str,
    reset_and_setup: bool,
    max_step_seconds: float = _MAX_STEP_SECONDS,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Create an exact reviewable action batch plus a fresh observable snapshot."""
    scenario = scenario_template(
        title=f"Semantic browser mission batch {key}",
        purpose=(
            "Execute one model-proposed, SOVA-validated browser batch against an explicitly "
            "controlled origin and judge only recorded observable state."
        ),
    )
    steps: list[dict[str, Any]] = []
    action_step_ids: list[str] = []
    action_snapshot_step_ids: list[str] = []

    if reset_and_setup:
        steps.append(
            _step(
                f"{key}-entry-before-reset",
                ("browser.navigate", {"url": mission.entry_url}),
                offensive=mission.offensive,
            )
        )
        for index, action in enumerate(mission.reset_actions, 1):
            steps.append(
                _step(
                    f"{key}-reset-{index:02d}",
                    action,
                    offensive=mission.offensive,
                )
            )
        if mission.reset_actions:
            steps.append(
                _step(
                    f"{key}-entry-after-reset",
                    ("browser.navigate", {"url": mission.entry_url}),
                    offensive=mission.offensive,
                )
            )
        for index, action in enumerate(mission.setup_actions, 1):
            steps.append(
                _step(
                    f"{key}-setup-{index:02d}",
                    action,
                    offensive=mission.offensive,
                )
            )

    for index, action in enumerate(actions, 1):
        step_id = f"{key}-action-{index:03d}"
        action_step_ids.append(step_id)
        action_step = _step(step_id, action, offensive=mission.offensive)
        # Continue only to the immediately following evidence snapshot. The plan
        # validator admits at most one observable UI boundary and requires it last.
        action_step["onFailure"] = "continue"
        steps.append(action_step)
        if (
            action.action == "browser.click"
            and index < len(actions)
            and actions[index].action == "browser.dialog"
        ):
            continue
        action_snapshot_id = f"{step_id}-snapshot"
        action_snapshot_step_ids.append(action_snapshot_id)
        steps.append(_step(action_snapshot_id, ("browser.snapshot", {}), offensive=False))

    if action_snapshot_step_ids:
        snapshot_id = action_snapshot_step_ids[-1]
    else:
        snapshot_id = f"{key}-snapshot"
        steps.append(_step(snapshot_id, ("browser.snapshot", {}), offensive=False))
    scenario["procedure"]["steps"] = steps
    scenario["parameters"] = {
        "missionDigest": mission.digest,
        "batchKey": key,
        "plannedActionDigests": [action.digest for action in actions],
    }
    scenario["preconditions"] = [
        {"kind": "target-control", "method": "verified-control-proof"},
        {"kind": "fresh-human-authorization", "required": True},
    ]
    scenario["triggers"] = [
        {
            "kind": "semantic-workflow",
            "objectiveDigest": sha256_digest(mission.objective.encode("utf-8")),
        }
    ]
    scenario["expectedEffects"] = [
        {"kind": "observable-browser-text", "contains": mission.oracle_contains}
    ]
    scenario["oracles"] = [
        {"kind": "field-contains", "path": "$.text", "contains": mission.oracle_contains}
    ]
    scenario["evidenceRequirements"] = [
        "authorization.decision",
        "tool.requested",
        "tool.completed",
        "oracle.completed",
        "run.lifecycle",
        "aria-snapshot",
    ]
    if not math.isfinite(max_step_seconds) or max_step_seconds <= 0:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-DEADLINE",
            "semantic browser batch has no remaining execution time",
        )
    bounded_step_seconds = max(1, min(_MAX_STEP_SECONDS, math.floor(max_step_seconds)))
    scenario["safety"] = {
        "budgets": {
            "maxSteps": len(steps),
            "maxStepSeconds": bounded_step_seconds,
        },
        "forbiddenEffects": [
            "filesystem.write",
            "process.spawn",
            "cross-origin-network",
            "credential-entry",
            "arbitrary-script-evaluation",
        ],
        "stopConditions": [{"kind": "complete-reviewed-batch-with-action-snapshots"}],
    }
    scenario["cleanup"] = [{"kind": "close-ephemeral-browser-context"}]
    scenario["limitations"] = [
        "The planner can choose only SOVA's declared typed browser actions.",
        "Every generated batch is independently authorized before execution.",
        "Success is a deterministic observable oracle, not a model assertion.",
        "Target observations are redacted and bounded before provider disclosure.",
        (
            "Allowed-origin request filtering and post-action page-origin drift detection "
            "are not process-level network egress confinement or a VM sandbox."
        ),
    ]
    scenario["extensions"] = {
        "x-sova-semantic-browser": {
            "missionDigest": mission.digest,
            "batchKey": key,
            "resetAndSetup": reset_and_setup,
            "snapshotStepId": snapshot_id,
            "actionSnapshotStepIds": action_snapshot_step_ids,
        }
    }
    return scenario, tuple(action_step_ids)


def _build_batch_capsule(  # noqa: PLR0913 - explicit evidence and deadline inputs
    mission: SemanticBrowserMission,
    actions: tuple[SemanticBrowserAction, ...],
    destination: Path,
    *,
    key: str,
    reset_and_setup: bool,
    max_step_seconds: float = _MAX_STEP_SECONDS,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    scenario, action_step_ids = _scenario(
        mission,
        actions,
        key=key,
        reset_and_setup=reset_and_setup,
        max_step_seconds=max_step_seconds,
    )
    manifest = capsule_manifest_template(
        title=scenario["title"],
        summary="One authorized action batch in a semantic browser security mission.",
        author="SOVA operator",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "low" if mission.offensive else "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1", "trace.core/0.1"]
    manifest["limitations"] = scenario["limitations"]
    build_capsule(destination, manifest, scenario=scenario)
    return scenario, action_step_ids


def _snapshot_text(trace: Path, snapshot_step_id: str) -> str:
    for event in reversed(TraceReader(trace).events()):
        if event["kind"] != "tool.completed" or event["phase"] != snapshot_step_id:
            continue
        payload = event.get("payload")
        outcome = payload.get("outcome") if isinstance(payload, dict) else None
        output = outcome.get("output") if isinstance(outcome, dict) else None
        values = output.get("text") if isinstance(output, dict) else None
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            break
        rendered = "\n".join(values)
        if rendered:
            return rendered
    raise FormatError(
        "SOVA-SEMANTIC-BROWSER-SNAPSHOT",
        "signed batch trace contains no usable final accessibility snapshot",
    )


def _bounded_snapshot(value: str) -> str:
    redacted, records = Redactor(context_id="sova-semantic-browser-provider-view").redact(value)
    if not isinstance(redacted, str):
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-DISCLOSURE",
            "browser snapshot contained credential-shaped material and was withheld",
            details={"redactionCount": len(records)},
        )
    if len(redacted) <= _MAX_DISCLOSED_SNAPSHOT_CHARS:
        return redacted
    half = (_MAX_DISCLOSED_SNAPSHOT_CHARS - 80) // 2
    return redacted[:half] + "\n...[SOVA SNAPSHOT TRUNCATED]...\n" + redacted[-half:]


def _observation(
    trace: Path, snapshot_step_id: str, *, oracle_passed: bool
) -> SemanticBrowserObservation:
    snapshot = _bounded_snapshot(_snapshot_text(trace, snapshot_step_id))
    url_match = _PAGE_URL.search(snapshot)
    if url_match is None:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-LOCATION",
            "final accessibility snapshot did not expose the current page URL",
        )
    title_match = _PAGE_TITLE.search(snapshot)
    return SemanticBrowserObservation(
        url_match.group(1),
        "" if title_match is None else title_match.group(1),
        snapshot,
        oracle_passed,
    )


def _action_statuses(trace: Path, step_ids: tuple[str, ...]) -> tuple[str, ...]:
    statuses: dict[str, str] = {}
    for event in TraceReader(trace).events():
        phase = event.get("phase")
        if phase not in step_ids or event["kind"] not in {"tool.completed", "tool.failed"}:
            continue
        payload = event.get("payload")
        outcome = payload.get("outcome") if isinstance(payload, dict) else None
        raw = outcome.get("status") if isinstance(outcome, dict) else None
        statuses[str(phase)] = (
            str(raw) if raw in {"succeeded", "failed", "timeout", "cancelled"} else "failed"
        )
    return tuple(statuses.get(step_id, "failed") for step_id in step_ids)


class _DeadlineBatchExecutor:
    """Cap every call to the shared deadline and stop after a failed prerequisite."""

    def __init__(self, executor: MCPExecutorAdapter, *, deadline: float) -> None:
        self._executor = executor
        self._deadline = deadline
        self._failed_prerequisite = False
        self._failure_snapshot_captured = False
        self._effects = {
            capability.name: capability.side_effect for capability in executor.capabilities()
        }

    @property
    def name(self) -> str:
        return self._executor.name

    def capabilities(self) -> tuple[Any, ...]:
        return self._executor.capabilities()

    def _refused(
        self,
        request: ActionRequest,
        *,
        status: OutcomeStatus,
        code: str,
        reason: str,
    ) -> ActionOutcome:
        return ActionOutcome(
            request_id=request.id,
            status=status,
            side_effect=self._effects.get(request.action, SideEffect.MUTATE),
            output={"executed": False, "reason": reason},
            error_code=code,
            failure_cause=(
                FailureCause.TIMEOUT if status == OutcomeStatus.TIMEOUT else FailureCause.POLICY
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: Any,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            return self._refused(
                request,
                status=OutcomeStatus.TIMEOUT,
                code="SOVA-SEMANTIC-BROWSER-DEADLINE",
                reason="shared mission deadline expired before execution",
            )

        if self._failed_prerequisite:
            if request.action == "browser.snapshot" and not self._failure_snapshot_captured:
                bounded = replace(request, timeout_seconds=min(request.timeout_seconds, remaining))
                outcome = self._executor.execute(bounded, context, cancellation)
                self._failure_snapshot_captured = True
                if time.monotonic() >= self._deadline:
                    return self._refused(
                        request,
                        status=OutcomeStatus.TIMEOUT,
                        code="SOVA-SEMANTIC-BROWSER-DEADLINE",
                        reason="failure snapshot returned after the shared mission deadline",
                    )
                return outcome
            return self._refused(
                request,
                status=OutcomeStatus.DENIED,
                code="SOVA-SEMANTIC-BROWSER-PREREQUISITE",
                reason="an earlier action failed; later batch actions were not executed",
            )

        bounded = replace(request, timeout_seconds=min(request.timeout_seconds, remaining))
        outcome = self._executor.execute(bounded, context, cancellation)
        if time.monotonic() >= self._deadline:
            self._failed_prerequisite = True
            return self._refused(
                request,
                status=OutcomeStatus.TIMEOUT,
                code="SOVA-SEMANTIC-BROWSER-DEADLINE",
                reason="executor call returned after the shared mission deadline",
            )
        if request.action != "browser.snapshot" and outcome.status != OutcomeStatus.SUCCEEDED:
            self._failed_prerequisite = True
        return outcome


class PlaywrightSemanticBrowserDriver(SemanticBrowserDriver):
    """Execute generated batches only through SOVA authorization and signed traces."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        destination: Path,
        executor: MCPExecutorAdapter,
        host: str,
        proof: ControlProof,
        containment_digest: str,
        approval_prompt: ApprovalPrompt,
        signing_key: Ed25519Keypair,
        environment: dict[str, Any],
        fingerprints: dict[str, Any],
        event_observer: Callable[[dict[str, Any]], None] | None,
        cancellation: CancellationToken | None,
    ) -> None:
        self.destination = destination
        self.executor = executor
        self.host = host
        self.proof = proof
        self.containment_digest = containment_digest
        self.approval_prompt = approval_prompt
        self.signing_key = signing_key
        self.environment = environment
        self.fingerprints = fingerprints
        self.event_observer = event_observer
        self.cancellation = cancellation
        self.capsules = destination / "capsules"
        self.traces_dir = destination / "traces"
        self.capsules.mkdir(parents=True, exist_ok=True)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.trace_paths: list[Path] = []
        self.capsule_paths: list[Path] = []
        self.discovery_trace: Path | None = None
        self.reproduction_trace: Path | None = None
        self.reproduction_capsule: Path | None = None
        self._deadline: float | None = None

    def set_deadline(self, deadline: float) -> None:
        """Bind the driver to the workflow's single monotonic wall-clock deadline."""
        if not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            raise FormatError(
                "SOVA-SEMANTIC-BROWSER-DEADLINE",
                "semantic browser deadline is invalid",
            )
        self._deadline = float(deadline)

    def _remaining_seconds(self) -> float:
        if self._deadline is None:
            raise FormatError(
                "SOVA-SEMANTIC-BROWSER-DEADLINE",
                "semantic browser workflow did not bind a shared deadline",
            )
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise FormatError(
                "SOVA-SEMANTIC-BROWSER-DEADLINE",
                "semantic browser mission duration budget expired",
            )
        return remaining

    def _run(
        self,
        mission: SemanticBrowserMission,
        actions: tuple[SemanticBrowserAction, ...],
        *,
        key: str,
        reset_and_setup: bool,
        source_trace_digest: str | None = None,
    ) -> SemanticExecutionBatch:
        remaining = self._remaining_seconds()
        capsule = self.capsules / f"{key}.sova"
        trace = self.traces_dir / f"{key}.sova-trace"
        scenario, action_step_ids = _build_batch_capsule(
            mission,
            actions,
            capsule,
            key=key,
            reset_and_setup=reset_and_setup,
            max_step_seconds=min(_MAX_STEP_SECONDS, remaining),
        )
        session, approvals = authorize_browser_scenarios(
            ((key, scenario),),
            self.executor.capabilities(),
            host=self.host,
            proof=self.proof,
            containment_digest=self.containment_digest,
            approval_prompt=self.approval_prompt,
            approval_ttl=timedelta(minutes=10),
        )
        # Human review is part of the mission wall-clock budget. Never dispatch
        # a previously approved batch if the deadline elapsed during review.
        self._remaining_seconds()
        deadline = self._deadline
        if deadline is None:  # pragma: no cover - guarded by _remaining_seconds
            raise AssertionError
        bounded_executor = _DeadlineBatchExecutor(self.executor, deadline=deadline)
        result = run_capsule(
            capsule,
            trace,
            executor=bounded_executor,
            workspace=self.destination,
            authorization_session=session,
            approvals=approvals[key],
            cancellation=self.cancellation,
            source_trace_digest=source_trace_digest,
            signing_key=self.signing_key,
            environment=self.environment,
            fingerprints=self.fingerprints,
            event_observer=self.event_observer,
        )
        TraceReader(trace).verify(require_signature=True)
        self.capsule_paths.append(capsule)
        self.trace_paths.append(trace)
        if result.oracle_status == "pass" and key != "reproduction":
            self.discovery_trace = trace
        if key == "reproduction":
            self.reproduction_trace = trace
            self.reproduction_capsule = capsule
        snapshot_step_id = str(scenario["extensions"]["x-sova-semantic-browser"]["snapshotStepId"])
        observation = _observation(
            trace,
            snapshot_step_id,
            oracle_passed=result.oracle_status == "pass",
        )
        action_snapshot_step_ids = tuple(
            str(item)
            for item in scenario["extensions"]["x-sova-semantic-browser"]["actionSnapshotStepIds"]
        )
        pages_visited = tuple(
            _observation(trace, step_id, oracle_passed=False).url
            for step_id in action_snapshot_step_ids
        )
        statuses = _action_statuses(trace, action_step_ids)
        if not statuses:
            statuses = ("succeeded" if result.completion == "completed" else "failed",)
        return SemanticExecutionBatch(
            observation,
            statuses,
            (TraceReader(trace).manifest()["id"],),
            pages_visited,
        )

    def start(self, mission: SemanticBrowserMission) -> SemanticBrowserObservation:
        return self._run(
            mission,
            (),
            key="start",
            reset_and_setup=True,
        ).observation

    def execute(
        self,
        mission: SemanticBrowserMission,
        actions: tuple[SemanticBrowserAction, ...],
        *,
        turn: int,
    ) -> SemanticExecutionBatch:
        return self._run(
            mission,
            actions,
            key=f"turn-{turn:03d}",
            reset_and_setup=False,
        )

    def reproduce(
        self,
        mission: SemanticBrowserMission,
        actions: tuple[SemanticBrowserAction, ...],
    ) -> SemanticExecutionBatch:
        source_digest = (
            None
            if self.discovery_trace is None
            else sha256_digest(self.discovery_trace.read_bytes())
        )
        return self._run(
            mission,
            actions,
            key="reproduction",
            reset_and_setup=True,
            source_trace_digest=source_digest,
        )


def _result_report(  # noqa: PLR0913 - report bindings are explicit evidence inputs
    result: SemanticWorkflowResult,
    *,
    target: TargetManifest,
    mission: SemanticBrowserMission,
    control_status: str,
    driver: PlaywrightSemanticBrowserDriver,
    comparison_equivalent: bool,
    visual_replays: tuple[Path, ...],
    replay_cues: Path | None,
) -> dict[str, Any]:
    return {
        "artifactType": "sova.semantic-browser-workflow-report",
        "schemaVersion": "0.1.0",
        "status": result.status,
        "stopReason": result.stop_reason,
        "targetDigest": target.digest,
        "missionDigest": mission.digest,
        "authorization": {
            "targetControl": control_status,
            "generatedBatchesRequireFreshApproval": True,
        },
        "planner": {
            "role": "explorer",
            "providerObservationDisclosure": mission.provider_observation_disclosure,
            "invocations": [invocation.to_mapping() for invocation in result.invocations],
            "modelCanExecuteTools": False,
            "modelCanDeclareFinding": False,
        },
        "execution": {
            "actions": [action.to_mapping() for action in result.actions],
            "actionDigests": [action.digest for action in result.actions],
            "pagesVisited": list(result.pages_visited),
            "tokensUsed": result.tokens_used,
            "traceFiles": [path.name for path in driver.trace_paths],
            "traceDigests": [sha256_digest(path.read_bytes()) for path in driver.trace_paths],
        },
        "evidence": {
            "discoveryTrace": (
                None if driver.discovery_trace is None else driver.discovery_trace.name
            ),
            "reproductionTrace": (
                None if driver.reproduction_trace is None else driver.reproduction_trace.name
            ),
            "reproductionEquivalent": comparison_equivalent,
            "visualReplays": [path.name for path in visual_replays],
            "replayCues": None if replay_cues is None else replay_cues.name,
        },
        "claims": {
            "autonomousWithinDeclaredActionPolicy": True,
            "allowedOriginRequestFiltering": True,
            "postActionOriginDriftDetection": True,
            "networkEgressSandbox": False,
            "deterministicOracleRequired": True,
            "freshReproductionRequiredForPass": True,
            "arbitraryUnreviewedToolUse": False,
            "unrestrictedInternetRoaming": False,
        },
        "limitations": [
            "A pass establishes only the declared deterministic observable oracle.",
            "Accessibility snapshots may omit visual-only interface state.",
            "Included-key trace signatures require an external trust policy for identity.",
            (
                "Allowed-origin request filtering and post-action page-origin drift detection "
                "are not process-level network egress confinement or a microVM boundary."
            ),
        ],
    }


def run_live_semantic_browser_workflow(  # noqa: PLR0912, PLR0913, PLR0915
    target: TargetManifest,
    mission: SemanticBrowserMission,
    destination: Path,
    *,
    router: ModelRouter,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    control_proof: ControlProof | None = None,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    profile_lease: BrowserProfileLease | None = None,
    cancellation: CancellationToken | None = None,
    event_observer: SemanticBrowserEventObserver | None = None,
    headless: bool = True,
    record_video: bool = False,
) -> SemanticBrowserWorkflowArtifacts:
    """Run an autonomous mission inside explicit target, action, and evidence boundaries."""
    if cancellation is not None and cancellation.cancelled:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-CANCELLED", "semantic browser mission was cancelled"
        )
    if profile_lease is not None:
        profile_lease.require_target(target.digest)
    control_now = datetime.now(UTC)
    minimum_window = timedelta(seconds=mission.max_duration_seconds + 30)
    origins, host, proof, control_status = verified_browser_control(
        target,
        control_proof,
        now=control_now,
        minimum_ttl=minimum_window,
    )
    if mission.entry_origin not in origins:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-SCOPE",
            "mission entry URL is outside the target's admitted origins",
        )
    if proof.expires_at - control_now < minimum_window:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-PROOF-WINDOW",
            "target-control proof expires before the mission can finish",
        )
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-EXISTS", "semantic browser destination is not empty"
        )
    destination.mkdir(parents=True, exist_ok=True)
    mission_path = destination / "mission.json"
    mission_path.write_bytes(canonical_json_bytes(mission.to_mapping()) + b"\n")
    target_path = destination / "target.json"
    target_path.write_bytes(canonical_json_bytes(target.to_mapping()) + b"\n")

    posture = {
        "backend": "microsoft-playwright-mcp",
        "version": "0.0.78",
        "ephemeralProfile": profile_lease is None,
        "profileMode": "ephemeral" if profile_lease is None else "opaque-exclusive-durable",
        "headless": headless,
        "visualRecording": record_video,
        "serviceWorkersBlocked": True,
        "allowedOrigins": list(origins),
        "nativeSandboxClaim": False,
        "semanticMissionDigest": mission.digest,
        "providerObservationDisclosure": mission.provider_observation_disclosure,
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
                "semanticWorkflowModule": sha256_digest(Path(__file__).read_bytes()),
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
    environment = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "codeDigest": code_digest,
        "model": {role.value: list(models) for role, models in router.model_ids().items()},
        "dependencies": dependencies,
    }
    fingerprints = {
        "environment": _fingerprint(
            sha256_digest(canonical_json_bytes(environment)),
            status="recorded",
            method="canonical-runtime-environment-digest",
            source="sova.live.semantic_browser_driver",
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
            source="sova.live.semantic_browser_driver",
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
            source="local semantic mission",
        ),
        "model": _fingerprint(
            sha256_digest(canonical_json_bytes(environment["model"])),
            status="recorded",
            method="declared-role-model-binding-digest",
            source="model router",
        ),
    }

    recording = None
    driver: PlaywrightSemanticBrowserDriver
    with (
        start_stdio_client(spec, StdioMCPClient) as client,
        MCPExecutorAdapter(
            "microsoft-playwright-mcp",
            client,
            playwright_mappings(allowed_origins=origins),
        ) as executor,
    ):
        recording_started = False
        try:
            if record_video:
                recording = start_visual_recording(client)
                recording_started = True
                add_visual_chapter(
                    client,
                    title="SOVA semantic mission",
                    description="Autonomous policy-confined browser exploration begins.",
                )
            observer = recorded_observer(
                recording,
                client,
                event_observer,
                "semantic-browser",
            )
            driver = PlaywrightSemanticBrowserDriver(
                destination=destination,
                executor=executor,
                host=host,
                proof=proof,
                containment_digest=containment_digest,
                approval_prompt=approval_prompt,
                signing_key=signing_key,
                environment=environment,
                fingerprints=fingerprints,
                event_observer=observer,
                cancellation=cancellation,
            )
            result = run_semantic_browser_workflow(mission, router=router, driver=driver)
            if record_video:
                stop_visual_recording(client)
                recording_started = False
        except BaseException:
            if recording_started:
                with contextlib.suppress(Exception):
                    stop_visual_recording(client)
            raise

    visual_replays = collect_visual_replays(destination) if record_video else ()
    replay_cues = (
        write_replay_cues(destination, recording, visual_replays[0])
        if recording is not None and recording.cues and visual_replays
        else None
    )
    comparison_equivalent = False
    if driver.discovery_trace is not None and driver.reproduction_trace is not None:
        comparison = compare_observable_outcomes(
            driver.discovery_trace,
            driver.reproduction_trace,
            kinds=("oracle.completed",),
        )
        comparison_equivalent = comparison.equivalent
    if result.status == "pass" and not comparison_equivalent:
        raise FormatError(
            "SOVA-SEMANTIC-BROWSER-REPRODUCTION",
            "workflow claimed pass without equivalent signed discovery and reproduction oracles",
        )

    report_value = _result_report(
        result,
        target=target,
        mission=mission,
        control_status=control_status,
        driver=driver,
        comparison_equivalent=comparison_equivalent,
        visual_replays=visual_replays,
        replay_cues=replay_cues,
    )
    report_path = destination / "report.json"
    report_path.write_bytes(canonical_json_bytes(report_value) + b"\n")

    discovery_capsule: Path | None = None
    if result.status == "pass" and driver.reproduction_capsule is not None:
        discovery_capsule = destination / "discovery.sova"
        manifest = capsule_manifest_template(
            title="SOVA semantic browser discovery",
            summary=(
                "A policy-confined autonomous browser finding with signed discovery, exact "
                "controlled reproduction, and optional decisive visual evidence."
            ),
            author="SOVA operator",
            domain_profile=DomainProfile.SECURITY,
        )
        manifest["license"] = "Apache-2.0"
        manifest["safety"]["impact"] = "low" if mission.offensive else "none"
        manifest["methodology"] = {
            "id": "SOVA-SEMANTIC-BROWSER-WORKFLOW",
            "version": "0.1.0",
            "digest": sha256_digest(canonical_json_bytes(report_value)),
        }
        manifest["taxonomy"] = {
            "id": "sova.semantic-browser-mission",
            "version": "0.1.0",
            "digest": mission.digest,
        }
        manifest["limitations"] = report_value["limitations"]
        attachments = {
            "mission.json": canonical_json_bytes(mission.to_mapping()),
            "target.json": canonical_json_bytes(target.to_mapping()),
            "report.json": canonical_json_bytes(report_value),
        }
        attachments.update({path.name: path.read_bytes() for path in visual_replays})
        if replay_cues is not None:
            attachments[replay_cues.name] = replay_cues.read_bytes()
        complete_traces = list(dict.fromkeys(driver.trace_paths))
        decisive_traces = [
            path for path in (driver.discovery_trace, driver.reproduction_trace) if path is not None
        ]
        trace_history: list[dict[str, Any]] = []
        for order, path in enumerate(complete_traces):
            digest = sha256_digest(path.read_bytes())
            role = (
                "decisive-discovery"
                if path == driver.discovery_trace
                else "decisive-reproduction"
                if path == driver.reproduction_trace
                else "exploration"
            )
            package_role = "trace" if path in decisive_traces else "attachment"
            trace_history.append(
                {
                    "order": order,
                    "file": path.name,
                    "digest": digest,
                    "role": role,
                    "packageRole": package_role,
                    "packagePath": (
                        f"traces/{path.name}"
                        if package_role == "trace"
                        else f"blobs/sha256/{digest[7:]}"
                    ),
                }
            )
            if package_role == "attachment":
                attachments[f"history-{order:03d}-{path.name}"] = path.read_bytes()
        attachments["trace-history.json"] = canonical_json_bytes(
            {
                "artifactType": "sova.semantic-browser-trace-history",
                "schemaVersion": "0.1.0",
                "ordering": "execution-order",
                "traces": trace_history,
            }
        )
        reproduction_scenario, _unused = _scenario(
            mission,
            result.actions,
            key="reproduction",
            reset_and_setup=True,
        )
        # Keep the two decisive traces as replay roles so `sova replay capsule`
        # remains unambiguous. Earlier signed traces are content-addressed
        # attachments indexed by trace-history.json in exact execution order.
        build_capsule(
            discovery_capsule,
            manifest,
            scenario=reproduction_scenario,
            attachments=attachments,
            traces=decisive_traces,
        )

    return SemanticBrowserWorkflowArtifacts(
        target_path,
        mission_path,
        report_path,
        discovery_capsule,
        tuple(driver.trace_paths),
        driver.reproduction_trace,
        result.status,
        visual_replays,
        replay_cues,
    )


__all__ = [
    "PlaywrightSemanticBrowserDriver",
    "SemanticBrowserEventObserver",
    "SemanticBrowserWorkflowArtifacts",
    "run_live_semantic_browser_workflow",
]
