# SPDX-License-Identifier: Apache-2.0
"""Seed differentiated swarm workers and merge their results into one `.sova`."""

from __future__ import annotations

import platform
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.capsule import (
    CaptureProfile,
    DomainProfile,
    build_capsule,
    capsule_manifest_template,
    scenario_template,
)
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.community.swarm.worker import SwarmWorkerSpec
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path

    from sova.community.executor_chamber import ExecutorChamberArtifacts
    from sova.community.swarm.blackboard import SwarmBlackboard

_DEFAULT_FOCUS_AREAS = (
    "broad reconnaissance and content/site-map coverage",
    "authentication, session, and access-control boundaries",
    "form inputs, submissions, and data validation",
    "navigation, state transitions, and multi-step workflows",
    "error handling, edge cases, and unexpected input",
    "client-side logic and embedded/third-party content",
)
_MAX_PERSONA_CHARS = 128
_OBSERVER_PARTICIPANT_ID = "swarm-inert-observer"
_OBSERVER_MODEL_ID = "sova-swarm-inert-observer/0.1"
_IMPACT_ORDER = {"none": 0, "low": 1, "moderate": 2, "high": 3, "unknown": 4}


def _observer_participant(*, allowed_grant: str) -> dict[str, Any]:
    """A framework-mandated second participant that stops on its first turn.

    `ExecutorChamberCase` requires 2-8 participants even for a single active
    swarm agent (see `_MIN_PARTICIPANTS` in `sova.community.executor_chamber`).
    This synthetic participant satisfies that floor without ever acting, so a
    swarm worker's isolated session still has exactly one effectively active
    agent.  Its `allowedGrants` must reference a real declared grant (an empty
    grant list is rejected by `ExecutorChamberParticipant`), but its scripted
    model always stops before proposing any action.
    """
    return {
        "id": _OBSERVER_PARTICIPANT_ID,
        "objective": "Take no action. Immediately stop on your first turn.",
        "allowedGrants": [allowed_grant],
        "model": {
            "adapter": "scripted",
            "modelId": _OBSERVER_MODEL_ID,
            "turns": [
                {
                    "expectedContains": "sova.executor-chamber-planner/0.1.0",
                    "responseText": "",
                    "structured": {
                        "status": "stop",
                        "message": "Inert swarm-floor participant; taking no action.",
                        "actions": [],
                        "coverage": [],
                        "reason": (
                            "This participant exists only to satisfy the minimum "
                            "participant count; the swarm worker's real agent is the "
                            "sole active participant."
                        ),
                    },
                    "tokenCount": 1,
                }
            ],
        },
    }


def _fingerprint(value: str | None, *, status: str, method: str, source: str) -> dict[str, Any]:
    return {
        "value": value,
        "status": status,
        "method": method,
        "source": source,
        "version": "0.1.0",
    }


@dataclass(frozen=True, slots=True)
class AgentRunResult:
    """One worker's outcome, always recorded even on failure."""

    agent_id: str
    persona: str
    status: str
    artifacts: ExecutorChamberArtifacts | None
    error: str | None


class SwarmCoordinator:
    """Seed N worker specs from one template; merge their results afterward."""

    def seed(
        self,
        base_chamber_document: dict[str, Any],
        *,
        agent_count: int,
        personas: tuple[str, ...] | None = None,
        focus_areas: tuple[str, ...] = _DEFAULT_FOCUS_AREAS,
    ) -> tuple[SwarmWorkerSpec, ...]:
        """Clone the operator's one-participant template into `agent_count` specs.

        Each clone's declared participant objective is extended with a persona
        label and a distinct focus area (round-robined from `focus_areas`) so
        concurrent agents naturally spread their exploration instead of
        duplicating each other's work; nothing else in the template changes.
        """
        if agent_count < 1:
            raise FormatError(
                "SOVA-SWARM-COORDINATOR-COUNT",
                "swarm agent count must be at least one",
            )
        if not focus_areas:
            raise FormatError(
                "SOVA-SWARM-COORDINATOR-FOCUS",
                "swarm coordinator requires at least one focus area",
            )
        participants = base_chamber_document.get("participants")
        if (
            not isinstance(participants, list)
            or len(participants) != 1
            or not isinstance(participants[0], dict)
            or not isinstance(participants[0].get("objective"), str)
        ):
            raise FormatError(
                "SOVA-SWARM-COORDINATOR-TEMPLATE",
                "swarm worker template must declare exactly one real participant with an "
                "objective; the coordinator adds the framework-mandated second participant",
            )
        grants = base_chamber_document.get("grants")
        if (
            not isinstance(grants, list)
            or not grants
            or not isinstance(grants[0], dict)
            or not isinstance(grants[0].get("id"), str)
        ):
            raise FormatError(
                "SOVA-SWARM-COORDINATOR-TEMPLATE",
                "swarm worker template must declare at least one grant",
            )
        observer_grant_id = grants[0]["id"]
        base_objective = participants[0]["objective"]
        specs: list[SwarmWorkerSpec] = []
        for index in range(agent_count):
            persona = (
                personas[index % len(personas)] if personas else f"swarm-agent-{index + 1:02d}"
            )
            if not isinstance(persona, str) or not persona or len(persona) > _MAX_PERSONA_CHARS:
                raise FormatError(
                    "SOVA-SWARM-COORDINATOR-PERSONA",
                    "swarm persona must be a bounded non-empty string",
                )
            focus = focus_areas[index % len(focus_areas)]
            document = strict_json_loads(canonical_json_bytes(base_chamber_document))
            if not isinstance(document, dict):  # pragma: no cover - source is an object
                raise TypeError
            document["participants"][0]["objective"] = (
                f"{base_objective}\n\n"
                f"You are '{persona}', one of {agent_count} agents concurrently testing this "
                f"same authorized target as an isolated swarm. Focus your exploration on: "
                f"{focus}. Other agents are covering different areas at the same time; do not "
                f"assume you are the only agent."
            )
            document["participants"].append(_observer_participant(allowed_grant=observer_grant_id))
            specs.append(
                SwarmWorkerSpec(
                    agent_id=f"agent-{index + 1:02d}",
                    persona=persona,
                    chamber_document=document,
                )
            )
        return tuple(specs)

    def merge(  # noqa: PLR0913 - merge evidence inputs remain independently bound
        self,
        results: tuple[AgentRunResult, ...],
        *,
        blackboard: SwarmBlackboard,
        destination: Path,
        target_digest: str,
        title: str = "SOVA concurrent swarm run",
        aggregate_budget: dict[str, Any] | None = None,
        measured_coverage: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the coordinator trace and aggregate `.sova`; return the report mapping.

        `destination` must be an existing empty directory; the coordinator
        writes `coordinator.sova-trace` and `swarm.sova` there.  Findings are
        deduplicated at the blackboard message level (see `_dedup_findings`);
        `ExecutorChamberArtifacts.report`/`.trace`/`.capsule` for each agent
        are referenced, not re-parsed.
        """
        transcript = blackboard.transcript()
        chain_head = blackboard.chain_head_digest()
        environment: dict[str, Any] = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "codeDigest": None,
            "model": {"agents": [item.agent_id for item in results]},
            "dependencies": [],
        }
        scope = {
            "targetDigest": target_digest,
            "agentCount": len(results),
            "agentIds": sorted(item.agent_id for item in results),
        }
        writer = TraceWriter(
            destination / "coordinator.sova-trace",
            capture_profile="standard",
            signing_key=generate_ed25519_keypair(),
            authorization={
                "decision": "allowed",
                "scopeDigest": sha256_digest(canonical_json_bytes(scope)),
                "decidedBy": "sova-swarm-coordinator",
            },
            environment=environment,
            executor={
                "id": "sova:executor:swarm-coordinator",
                "name": "sova-swarm-coordinator",
                "version": "0.1.0",
                "capabilityDigest": None,
            },
            fingerprints={
                "environment": _fingerprint(
                    sha256_digest(canonical_json_bytes(environment)),
                    status="recorded",
                    method="canonical-environment-digest",
                    source="sova.community.swarm.coordinator",
                ),
                "target": _fingerprint(
                    target_digest,
                    status="recorded",
                    method="target-manifest-digest",
                    source="swarm target",
                ),
                "code": _fingerprint(
                    None, status="not-recorded", method="not-recorded", source="recorder"
                ),
                "dependencies": _fingerprint(
                    None, status="not-recorded", method="not-recorded", source="recorder"
                ),
                "registry": _fingerprint(
                    None, status="not-recorded", method="not-recorded", source="recorder"
                ),
                "model": _fingerprint(
                    None, status="not-recorded", method="not-recorded", source="recorder"
                ),
            },
        )
        try:
            writer.append(
                "run.started",
                {
                    "agentCount": len(results),
                    "agentIds": scope["agentIds"],
                    "aggregateBudget": aggregate_budget,
                    "measuredCoverage": measured_coverage,
                },
                phase="swarm",
            )
            for message in transcript:
                sent = writer.append(
                    "inter-agent.sent",
                    {
                        "from": message.author_agent_id,
                        "to": "swarm-blackboard",
                        "kind": message.kind.value,
                        "messageId": message.id,
                        "messageDigest": message.digest,
                        "payload": message.payload,
                    },
                    phase="swarm",
                    actor={
                        "id": message.author_agent_id,
                        "kind": "agent",
                        "name": message.author_agent_id,
                    },
                )
                writer.append(
                    "inter-agent.received",
                    {
                        "from": message.author_agent_id,
                        "to": "sova-swarm-coordinator",
                        "kind": message.kind.value,
                        "messageId": message.id,
                        "messageDigest": message.digest,
                    },
                    phase="swarm",
                    parents=[sent] if sent else [],
                )
            for result in results:
                writer.append(
                    "run.completed" if result.status == "pass" else "error.recorded",
                    (
                        {
                            "agentId": result.agent_id,
                            "persona": result.persona,
                            "status": result.status,
                        }
                        if result.status == "pass"
                        else {
                            "agentId": result.agent_id,
                            "persona": result.persona,
                            "status": result.status,
                            "code": "SOVA-SWARM-WORKER-FAILED",
                            "message": result.error or "worker failed",
                        }
                    ),
                    phase="swarm",
                    actor={"id": result.agent_id, "kind": "agent", "name": result.agent_id},
                )
            writer.append(
                "run.completed",
                {
                    "completion": "completed",
                    "agentCount": len(results),
                    "boardMessageCount": len(transcript),
                    "boardChainHead": chain_head,
                    "aggregateBudget": aggregate_budget,
                    "measuredCoverage": measured_coverage,
                },
                phase="swarm",
            )
            writer.finalize(completion="completed")
        except Exception as error:
            with suppress(Exception):
                writer.append(
                    "error.recorded",
                    {
                        "code": (
                            error.issue.code
                            if isinstance(error, FormatError)
                            else "SOVA-SWARM-COORDINATOR-FAILED"
                        ),
                        "message": "Swarm coordinator failed; provider details omitted.",
                    },
                    phase="swarm",
                )
                writer.finalize(completion="failed")
            raise

        findings = _dedup_findings(transcript)
        report = {
            "artifactType": "sova.swarm-report",
            "schemaVersion": "0.1.0",
            "title": title,
            "agentCount": len(results),
            "personas": {item.agent_id: item.persona for item in results},
            "perAgentSummaries": [
                {
                    "agentId": item.agent_id,
                    "persona": item.persona,
                    "status": item.status,
                    "report": None if item.artifacts is None else str(item.artifacts.report),
                    "trace": None if item.artifacts is None else str(item.artifacts.trace),
                    "capsule": (
                        None
                        if item.artifacts is None or item.artifacts.capsule is None
                        else str(item.artifacts.capsule)
                    ),
                    "error": item.error,
                }
                for item in results
            ],
            "mergedFindings": [
                {
                    "authorAgentId": item.author_agent_id,
                    "summary": item.payload.get("summary", ""),
                    "chamberEventId": item.payload.get("chamberEventId"),
                }
                for item in findings
            ],
            "boardMessageCount": len(transcript),
            "boardChainHead": chain_head,
            "coordination": {
                "mode": "adaptive-per-planner-turn",
                "peerMessagesAreUntrustedData": True,
                "plannerAuthorityGranted": False,
                "snapshotsSignedInWorkerTraces": True,
            },
            "aggregateBudget": aggregate_budget,
            "measuredCoverage": measured_coverage,
            "nestedFindingCapsules": [
                f"capsules/{item.agent_id}-finding.sova"
                for item in results
                if item.artifacts is not None and item.artifacts.capsule is not None
            ],
            "coordinatorTrace": "coordinator.sova-trace",
        }
        manifest = capsule_manifest_template(
            title=title,
            summary=(
                f"A {len(results)}-agent concurrent swarm run against one authorized target, "
                "with a shared redacted inter-agent message board recorded alongside every "
                "agent's independent evidence."
            ),
            author="SOVA operator",
            domain_profile=DomainProfile.SECURITY,
            capture_profile=CaptureProfile.STANDARD,
        )
        manifest["license"] = "Apache-2.0"
        child_impacts = [
            PackageReader(item.artifacts.capsule).manifest("sova.capsule")["safety"]["impact"]
            for item in results
            if item.artifacts is not None and item.artifacts.capsule is not None
        ]
        manifest["safety"]["impact"] = (
            max(child_impacts, key=lambda value: _IMPACT_ORDER.get(value, 4))
            if child_impacts
            else "unknown"
        )
        manifest["requiredFeatures"] = ["capsule.core/0.1", "scenario.core/0.1"]
        manifest["limitations"] = [
            "Peer context is refreshed before each planner turn, so coordination latency "
            "is bounded by each worker's current action rather than being instantaneous.",
            "Merged findings are deduplicated by blackboard message content, not by "
            "independent semantic analysis of each agent's full report.",
            "The capsule does not contain credentials, raw profile handles, executor "
            "sockets, or model tool authority.",
        ]
        named_traces = {"coordinator.sova-trace": destination / "coordinator.sova-trace"}
        named_traces.update(
            {
                (
                    item.artifacts.trace.name
                    if item.artifacts.trace.name == f"{item.agent_id}.sova-trace"
                    or item.artifacts.trace.name.startswith(f"{item.agent_id}-")
                    else f"{item.agent_id}-{item.artifacts.trace.name}"
                ): item.artifacts.trace
                for item in results
                if item.artifacts is not None
            }
        )
        named_capsules = {
            f"{item.agent_id}-finding.sova": item.artifacts.capsule
            for item in results
            if item.artifacts is not None and item.artifacts.capsule is not None
        }
        scenario = scenario_template(
            title=f"{title} nested finding replay",
            purpose=(
                "Select and verify each independently reproduced nested finding capsule, "
                "then open its decisive replay cue when recorded media is present."
            ),
        )
        replay_steps = [
            {
                "id": f"replay-{item.agent_id}",
                "action": "sova.capsule.replay",
                "inputs": {"capsule": f"capsules/{item.agent_id}-finding.sova"},
                "onFailure": "inconclusive",
                "requires": ["capsule.replay/0.1"],
            }
            for item in results
            if item.artifacts is not None and item.artifacts.capsule is not None
        ]
        replay_effects = [
            {
                "kind": "nested-finding-replay",
                "capsule": f"capsules/{item.agent_id}-finding.sova",
                "status": item.status,
            }
            for item in results
            if item.artifacts is not None and item.artifacts.capsule is not None
        ]
        scenario["limitations"] = list(manifest["limitations"])
        if replay_steps:
            scenario["procedure"]["steps"] = replay_steps
            scenario["expectedEffects"] = replay_effects
        else:
            scenario["procedure"]["steps"] = [
                {
                    "id": "inspect-no-reproduced-finding",
                    "action": "sova.swarm.inspect-report",
                    "inputs": {
                        "reportDigest": sha256_digest(canonical_json_bytes(report)),
                        "findingCount": 0,
                    },
                    "onFailure": "inconclusive",
                    "requires": ["swarm.report.inspect/0.1"],
                }
            ]
            scenario["expectedEffects"] = [
                {
                    "kind": "no-reproduced-finding",
                    "status": "inconclusive",
                }
            ]
            scenario["limitations"].append(
                "No worker produced an independently reproduced nested finding capsule."
            )
        scenario["safety"]["budgets"] = {"maxSteps": len(scenario["procedure"]["steps"])}
        capsule_digest = build_capsule(
            destination / "swarm.sova",
            manifest,
            scenario=scenario,
            attachments={"swarm-report.json": canonical_json_bytes(report)},
            named_traces=named_traces,
            named_capsules=named_capsules,
        )
        report["swarmCapsule"] = "swarm.sova"
        report["swarmCapsuleDigest"] = capsule_digest
        return report


def _dedup_findings(transcript: tuple[SwarmMessage, ...]) -> tuple[SwarmMessage, ...]:
    seen: set[str] = set()
    deduped: list[SwarmMessage] = []
    for message in transcript:
        if message.kind != SwarmMessageKind.FINDING:
            continue
        key = message.payload.get("summary", "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(message)
    return tuple(deduped)


__all__ = ["AgentRunResult", "SwarmCoordinator"]
