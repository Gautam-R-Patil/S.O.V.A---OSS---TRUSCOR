# SPDX-License-Identifier: Apache-2.0
"""Zero-setup, no-native-code sleeper detonation demonstration."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template
from sova.detonation.backends import SyntheticDetonationBackend
from sova.detonation.sensors import SensorHealth, SensorKind, SensorMesh
from sova.detonation.targets import GroundTruthTarget, TargetKind
from sova.detonation.world import SyntheticWorld
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.oracles import ObservableRecord, evaluate_oracles
from sova.safety.authorization import (
    ActionIntent,
    AuthorityEnvelope,
    AuthorizationKernel,
    AuthorizationSession,
    BudgetCost,
    ControlProof,
    ControlProofMethod,
    EffectBudget,
    EffectClass,
    Principal,
    PrincipalKind,
    Scope,
)
from sova.safety.containment import (
    ContainmentGate,
    ContainmentRequirements,
    IsolationKind,
    NetworkMode,
    known_backend_descriptors,
)
from sova.trace import TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class DemoArtifacts:
    capsule: Path
    trace: Path
    summary: Path
    oracle_status: str
    evidence_closure: str
    cleanup_verified: bool


def _scenario() -> dict[str, Any]:
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": "sova:scenario:019fb800-0000-7000-8000-000000000008",
        "version": "0.1.0",
        "title": "Synthetic planted sleeper",
        "purpose": "Trigger a harmless deterministic target inside SOVA's no-native-code world.",
        "parameters": {"trigger": "blue-owl"},
        "preconditions": [{"kind": "synthetic-world", "owned": True}],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "invoke-sleeper",
                    "action": "synthetic.target.invoke",
                    "inputs": {"message": "blue-owl", "target": "sova:target:sleeper"},
                    "onFailure": "stop",
                    "requires": ["synthetic.target.invoke/0.1"],
                }
            ]
        },
        "triggers": [
            {"kind": "exact-phrase", "parameter": "trigger"},
            {"kind": "environment", "name": "SOVA_MODE", "value": "research"},
        ],
        "mutations": [
            {"parameter": "trigger", "domain": ["hello", "blue-owl"]},
            {"parameter": "SOVA_MODE", "domain": ["default", "research"]},
        ],
        "expectedEffects": [
            {"kind": "canary.read", "simulated": True},
            {"kind": "network.egress-attempt", "sinkOnly": True},
        ],
        "oracles": [
            {"kind": "trigger-activation", "triggered": True, "state": "triggered"},
            {
                "kind": "network-effect",
                "destination": "collector.sova.invalid",
                "delivered": False,
                "sinkOnly": True,
            },
        ],
        "evidenceRequirements": [
            "authorization.decision",
            "safety.containment",
            "filesystem.read",
            "network.egress-attempt",
            "oracle.completed",
        ],
        "safety": {
            "budgets": {"maxSteps": 1, "maxStepSeconds": 5},
            "forbiddenEffects": ["native-code", "real-network", "live-third-party"],
            "stopConditions": [],
        },
        "cleanup": [{"kind": "synthetic-reset", "verify": True}],
        "limitations": [
            "The target is a deterministic simulator and does not execute native target code.",
            "Sensor coverage does not imply complete observability of a real environment.",
        ],
        "extensions": {},
    }


def _manifest() -> dict[str, Any]:
    manifest = capsule_manifest_template(
        title="SOVA synthetic sleeper detonation",
        summary=(
            "A safe zero-setup demonstration of a planted conditional behavior, "
            "run-unique canary evidence, sink-only egress, reset, and offline verification."
        ),
        author="SOVA OSS synthetic fixture authors",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["safety"]["forbiddenEffects"] = [
        "native target code",
        "real network egress",
        "live third-party access",
    ]
    manifest["requiredFeatures"] = ["scenario.core/0.1", "detonation.synthetic/0.1"]
    manifest["optionalFeatures"] = ["sensor.evidence-closure/0.1"]
    return manifest


def run_sleeper_demo(destination: Path) -> DemoArtifacts:  # noqa: PLR0915
    """Create a capsule and trace from an entirely synthetic detonation."""
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    capsule_path = destination / "synthetic-sleeper.sova"
    trace_path = destination / "synthetic-sleeper.sova-trace"
    summary_path = destination / "synthetic-sleeper-summary.json"
    if any(path.exists() for path in (capsule_path, trace_path, summary_path)):
        raise FormatError("SOVA-DEMO-EXISTS", "demo output already exists; choose a new directory")

    descriptor = next(
        item for item in known_backend_descriptors() if item.id == "sova:backend:synthetic"
    )
    containment = ContainmentGate().assess(
        descriptor,
        ContainmentRequirements(
            minimum_isolation=IsolationKind.MICROVM,
            maximum_network_mode=NetworkMode.SINK_ONLY,
            allow_no_native_code_simulation=True,
        ),
    )
    if not containment.allowed:
        raise FormatError("SOVA-DEMO-CONTAINMENT", "synthetic backend failed admission")

    now = datetime.now(UTC)
    actor = Principal("sova:principal:demo-agent", PrincipalKind.AGENT, "Synthetic demo agent")
    issuer = Principal(
        "sova:principal:fixture-authority",
        PrincipalKind.SERVICE,
        "SOVA fixture authority",
    )
    authority = AuthorityEnvelope(
        id="sova:authorization:synthetic-demo",
        issued_by=issuer,
        subject=actor,
        scope=Scope(
            targets=frozenset({"sova:sandbox:synthetic-sleeper"}),
            actions=frozenset({"synthetic.target.invoke"}),
        ),
        max_effect=EffectClass.OBSERVE,
        budget=EffectBudget(max_steps=1, max_duration_ms=5000),
        valid_from=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
        single_use=True,
        ownership="self",
        required_containment_digest=containment.backend_digest,
    )
    challenge = "sova-control:" + sha256_digest(canonical_json_bytes(_scenario()))[7:31]
    proof = ControlProof(
        ControlProofMethod.SANDBOX,
        "sova:sandbox:synthetic-sleeper",
        challenge,
        {"challenge": challenge, "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
        "sova.synthetic-world/0.1",
    )
    intent = ActionIntent(
        "sova:intent:synthetic-sleeper",
        "sova:sandbox:synthetic-sleeper",
        "synthetic.target.invoke",
        EffectClass.OBSERVE,
        frozenset({"filesystem.read", "network.egress-attempt", "oracle.completed"}),
        BudgetCost(steps=1, duration_ms=1),
    )
    session = AuthorizationSession(
        authority,
        proof,
        containment.allowed,
        containment.backend_digest,
        AuthorizationKernel(),
    )
    session.claim_invocation("sova:run:synthetic-sleeper")
    authorization = session.authorize(intent, now=now)
    if not authorization.allowed:
        raise FormatError(
            "SOVA-DEMO-AUTHORIZATION",
            "synthetic demo authorization failed",
            details={"reasons": list(authorization.reasons)},
        )

    sensors = SensorMesh(dict.fromkeys(SensorKind, SensorHealth.HEALTHY))
    world = SyntheticWorld(
        "sova:run:synthetic-sleeper",
        seed=b"SOVA synthetic sleeper fixture seed 0.1",
        sensors=sensors,
    )
    target = GroundTruthTarget("sova:target:sleeper", TargetKind.ENVIRONMENT_GATED)
    backend = SyntheticDetonationBackend(world, descriptor)
    baseline = {
        "static": {
            "detected": False,
            "method": "minimal-known-signature-rule/0.1",
            "reason": "No known-signature rule exposes the runtime environment conjunction.",
        },
        "onePassDynamic": {
            "detected": False,
            "input": {"message": "hello", "SOVA_MODE": "default"},
            "evidenceAttempt": 0,
            "reason": "The single run exercised neither required trigger value.",
        },
        "passiveRecording": {
            "detected": False,
            "evidenceAttempt": 0,
            "reason": "Recording a dormant baseline cannot discover an unexecuted condition.",
        },
    }
    search_rows: list[dict[str, Any]] = []
    result = None
    for mode in ("default", "research"):
        for message in ("hello", "blue-owl"):
            world.environment["SOVA_MODE"] = mode
            trial = backend.detonate(target, message, containment=containment)
            search_rows.append(
                {
                    "attempt": len(search_rows),
                    "message": message,
                    "SOVA_MODE": mode,
                    "triggered": trial.observation.triggered,
                    "state": trial.observation.state,
                }
            )
            if trial.observation.triggered:
                result = trial
    if result is None:  # pragma: no cover - planted fixture invariant
        raise FormatError("SOVA-DEMO-SEARCH", "bounded search did not find the planted trigger")

    signing_key = generate_ed25519_keypair()
    writer = TraceWriter(
        trace_path,
        authorization={
            "decision": authorization.status,
            "scopeDigest": authorization.scope_digest,
            "decidedBy": "sova.authorization-kernel/0.1",
        },
        environment={
            "platform": "sova-synthetic-world/0.1",
            "python": platform.python_version(),
            "codeDigest": None,
            "model": None,
            "dependencies": [],
        },
        executor={
            "id": descriptor.id,
            "name": descriptor.name,
            "version": "0.1",
            "capabilityDigest": descriptor.digest,
        },
        signing_key=signing_key,
    )
    authorization_event = writer.append(
        "authorization.decision",
        authorization.to_mapping(),
        actor={"id": issuer.id, "kind": issuer.kind.value, "name": issuer.display_name},
        target={"id": intent.target, "kind": "synthetic-world", "name": "sleeper"},
    )
    containment_event = writer.append(
        "safety.containment",
        containment.to_mapping(),
        parents=[authorization_event] if authorization_event else [],
    )
    started = writer.append(
        "run.started",
        {"scenarioId": _scenario()["id"], "target": target.id},
        parents=[containment_event] if containment_event else [],
    )
    for row in search_rows:
        attempt_started = writer.append(
            "attempt.started",
            {
                "attemptIndex": row["attempt"],
                "dimensions": {
                    "message": row["message"],
                    "SOVA_MODE": row["SOVA_MODE"],
                },
                "baseline": False,
            },
            phase="trigger-search",
            parents=[started] if started else [],
        )
        writer.append(
            "attempt.completed",
            {
                "attemptIndex": row["attempt"],
                "triggered": row["triggered"],
                "state": row["state"],
            },
            phase="trigger-search",
            parents=[attempt_started] if attempt_started else [],
        )
    requested = writer.append(
        "tool.requested",
        {"action": "synthetic.target.invoke", "message": "blue-owl", "simulated": True},
        parents=[started] if started else [],
    )
    observable: list[ObservableRecord] = []
    sensor_event_ids: list[str] = []
    for observation in result.observations:
        event_id = writer.append(
            observation.kind,
            observation.payload,
            actor={"id": observation.actor, "kind": "agent", "name": observation.actor},
            target={"id": observation.target, "kind": "synthetic", "name": observation.target},
            parents=[requested] if requested else [],
            producer={
                "id": f"sova:sensor:{observation.sensor.value}",
                "kind": "observer",
                "name": observation.sensor.value,
            },
        )
        if event_id:
            sensor_event_ids.append(event_id)
        observable.append(ObservableRecord(observation.kind, event_id, observation.payload))
    trigger_event = writer.append(
        "safety.trigger-activation",
        {
            "triggered": result.observation.triggered,
            "state": result.observation.state,
            "trigger": "blue-owl",
            "responsibleLayer": result.observation.responsible_layer,
        },
        parents=sensor_event_ids,
    )
    observable.append(
        ObservableRecord(
            "safety.trigger-activation",
            trigger_event,
            {"triggered": True, "state": "triggered", "trigger": "blue-owl"},
        )
    )
    oracle_report = evaluate_oracles(_scenario()["oracles"], observable)
    oracle_event = writer.append(
        "oracle.completed",
        {
            **oracle_report.to_mapping(),
            "evidenceClosure": result.evidence_closure.to_mapping(),
        },
        parents=[*sensor_event_ids, *([trigger_event] if trigger_event else [])],
    )
    writer.append(
        "run.completed",
        {
            "completion": "completed",
            "oracleStatus": oracle_report.status.value,
            "evidenceClosure": result.evidence_closure.status,
            "cleanupVerified": result.cleanup_verified,
            "cleanupFailure": result.cleanup_failure,
        },
        parents=[oracle_event] if oracle_event else [],
    )
    writer.finalize(completion="completed")

    build_capsule(capsule_path, _manifest(), scenario=_scenario(), traces=[trace_path])
    summary = {
        "capsule": capsule_path.name,
        "trace": trace_path.name,
        "oracleStatus": oracle_report.status.value,
        "evidenceClosure": result.evidence_closure.status,
        "cleanupVerified": result.cleanup_verified,
        "cleanupFailure": result.cleanup_failure,
        "baselines": baseline,
        "search": {
            "method": "bounded-grid/0.1",
            "dimensions": ["message", "SOVA_MODE"],
            "attempts": search_rows,
            "found": True,
            "minimalTrigger": {"message": "blue-owl", "SOVA_MODE": "research"},
        },
        "signature": {
            "algorithm": "Ed25519",
            "keyId": signing_key.key_id,
            "identityClaim": "none-ephemeral-demo-key",
        },
        "containment": containment.to_mapping(),
        "limitations": list(descriptor.limitations),
    }
    summary_path.write_bytes(canonical_json_bytes(summary) + b"\n")
    return DemoArtifacts(
        capsule_path,
        trace_path,
        summary_path,
        oracle_report.status.value,
        result.evidence_closure.status,
        result.cleanup_verified,
    )


__all__ = ["DemoArtifacts", "run_sleeper_demo"]
