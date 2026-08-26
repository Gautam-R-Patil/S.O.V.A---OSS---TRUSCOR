# SPDX-License-Identifier: Apache-2.0
"""Session, affinity, authorization-binding, and scheduler safety contracts."""

from __future__ import annotations

import threading
import time
from dataclasses import FrozenInstanceError, replace
from typing import Any, cast

import pytest

from sova.executors import EvidenceReference, SideEffect
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
    TargetLifecycle,
)
from sova.runtime.unified_execution import (
    BoundActionProposal,
    CapabilityBinding,
    CompletionState,
    ExecutionGrant,
    MutationScheduler,
    ObservationVersion,
    SingleCoordinatorSink,
)


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _target(*, generation: int = 1) -> TargetInstance:
    return TargetInstance(
        instance_id="target:owned-browser",
        target_manifest_digest=_digest("target-manifest"),
        environment_digest=_digest("owned-vm-generation-1"),
        containment_digest=_digest("owned-vm-policy"),
        generation=generation,
        clock_domain="vm:owned-browser",
        lifecycle=TargetLifecycle.READY,
        process_id=4242,
        process_start_digest=_digest(f"process-start-{generation}"),
        browser_context_digest=_digest(f"browser-context-{generation}"),
        window_handle_digest=_digest(f"window-handle-{generation}"),
        endpoint_digest=_digest("loopback-endpoint"),
    )


def _capability(
    identifier: str,
    *,
    generation: int = 1,
) -> CapabilityGeneration:
    return CapabilityGeneration(
        identifier,
        generation,
        _digest(f"contract:{identifier}:generation:{generation}"),
    )


def _backend(
    backend_id: str,
    target: TargetInstance,
    *,
    generation: int = 1,
) -> BackendGeneration:
    return BackendGeneration(
        backend_id,
        generation,
        target.digest,
        target.environment_digest,
        (
            _capability("browser.click/0.1"),
            _capability("browser.snapshot/0.1"),
        ),
    )


def _session(target: TargetInstance, *, generation: int = 1) -> SessionEnvelope:
    return SessionEnvelope(
        session_id="session:owned-browser",
        run_id="run:unified-core",
        generation=generation,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        identity_digest=_digest("fixture-identity"),
        clock_domain=target.clock_domain,
        backend_generations=(
            _backend("backend:playwright", target),
            _backend("backend:secondary", target),
        ),
        affinity_resources=(
            "profile:fixture",
            "target:fixture",
            "window:fixture",
        ),
        profile_lease_digest=_digest("profile-lease"),
    )


def _binding(  # noqa: PLR0913 - fixture exposes each binding dimension
    session: SessionEnvelope,
    target: TargetInstance,
    *,
    backend_id: str = "backend:playwright",
    action: str = "browser.snapshot",
    side_effect: SideEffect = SideEffect.READ,
    idempotent: bool = True,
    affinity_resources: tuple[str, ...] = (
        "profile:fixture",
        "target:fixture",
        "window:fixture",
    ),
) -> CapabilityBinding:
    backend = session.backend(backend_id)
    capability = backend.capability(f"{action}/0.1")
    effect_resources = () if side_effect == SideEffect.READ else ("effect:browser-state",)
    return CapabilityBinding(
        binding_id=f"binding:{backend_id.rsplit(':', 1)[-1]}:{action.replace('.', '-')}",
        backend_id=backend_id,
        backend_generation=backend.generation,
        backend_generation_digest=backend.digest,
        capability_name=action,
        capability_version="0.1",
        capability_generation=capability.generation,
        capability_contract_digest=capability.contract_digest,
        session_digest=session.digest,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        side_effect=side_effect,
        idempotent=idempotent,
        expected_evidence=("post-observation",),
        verifier_id="verifier:owned-target",
        affinity_resources=affinity_resources,
        effect_resources=effect_resources,
    )


def _proposal(  # noqa: PLR0913 - fixture exposes each proposal dimension
    session: SessionEnvelope,
    target: TargetInstance,
    observation: ObservationVersion,
    binding: CapabilityBinding,
    *,
    arguments: dict[str, Any] | None = None,
    participant_id: str = "agent:explorer",
) -> BoundActionProposal:
    return BoundActionProposal.create(
        proposal_id="proposal:turn-1",
        participant_id=participant_id,
        turn=1,
        session=session,
        target=target,
        observation=observation,
        action=binding.capability_name,
        capability_version=binding.capability_version,
        arguments=arguments or {"target": "button:submit"},
        expected_effect=binding.side_effect,
        required_evidence=binding.expected_evidence,
        affinity_resources=binding.affinity_resources,
        effect_resources=binding.effect_resources,
    )


def _decision(
    proposal: BoundActionProposal,
    binding: CapabilityBinding,
    session: SessionEnvelope,
) -> dict[str, Any]:
    return {
        "decision": "allowed",
        "proposalDigest": proposal.digest,
        "bindingDigest": binding.digest,
        "sessionDigest": session.digest,
        "intentDigest": _digest("authorization-intent"),
    }


def test_target_session_and_backend_generations_are_immutable_and_exact() -> None:
    target = _target()
    session = _session(target)
    session.assert_target(target)
    assert session.backend("backend:playwright").capability("browser.snapshot/0.1").generation == 1
    assert session.backend_generations[0].backend_id == "backend:playwright"
    assert session.affinity_resources == (
        "profile:fixture",
        "target:fixture",
        "window:fixture",
    )
    field_name = "instance_id"
    with pytest.raises(FrozenInstanceError):
        setattr(target, field_name, "target:substituted")
    with pytest.raises(FormatError, match="process id and process-start"):
        replace(target, process_start_digest=None)
    with pytest.raises(FormatError, match="canonical lowercase"):
        replace(session, identity_digest="SHA256:not-canonical")
    with pytest.raises(FormatError, match="target instance was substituted"):
        session.assert_target(_target(generation=2))


def test_target_environment_contract_rejects_every_generation_and_affinity_substitution() -> None:  # noqa: PLR0915
    target = _target()
    backend = _backend("backend:playwright", target)
    session = _session(target)

    with pytest.raises(FormatError, match="invalid"):
        replace(target, instance_id="bad target")
    with pytest.raises(FormatError, match="generation"):
        replace(target, generation=True)
    with pytest.raises(FormatError, match="positive integer"):
        replace(target, process_id=0)
    with pytest.raises(FormatError, match="target window"):
        replace(target, process_id=None, process_start_digest=None)
    with pytest.raises(FormatError, match="lifecycle"):
        replace(target, lifecycle=cast("Any", "ready"))

    capability = _capability("browser.snapshot/0.1")
    with pytest.raises(FormatError, match="exact version"):
        replace(capability, identifier="browser.snapshot")
    with pytest.raises(FormatError, match="generation"):
        replace(capability, generation=0)

    with pytest.raises(FormatError, match="generation"):
        replace(backend, generation=True)
    with pytest.raises(FormatError, match="at least one"):
        replace(backend, capabilities=())
    with pytest.raises(FormatError, match="duplicated"):
        replace(backend, capabilities=(capability, capability))
    with pytest.raises(FormatError, match="does not contain"):
        backend.capability("browser.missing/0.1")

    with pytest.raises(FormatError, match="generation"):
        replace(session, generation=0)
    with pytest.raises(FormatError, match="at least one backend"):
        replace(session, backend_generations=())
    with pytest.raises(FormatError, match="backend id is duplicated"):
        replace(session, backend_generations=(backend, backend))
    with pytest.raises(FormatError, match="different target"):
        replace(
            session,
            backend_generations=(replace(backend, target_instance_digest=_digest("other-target")),),
        )
    with pytest.raises(FormatError, match="different environment"):
        replace(
            session,
            backend_generations=(replace(backend, environment_digest=_digest("other-env")),),
        )
    with pytest.raises(FormatError, match="at least one affinity"):
        replace(session, affinity_resources=())
    with pytest.raises(FormatError, match="duplicate"):
        replace(session, affinity_resources=("target:fixture", "target:fixture"))
    with pytest.raises(FormatError, match="not attached"):
        session.backend("backend:missing")

    other_environment = replace(target, environment_digest=_digest("other-env"))
    environment_session = replace(
        session,
        target_instance_digest=other_environment.digest,
        backend_generations=(replace(backend, target_instance_digest=other_environment.digest),),
    )
    with pytest.raises(FormatError, match="environment digests differ"):
        environment_session.assert_target(other_environment)
    other_containment = replace(target, containment_digest=_digest("other-containment"))
    containment_session = replace(
        session,
        target_instance_digest=other_containment.digest,
        backend_generations=(replace(backend, target_instance_digest=other_containment.digest),),
    )
    with pytest.raises(FormatError, match="containment digests differ"):
        containment_session.assert_target(other_containment)
    other_clock = replace(target, clock_domain="clock:other")
    clock_session = replace(
        session,
        target_instance_digest=other_clock.digest,
        backend_generations=(replace(backend, target_instance_digest=other_clock.digest),),
    )
    with pytest.raises(FormatError, match="clock domains differ"):
        clock_session.assert_target(other_clock)
    with pytest.raises(FormatError, match="not ready"):
        closed_target = replace(target, lifecycle=TargetLifecycle.CLOSED)
        replace(
            session,
            target_instance_digest=closed_target.digest,
            backend_generations=(replace(backend, target_instance_digest=closed_target.digest),),
        ).assert_target(closed_target)
    with pytest.raises(FormatError, match="outside the session affinity"):
        session.assert_affinity(("target:other",))


def test_proposal_digest_binds_complete_canonical_arguments_and_actor() -> None:
    target = _target()
    session = _session(target)
    observation = ObservationVersion.capture(session, target, 0, {"url": "http://fixture/"})
    binding = _binding(session, target)
    proposal = _proposal(
        session,
        target,
        observation,
        binding,
        arguments={"text": "exact approved text", "target": "field:prompt"},
    )
    changed_text = _proposal(
        session,
        target,
        observation,
        binding,
        arguments={"text": "substituted text", "target": "field:prompt"},
    )
    changed_actor = _proposal(
        session,
        target,
        observation,
        binding,
        arguments={"text": "exact approved text", "target": "field:prompt"},
        participant_id="agent:other",
    )
    assert proposal.digest != changed_text.digest
    assert proposal.digest != changed_actor.digest
    assert proposal.arguments_digest == sha256_digest(proposal.canonical_arguments)
    detached = proposal.arguments
    detached["text"] = "local mutation"
    assert proposal.arguments["text"] == "exact approved text"

    noncanonical = b'{"text": "exact approved text", "target": "field:prompt"}'
    with pytest.raises(FormatError, match="not canonical"):
        replace(
            proposal,
            canonical_arguments=noncanonical,
            arguments_digest=sha256_digest(noncanonical),
        )
    with pytest.raises(FormatError, match="bound digest"):
        replace(proposal, arguments_digest=_digest("wrong-arguments"))


def test_binding_rejects_backend_capability_environment_and_session_substitution() -> None:
    target = _target()
    session = _session(target)
    observation = ObservationVersion.capture(session, target, 0, {"state": "ready"})
    binding = _binding(session, target)
    proposal = _proposal(session, target, observation, binding)
    binding.assert_session_generation(session, target)
    binding.assert_admits(proposal, session, target)

    with pytest.raises(FormatError, match="another session generation"):
        binding.assert_session_generation(replace(session, generation=2), target)
    with pytest.raises(FormatError, match="backend generation"):
        replace(binding, backend_generation=2).assert_session_generation(session, target)
    with pytest.raises(FormatError, match="capability generation"):
        replace(binding, capability_generation=2).assert_admits(proposal, session, target)
    with pytest.raises(FormatError, match="another environment"):
        replace(binding, environment_digest=_digest("another-environment")).assert_admits(
            proposal,
            session,
            target,
        )
    with pytest.raises(FormatError, match="another session generation"):
        replace(binding, session_digest=_digest("another-session")).assert_admits(
            proposal,
            session,
            target,
        )


def test_execution_grant_requires_allowed_exact_decision_and_fresh_observation() -> None:
    target = _target()
    session = _session(target)
    observation = ObservationVersion.capture(session, target, 4, {"page": "before"})
    binding = _binding(session, target)
    proposal = _proposal(session, target, observation, binding)
    grant = ExecutionGrant.issue(
        grant_id="grant:turn-1",
        proposal=proposal,
        binding=binding,
        session=session,
        target=target,
        observation=observation,
        authorization_decision=_decision(proposal, binding, session),
        issued_monotonic_ns=100,
        expires_monotonic_ns=200,
    )
    grant.assert_valid(
        proposal,
        binding,
        session,
        target,
        observation,
        now_monotonic_ns=150,
    )
    with pytest.raises(FormatError, match="outside its monotonic"):
        grant.assert_valid(
            proposal,
            binding,
            session,
            target,
            observation,
            now_monotonic_ns=200,
        )

    stale = observation.advance({"page": "after"})
    with pytest.raises(FormatError, match="stale observation"):
        grant.assert_valid(
            proposal,
            binding,
            session,
            target,
            stale,
            now_monotonic_ns=150,
        )
    denied = _decision(proposal, binding, session)
    denied["decision"] = "denied"
    with pytest.raises(FormatError, match="not allowed"):
        ExecutionGrant.issue(
            grant_id="grant:denied",
            proposal=proposal,
            binding=binding,
            session=session,
            target=target,
            observation=observation,
            authorization_decision=denied,
            issued_monotonic_ns=100,
            expires_monotonic_ns=200,
        )
    substituted = _decision(proposal, binding, session)
    substituted["proposalDigest"] = _digest("another-proposal")
    with pytest.raises(FormatError, match="another action"):
        ExecutionGrant.issue(
            grant_id="grant:substituted",
            proposal=proposal,
            binding=binding,
            session=session,
            target=target,
            observation=observation,
            authorization_decision=substituted,
            issued_monotonic_ns=100,
            expires_monotonic_ns=200,
        )


def test_fallback_stays_in_session_affinity_and_unsafe_retries_are_refused() -> None:
    target = _target()
    session = _session(target)
    primary = _binding(session, target)
    secondary = _binding(session, target, backend_id="backend:secondary")
    assert primary.retry_allowed(CompletionState.CONFIRMED_FAILED)
    assert primary.fallback_allowed_to(
        secondary,
        completion=CompletionState.CONFIRMED_FAILED,
        session=session,
        target=target,
    )
    assert not primary.retry_allowed(CompletionState.AMBIGUOUS)

    different_affinity = _binding(
        session,
        target,
        backend_id="backend:secondary",
        affinity_resources=("target:fixture",),
    )
    assert not primary.fallback_allowed_to(
        different_affinity,
        completion=CompletionState.CONFIRMED_FAILED,
        session=session,
        target=target,
    )
    with pytest.raises(FormatError, match="cross affinity"):
        primary.assert_fallback_allowed(
            different_affinity,
            completion=CompletionState.CONFIRMED_FAILED,
            session=session,
            target=target,
        )

    mutation = _binding(
        session,
        target,
        action="browser.click",
        side_effect=SideEffect.MUTATE,
        idempotent=False,
    )
    assert not mutation.retry_allowed(CompletionState.NOT_STARTED)
    assert not mutation.retry_allowed(CompletionState.CONFIRMED_FAILED)
    assert not mutation.retry_allowed(CompletionState.AMBIGUOUS)
    idempotent_mutation = replace(mutation, idempotent=True)
    assert idempotent_mutation.retry_allowed(CompletionState.NOT_STARTED)
    assert not idempotent_mutation.retry_allowed(CompletionState.CONFIRMED_FAILED)
    assert not idempotent_mutation.retry_allowed(CompletionState.AMBIGUOUS)


def _wait_until(predicate: Any, *, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            pytest.fail("condition was not reached before the test deadline")
        time.sleep(0.005)


def test_mutation_scheduler_serializes_conflicts_in_ticket_order() -> None:
    scheduler = MutationScheduler()
    entered: list[str] = []
    release_first = threading.Event()

    def worker(name: str) -> None:
        with scheduler.hold(("target:fixture",), ("effect:browser-state",), timeout_seconds=1):
            entered.append(name)

    with scheduler.hold(("target:fixture",), timeout_seconds=1):
        first = threading.Thread(target=worker, args=("first",))
        first.start()
        _wait_until(lambda: len(scheduler.waiting) == 1)
        second = threading.Thread(target=worker, args=("second",))
        second.start()
        _wait_until(lambda: len(scheduler.waiting) == 2)
        assert scheduler.active[0].resources == ("target:fixture",)
        release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)
    assert release_first.is_set()
    assert not first.is_alive() and not second.is_alive()
    assert entered == ["first", "second"]
    assert scheduler.active == ()


def test_mutation_scheduler_allows_disjoint_resources_and_times_out_safely() -> None:
    scheduler = MutationScheduler()
    disjoint_entered = threading.Event()
    errors: list[BaseException] = []

    def disjoint() -> None:
        try:
            with scheduler.hold(("target:other",), timeout_seconds=1):
                disjoint_entered.set()
        except BaseException as error:  # noqa: BLE001 - test captures worker failures
            errors.append(error)

    with scheduler.hold(("target:fixture",), timeout_seconds=1):
        thread = threading.Thread(target=disjoint)
        thread.start()
        assert disjoint_entered.wait(timeout=1)
        thread.join(timeout=1)
        with (
            pytest.raises(FormatError, match="timed out"),
            scheduler.hold(("target:fixture",), timeout_seconds=0.01),
        ):
            pytest.fail("conflicting scheduler claim unexpectedly entered")
    assert errors == []


class _MemorySink:
    coordinator_id = "coordinator:test"

    def __init__(self, *, corrupt: bool = False) -> None:
        self.events: list[dict[str, Any]] = []
        self.evidence: dict[str, bytes] = {}
        self.corrupt = corrupt

    def append_event(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        parents: tuple[str, ...] = (),
    ) -> str:
        self.events.append({"kind": kind, "payload": payload, "parents": parents})
        return f"event:{len(self.events)}"

    def persist_evidence(
        self,
        role: str,
        media_type: str,
        data: bytes,
    ) -> EvidenceReference:
        digest = _digest("corrupt") if self.corrupt else sha256_digest(data)
        self.evidence[digest] = data
        return EvidenceReference(role, media_type, digest, len(data))


def test_single_coordinator_sink_persists_exact_bytes_and_refuses_worker_writes() -> None:
    delegate = _MemorySink()
    sink = SingleCoordinatorSink(delegate)
    event_id = sink.append_event("tool.requested", {"action": "browser.snapshot"})
    evidence = sink.persist_evidence("snapshot", "application/json", b'{"ready":true}')
    assert event_id == "event:1"
    assert delegate.evidence[evidence.digest] == b'{"ready":true}'

    errors: list[BaseException] = []

    def write_from_worker() -> None:
        try:
            sink.append_event("tool.completed", {"status": "succeeded"})
        except BaseException as error:  # noqa: BLE001 - test captures the thread boundary
            errors.append(error)

    worker = threading.Thread(target=write_from_worker)
    worker.start()
    worker.join(timeout=2)
    assert len(errors) == 1
    assert isinstance(errors[0], FormatError)
    assert errors[0].issue.code == "SOVA-UNIFIED-COORDINATOR-THREAD"

    corrupt = SingleCoordinatorSink(_MemorySink(corrupt=True))
    with pytest.raises(FormatError, match="does not resolve"):
        corrupt.persist_evidence("snapshot", "application/json", b"exact bytes")


def test_canonical_mappings_include_every_security_binding() -> None:
    target = _target()
    session = _session(target)
    observation = ObservationVersion.capture(session, target, 2, {"state": "observed"})
    binding = _binding(session, target)
    proposal = _proposal(session, target, observation, binding)
    decision = _decision(proposal, binding, session)
    grant = ExecutionGrant.issue(
        grant_id="grant:canonical",
        proposal=proposal,
        binding=binding,
        session=session,
        target=target,
        observation=observation,
        authorization_decision=decision,
        issued_monotonic_ns=10,
        expires_monotonic_ns=20,
    )
    for value in (target, session, observation, proposal, binding, grant):
        encoded = canonical_json_bytes(value.to_mapping())
        assert value.digest == sha256_digest(encoded)
    assert proposal.to_mapping()["arguments"] == {"target": "button:submit"}
    assert grant.to_mapping()["authorizationDecisionDigest"] == sha256_digest(
        canonical_json_bytes(decision)
    )


def test_unified_contract_constructors_fail_closed_on_each_malformed_binding() -> None:
    target = _target()
    session = _session(target)
    observation = ObservationVersion.capture(session, target, 0, {"state": "ready"})
    binding = _binding(session, target)
    proposal = _proposal(session, target, observation, binding)

    with pytest.raises(FormatError, match="invalid"):
        replace(proposal, participant_id="bad participant")
    with pytest.raises(FormatError, match="digest"):
        replace(proposal, session_digest="bad")
    with pytest.raises(FormatError, match="turn"):
        replace(proposal, turn=True)
    with pytest.raises(FormatError, match="sequence"):
        replace(proposal, observation_sequence=-1)
    with pytest.raises(FormatError, match="1 byte"):
        replace(proposal, canonical_arguments=b"")
    array = b"[]"
    with pytest.raises(FormatError, match="JSON object"):
        replace(proposal, canonical_arguments=array, arguments_digest=sha256_digest(array))
    with pytest.raises(FormatError, match="requires evidence"):
        replace(proposal, required_evidence=())
    with pytest.raises(FormatError, match="requires session affinity"):
        replace(proposal, affinity_resources=())
    with pytest.raises(FormatError, match="effect resource"):
        replace(
            proposal,
            expected_effect=SideEffect.MUTATE,
            effect_resources=(),
        )
    with pytest.raises(FormatError, match="side effect"):
        replace(proposal, expected_effect=cast("Any", "read"))
    with pytest.raises(FormatError, match="duplicate"):
        replace(proposal, required_evidence=("snapshot", "snapshot"))

    with pytest.raises(FormatError, match="invalid"):
        replace(binding, backend_id="bad backend")
    with pytest.raises(FormatError, match="backend generation"):
        replace(binding, backend_generation=True)
    with pytest.raises(FormatError, match="capability generation"):
        replace(binding, capability_generation=0)
    with pytest.raises(FormatError, match="requires evidence"):
        replace(binding, expected_evidence=())
    with pytest.raises(FormatError, match="requires session affinity"):
        replace(binding, affinity_resources=())
    with pytest.raises(FormatError, match="effect resource"):
        replace(binding, side_effect=SideEffect.MUTATE, effect_resources=())
    with pytest.raises(FormatError, match="exact contract types"):
        replace(binding, idempotent=cast("Any", 1))
    with pytest.raises(FormatError, match="completion state"):
        binding.retry_allowed(cast("Any", "ambiguous"))


def test_observation_capture_and_proposal_creation_reject_generation_drift() -> None:
    target = _target()
    session = _session(target)
    with pytest.raises(FormatError, match="sequence"):
        ObservationVersion(
            session_digest=session.digest,
            target_instance_digest=target.digest,
            sequence=True,
            content_digest=_digest("content"),
        )
    observation = ObservationVersion.capture(session, target, 0, {"state": "ready"})
    binding = _binding(session, target)
    with pytest.raises(FormatError, match="another target or session"):
        BoundActionProposal.create(
            proposal_id="proposal:drift",
            participant_id="agent:fixture",
            turn=0,
            session=session,
            target=target,
            observation=replace(observation, session_digest=_digest("other-session")),
            action=binding.capability_name,
            capability_version=binding.capability_version,
            arguments={},
            expected_effect=binding.side_effect,
            required_evidence=binding.expected_evidence,
            affinity_resources=binding.affinity_resources,
            effect_resources=binding.effect_resources,
        )


def test_binding_admission_reports_all_proposal_dimensions_and_fallback_type_errors() -> None:
    target = _target()
    session = _session(target)
    observation = ObservationVersion.capture(session, target, 0, {"state": "ready"})
    binding = _binding(session, target)
    proposal = _proposal(session, target, observation, binding)
    changed = replace(
        proposal,
        session_digest=_digest("other-session"),
        target_instance_digest=_digest("other-target"),
        environment_digest=_digest("other-environment"),
        action="browser.click",
        expected_effect=SideEffect.MUTATE,
        required_evidence=("other-evidence",),
        affinity_resources=("other-affinity",),
        effect_resources=("other-effect",),
    )
    with pytest.raises(FormatError) as mismatch:
        binding.assert_admits(changed, session, target)
    details = mismatch.value.issue.details
    assert details is not None
    assert set(details["dimensions"]) == {
        "session",
        "target",
        "environment",
        "capability",
        "effect",
        "evidence",
        "affinity-resources",
        "effect-resources",
    }
    assert not binding.fallback_allowed_to(
        replace(binding, session_digest=_digest("other-session")),
        completion=CompletionState.CONFIRMED_FAILED,
        session=session,
        target=target,
    )
