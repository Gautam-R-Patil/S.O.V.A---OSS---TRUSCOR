# SPDX-License-Identifier: Apache-2.0
"""Construction and integration tests for the trusted environment builder."""

from __future__ import annotations

import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from sova.community.executor_chamber import (
    ChamberObservation,
    ChamberVerification,
    ExecutorChamberEnvironment,
)
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.environment_builder import (
    BackendAdmission,
    TargetEnvironmentAdmission,
    build_bound_executor_environment,
    capability_contract_digest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from sova.runtime.bound_environment import BoundExecutorChamberEnvironment
    from sova.runtime.unified_execution import CapabilityBinding


_CLICK_EVIDENCE = b'{"state":"clicked"}'
_SNAPSHOT_EVIDENCE = b'{"state":"ready"}'
_PROCESS_EVIDENCE = b"bounded-process-output"


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


class _Executor:
    def __init__(
        self,
        name: str,
        capabilities: tuple[Capability, ...],
        evidence: Mapping[str, bytes],
    ) -> None:
        self._name = name
        self._capabilities = capabilities
        self._evidence = dict(evidence)
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    def capabilities(self) -> tuple[Capability, ...]:
        return self._capabilities

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context, cancellation
        capability = next(item for item in self._capabilities if item.name == request.action)
        data = self._evidence[request.action]
        role = capability.evidence[0]
        self.calls += 1
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            capability.side_effect,
            {"action": request.action, "completed": True},
            (EvidenceReference(role, "application/octet-stream", sha256_digest(data), len(data)),),
            verification="executor-claim-not-trusted",
        )


class _Observation:
    def __init__(self) -> None:
        self.state: dict[str, Any] = {
            "screen": "ready",
            "apiKey": "sk-" + "builder-private-value",
        }

    def __call__(self) -> Mapping[str, Any]:
        return self.state


class _Verifier:
    def __call__(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification:
        del request, before
        return ChamberVerification(
            verified=True,
            independence="agent-independent",
            method="builder-fixture-independent-state-check",
            evidence_digests=tuple(
                sorted(
                    {
                        after.version.content_digest,
                        *(reference.digest for reference in outcome.evidence),
                    }
                )
            ),
            satisfied_evidence=binding.expected_evidence,
        )


class _EvidenceReader:
    def __init__(self, values: tuple[bytes, ...]) -> None:
        self._values = {sha256_digest(value): value for value in values}

    def __call__(self, reference: EvidenceReference) -> bytes:
        return self._values[reference.digest]


def _capabilities() -> tuple[Capability, Capability, Capability]:
    snapshot = Capability(
        name="browser.snapshot",
        version="0.1",
        side_effect=SideEffect.READ,
        idempotent=True,
        evidence=("dom-snapshot",),
    )
    click = Capability(
        name="browser.click",
        version="0.1",
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        evidence=("post-observation",),
    )
    process = Capability(
        name="process.run",
        version="0.2",
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        evidence=("stdout",),
    )
    return snapshot, click, process


def _admission() -> TargetEnvironmentAdmission:
    return TargetEnvironmentAdmission(
        instance_id="owned-ui",
        target_manifest_digest=_digest("target-manifest"),
        environment_digest=_digest("environment-generation"),
        containment_digest=_digest("containment-policy"),
        identity_digest=_digest("operator-identity"),
        clock_domain="clock:owned-ui",
        generation=4,
        process_id=4242,
        process_start_digest=_digest("process-start"),
        browser_context_digest=_digest("browser-context"),
        window_handle_digest=_digest("window-handle"),
        endpoint_digest=_digest("loopback-endpoint"),
        profile_lease_digest=_digest("browser-profile-lease"),
    )


def _backends() -> tuple[tuple[BackendAdmission, ...], _Executor, _Executor]:
    snapshot, click, process = _capabilities()
    browser = _Executor(
        "fixture-browser",
        (snapshot, click),
        {
            snapshot.name: _SNAPSHOT_EVIDENCE,
            click.name: _CLICK_EVIDENCE,
        },
    )
    terminal = _Executor(
        "fixture-process",
        (process,),
        {process.name: _PROCESS_EVIDENCE},
    )
    admissions = (
        BackendAdmission(
            backend_id="backend:browser",
            executor=browser,
            verifier_id="verifier:browser",
            affinity_resources=("profile:owned", "window:owned"),
            effect_resources={click.name: ("effect:browser-state",)},
            generation=2,
            capability_generation=7,
        ),
        BackendAdmission(
            backend_id="backend:process",
            executor=terminal,
            verifier_id="verifier:process",
            affinity_resources=("process:owned",),
            effect_resources={process.name: ("effect:filesystem",)},
            generation=3,
            capability_generation=8,
        ),
    )
    return admissions, browser, terminal


def _build(
    tmp_path: Path,
) -> tuple[
    BoundExecutorChamberEnvironment,
    _Executor,
    _Executor,
    _Observation,
]:
    backends, browser, terminal = _backends()
    observation = _Observation()
    environment = build_bound_executor_environment(
        _admission(),
        backends,
        observe=observation,
        verify=_Verifier(),
        workspace_parent=tmp_path,
        evidence_reader=_EvidenceReader((_CLICK_EVIDENCE, _SNAPSHOT_EVIDENCE, _PROCESS_EVIDENCE)),
    )
    return environment, browser, terminal, observation


def _binding_for(
    environment: BoundExecutorChamberEnvironment,
    identifier: str,
) -> CapabilityBinding:
    return next(
        binding
        for binding in environment.bindings.values()
        if binding.capability_identifier == identifier
    )


def _context(
    environment: BoundExecutorChamberEnvironment,
    binding: CapabilityBinding,
) -> ExecutionContext:
    proposal_digest = _digest("builder-proposal")
    decision = {
        "decision": "allowed",
        "proposalDigest": proposal_digest,
        "bindingDigest": binding.digest,
        "sessionDigest": environment.session.digest,
    }
    issued = time.monotonic_ns()
    execution_grant = {
        "grantId": "grant:builder-fixture",
        "proposalDigest": proposal_digest,
        "bindingDigest": binding.digest,
        "sessionDigest": environment.session.digest,
        "targetInstanceDigest": environment.target.digest,
        "environmentDigest": environment.target.environment_digest,
        "observationVersionDigest": _digest("builder-observation"),
        "backendGenerationDigest": binding.backend_generation_digest,
        "capabilityContractDigest": binding.capability_contract_digest,
        "authorizationDecision": decision,
        "authorizationDecisionDigest": sha256_digest(canonical_json_bytes(decision)),
        "issuedMonotonicNs": issued,
        "expiresMonotonicNs": issued + 10_000_000_000,
    }
    return ExecutionContext(
        workspace=environment.workspace,
        authorization={**decision, "executionGrant": execution_grant},
        environment={
            "targetInstanceDigest": environment.target.digest,
            "sessionDigest": environment.session.digest,
            "bindingDigest": binding.digest,
        },
        secret_provider=environment.secret_provider,
    )


def test_builder_constructs_exact_target_session_backend_and_capability_bindings(
    tmp_path: Path,
) -> None:
    environment, browser, terminal, _observation = _build(tmp_path)
    with environment:
        target = environment.target
        session = environment.session
        admission = _admission()
        assert target == admission.target()
        assert target.generation == 4
        assert target.process_id == 4242
        assert target.process_start_digest == admission.process_start_digest
        assert target.browser_context_digest == admission.browser_context_digest
        assert target.window_handle_digest == admission.window_handle_digest
        assert target.endpoint_digest == admission.endpoint_digest
        assert session.profile_lease_digest == admission.profile_lease_digest
        assert session.target_instance_digest == target.digest
        assert session.environment_digest == target.environment_digest
        assert session.containment_digest == target.containment_digest
        assert session.identity_digest == admission.identity_digest
        assert session.affinity_resources == (
            "process:owned",
            "profile:owned",
            "target:owned-ui",
            "window:owned",
        )

        browser_generation = session.backend("backend:browser")
        process_generation = session.backend("backend:process")
        assert browser_generation.generation == 2
        assert process_generation.generation == 3
        expected_capabilities = {
            capability.identifier: capability for capability in _capabilities()
        }
        for generation in session.backend_generations:
            for capability_generation in generation.capabilities:
                capability = expected_capabilities[capability_generation.identifier]
                assert capability_generation.contract_digest == capability_contract_digest(
                    capability
                )
                expected_generation = 7 if generation.backend_id == "backend:browser" else 8
                assert capability_generation.generation == expected_generation

        snapshot, click, process = _capabilities()
        snapshot_binding = _binding_for(environment, snapshot.identifier)
        click_binding = _binding_for(environment, click.identifier)
        process_binding = _binding_for(environment, process.identifier)
        assert snapshot_binding.effect_resources == ()
        assert click_binding.effect_resources == ("effect:browser-state",)
        assert process_binding.effect_resources == ("effect:filesystem",)
        assert click_binding.backend_generation_digest == browser_generation.digest
        assert process_binding.backend_generation_digest == process_generation.digest
        assert click_binding.affinity_resources == (
            "profile:owned",
            "target:owned-ui",
            "window:owned",
        )
        assert process_binding.affinity_resources == (
            "process:owned",
            "target:owned-ui",
        )

        guarded = environment.executors
        assert set(guarded) == {"backend:browser", "backend:process"}
        assert guarded["backend:browser"] is not browser
        assert guarded["backend:process"] is not terminal
        assert guarded["backend:browser"] is not guarded["backend:process"]
        assert guarded["backend:browser"].capabilities() == tuple(
            sorted(browser.capabilities(), key=lambda capability: capability.identifier)
        )


def test_backend_admission_requires_exact_mutation_effect_policy() -> None:
    snapshot, click, _process = _capabilities()
    mutating_executor = _Executor("mutating", (click,), {click.name: _CLICK_EVIDENCE})
    with pytest.raises(FormatError, match="mutating capability requires"):
        BackendAdmission(
            "backend:mutating",
            mutating_executor,
            "verifier:fixture",
            ("target:owned",),
            {},
        )

    reading_executor = _Executor("reading", (snapshot,), {snapshot.name: _SNAPSHOT_EVIDENCE})
    with pytest.raises(FormatError, match="read-only capability cannot"):
        BackendAdmission(
            "backend:reading",
            reading_executor,
            "verifier:fixture",
            ("target:owned",),
            {snapshot.name: ("effect:not-allowed",)},
        )
    with pytest.raises(FormatError, match="absent capability"):
        BackendAdmission(
            "backend:reading",
            reading_executor,
            "verifier:fixture",
            ("target:owned",),
            {"browser.absent": ("effect:absent",)},
        )


def test_builder_rejects_duplicate_backend_executor_and_action_contracts(
    tmp_path: Path,
) -> None:
    admission = _admission()
    observation = _Observation()
    verifier = _Verifier()
    backends, browser, terminal = _backends()
    duplicate_backend = replace(backends[1], backend_id=backends[0].backend_id)
    with pytest.raises(FormatError, match="unique backend set"):
        build_bound_executor_environment(
            admission,
            (backends[0], duplicate_backend),
            observe=observation,
            verify=verifier,
            workspace_parent=tmp_path,
        )

    reused_executor = BackendAdmission(
        backend_id="backend:reused",
        executor=browser,
        verifier_id="verifier:reused",
        affinity_resources=("target:owned",),
        effect_resources={"browser.click": ("effect:browser-state",)},
    )
    with pytest.raises(FormatError, match="one executor object"):
        build_bound_executor_environment(
            admission,
            (backends[0], reused_executor),
            observe=observation,
            verify=verifier,
            workspace_parent=tmp_path,
        )

    snapshot, click, _process = _capabilities()
    duplicated_inventory = _Executor(
        "duplicate-capability",
        (click, click),
        {click.name: _CLICK_EVIDENCE},
    )
    duplicated_backend = BackendAdmission(
        "backend:duplicate-capability",
        duplicated_inventory,
        "verifier:duplicate",
        ("target:owned",),
        {click.name: ("effect:browser-state",)},
    )
    with pytest.raises(FormatError, match="identifier is duplicated"):
        build_bound_executor_environment(
            admission,
            (duplicated_backend,),
            observe=observation,
            verify=verifier,
            workspace_parent=tmp_path,
        )

    alternate_version = replace(click, version="0.2")
    ambiguous_executor = _Executor(
        "ambiguous-action",
        (click, alternate_version),
        {click.name: _CLICK_EVIDENCE},
    )
    ambiguous_backend = BackendAdmission(
        "backend:ambiguous-action",
        ambiguous_executor,
        "verifier:ambiguous",
        ("target:owned",),
        {click.name: ("effect:browser-state",)},
    )
    with pytest.raises(FormatError, match="multiple bound versions"):
        build_bound_executor_environment(
            admission,
            (ambiguous_backend,),
            observe=observation,
            verify=verifier,
            workspace_parent=tmp_path,
        )

    colliding_name = replace(snapshot, name="browser-snapshot")
    colliding_executor = _Executor(
        "binding-collision",
        (snapshot, colliding_name),
        {
            snapshot.name: _SNAPSHOT_EVIDENCE,
            colliding_name.name: _SNAPSHOT_EVIDENCE,
        },
    )
    colliding_backend = BackendAdmission(
        "backend:binding-collision",
        colliding_executor,
        "verifier:collision",
        ("target:owned",),
        {},
    )
    with pytest.raises(FormatError, match="binding id is duplicated"):
        build_bound_executor_environment(
            admission,
            (colliding_backend,),
            observe=observation,
            verify=verifier,
            workspace_parent=tmp_path,
        )
    assert terminal.calls == 0


def test_fresh_builds_rotate_session_and_run_but_preserve_attested_target(
    tmp_path: Path,
) -> None:
    backends, _browser, _terminal = _backends()
    admission = _admission()
    first = build_bound_executor_environment(
        admission,
        backends,
        observe=_Observation(),
        verify=_Verifier(),
        workspace_parent=tmp_path,
    )
    second = build_bound_executor_environment(
        admission,
        backends,
        observe=_Observation(),
        verify=_Verifier(),
        workspace_parent=tmp_path,
    )
    try:
        assert first.target == second.target == admission.target()
        assert first.target.digest == second.target.digest
        assert first.session.session_id != second.session.session_id
        assert first.session.run_id != second.session.run_id
        assert first.session.digest != second.session.digest
        assert first.workspace != second.workspace
        assert tuple(item.digest for item in first.session.backend_generations) == tuple(
            item.digest for item in second.session.backend_generations
        )
        first_click = _binding_for(first, "browser.click/0.1")
        second_click = _binding_for(second, "browser.click/0.1")
        assert first_click.session_digest != second_click.session_digest
        assert first_click.digest != second_click.digest
    finally:
        first.close()
        second.close()


def test_builder_environment_executes_through_guard_and_independent_verifier(
    tmp_path: Path,
) -> None:
    environment, browser, _terminal, observation = _build(tmp_path)
    with environment:
        structural_environment: ExecutorChamberEnvironment = environment
        assert structural_environment is environment
        binding = _binding_for(environment, "browser.click/0.1")
        before = ChamberObservation.capture(
            environment.session,
            environment.target,
            0,
            environment.observe(),
        )
        request = ActionRequest(
            "request:builder-click",
            binding.capability_name,
            {"selector": "#submit"},
            5,
        )
        outcome = environment.executors[binding.backend_id].execute(
            request,
            _context(environment, binding),
            CancellationToken(),
        )
        observation.state["screen"] = "clicked"
        after = before.advance(environment.observe())
        verification = environment.verify(request, outcome, binding, before, after)
        assert browser.calls == 1
        assert outcome.status == OutcomeStatus.SUCCEEDED
        assert verification.verified
        assert verification.satisfied_evidence == binding.expected_evidence
        assert set(verification.evidence_digests) == {
            outcome.evidence[0].digest,
            after.version.content_digest,
        }
        assert ("sk-" + "builder-private-value").encode() not in canonical_json_bytes(
            after.projection
        )
