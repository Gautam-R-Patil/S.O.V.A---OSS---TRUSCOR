# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the concrete session-bound chamber environment."""

from __future__ import annotations

import shutil
import threading
import time
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.runtime.bound_environment as bound_environment_module
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
from sova.runtime.bound_environment import BoundExecutorChamberEnvironment
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
)
from sova.runtime.unified_execution import CapabilityBinding

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _capability_document(capability: Capability) -> dict[str, Any]:
    return {
        "name": capability.name,
        "version": capability.version,
        "sideEffect": capability.side_effect.value,
        "idempotent": capability.idempotent,
        "evidence": list(capability.evidence),
    }


class _FixtureExecutor:
    def __init__(self, capability: Capability, evidence: bytes) -> None:
        self.capability = capability
        self.evidence = evidence
        self.calls = 0
        self.secret_value: str | None = None

    @property
    def name(self) -> str:
        return "fixture-bound-executor"

    def capabilities(self) -> tuple[Capability, ...]:
        return (self.capability,)

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del cancellation
        self.calls += 1
        if context.secret_provider is not None:
            self.secret_value = context.secret_provider.resolve("secret:fixture")
        return ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            self.capability.side_effect,
            {"clicked": True},
            (
                EvidenceReference(
                    "post-observation",
                    "application/json",
                    sha256_digest(self.evidence),
                    len(self.evidence),
                ),
            ),
            verification="executor-result-untrusted",
        )


class _ObservationSource:
    def __init__(self) -> None:
        self.value: dict[str, Any] = {
            "state": "ready",
            "nested": {"items": ["initial"]},
            "apiKey": "sk-" + "private-observation-value",
        }

    def __call__(self) -> Mapping[str, Any]:
        return self.value


class _SecretProvider:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, reference: str) -> str:
        assert reference == "secret:fixture"
        self.calls += 1
        return "private-action-secret"


class _EvidenceReader:
    def __init__(self, values: Mapping[str, bytes]) -> None:
        self.values = dict(values)

    def __call__(self, reference: EvidenceReference) -> bytes:
        return self.values[reference.digest]


class _Verifier:
    def __init__(self, *, mode: str = "verified") -> None:
        self.mode = mode

    def __call__(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification:
        del request, before
        digests = tuple(
            sorted(
                {
                    after.version.content_digest,
                    *(reference.digest for reference in outcome.evidence),
                }
            )
        )
        if self.mode == "unknown-digest":
            digests = (_digest("not-bound-to-this-outcome"),)
        independence = "provider-only" if self.mode == "provider-only" else "agent-independent"
        satisfied_evidence = (
            ("unexpected-evidence",)
            if self.mode == "unknown-label"
            else (
                ("post-observation", "post-observation")
                if self.mode == "duplicate-label"
                else (
                    ()
                    if self.mode in {"not-verified", "missing-label"}
                    else binding.expected_evidence
                )
            )
        )
        return ChamberVerification(
            verified=self.mode != "not-verified",
            independence=independence,
            method="fixture-independent-state-check",
            evidence_digests=digests,
            satisfied_evidence=satisfied_evidence,
            limitations=(),
        )


class _MutatingVerifier(_Verifier):
    def __call__(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification:
        after.projection["state"] = "verifier-mutated"
        return super().__call__(request, outcome, binding, before, after)


def _contracts() -> tuple[
    TargetInstance,
    SessionEnvelope,
    CapabilityBinding,
    Capability,
]:
    capability = Capability(
        name="browser.click",
        version="0.1",
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        evidence=("post-observation",),
    )
    contract_digest = sha256_digest(canonical_json_bytes(_capability_document(capability)))
    target = TargetInstance(
        instance_id="target:fixture",
        target_manifest_digest=_digest("target-manifest"),
        environment_digest=_digest("environment-generation-1"),
        containment_digest=_digest("containment-policy"),
        generation=1,
        clock_domain="clock:fixture",
        endpoint_digest=_digest("loopback-endpoint"),
    )
    backend = BackendGeneration(
        "backend:fixture",
        1,
        target.digest,
        target.environment_digest,
        (CapabilityGeneration(capability.identifier, 1, contract_digest),),
    )
    session = SessionEnvelope(
        session_id="session:fixture",
        run_id="run:fixture",
        generation=1,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        identity_digest=_digest("identity"),
        clock_domain=target.clock_domain,
        backend_generations=(backend,),
        affinity_resources=("target:fixture",),
    )
    binding = CapabilityBinding(
        binding_id="binding:browser-click",
        backend_id=backend.backend_id,
        backend_generation=backend.generation,
        backend_generation_digest=backend.digest,
        capability_name=capability.name,
        capability_version=capability.version,
        capability_generation=1,
        capability_contract_digest=contract_digest,
        session_digest=session.digest,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        side_effect=capability.side_effect,
        idempotent=capability.idempotent,
        expected_evidence=("post-observation",),
        verifier_id="verifier:fixture",
        affinity_resources=("target:fixture",),
        effect_resources=("effect:browser-state",),
    )
    return target, session, binding, capability


def _environment(  # noqa: PLR0913 - fixture exposes independent trust inputs
    tmp_path: Path,
    *,
    verifier: _Verifier | None = None,
    reader_bytes: bytes | None = None,
    cleanup: Any = None,
    secret_provider: _SecretProvider | None = None,
    precreated_workspace: Path | None = None,
) -> tuple[
    BoundExecutorChamberEnvironment,
    _FixtureExecutor,
    CapabilityBinding,
    _ObservationSource,
    bytes,
]:
    target, session, binding, capability = _contracts()
    evidence = b'{"state":"clicked"}'
    executor = _FixtureExecutor(capability, evidence)
    source = _ObservationSource()
    actual_reader_bytes = evidence if reader_bytes is None else reader_bytes
    environment = BoundExecutorChamberEnvironment(
        target=target,
        session=session,
        bindings={binding.binding_id: binding},
        executors={binding.backend_id: executor},
        observe=source,
        verify=_Verifier() if verifier is None else verifier,
        workspace_parent=tmp_path,
        precreated_workspace=precreated_workspace,
        evidence_reader=_EvidenceReader({sha256_digest(evidence): actual_reader_bytes}),
        secret_provider=secret_provider,
        cleanup=cleanup,
    )
    return environment, executor, binding, source, evidence


def test_precreated_disposable_workspace_is_adopted_and_removed(tmp_path: Path) -> None:
    workspace = tmp_path / "sova-precreated-fixture"
    workspace.mkdir()
    (workspace / "seed.txt").write_text("seed", encoding="utf-8")
    environment, _executor, _binding, _source, _evidence = _environment(
        tmp_path,
        precreated_workspace=workspace,
    )
    assert environment.workspace == workspace.resolve()
    assert (environment.workspace / "seed.txt").read_text(encoding="utf-8") == "seed"
    environment.close()
    assert not workspace.exists()


def _execution_context(
    environment: BoundExecutorChamberEnvironment,
    binding: CapabilityBinding,
) -> ExecutionContext:
    proposal_digest = _digest("proposal")
    decision = {
        "decision": "allowed",
        "proposalDigest": proposal_digest,
        "bindingDigest": binding.digest,
        "sessionDigest": environment.session.digest,
    }
    issued = time.monotonic_ns()
    grant = {
        "grantId": "grant:fixture",
        "proposalDigest": proposal_digest,
        "bindingDigest": binding.digest,
        "sessionDigest": environment.session.digest,
        "targetInstanceDigest": environment.target.digest,
        "environmentDigest": environment.target.environment_digest,
        "observationVersionDigest": _digest("observation"),
        "backendGenerationDigest": binding.backend_generation_digest,
        "capabilityContractDigest": binding.capability_contract_digest,
        "authorizationDecision": decision,
        "authorizationDecisionDigest": sha256_digest(canonical_json_bytes(decision)),
        "issuedMonotonicNs": issued,
        "expiresMonotonicNs": issued + 10_000_000_000,
    }
    return ExecutionContext(
        environment.workspace,
        {
            **decision,
            "executionGrant": grant,
        },
        environment={
            "targetInstanceDigest": environment.target.digest,
            "sessionDigest": environment.session.digest,
            "bindingDigest": binding.digest,
        },
        secret_provider=environment.secret_provider,
    )


def _observations(
    environment: BoundExecutorChamberEnvironment,
    source: _ObservationSource,
) -> tuple[ChamberObservation, ChamberObservation]:
    before = ChamberObservation.capture(
        environment.session,
        environment.target,
        0,
        environment.observe(),
    )
    source.value["state"] = "clicked"
    after = before.advance(environment.observe())
    return before, after


def test_protocol_surface_is_guarded_redacted_detached_and_independently_verified(
    tmp_path: Path,
) -> None:
    secret = _SecretProvider()
    environment, raw_executor, binding, source, _evidence = _environment(
        tmp_path,
        secret_provider=secret,
    )
    workspace = environment.workspace
    with environment as active:
        protocol_environment: ExecutorChamberEnvironment = active
        assert protocol_environment is active
        assert "ChamberObservation" not in bound_environment_module.__dict__
        assert active.executors[binding.backend_id] is not raw_executor
        assert active.secret_provider is not secret
        with pytest.raises(TypeError):
            active.bindings[binding.binding_id] = binding  # type: ignore[index]

        observed = active.observe()
        assert ("sk-" + "private-observation-value").encode() not in canonical_json_bytes(observed)
        source.value["nested"]["items"].append("source-mutated")
        assert observed["nested"]["items"] == ["initial"]
        assert active.secret_provider is not None
        with pytest.raises(FormatError, match="only be resolved during"):
            active.secret_provider.resolve("secret:fixture")

        request = ActionRequest(
            "request:click",
            binding.capability_name,
            {"selector": "#submit"},
            5,
        )
        outcome = active.executors[binding.backend_id].execute(
            request,
            _execution_context(active, binding),
            CancellationToken(),
        )
        assert raw_executor.calls == 1
        assert raw_executor.secret_value is not None
        assert secret.calls == 1
        before, after = _observations(active, source)
        verification = active.verify(request, outcome, binding, before, after)
        assert verification.verified
        assert verification.independence == "agent-independent"
    assert environment.closed
    assert environment.cleanup_complete
    assert not workspace.exists()


def test_admission_rejects_binding_backend_and_capability_substitution(tmp_path: Path) -> None:
    target, session, binding, capability = _contracts()
    source = _ObservationSource()
    verifier = _Verifier()
    executor = _FixtureExecutor(capability, b"evidence")

    with pytest.raises(FormatError, match="binding registry key"):
        BoundExecutorChamberEnvironment(
            target=target,
            session=session,
            bindings={"binding:substituted": binding},
            executors={binding.backend_id: executor},
            observe=source,
            verify=verifier,
            workspace_parent=tmp_path,
        )
    with pytest.raises(FormatError, match="another session generation"):
        BoundExecutorChamberEnvironment(
            target=target,
            session=session,
            bindings={binding.binding_id: replace(binding, session_digest=_digest("substituted"))},
            executors={binding.backend_id: executor},
            observe=source,
            verify=verifier,
            workspace_parent=tmp_path,
        )
    with pytest.raises(FormatError, match="exactly match admitted backend"):
        BoundExecutorChamberEnvironment(
            target=target,
            session=session,
            bindings={binding.binding_id: binding},
            executors={"backend:other": executor},
            observe=source,
            verify=verifier,
            workspace_parent=tmp_path,
        )
    executor.capability = replace(capability, idempotent=True)
    with pytest.raises(FormatError, match="inventory differs"):
        BoundExecutorChamberEnvironment(
            target=target,
            session=session,
            bindings={binding.binding_id: binding},
            executors={binding.backend_id: executor},
            observe=source,
            verify=verifier,
            workspace_parent=tmp_path,
        )


def test_runtime_inventory_drift_context_substitution_and_cross_thread_use_fail(
    tmp_path: Path,
) -> None:
    environment, executor, binding, _source, _evidence = _environment(tmp_path)
    with environment:
        request = ActionRequest("request:click", binding.capability_name, {}, 5)
        context = _execution_context(environment, binding)
        wrong_context = replace(
            context,
            environment={**context.environment, "bindingDigest": _digest("wrong-binding")},
        )
        with pytest.raises(FormatError, match="changed workspace"):
            environment.executors[binding.backend_id].execute(
                request,
                wrong_context,
                CancellationToken(),
            )
        assert executor.calls == 0

        errors: list[BaseException] = []

        def observe_on_worker() -> None:
            try:
                environment.observe()
            except BaseException as error:  # noqa: BLE001 - captured for assertion
                errors.append(error)

        worker = threading.Thread(target=observe_on_worker)
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], FormatError)
        assert "creating coordinator thread" in str(errors[0])

        executor.capability = replace(executor.capability, version="0.2")
        with pytest.raises(FormatError, match="inventory changed"):
            _ = environment.executors


@pytest.mark.parametrize(
    "mode",
    [
        "unknown-digest",
        "provider-only",
        "unknown-label",
        "missing-label",
        "duplicate-label",
    ],
)
def test_verifier_rejects_unbound_digest_or_non_independent_result(
    tmp_path: Path,
    mode: str,
) -> None:
    environment, _executor, binding, source, evidence = _environment(
        tmp_path,
        verifier=_Verifier(mode=mode),
    )
    with environment:
        request = ActionRequest("request:click", binding.capability_name, {}, 5)
        outcome = ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            binding.side_effect,
            {},
            (
                EvidenceReference(
                    "post-observation",
                    "application/json",
                    sha256_digest(evidence),
                    len(evidence),
                ),
            ),
        )
        before, after = _observations(environment, source)
        messages = {
            "unknown-digest": "absent or unbound",
            "provider-only": "provider-only",
            "unknown-label": "outside the binding",
            "missing-label": "did not satisfy every bound evidence label",
            "duplicate-label": "duplicated",
        }
        with pytest.raises(FormatError, match=messages[mode]):
            environment.verify(request, outcome, binding, before, after)


def test_verifier_resolves_cited_bytes_and_accepts_observation_backed_labels(
    tmp_path: Path,
) -> None:
    environment, _executor, binding, source, evidence = _environment(
        tmp_path,
        reader_bytes=b"tampered-evidence",
    )
    with environment:
        request = ActionRequest("request:click", binding.capability_name, {}, 5)
        reference = EvidenceReference(
            "post-observation",
            "application/json",
            sha256_digest(evidence),
            len(evidence),
        )
        outcome = ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            binding.side_effect,
            {},
            (reference,),
        )
        before, after = _observations(environment, source)
        with pytest.raises(FormatError, match="do not match reference"):
            environment.verify(request, outcome, binding, before, after)

        observation_backed = replace(outcome, evidence=())
        verification = environment.verify(request, observation_backed, binding, before, after)
        assert verification.verified is True
        assert verification.satisfied_evidence == binding.expected_evidence


def test_verifier_receives_detached_inputs_and_mutation_is_rejected(tmp_path: Path) -> None:
    environment, _executor, binding, source, evidence = _environment(
        tmp_path,
        verifier=_MutatingVerifier(),
    )
    with environment:
        request = ActionRequest("request:click", binding.capability_name, {}, 5)
        outcome = ActionOutcome(
            request.id,
            OutcomeStatus.SUCCEEDED,
            binding.side_effect,
            {},
            (
                EvidenceReference(
                    "post-observation",
                    "application/json",
                    sha256_digest(evidence),
                    len(evidence),
                ),
            ),
        )
        before, after = _observations(environment, source)
        assert after.projection["state"] == "clicked"
        with pytest.raises(FormatError, match="mutated trusted"):
            environment.verify(request, outcome, binding, before, after)
        assert after.projection["state"] == "clicked"


def test_close_is_fail_closed_and_workspace_cleanup_is_attempted(tmp_path: Path) -> None:
    cleanup_calls = 0

    def failing_cleanup() -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        raise RuntimeError

    environment, _executor, _binding, _source, _evidence = _environment(
        tmp_path,
        cleanup=failing_cleanup,
    )
    workspace = environment.workspace
    with pytest.raises(FormatError, match=r"cleanup did not complete|cleanup steps failed"):
        environment.close()
    assert cleanup_calls == 1
    assert environment.closed
    assert not environment.cleanup_complete
    assert not workspace.exists()
    with pytest.raises(FormatError, match="closed"):
        environment.observe()
    with pytest.raises(FormatError, match="cleanup did not complete"):
        environment.close()


def test_workspace_cleanup_retries_transient_handles_and_preserves_persistent_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transient = tmp_path / "transient"
    transient.mkdir()
    original = shutil.rmtree
    calls = 0

    def flaky(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise OSError
        original(path)

    monkeypatch.setattr(shutil, "rmtree", flaky)
    assert bound_environment_module._remove_workspace_with_retries(
        transient,
        attempts=3,
        retry_seconds=0,
    )
    assert calls == 3

    persistent = tmp_path / "persistent"
    persistent.mkdir()

    def always_fails(_path: Path) -> None:
        raise OSError

    monkeypatch.setattr(shutil, "rmtree", always_fails)
    assert not bound_environment_module._remove_workspace_with_retries(
        persistent,
        attempts=2,
        retry_seconds=0,
    )
    assert persistent.exists()
    original(persistent)


def test_internal_contract_validation_rejects_malformed_capabilities_and_evidence() -> None:
    _target, _session, _binding, capability = _contracts()
    with pytest.raises(FormatError, match="canonical lowercase"):
        bound_environment_module._require_digest("SHA256:nope", "fixture")
    with pytest.raises(FormatError, match="exact Capability"):
        bound_environment_module._validate_capability(object())
    with pytest.raises(FormatError, match="malformed capability"):
        bound_environment_module._validate_capability(replace(capability, name=""))
    with pytest.raises(FormatError, match="size boundary"):
        bound_environment_module._detached_mapping({"oversized": "x" * 300_000}, max_bytes=1024)

    reference = EvidenceReference("role", "application/json", _digest("evidence"), 1)
    with pytest.raises(FormatError, match="immutable tuple"):
        bound_environment_module._validate_evidence_references(
            cast("tuple[EvidenceReference, ...]", [reference])
        )
    with pytest.raises(FormatError, match="malformed evidence"):
        bound_environment_module._validate_evidence_references(
            cast("tuple[EvidenceReference, ...]", (object(),))
        )
    with pytest.raises(FormatError, match="invalid evidence"):
        bound_environment_module._validate_evidence_references((replace(reference, role=""),))
    with pytest.raises(FormatError, match="canonical lowercase"):
        bound_environment_module._validate_evidence_references(
            (replace(reference, digest="invalid"),)
        )
    with pytest.raises(FormatError, match="duplicate evidence"):
        bound_environment_module._validate_evidence_references((reference, reference))


def test_executor_inventory_boundary_wraps_failures_and_rejects_duplicates() -> None:
    _target, _session, _binding, capability = _contracts()

    class RaisingInventory:
        @property
        def name(self) -> str:
            raise RuntimeError

        def capabilities(self) -> tuple[Capability, ...]:
            return ()

    class InvalidInventory:
        name = ""

        def capabilities(self) -> tuple[Capability, ...]:
            return ()

    class DuplicateInventory:
        name = "duplicate"

        def capabilities(self) -> tuple[Capability, ...]:
            return (capability, capability)

    with pytest.raises(FormatError, match="could not be read"):
        bound_environment_module._executor_inventory(cast("Any", RaisingInventory()))
    with pytest.raises(FormatError, match="name or capability"):
        bound_environment_module._executor_inventory(cast("Any", InvalidInventory()))
    with pytest.raises(FormatError, match="duplicate identifier"):
        bound_environment_module._executor_inventory(cast("Any", DuplicateInventory()))


def test_workspace_callback_and_observation_failures_are_fail_closed(tmp_path: Path) -> None:
    target, session, binding, capability = _contracts()
    source = _ObservationSource()
    executor = _FixtureExecutor(capability, b"evidence")
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="parent must be"):
        BoundExecutorChamberEnvironment(
            target=target,
            session=session,
            bindings={binding.binding_id: binding},
            executors={binding.backend_id: executor},
            observe=source,
            verify=_Verifier(),
            workspace_parent=parent_file,
        )
    with pytest.raises(FormatError, match="callbacks are required"):
        BoundExecutorChamberEnvironment(
            target=target,
            session=session,
            bindings={binding.binding_id: binding},
            executors={binding.backend_id: executor},
            observe=cast("Any", None),
            verify=_Verifier(),
            workspace_parent=tmp_path,
        )

    environment, _executor, _binding, _source, _evidence = _environment(tmp_path)
    with environment:
        environment._observation_callback = lambda: (_ for _ in ()).throw(RuntimeError())
        with pytest.raises(FormatError, match="callback failed"):
            environment.observe()
        environment._observation_callback = cast("Any", list)
        with pytest.raises(FormatError, match="must return an object"):
            environment.observe()
        environment._observation_callback = lambda: {"large": "x" * 300_000}
        with pytest.raises(FormatError, match="size boundary"):
            environment.observe()


def test_disappeared_workspace_and_execution_request_guards(tmp_path: Path) -> None:
    environment, _executor, binding, _source, _evidence = _environment(tmp_path)
    record = environment._records[binding.backend_id]
    with pytest.raises(FormatError, match="non-retry"):
        environment._binding_for_request(
            record,
            ActionRequest("request:retry", binding.capability_name, {}, 5, retry_attempt=1),
        )
    with pytest.raises(FormatError, match="one exact backend binding"):
        environment._binding_for_request(
            record, ActionRequest("request:unknown", "browser.unknown", {}, 5)
        )
    workspace = environment.workspace
    workspace.rmdir()
    with pytest.raises(FormatError, match="disappeared"):
        _ = environment.workspace
    environment.close()


def test_execution_grant_and_context_substitution_guards(tmp_path: Path) -> None:
    secret = _SecretProvider()
    environment, _executor, binding, _source, _evidence = _environment(
        tmp_path, secret_provider=secret
    )
    context = _execution_context(environment, binding)
    grant = cast("dict[str, Any]", context.authorization["executionGrant"])
    cases = [
        (cast("Any", object()), "exact ExecutionContext"),
        (replace(context, secret_provider=None), "opaque secret provider"),
        (replace(context, authorization={}), "lacks an exact execution grant"),
        (
            replace(
                context,
                authorization={
                    **context.authorization,
                    "executionGrant": {**grant, "environmentDigest": _digest("wrong")},
                },
            ),
            "changed an admitted trust dimension",
        ),
        (
            replace(
                context,
                authorization={
                    **context.authorization,
                    "executionGrant": {**grant, "authorizationDecision": {}},
                },
            ),
            "exact allowed decision",
        ),
        (
            replace(
                context,
                authorization={
                    **context.authorization,
                    "executionGrant": {**grant, "authorizationDecisionDigest": _digest("wrong")},
                },
            ),
            "envelope does not match",
        ),
        (
            replace(
                context,
                authorization={
                    **context.authorization,
                    "executionGrant": {**grant, "expiresMonotonicNs": 0},
                },
            ),
            "validity window",
        ),
    ]
    with environment:
        for candidate, message in cases:
            with pytest.raises(FormatError, match=message):
                environment._assert_execution_context(candidate, binding)


def test_secret_provider_and_executor_failures_are_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BadSecret:
        def __init__(self, value: object = None, *, raises: bool = False) -> None:
            self.value = value
            self.raises = raises

        def resolve(self, _reference: str) -> str:
            if self.raises:
                raise RuntimeError
            return cast("str", self.value)

    for provider, reference, message in (
        (BadSecret("value"), "", "non-empty opaque"),
        (BadSecret(raises=True), "secret:fixture", "provider failed"),
        (BadSecret(123), "secret:fixture", "non-string value"),
    ):
        parent = tmp_path / str(id(provider))
        parent.mkdir()
        environment, _executor, _binding, _source, _evidence = _environment(
            parent, secret_provider=cast("Any", provider)
        )
        with environment:
            assert environment.secret_provider is not None
            with environment._executor_secret_lease(), pytest.raises(FormatError, match=message):
                environment.secret_provider.resolve(reference)

    executor_parent = tmp_path / "executor"
    executor_parent.mkdir()
    environment, executor, binding, _source, _evidence = _environment(executor_parent)
    request = ActionRequest("request:fail", binding.capability_name, {}, 5)
    monkeypatch.setattr(
        executor,
        "execute",
        cast("Any", lambda *_args: (_ for _ in ()).throw(RuntimeError("private adapter detail"))),
    )
    with environment, pytest.raises(FormatError, match="failed without exposing"):
        environment.executors[binding.backend_id].execute(
            request, _execution_context(environment, binding), CancellationToken()
        )


def test_outcome_observation_evidence_and_verifier_guards(tmp_path: Path) -> None:
    environment, _executor, binding, source, evidence = _environment(tmp_path)
    request = ActionRequest("request:verify", binding.capability_name, {}, 5)
    valid = ActionOutcome(
        request.id,
        OutcomeStatus.SUCCEEDED,
        binding.side_effect,
        {},
        (
            EvidenceReference(
                "post-observation", "application/json", sha256_digest(evidence), len(evidence)
            ),
        ),
    )
    with pytest.raises(FormatError, match="malformed outcome"):
        environment._assert_outcome(request, binding, object())
    with pytest.raises(FormatError, match="changed request"):
        environment._assert_outcome(request, binding, replace(valid, request_id="other"))

    before, after = _observations(environment, source)
    malformed_before = replace(before, projection=cast("Any", []))
    with pytest.raises(FormatError, match="malformed chamber"):
        environment._assert_observation(malformed_before, environment.session, environment.target)
    substituted_before = replace(
        before,
        version=replace(before.version, content_digest=_digest("wrong")),
    )
    with pytest.raises(FormatError, match="changed session"):
        environment._assert_observation(substituted_before, environment.session, environment.target)

    environment._evidence_reader = None
    with environment, pytest.raises(FormatError, match="requires an independent byte reader"):
        environment.verify(request, valid, binding, before, after)


def test_verifier_binding_request_freshness_and_callback_failures(tmp_path: Path) -> None:
    environment, _executor, binding, source, _evidence = _environment(tmp_path)
    request = ActionRequest("request:verify", binding.capability_name, {}, 5)
    outcome = ActionOutcome(request.id, OutcomeStatus.SUCCEEDED, binding.side_effect, {})
    before, after = _observations(environment, source)
    with environment:
        with pytest.raises(FormatError, match="outside the immutable registry"):
            environment.verify(
                request,
                outcome,
                replace(binding, binding_id="binding:other"),
                before,
                after,
            )
        with pytest.raises(FormatError, match="does not match the admitted capability"):
            environment.verify(
                ActionRequest("request:other", "browser.other", {}, 5),
                outcome,
                binding,
                before,
                after,
            )
        with pytest.raises(FormatError, match="next fresh observation"):
            environment.verify(request, outcome, binding, before, before)
        environment._verifier_callback = cast(
            "Any", lambda *_args: (_ for _ in ()).throw(RuntimeError("private verifier detail"))
        )
        with pytest.raises(FormatError, match="failed without exposing"):
            environment.verify(request, outcome, binding, before, after)
