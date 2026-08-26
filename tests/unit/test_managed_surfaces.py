# SPDX-License-Identifier: Apache-2.0
"""Trust-boundary tests for managed executor and observation surfaces."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import sova.runtime.managed_surfaces as managed_surfaces_module
from sova.community.executor_chamber import ChamberObservation
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.mcp import MCPTool, MCPToolResult, StdioMCPClient, StdioServerSpec
from sova.runtime.managed_surfaces import (
    CompositeObservationSource,
    EvidenceSatisfactionPolicy,
    LazyStdioExecutor,
    PolicyEvidenceVerifier,
)
from sova.runtime.unified_execution import CapabilityBinding, ObservationVersion

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _read_capability() -> Capability:
    return Capability(
        name="browser.snapshot",
        version="0.1",
        side_effect=SideEffect.READ,
        idempotent=True,
        evidence=("dom-snapshot",),
    )


def _mutating_capability() -> Capability:
    return Capability(
        name="browser.click",
        version="0.1",
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        evidence=("post-observation",),
    )


class _Client:
    def __init__(self, *, fail_close: bool = False) -> None:
        self.fail_close = fail_close
        self.close_calls = 0

    @property
    def server_name(self) -> str:
        return "fixture-client"

    @property
    def process_id(self) -> int:
        return 4242

    def list_tools(self) -> tuple[MCPTool, ...]:
        return ()

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> MCPToolResult:
        del name, arguments, timeout_seconds
        raise AssertionError

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError


class _Adapter:
    def __init__(
        self,
        capabilities: tuple[Capability, ...],
        *,
        status: OutcomeStatus = OutcomeStatus.SUCCEEDED,
        outcome_effect: SideEffect | None = None,
        fail_close: bool = False,
        post_execute_inventory: tuple[Capability, ...] | None = None,
    ) -> None:
        self.inventory = capabilities
        self.status = status
        self.outcome_effect = outcome_effect
        self.fail_close = fail_close
        self.post_execute_inventory = post_execute_inventory
        self.execute_calls = 0
        self.close_calls = 0
        self.last_request: ActionRequest | None = None
        self.last_workspace: Path | None = None

    @property
    def name(self) -> str:
        return "fixture-adapter"

    def capabilities(self) -> tuple[Capability, ...]:
        return self.inventory

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del cancellation
        self.execute_calls += 1
        self.last_request = request
        self.last_workspace = context.workspace
        nested = request.inputs.get("nested")
        if isinstance(nested, dict):
            nested["adapterMutation"] = True
        capability = next(item for item in self.inventory if item.name == request.action)
        outcome = ActionOutcome(
            request.id,
            self.status,
            capability.side_effect if self.outcome_effect is None else self.outcome_effect,
            {"observed": True},
        )
        if self.post_execute_inventory is not None:
            self.inventory = self.post_execute_inventory
        return outcome

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError


class _SpecFactory:
    def __init__(self) -> None:
        self.workspaces: list[Path] = []

    def __call__(self, workspace: Path) -> StdioServerSpec:
        self.workspaces.append(workspace)
        return StdioServerSpec(
            name="fixture-server",
            argv=("fixture-server",),
            cwd=workspace,
            environment={},
            version="1.0.0",
            source="fixture",
            license="Apache-2.0",
        )


def _lazy(
    monkeypatch: pytest.MonkeyPatch,
    adapter: _Adapter,
    client: _Client,
    *,
    expected: tuple[Capability, ...] | None = None,
) -> tuple[LazyStdioExecutor, _SpecFactory, list[StdioServerSpec]]:
    starts: list[StdioServerSpec] = []

    def fake_start(
        spec: StdioServerSpec,
        factory: Callable[[StdioServerSpec], StdioMCPClient],
    ) -> _Client:
        del factory
        starts.append(spec)
        return client

    monkeypatch.setattr(managed_surfaces_module, "start_stdio_client", fake_start)
    spec_factory = _SpecFactory()

    def adapter_factory(value: Any) -> _Adapter:
        assert value is client
        return adapter

    lazy = LazyStdioExecutor(
        name="managed:fixture",
        capabilities=adapter.capabilities() if expected is None else expected,
        spec_factory=spec_factory,
        adapter_factory=adapter_factory,
    )
    return lazy, spec_factory, starts


def _context(workspace: Path, session: str) -> ExecutionContext:
    return ExecutionContext(
        workspace,
        {"decision": "allowed"},
        environment={"sessionDigest": session},
    )


def test_lazy_stdio_starts_once_on_trusted_use_and_binds_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _read_capability()
    adapter = _Adapter((capability,))
    client = _Client()
    lazy, spec_factory, starts = _lazy(monkeypatch, adapter, client)
    other = tmp_path / "other"
    other.mkdir()

    started_before = lazy.started
    assert not started_before
    assert lazy.capabilities() == (capability,)
    inputs: dict[str, Any] = {"nested": {"selector": "body"}}
    outcome = lazy.trusted_observe(
        workspace=tmp_path,
        action=capability.name,
        inputs=inputs,
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert lazy.started
    assert len(starts) == 1
    assert spec_factory.workspaces == [tmp_path.resolve()]
    assert inputs == {"nested": {"selector": "body"}}
    assert adapter.last_request is not None
    assert adapter.last_request.inputs["nested"]["adapterMutation"] is True
    assert adapter.last_workspace == tmp_path.resolve()

    lazy.trusted_observe(workspace=tmp_path, action=capability.name, inputs={})
    assert len(starts) == 1
    with pytest.raises(FormatError, match="another workspace generation"):
        lazy.trusted_observe(workspace=other, action=capability.name, inputs={})
    lazy.close()
    assert lazy.closed
    assert lazy.cleanup_complete
    assert adapter.close_calls == 1
    assert client.close_calls == 1
    lazy.close()
    assert adapter.close_calls == 1
    assert client.close_calls == 1


def test_lazy_stdio_enforces_session_affinity_and_reviewed_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read = _read_capability()
    mutate = _mutating_capability()
    adapter = _Adapter((mutate, read))
    lazy, _spec_factory, starts = _lazy(
        monkeypatch,
        adapter,
        _Client(),
        expected=(read, mutate),
    )
    request = ActionRequest("request:click", mutate.name, {"selector": "#submit"}, 5)
    session = _digest("session-one")
    outcome = lazy.execute(request, _context(tmp_path, session), CancellationToken())
    assert outcome.request_id == request.id
    assert len(starts) == 1
    lazy.execute(request, _context(tmp_path, session), CancellationToken())
    with pytest.raises(FormatError, match="another session generation"):
        lazy.execute(
            request,
            _context(tmp_path, _digest("session-two")),
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="requires a bound session digest"):
        lazy.execute(
            request,
            ExecutionContext(tmp_path, {}, environment={}),
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="outside the reviewed"):
        lazy.execute(
            ActionRequest("request:absent", "browser.absent", {}, 5),
            _context(tmp_path, session),
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="read-only capability"):
        lazy.trusted_observe(workspace=tmp_path, action=mutate.name, inputs={})
    lazy.close()


def test_exact_capability_inventory_is_checked_at_start_and_every_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read = _read_capability()
    substituted = replace(read, version="0.2")
    adapter = _Adapter((substituted,))
    client = _Client()
    lazy, _spec_factory, _starts = _lazy(
        monkeypatch,
        adapter,
        client,
        expected=(read,),
    )
    with pytest.raises(FormatError, match="differs from its reviewed contract"):
        lazy.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    assert not lazy.started
    assert adapter.close_calls == 1
    assert client.close_calls == 1

    live_adapter = _Adapter((read,))
    live_client = _Client()
    live, _spec_factory, _starts = _lazy(monkeypatch, live_adapter, live_client)
    live.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    calls = live_adapter.execute_calls
    live_adapter.inventory = (substituted,)
    with pytest.raises(FormatError, match="differs from its reviewed contract"):
        live.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    assert live_adapter.execute_calls == calls
    live.close()

    drifting_adapter = _Adapter((read,), post_execute_inventory=(substituted,))
    drifting, _spec_factory, _starts = _lazy(
        monkeypatch,
        drifting_adapter,
        _Client(),
        expected=(read,),
    )
    with pytest.raises(FormatError, match="differs from its reviewed contract"):
        drifting.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    assert drifting_adapter.execute_calls == 1
    drifting.close()


def test_duplicate_action_versions_and_trusted_outcome_substitution_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read = _read_capability()
    with pytest.raises(FormatError, match="multiple versions"):
        LazyStdioExecutor(
            name="managed:ambiguous",
            capabilities=(read, replace(read, version="0.2")),
            spec_factory=_SpecFactory(),
            adapter_factory=lambda _client: _Adapter((read,)),
        )

    adapter = _Adapter((read,), outcome_effect=SideEffect.MUTATE)
    lazy, _spec_factory, _starts = _lazy(monkeypatch, adapter, _Client())
    with pytest.raises(FormatError, match="changed request or side-effect"):
        lazy.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    lazy.close()


def test_workspace_identity_and_cleanup_failure_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read = _read_capability()
    missing = tmp_path / "missing"
    lazy, _spec_factory, starts = _lazy(monkeypatch, _Adapter((read,)), _Client())
    with pytest.raises(FormatError, match="does not resolve"):
        lazy.trusted_observe(workspace=missing, action=read.name, inputs={})
    assert not starts

    outside = tmp_path / "outside"
    outside.mkdir()

    def escaping_spec(_workspace: Path) -> StdioServerSpec:
        return StdioServerSpec(
            name="escaping-server",
            argv=("escaping-server",),
            cwd=outside,
            environment={},
            version="1.0.0",
            source="fixture",
            license="Apache-2.0",
        )

    escaping = LazyStdioExecutor(
        name="managed:escaping",
        capabilities=(read,),
        spec_factory=escaping_spec,
        adapter_factory=lambda _client: _Adapter((read,)),
    )
    with pytest.raises(FormatError, match="escaped its bound workspace"):
        escaping.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    assert not starts

    original_is_symlink = Path.is_symlink

    def report_workspace_as_symlink(path: Path) -> bool:
        return path == tmp_path or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", report_workspace_as_symlink)
    with pytest.raises(FormatError, match="cannot be a symbolic link"):
        lazy.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    assert not starts
    monkeypatch.setattr(Path, "is_symlink", original_is_symlink)

    adapter = _Adapter((read,), fail_close=True)
    client = _Client(fail_close=True)
    failing, _spec_factory, _starts = _lazy(monkeypatch, adapter, client)
    failing.trusted_observe(workspace=tmp_path, action=read.name, inputs={})
    with pytest.raises(FormatError, match="cleanup could not be verified"):
        failing.close()
    assert failing.closed
    assert not failing.cleanup_complete
    assert adapter.close_calls == 1
    assert client.close_calls == 1
    with pytest.raises(FormatError, match="cleanup was not verified"):
        failing.close()


def test_composite_observations_are_ordered_canonical_and_deeply_detached() -> None:
    first: dict[str, Any] = {"nested": {"items": ["initial"]}}
    second: dict[str, Any] = {"state": "ready"}
    source = CompositeObservationSource(
        {
            "zeta": lambda: second,
            "alpha": lambda: first,
        }
    )
    projection = source()
    assert list(projection) == ["alpha", "zeta"]
    first["nested"]["items"].append("source-mutated")
    second["state"] = "source-mutated"
    assert projection == {
        "alpha": {"nested": {"items": ["initial"]}},
        "zeta": {"state": "ready"},
    }
    projection["alpha"]["nested"]["items"].append("projection-mutated")
    assert first["nested"]["items"] == ["initial", "source-mutated"]


def test_composite_observation_rejects_sensor_failures_types_and_size() -> None:
    with pytest.raises(FormatError, match="requires named trusted sensors"):
        CompositeObservationSource({})

    def non_mapping_sensor() -> Any:
        return 1

    with pytest.raises(FormatError, match="non-object"):
        CompositeObservationSource({"bad": non_mapping_sensor})()

    def raising_sensor() -> Mapping[str, Any]:
        raise RuntimeError

    with pytest.raises(FormatError, match="failed without exposing"):
        CompositeObservationSource({"bad": raising_sensor})()
    with pytest.raises(FormatError, match="exceeds 256 KiB"):
        CompositeObservationSource({"large": lambda: {"value": "x" * (300 * 1024)}})()


def _binding() -> CapabilityBinding:
    return CapabilityBinding(
        binding_id="binding:browser-click",
        backend_id="backend:browser",
        backend_generation=1,
        backend_generation_digest=_digest("backend"),
        capability_name="browser.click",
        capability_version="0.1",
        capability_generation=1,
        capability_contract_digest=_digest("contract"),
        session_digest=_digest("session"),
        target_instance_digest=_digest("target"),
        environment_digest=_digest("environment"),
        side_effect=SideEffect.MUTATE,
        idempotent=False,
        expected_evidence=("dom-snapshot", "post-observation"),
        verifier_id="verifier:policy",
        affinity_resources=("target:owned",),
        effect_resources=("effect:browser-state",),
    )


def _observation(
    sequence: int,
    projection: dict[str, Any],
) -> ChamberObservation:
    return ChamberObservation(
        ObservationVersion(
            session_digest=_digest("session"),
            target_instance_digest=_digest("target"),
            sequence=sequence,
            content_digest=sha256_digest(canonical_json_bytes(projection)),
        ),
        projection,
    )


def test_evidence_policy_returns_only_exact_satisfied_labels_and_bound_digest() -> None:
    assert "ChamberVerification" not in managed_surfaces_module.__dict__
    binding = _binding()
    policy = EvidenceSatisfactionPolicy(
        capability=binding.capability_identifier,
        satisfied_evidence=("post-observation", "dom-snapshot"),
        required_projection_paths=(("surface", "state"),),
        required_output_keys=("completed",),
        require_observation_change=True,
    )
    assert policy.satisfied_evidence == binding.expected_evidence
    verifier = PolicyEvidenceVerifier((policy,))
    before = _observation(0, {"surface": {"state": "ready"}})
    after = _observation(1, {"surface": {"state": "clicked"}})
    request = ActionRequest("request:click", binding.capability_name, {}, 5)
    outcome = ActionOutcome(
        request.id,
        OutcomeStatus.SUCCEEDED,
        binding.side_effect,
        {"completed": True},
    )
    result = verifier(request, outcome, binding, before, after)
    assert result.verified
    assert result.satisfied_evidence == binding.expected_evidence
    assert result.evidence_digests == (after.version.content_digest,)
    assert result.independence == "agent-independent"

    missing_output = replace(outcome, output={})
    failed = verifier(request, missing_output, binding, before, after)
    assert not failed.verified
    assert failed.satisfied_evidence == ()
    assert "Required normalized outcome fields were absent." in failed.limitations


def test_evidence_policy_rejects_invalid_contracts_and_uncovered_capabilities() -> None:
    with pytest.raises(FormatError, match="policy is invalid"):
        EvidenceSatisfactionPolicy("browser.click/0.1", ("same", "same"))
    with pytest.raises(FormatError, match="projection path is invalid"):
        EvidenceSatisfactionPolicy(
            "browser.click/0.1",
            ("evidence",),
            required_projection_paths=(("surface",), ("surface",)),
        )
    with pytest.raises(FormatError, match="output-key contract is invalid"):
        EvidenceSatisfactionPolicy(
            "browser.click/0.1",
            ("evidence",),
            required_output_keys=("",),
        )
    policy = EvidenceSatisfactionPolicy("browser.other/0.1", ("evidence",))
    verifier = PolicyEvidenceVerifier((policy,))
    binding = _binding()
    before = _observation(0, {"state": "ready"})
    after = _observation(1, {"state": "after"})
    request = ActionRequest("request:click", binding.capability_name, {}, 5)
    outcome = ActionOutcome(
        request.id,
        OutcomeStatus.SUCCEEDED,
        binding.side_effect,
        {},
    )
    with pytest.raises(FormatError, match="no independent evidence policy"):
        verifier(request, outcome, binding, before, after)
