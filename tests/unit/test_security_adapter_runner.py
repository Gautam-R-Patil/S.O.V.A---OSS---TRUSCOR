# SPDX-License-Identifier: Apache-2.0
"""Authorization, execution, failure, and cleanup tests for the P3 runner."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import sova.adapters.security_runner as runner_module
from sova.adapters.security_catalog import get_security_adapter, promoted_security_adapters
from sova.adapters.security_contracts import (
    AdapterInvocation,
    AdapterRunReport,
    ExternalTransferDecision,
    ExternalTransferGate,
    ExternalTransferRequest,
    ObservationState,
)
from sova.adapters.security_parsers import compare_reproduction
from sova.adapters.security_runner import (
    AdapterExecutionProposal,
    build_security_adapter_proposal,
    run_security_adapter,
)
from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.safety import (
    ApprovalLevel,
    ApprovalToken,
    AuthorityEnvelope,
    AuthorizationKernel,
    AuthorizationSession,
    ControlProof,
    ControlProofMethod,
    EffectBudget,
    EffectClass,
    OutOfBandApprovalAuthority,
    Principal,
    PrincipalKind,
    Scope,
)
from tests.unit.test_security_adapter_contracts import PROMOTED_FIXTURES

_TARGET_ID = "sova:sandbox:owned-adapter-fixture"
_CONTAINMENT = "sha256:" + "f" * 64
_SYFT_OUTPUT = (
    b'{"artifacts":[{"id":"pkg-1","name":"owned-package","version":"1.0",'
    b'"type":"python","purl":"pkg:pypi/owned-package@1.0"}]}'
)
_SCHEMATHESIS_OUTPUT = (
    b'<testsuite tests="1"><testcase name="GET /owned" classname="api">'
    b'<failure message="status mismatch"/></testcase></testsuite>'
)


class FixtureExecutor:
    """Deterministic executor fixture; it never starts a host process."""

    name = "sova-fixture-executor"

    def __init__(self, output_path: str, *, mode: str, raw: bytes = b"{}") -> None:
        self.output_path = output_path
        self.mode = mode
        self.raw = raw
        self.calls = 0

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="process.exec",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("stdout", "stderr", "returncode"),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        _cancellation: CancellationToken,
    ) -> ActionOutcome:
        self.calls += 1
        path = context.workspace / self.output_path
        if self.mode == "exception":
            raise RuntimeError
        if self.mode == "timeout":
            return ActionOutcome(
                request.id,
                OutcomeStatus.TIMEOUT,
                SideEffect.MUTATE,
                {"returncode": None, "stdout": "", "stderr": ""},
            )
        if self.mode == "cleanup-directory":
            path.mkdir()
        else:
            path.write_bytes(self.raw)
        status = (
            OutcomeStatus.PARTIAL
            if self.mode == "partial"
            else OutcomeStatus.FAILED
            if self.mode == "accepted-result-exit"
            else OutcomeStatus.SUCCEEDED
        )
        returncode = 1 if self.mode == "accepted-result-exit" else 0
        return ActionOutcome(
            request.id,
            status,
            SideEffect.MUTATE,
            {"returncode": returncode, "stdout": "", "stderr": ""},
        )


def _case(
    tmp_path: Path,
    adapter_id: str,
    *,
    mode: str,
    raw: bytes = b"{}",
) -> tuple[bytes, AdapterInvocation, FixtureExecutor, ExternalTransferDecision | None]:
    descriptor = get_security_adapter(adapter_id)
    executable = tmp_path / descriptor.executable_names[0]
    executable.write_bytes(f"fixture executable for {adapter_id}".encode())
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    ruleset = tmp_path / "ruleset.json"
    ruleset.write_text("{}", encoding="utf-8")
    version_evidence = f"{descriptor.tool_name} {descriptor.tool_version}".encode()
    output_name = "result.json"
    target = (
        "https://owned.invalid" if descriptor.network_requirement != "none" else "owned-workspace"
    )
    disclosure = (
        ExternalTransferGate().assess(
            ExternalTransferRequest(
                target_id=_TARGET_ID,
                destination=target,
                purpose="owned adapter fixture",
                data_classes=("synthetic-test-input",),
                authorization_reference="sova:authorization:fixture",
                human_reviewed=True,
                retention_reviewed=True,
            )
        )
        if descriptor.network_requirement != "none"
        else None
    )
    invocation = AdapterInvocation(
        identifier=f"fixture-{adapter_id}-{mode}",
        descriptor_id=adapter_id,
        target_id=_TARGET_ID,
        target=target,
        target_predicate=descriptor.target_predicates[0],
        target_profile_digest="sha256:" + "a" * 64,
        target_generation="sha256:" + "b" * 64,
        executable_path=str(executable.resolve()),
        observed_tool_version=descriptor.tool_version,
        version_evidence_digest=sha256_digest(version_evidence),
        output_path=output_name,
        config_path=config.name,
        config_digest=sha256_digest(config.read_bytes()),
        ruleset_path=ruleset.name,
        ruleset_digest=sha256_digest(ruleset.read_bytes()),
        disclosure_gate_id=disclosure.identifier if disclosure is not None else None,
        disclosure_gate_digest=disclosure.digest if disclosure is not None else None,
    )
    return (
        version_evidence,
        invocation,
        FixtureExecutor(output_name, mode=mode, raw=raw),
        disclosure,
    )


def _authorized(
    proposal: AdapterExecutionProposal,
) -> tuple[AuthorizationSession, ApprovalToken]:
    now = datetime.now(UTC)
    issuer = Principal("sova:principal:fixture-owner", PrincipalKind.HUMAN, "fixture owner")
    subject = Principal("sova:principal:fixture-agent", PrincipalKind.AGENT, "fixture agent")
    domains = (
        frozenset({proposal.intent.domain}) if proposal.intent.domain is not None else frozenset()
    )
    authority = AuthorityEnvelope(
        id=f"sova:authorization:{proposal.request.id}",
        issued_by=issuer,
        subject=subject,
        scope=Scope(
            targets=frozenset({_TARGET_ID}),
            actions=frozenset({"adapter.execute"}),
            tools=frozenset({proposal.intent.tool or "missing"}),
            domains=domains,
        ),
        max_effect=EffectClass.DESTRUCTIVE,
        budget=EffectBudget(
            max_steps=1,
            max_duration_ms=proposal.intent.cost.duration_ms,
            max_mutations=1,
            max_processes=1,
            max_files=1,
            max_network_requests=proposal.intent.cost.network_requests,
        ),
        valid_from=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        single_use=True,
        ownership="self",
        required_containment_digest=_CONTAINMENT,
    )
    challenge_text = "sova-control:owned-adapter-fixture"
    proof = ControlProof(
        ControlProofMethod.SANDBOX,
        _TARGET_ID,
        challenge_text,
        {"challenge": challenge_text, "synthetic": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=4),
        "sova.adapter-fixture/0.1",
    )
    approval_authority = OutOfBandApprovalAuthority(b"a" * 32)
    level = (
        ApprovalLevel.DESTRUCTIVE
        if proposal.intent.offensive or proposal.intent.effect == EffectClass.DESTRUCTIVE
        else ApprovalLevel.EXTERNAL
        if proposal.intent.effect == EffectClass.EXTERNAL
        else ApprovalLevel.NORMAL
    )
    challenge = approval_authority.challenge(authority, proposal.intent, level=level, now=now)
    approval = approval_authority.approve(
        challenge,
        approver=Principal(
            "sova:principal:fixture-reviewer",
            PrincipalKind.HUMAN,
            "fixture reviewer",
        ),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    session = AuthorizationSession(
        authority,
        proof,
        containment_allowed=True,
        containment_digest=_CONTAINMENT,
        kernel=AuthorizationKernel(approval_authority),
    )
    return session, approval


def _run_authorized(
    tmp_path: Path,
    adapter_id: str,
    *,
    mode: str,
    raw: bytes = b"{}",
) -> tuple[AdapterRunReport, FixtureExecutor]:
    descriptor = get_security_adapter(adapter_id)
    version_evidence, invocation, executor, disclosure = _case(
        tmp_path,
        adapter_id,
        mode=mode,
        raw=raw,
    )
    proposal = build_security_adapter_proposal(
        descriptor,
        invocation,
        executor=executor,
        workspace=tmp_path,
        version_evidence=version_evidence,
        disclosure_decision=disclosure,
    )
    session, approval = _authorized(proposal)
    report = run_security_adapter(
        descriptor,
        invocation,
        executor=executor,
        authorization_session=session,
        workspace=tmp_path,
        trace_path=tmp_path / "result.sova-trace",
        version_evidence=version_evidence,
        disclosure_decision=disclosure,
        approval=approval,
    )
    return report, executor


def test_owned_fixture_success_is_trace_bound_and_cleanup_verified(tmp_path: Path) -> None:
    report, executor = _run_authorized(
        tmp_path,
        "adapter.syft",
        mode="success",
        raw=_SYFT_OUTPUT,
    )
    assert executor.calls == 1
    assert report.outcome_status == "completed"
    assert report.infrastructure_failure is False
    assert report.cleanup_verified is True
    assert not (tmp_path / "result.json").exists()
    assert report.observations[0].state == ObservationState.INFORMATIONAL
    assert report.observations[0].finding_confirmed is False
    assert Path(report.trace_path).is_file()
    validate_document(report.to_mapping())


def test_expected_scanner_exit_is_not_itself_a_finding(tmp_path: Path) -> None:
    report, _executor = _run_authorized(
        tmp_path,
        "adapter.schemathesis",
        mode="accepted-result-exit",
        raw=_SCHEMATHESIS_OUTPUT,
    )
    assert report.outcome_status == "completed"
    assert report.infrastructure_failure is False
    assert report.observations[0].rule_id == "GET /owned"
    assert report.observations[0].finding_confirmed is False


@pytest.mark.parametrize("adapter_id", [item.identifier for item in promoted_security_adapters()])
def test_every_promoted_adapter_reproduces_on_an_owned_executor_fixture(
    tmp_path: Path,
    adapter_id: str,
) -> None:
    primary = tmp_path / "primary"
    reproduction = tmp_path / "reproduction"
    primary.mkdir()
    reproduction.mkdir()
    first, first_executor = _run_authorized(
        primary,
        adapter_id,
        mode="success",
        raw=PROMOTED_FIXTURES[adapter_id],
    )
    second, second_executor = _run_authorized(
        reproduction,
        adapter_id,
        mode="success",
        raw=PROMOTED_FIXTURES[adapter_id] + b"\n",
    )
    assert first.outcome_status == second.outcome_status == "completed"
    assert first_executor.calls == second_executor.calls == 1
    assessment = compare_reproduction(first.observations, second.observations)
    assert assessment["matched"] is True
    assert assessment["independentlyReproduced"] is True


@pytest.mark.parametrize("adapter_id", [item.identifier for item in promoted_security_adapters()])
def test_every_promoted_runner_separates_timeout_from_target_assertions(
    tmp_path: Path,
    adapter_id: str,
) -> None:
    report, executor = _run_authorized(tmp_path, adapter_id, mode="timeout")
    assert executor.calls == 1
    assert report.infrastructure_failure is True
    assert report.cleanup_verified is True
    assert len(report.observations) == 1
    assert report.observations[0].state == ObservationState.INFRASTRUCTURE_FAILURE
    assert report.observations[0].finding_confirmed is False


@pytest.mark.parametrize("adapter_id", [item.identifier for item in promoted_security_adapters()])
def test_every_promoted_runner_reports_partial_output_as_infrastructure_failure(
    tmp_path: Path,
    adapter_id: str,
) -> None:
    report, _executor = _run_authorized(tmp_path, adapter_id, mode="partial")
    assert report.infrastructure_failure is True
    assert report.observations[0].state == ObservationState.INFRASTRUCTURE_FAILURE
    assert report.cleanup_verified is True


@pytest.mark.parametrize("adapter_id", [item.identifier for item in promoted_security_adapters()])
def test_every_promoted_runner_makes_cleanup_failure_terminal(
    tmp_path: Path,
    adapter_id: str,
) -> None:
    report, _executor = _run_authorized(tmp_path, adapter_id, mode="cleanup-directory")
    assert report.infrastructure_failure is True
    assert report.cleanup_verified is False
    assert report.outcome_status == "cleanup-failed"


@pytest.mark.parametrize("adapter_id", [item.identifier for item in promoted_security_adapters()])
def test_every_promoted_runner_rejects_version_drift_before_execution(
    tmp_path: Path,
    adapter_id: str,
) -> None:
    descriptor = get_security_adapter(adapter_id)
    evidence, invocation, executor, disclosure = _case(tmp_path, adapter_id, mode="success")
    drifted_evidence = b"unexpected 999.0"
    invocation = replace(
        invocation,
        observed_tool_version="999.0",
        version_evidence_digest=sha256_digest(drifted_evidence),
    )
    with pytest.raises(FormatError, match="version does not match"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=drifted_evidence,
            disclosure_decision=disclosure,
        )
    assert executor.calls == 0
    assert evidence != drifted_evidence


def test_denied_authority_never_calls_executor(tmp_path: Path) -> None:
    descriptor = get_security_adapter("adapter.syft")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    proposal = build_security_adapter_proposal(
        descriptor,
        invocation,
        executor=executor,
        workspace=tmp_path,
        version_evidence=evidence,
        disclosure_decision=disclosure,
    )
    session, _unused_approval = _authorized(proposal)
    report = run_security_adapter(
        descriptor,
        invocation,
        executor=executor,
        authorization_session=session,
        workspace=tmp_path,
        trace_path=tmp_path / "denied.sova-trace",
        version_evidence=evidence,
        disclosure_decision=disclosure,
        approval=None,
    )
    assert report.outcome_status == "denied"
    assert report.to_mapping()["rawArtifact"] is None
    assert executor.calls == 0
    assert not (tmp_path / "result.json").exists()


def test_executable_byte_drift_invalidates_the_approved_request(tmp_path: Path) -> None:
    descriptor = get_security_adapter("adapter.syft")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    proposal = build_security_adapter_proposal(
        descriptor,
        invocation,
        executor=executor,
        workspace=tmp_path,
        version_evidence=evidence,
        disclosure_decision=disclosure,
    )
    assert proposal.request.inputs["sovaBinding"]["executableDigest"] == (
        proposal.executable_digest
    )
    session, approval = _authorized(proposal)
    Path(invocation.executable_path).write_bytes(b"different executable bytes")
    report = run_security_adapter(
        descriptor,
        invocation,
        executor=executor,
        authorization_session=session,
        workspace=tmp_path,
        trace_path=tmp_path / "drift-denied.sova-trace",
        version_evidence=evidence,
        disclosure_decision=disclosure,
        approval=approval,
    )
    assert report.outcome_status == "denied"
    assert "approval-scope-mismatch" in report.limitations
    assert executor.calls == 0


def test_network_adapter_requires_disclosure_gate_before_authority(tmp_path: Path) -> None:
    descriptor = get_security_adapter("adapter.zap")
    evidence, invocation, executor, _disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    with pytest.raises(FormatError, match="disclosure-gate"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, disclosure_gate_id=None, disclosure_gate_digest=None),
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
        )
    assert executor.calls == 0


def test_network_adapter_rejects_neighboring_disclosure_decision(tmp_path: Path) -> None:
    descriptor = get_security_adapter("adapter.zap")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    assert disclosure is not None
    neighboring = replace(disclosure, destination="https://other.invalid")
    with pytest.raises(FormatError, match="disclosure-gate"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=neighboring,
        )
    assert executor.calls == 0


def test_nmap_legal_hold_cannot_reach_executor(tmp_path: Path) -> None:
    descriptor = get_security_adapter("adapter.nmap")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    with pytest.raises(FormatError, match="legal-hold"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
            allow_constrained=True,
        )
    assert executor.calls == 0


def test_executor_exception_is_sanitized_as_infrastructure_failure(tmp_path: Path) -> None:
    report, executor = _run_authorized(tmp_path, "adapter.syft", mode="exception")
    assert executor.calls == 1
    assert report.outcome_status == "infrastructure-failure"
    assert report.infrastructure_failure is True
    assert report.observations[0].rule_id == "infrastructure.partial"
    assert "sensitive provider exception" not in str(report.to_mapping())


def test_parser_failure_after_authorized_execution_remains_infrastructure_failure(
    tmp_path: Path,
) -> None:
    report, executor = _run_authorized(
        tmp_path,
        "adapter.syft",
        mode="success",
        raw=b"[]",
    )
    assert executor.calls == 1
    assert report.outcome_status == "infrastructure-failure"
    assert "SOVA-ADAPTER-SYFT" in report.limitations
    assert report.observations[0].state == ObservationState.INFRASTRUCTURE_FAILURE


def test_proposal_preflight_rejects_unbound_runtime_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = get_security_adapter("adapter.syft")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )

    with pytest.raises(FormatError, match="descriptor binding"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, descriptor_id="adapter.grype"),
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )
    with pytest.raises(FormatError, match="target predicate"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, target_predicate="target.unsupported"),
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )

    monkeypatch.setattr(runner_module, "_platform_name", lambda: "plan9")
    with pytest.raises(FormatError, match="not admitted on this platform"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )
    monkeypatch.setattr(runner_module, "_platform_name", lambda: "windows")

    with pytest.raises(FormatError, match="declared digest"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=b"different evidence",
            disclosure_decision=disclosure,
        )
    invalid_utf8 = b"\xff" + descriptor.tool_version.encode()
    with pytest.raises(FormatError, match="UTF-8"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, version_evidence_digest=sha256_digest(invalid_utf8)),
            executor=executor,
            workspace=tmp_path,
            version_evidence=invalid_utf8,
            disclosure_decision=disclosure,
        )
    missing_version = b"tool output without the pinned version"
    with pytest.raises(FormatError, match="does not contain"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, version_evidence_digest=sha256_digest(missing_version)),
            executor=executor,
            workspace=tmp_path,
            version_evidence=missing_version,
            disclosure_decision=disclosure,
        )

    with pytest.raises(FormatError, match="workspace does not exist"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path / "missing-workspace",
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )
    with pytest.raises(FormatError, match="operator-supplied executable"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, executable_path="relative-tool"),
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )


def test_proposal_preflight_rejects_output_and_pin_collisions(tmp_path: Path) -> None:
    descriptor = get_security_adapter("adapter.syft")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    with pytest.raises(FormatError, match="requires an output path"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, output_path=None),
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )
    (tmp_path / "result.json").write_text("occupied", encoding="utf-8")
    with pytest.raises(FormatError, match="must not already exist"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )
    (tmp_path / "result.json").unlink()
    with pytest.raises(FormatError, match="parent directory"):
        build_security_adapter_proposal(
            descriptor,
            replace(invocation, output_path="missing/result.json"),
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )

    promptfoo = get_security_adapter("adapter.promptfoo")
    prompt_evidence, prompt_invocation, prompt_executor, prompt_disclosure = _case(
        tmp_path, promptfoo.identifier, mode="success"
    )
    with pytest.raises(FormatError, match="configuration is missing"):
        build_security_adapter_proposal(
            promptfoo,
            replace(prompt_invocation, config_path="missing.json"),
            executor=prompt_executor,
            workspace=tmp_path,
            version_evidence=prompt_evidence,
            disclosure_decision=prompt_disclosure,
        )

    nuclei = get_security_adapter("adapter.nuclei")
    nuclei_evidence, nuclei_invocation, nuclei_executor, nuclei_disclosure = _case(
        tmp_path, nuclei.identifier, mode="success"
    )
    with pytest.raises(FormatError, match="ruleset is missing"):
        build_security_adapter_proposal(
            nuclei,
            replace(nuclei_invocation, ruleset_digest="sha256:" + "0" * 64),
            executor=nuclei_executor,
            workspace=tmp_path,
            version_evidence=nuclei_evidence,
            disclosure_decision=nuclei_disclosure,
        )


def test_constrained_adapter_and_executor_capability_require_explicit_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = get_security_adapter("adapter.ffuf")
    evidence, invocation, executor, disclosure = _case(
        tmp_path, descriptor.identifier, mode="success"
    )
    with pytest.raises(FormatError, match="per-call opt-in"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
        )
    monkeypatch.setattr(executor, "capabilities", lambda: ())
    with pytest.raises(FormatError, match=r"required process\.exec"):
        build_security_adapter_proposal(
            descriptor,
            invocation,
            executor=executor,
            workspace=tmp_path,
            version_evidence=evidence,
            disclosure_decision=disclosure,
            allow_constrained=True,
        )
