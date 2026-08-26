# SPDX-License-Identifier: Apache-2.0
"""Authorization-routed runner for external security-tool adapters."""

from __future__ import annotations

import hashlib
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from sova.adapters.security_contracts import (
    AdapterAdmission,
    AdapterDescriptor,
    AdapterInvocation,
    AdapterRunReport,
    ExternalTransferDecision,
    NormalizedObservation,
    OutputSource,
    RawArtifact,
)
from sova.adapters.security_parsers import (
    infrastructure_failure_observation,
    normalize_security_output,
)
from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
    negotiate,
)
from sova.executors.runner import canonical_action_request_digest
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.safety.authorization import ActionIntent, BudgetCost, EffectClass
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from sova.executors.contract import Executor
    from sova.safety.authorization import ApprovalToken, AuthorizationSession
    from sova.trace.integrity import Ed25519Keypair

_EXECUTABLE_CHUNK_BYTES = 1024 * 1024
_OFFENSIVE_ADAPTERS = frozenset(
    {
        "adapter.zap",
        "adapter.nuclei",
        "adapter.ffuf",
        "adapter.sqlmap",
        "adapter.zgrab2",
    }
)


@dataclass(frozen=True, slots=True)
class AdapterExecutionProposal:
    """Pure, reviewable request and authorization intent before execution."""

    request: ActionRequest
    intent: ActionIntent
    executable_digest: str
    capability_generation: str
    output_path: Path | None


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_EXECUTABLE_CHUNK_BYTES):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _platform_name() -> str:
    name = platform.system().casefold()
    return {"darwin": "macos"}.get(name, name)


def _workspace_path(workspace: Path, relative: str, *, purpose: str) -> Path:
    value = Path(relative)
    if value.is_absolute() or "\x00" in relative:
        raise FormatError("SOVA-ADAPTER-PATH", f"{purpose} must be a safe workspace-relative path")
    resolved_workspace = workspace.resolve()
    resolved = (resolved_workspace / value).resolve()
    try:
        resolved.relative_to(resolved_workspace)
    except ValueError as error:
        raise FormatError(
            "SOVA-ADAPTER-PATH",
            f"{purpose} escapes the execution workspace",
        ) from error
    return resolved


def _pinned_input(
    workspace: Path,
    path_value: str | None,
    expected_digest: str | None,
    *,
    purpose: str,
) -> Path:
    if path_value is None or expected_digest is None:
        raise FormatError(
            "SOVA-ADAPTER-PIN",
            f"{purpose} path and digest are required by this descriptor",
        )
    path = _workspace_path(workspace, path_value, purpose=purpose)
    if not path.is_file() or _file_digest(path) != expected_digest:
        raise FormatError(
            "SOVA-ADAPTER-PIN",
            f"{purpose} is missing or does not match its declared SHA-256 digest",
        )
    return path


def _version_evidence(invocation: AdapterInvocation, evidence: bytes) -> None:
    if sha256_digest(evidence) != invocation.version_evidence_digest:
        raise FormatError(
            "SOVA-ADAPTER-VERSION-EVIDENCE",
            "captured version evidence does not match its declared digest",
        )
    try:
        rendered = evidence.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FormatError(
            "SOVA-ADAPTER-VERSION-EVIDENCE",
            "version evidence must be UTF-8 text",
        ) from error
    if invocation.observed_tool_version not in rendered:
        raise FormatError(
            "SOVA-ADAPTER-VERSION-EVIDENCE",
            "captured version evidence does not contain the observed exact version",
        )


def _render_argv(
    descriptor: AdapterDescriptor,
    invocation: AdapterInvocation,
    *,
    executable: Path,
    workspace: Path,
) -> tuple[tuple[str, ...], Path | None]:
    output: Path | None = None
    output_value = ""
    if "{output}" in "".join(descriptor.argv_template):
        if invocation.output_path is None:
            raise FormatError("SOVA-ADAPTER-OUTPUT", "descriptor requires an output path")
        output = _workspace_path(workspace, invocation.output_path, purpose="adapter output")
        if output.exists() or output.is_symlink():
            raise FormatError(
                "SOVA-ADAPTER-OUTPUT-EXISTS",
                "adapter output path must not already exist",
            )
        if not output.parent.is_dir():
            raise FormatError(
                "SOVA-ADAPTER-OUTPUT-PARENT",
                "adapter output parent directory must already exist",
            )
        output_value = invocation.output_path
    config_value = ""
    if "{config}" in "".join(descriptor.argv_template):
        config = _pinned_input(
            workspace,
            invocation.config_path,
            invocation.config_digest,
            purpose="adapter configuration",
        )
        config_value = str(config.relative_to(workspace.resolve()))
    ruleset_value = ""
    if "{ruleset}" in "".join(descriptor.argv_template):
        ruleset = _pinned_input(
            workspace,
            invocation.ruleset_path,
            invocation.ruleset_digest,
            purpose="adapter ruleset",
        )
        ruleset_value = str(ruleset.relative_to(workspace.resolve()))
    values = {
        "{executable}": str(executable),
        "{target}": invocation.target,
        "{output}": output_value,
        "{config}": config_value,
        "{ruleset}": ruleset_value,
    }
    rendered: list[str] = []
    for template in descriptor.argv_template:
        argument = template
        for token, value in values.items():
            argument = argument.replace(token, value)
        if not argument:
            raise FormatError("SOVA-ADAPTER-ARGV", "argv rendering produced an empty argument")
        rendered.append(argument)
    return tuple(rendered), output


def _capability_generation(executor: Executor, descriptor: AdapterDescriptor) -> str:
    capabilities = executor.capabilities()
    report = negotiate(capabilities, ("process.exec/0.1",))
    if not report.compatible:
        raise FormatError(
            "SOVA-ADAPTER-EXECUTOR",
            "executor does not expose the required process.exec/0.1 capability",
        )
    return sha256_digest(
        canonical_json_bytes(
            {
                "descriptorDigest": descriptor.digest,
                "executor": executor.name,
                "capabilities": [
                    {
                        "name": item.name,
                        "version": item.version,
                        "sideEffect": item.side_effect.value,
                        "idempotent": item.idempotent,
                        "evidence": list(item.evidence),
                    }
                    for item in capabilities
                ],
            }
        )
    )


def _domain(descriptor: AdapterDescriptor, target: str) -> str | None:
    if descriptor.network_requirement == "none":
        return None
    parsed = urlsplit(target if "://" in target else f"//{target}")
    return parsed.hostname


def _raw_output(
    descriptor: AdapterDescriptor,
    output_path: Path | None,
    outcome: ActionOutcome,
) -> tuple[bytes, bool]:
    if descriptor.output_source == OutputSource.STDOUT:
        stdout = outcome.output.get("stdout")
        if not isinstance(stdout, str):
            return b"", False
        encoded = stdout.encode("utf-8")
        return encoded[: descriptor.bounds.max_output_bytes], (
            len(encoded) <= descriptor.bounds.max_output_bytes
        )
    if output_path is None or output_path.is_symlink() or not output_path.is_file():
        return b"", False
    with output_path.open("rb") as handle:
        data = handle.read(descriptor.bounds.max_output_bytes + 1)
    return data[: descriptor.bounds.max_output_bytes], len(
        data
    ) <= descriptor.bounds.max_output_bytes


def _cleanup_output(output_path: Path | None) -> bool:
    if output_path is None:
        return True
    if output_path.is_symlink():
        return False
    if not output_path.exists():
        return True
    if not output_path.is_file():
        return False
    try:
        output_path.unlink()
    except OSError:
        return False
    return not output_path.exists()


def _failure_outcome(request: ActionRequest, error: BaseException) -> ActionOutcome:
    return ActionOutcome(
        request_id=request.id,
        status=OutcomeStatus.FAILED,
        side_effect=SideEffect.MUTATE,
        output={"exceptionType": type(error).__name__},
        error_code="SOVA-ADAPTER-EXECUTOR-EXCEPTION",
        limitations=("Executor exception text was omitted because it may contain sensitive data.",),
        failure_cause=FailureCause.EXECUTOR,
    )


def _empty_report(  # noqa: PLR0913 - terminal bindings stay explicit
    descriptor: AdapterDescriptor,
    invocation: AdapterInvocation,
    executable_digest: str,
    trace_path: Path,
    trace_digest: str,
    *,
    status: str,
    limitations: tuple[str, ...],
) -> AdapterRunReport:
    return AdapterRunReport(
        invocation_id=invocation.identifier,
        descriptor_id=descriptor.identifier,
        descriptor_digest=descriptor.digest,
        executable_digest=executable_digest,
        outcome_status=status,
        infrastructure_failure=True,
        cleanup_verified=True,
        trace_path=str(trace_path.resolve()),
        trace_digest=trace_digest,
        raw_artifact=None,
        observations=(),
        limitations=limitations,
    )


def build_security_adapter_proposal(  # noqa: PLR0913
    descriptor: AdapterDescriptor,
    invocation: AdapterInvocation,
    *,
    executor: Executor,
    workspace: Path,
    version_evidence: bytes,
    disclosure_decision: ExternalTransferDecision | None = None,
    allow_constrained: bool = False,
) -> AdapterExecutionProposal:
    """Build the exact proposal a human approval must bind before execution."""
    if descriptor.admission == AdapterAdmission.LEGAL_HOLD:
        raise FormatError(
            "SOVA-ADAPTER-LEGAL-HOLD",
            "legal-hold adapters cannot be executed by the SOVA runner",
        )
    if descriptor.admission == AdapterAdmission.CONSTRAINED and not allow_constrained:
        raise FormatError(
            "SOVA-ADAPTER-CONSTRAINED",
            "constrained adapter execution requires an explicit per-call opt-in",
        )
    if invocation.descriptor_id != descriptor.identifier:
        raise FormatError("SOVA-ADAPTER-BINDING", "invocation descriptor binding does not match")
    if invocation.target_predicate not in descriptor.target_predicates:
        raise FormatError(
            "SOVA-ADAPTER-TARGET-PREDICATE",
            "invocation target predicate is not admitted by the descriptor",
        )
    if _platform_name() not in descriptor.platforms:
        raise FormatError("SOVA-ADAPTER-PLATFORM", "adapter is not admitted on this platform")
    if invocation.observed_tool_version != descriptor.tool_version:
        raise FormatError("SOVA-ADAPTER-VERSION", "observed tool version does not match the pin")
    _version_evidence(invocation, version_evidence)
    if descriptor.network_requirement != "none" and (
        disclosure_decision is None
        or not disclosure_decision.allowed
        or invocation.disclosure_gate_id != disclosure_decision.identifier
        or invocation.disclosure_gate_digest != disclosure_decision.digest
        or disclosure_decision.target_id != invocation.target_id
        or disclosure_decision.destination != invocation.target
    ):
        raise FormatError(
            "SOVA-ADAPTER-DISCLOSURE-GATE",
            "external transfer requires an allowed, exact disclosure-gate decision",
        )
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise FormatError("SOVA-ADAPTER-WORKSPACE", "adapter workspace does not exist")
    executable = Path(invocation.executable_path)
    if (
        not executable.is_absolute()
        or not executable.is_file()
        or executable.is_symlink()
        or executable.name.casefold()
        not in {name.casefold() for name in descriptor.executable_names}
    ):
        raise FormatError(
            "SOVA-ADAPTER-EXECUTABLE",
            "operator-supplied executable is missing, relative, or has an unadmitted name",
        )
    executable_digest = _file_digest(executable)
    argv, output_path = _render_argv(
        descriptor,
        invocation,
        executable=executable.resolve(),
        workspace=workspace,
    )
    request = ActionRequest(
        id=f"{invocation.identifier}.process",
        action="process.exec",
        inputs={
            "argv": list(argv),
            "cwd": ".",
            "env": dict(descriptor.environment),
            "resources": {"maxOutputBytes": descriptor.bounds.max_output_bytes},
            "sovaBinding": {
                "descriptorDigest": descriptor.digest,
                "executableDigest": executable_digest,
                "toolVersion": descriptor.tool_version,
                "versionEvidenceDigest": invocation.version_evidence_digest,
                "targetId": invocation.target_id,
                "targetPredicate": invocation.target_predicate,
                "targetProfileDigest": invocation.target_profile_digest,
                "targetGeneration": invocation.target_generation,
                "configDigest": invocation.config_digest,
                "rulesetDigest": invocation.ruleset_digest,
                "disclosureGateId": invocation.disclosure_gate_id,
                "disclosureGateDigest": invocation.disclosure_gate_digest,
            },
        },
        timeout_seconds=float(descriptor.bounds.timeout_seconds),
    )
    request_digest = canonical_action_request_digest(request)
    capability_generation = _capability_generation(executor, descriptor)
    effect = (
        EffectClass.EXTERNAL
        if descriptor.required_effect == "external" or descriptor.network_requirement != "none"
        else EffectClass.DESTRUCTIVE
        if descriptor.required_effect == "destructive"
        else EffectClass.MUTATE
    )
    intent = ActionIntent(
        id=f"{invocation.identifier}.intent",
        target=invocation.target_id,
        action="adapter.execute",
        effect=effect,
        required_evidence=frozenset(
            {"authorization.decision", "tool.completed", "artifact.digest", "finding.observed"}
        ),
        cost=BudgetCost(
            steps=1,
            duration_ms=descriptor.bounds.timeout_seconds * 1000,
            mutations=1,
            processes=1,
            files=int(output_path is not None),
            network_requests=descriptor.bounds.max_network_requests,
        ),
        tool=descriptor.identifier,
        domain=_domain(descriptor, invocation.target),
        offensive=descriptor.identifier in _OFFENSIVE_ADAPTERS,
        request_digest=request_digest,
        capability_generation=capability_generation,
    )
    return AdapterExecutionProposal(
        request=request,
        intent=intent,
        executable_digest=executable_digest,
        capability_generation=capability_generation,
        output_path=output_path,
    )


def run_security_adapter(  # noqa: PLR0913, PLR0915
    descriptor: AdapterDescriptor,
    invocation: AdapterInvocation,
    *,
    executor: Executor,
    authorization_session: AuthorizationSession,
    workspace: Path,
    trace_path: Path,
    version_evidence: bytes,
    disclosure_decision: ExternalTransferDecision | None = None,
    approval: ApprovalToken | None = None,
    cancellation: CancellationToken | None = None,
    signing_key: Ed25519Keypair | None = None,
    allow_constrained: bool = False,
) -> AdapterRunReport:
    """Execute one exact adapter proposal after all policy and byte bindings pass."""
    proposal = build_security_adapter_proposal(
        descriptor,
        invocation,
        executor=executor,
        workspace=workspace,
        version_evidence=version_evidence,
        disclosure_decision=disclosure_decision,
        allow_constrained=allow_constrained,
    )
    workspace = workspace.resolve()
    request = proposal.request
    intent = proposal.intent
    executable_digest = proposal.executable_digest
    capability_generation = proposal.capability_generation
    output_path = proposal.output_path
    request_digest = canonical_action_request_digest(request)
    authorization_session.claim_invocation(invocation.identifier)
    trace_authorization = {
        "decision": "unknown",
        "scopeDigest": sha256_digest(
            canonical_json_bytes(authorization_session.authority.scope.to_mapping())
        ),
        "decidedBy": "sova.authorization-kernel/0.1",
    }
    writer = TraceWriter(
        trace_path,
        capture_profile="standard",
        authorization=trace_authorization,
        executor={
            "id": f"sova:executor:{executor.name}",
            "name": executor.name,
            "version": "0.1",
            "capabilityDigest": capability_generation,
        },
        signing_key=signing_key,
    )
    decision = authorization_session.authorize(intent, approval=approval)
    authorization_event = writer.append("authorization.decision", decision.to_mapping())
    if (
        not decision.allowed
        or decision.intent_digest != intent.digest
        or decision.request_digest != request_digest
        or decision.capability_generation != capability_generation
    ):
        reasons = list(decision.reasons)
        if decision.allowed:
            reasons.append("authorization-decision-binding-mismatch")
        writer.append(
            "blocked.authorization",
            {"adapterId": descriptor.identifier, "reasons": reasons},
            parents=[authorization_event] if authorization_event else [],
        )
        trace_digest = writer.finalize(completion="failed")
        _cleanup_output(output_path)
        return _empty_report(
            descriptor,
            invocation,
            executable_digest,
            trace_path,
            trace_digest,
            status="denied",
            limitations=tuple(reasons),
        )
    executable_path = Path(request.inputs["argv"][0])
    if executable_path.is_symlink() or _file_digest(executable_path) != executable_digest:
        writer.append(
            "blocked.executable-drift",
            {
                "adapterId": descriptor.identifier,
                "authorizedExecutableDigest": executable_digest,
            },
            parents=[authorization_event] if authorization_event else [],
        )
        trace_digest = writer.finalize(completion="failed")
        _cleanup_output(output_path)
        return _empty_report(
            descriptor,
            invocation,
            executable_digest,
            trace_path,
            trace_digest,
            status="infrastructure-failure",
            limitations=("executable-drift-after-authorization",),
        )
    requested_event = writer.append(
        "tool.requested",
        {
            "adapterId": descriptor.identifier,
            "descriptorDigest": descriptor.digest,
            "toolVersion": descriptor.tool_version,
            "versionEvidenceDigest": invocation.version_evidence_digest,
            "executableDigest": executable_digest,
            "requestDigest": request_digest,
            "configDigest": invocation.config_digest,
            "rulesetDigest": invocation.ruleset_digest,
            "catalogRulesetPin": descriptor.ruleset_pin,
            "catalogConfigPin": descriptor.config_pin,
            "disclosureGateId": invocation.disclosure_gate_id,
            "disclosureGateDigest": invocation.disclosure_gate_digest,
            "request": {"action": request.action, "inputs": request.inputs},
        },
        parents=[authorization_event] if authorization_event else [],
    )
    context = ExecutionContext(
        workspace=workspace,
        authorization=decision.to_mapping(),
        environment=dict(descriptor.environment),
    )
    try:
        outcome = executor.execute(request, context, cancellation or CancellationToken())
    except Exception as error:  # noqa: BLE001 - provider boundary must fail visibly
        outcome = _failure_outcome(request, error)
    writer.append(
        "tool.completed" if outcome.status == OutcomeStatus.SUCCEEDED else "tool.failed",
        {"outcome": asdict(outcome)},
        parents=[requested_event] if requested_event else [],
    )
    raw_bytes, complete = _raw_output(descriptor, output_path, outcome)
    media_type = descriptor.output_media_types[0]
    raw_artifact = RawArtifact(
        digest=sha256_digest(raw_bytes),
        media_type=media_type,
        size=len(raw_bytes),
        complete=complete,
        source=descriptor.output_source,
    )
    writer.append(
        "artifact.observed",
        {
            "role": "adapter-raw-output",
            "digest": raw_artifact.digest,
            "size": raw_artifact.size,
            "mediaType": raw_artifact.media_type,
            "complete": raw_artifact.complete,
            "contentRetained": False,
        },
    )
    returncode = outcome.output.get("returncode")
    result_exit = (
        isinstance(returncode, int)
        and not isinstance(returncode, bool)
        and returncode in descriptor.accepted_result_exit_codes
    )
    infrastructure_failure = outcome.status != OutcomeStatus.SUCCEEDED and not (
        outcome.status == OutcomeStatus.FAILED and result_exit and complete
    )
    observations: tuple[NormalizedObservation, ...] = ()
    limitations = list(outcome.limitations)
    if not infrastructure_failure and complete:
        try:
            observations = normalize_security_output(
                descriptor,
                invocation,
                executable_digest=executable_digest,
                raw=raw_bytes,
                media_type=media_type,
            )
        except FormatError as error:
            infrastructure_failure = True
            limitations.append(error.issue.code)
            writer.append(
                "error.adapter-parser",
                {"code": error.issue.code, "message": error.issue.message},
            )
    if infrastructure_failure or not complete:
        status = outcome.status.value if complete else "partial"
        observations = (
            infrastructure_failure_observation(
                descriptor,
                invocation,
                executable_digest=executable_digest,
                status=status,
                raw=raw_artifact,
            ),
        )
    for observation in observations:
        writer.append(
            "finding.observed",
            observation.to_mapping(),
            target={"id": invocation.target_id, "kind": "target", "name": invocation.target_id},
        )
    cleanup_verified = _cleanup_output(output_path)
    if not cleanup_verified:
        infrastructure_failure = True
        limitations.append("SOVA-ADAPTER-CLEANUP-FAILED")
        writer.append(
            "error.adapter-cleanup",
            {"outputPathDigest": sha256_digest(str(output_path).encode("utf-8"))},
        )
    final_status = (
        "cleanup-failed"
        if not cleanup_verified
        else "infrastructure-failure"
        if infrastructure_failure
        else "completed"
    )
    trace_digest = writer.finalize(
        completion="partial"
        if not cleanup_verified
        else "failed"
        if infrastructure_failure
        else "completed"
    )
    return AdapterRunReport(
        invocation_id=invocation.identifier,
        descriptor_id=descriptor.identifier,
        descriptor_digest=descriptor.digest,
        executable_digest=executable_digest,
        outcome_status=final_status,
        infrastructure_failure=infrastructure_failure,
        cleanup_verified=cleanup_verified,
        trace_path=str(trace_path.resolve()),
        trace_digest=trace_digest,
        raw_artifact=raw_artifact,
        observations=observations,
        limitations=tuple(limitations),
    )


__all__ = [
    "AdapterExecutionProposal",
    "build_security_adapter_proposal",
    "run_security_adapter",
]
