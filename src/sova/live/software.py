# SPDX-License-Identifier: Apache-2.0
"""Authorization-gated local software assessment on disposable clean-room copies."""

from __future__ import annotations

import os
import platform
import secrets
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from sova import __version__
from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    EvidenceReference,
    ExecutionContext,
    OutcomeStatus,
    RestrictedLocalExecutor,
    action_intent_for_step,
    expanded_steps,
    run_capsule,
)
from sova.formats import (
    PackageReader,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.rehearsal import prepare_rehearsal_environment
from sova.replay import verify_artifact
from sova.reproduction import compare_observable_outcomes
from sova.safety import (
    ActionIntent,
    ApprovalBatchChallenge,
    ApprovalLevel,
    ApprovalToken,
    AuthorityEnvelope,
    AuthorizationKernel,
    AuthorizationSession,
    ControlProof,
    ControlProofMethod,
    EffectBudget,
    EffectClass,
    InteractiveTerminalApprovalAuthority,
    Principal,
    PrincipalKind,
    Scope,
)
from sova.targets import TargetKind, TargetManifest, validate_target_manifest
from sova.trace import TraceReader, generate_ed25519_keypair

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sova.executors import Capability

_MAX_SNAPSHOT_FILES = 4096
_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
_MAX_STEPS = 32


SoftwareApprovalPrompt = Callable[
    [ApprovalBatchChallenge, tuple[ActionIntent, ...]],
    str,
]
SoftwareEventObserver = Callable[[str, dict[str, Any]], None]


def _channel_observer(
    observer: SoftwareEventObserver | None,
    channel: str,
) -> Callable[[dict[str, Any]], None] | None:
    if observer is None:
        return None

    def emit(event: dict[str, Any]) -> None:
        observer(channel, event)

    return emit


@dataclass(frozen=True, slots=True)
class LiveSoftwareArtifacts:
    """Artifacts from one primary run and one clean-room controlled reproduction."""

    target: Path
    source_capsule: Path
    trace: Path
    reproduction_trace: Path
    evidence_capsule: Path
    report: Path
    status: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.live-software-artifacts",
            "schemaVersion": "0.1.0",
            "status": self.status,
            "target": str(self.target),
            "sourceCapsule": str(self.source_capsule),
            "trace": str(self.trace),
            "reproductionTrace": str(self.reproduction_trace),
            "evidenceCapsule": str(self.evidence_capsule),
            "report": str(self.report),
        }


@dataclass(frozen=True, slots=True)
class _WorkspaceSnapshot:
    files: Mapping[str, tuple[str, int]]
    complete: bool
    limitations: tuple[str, ...]


class _ObservedLocalExecutor:
    """Add a bounded workspace-delta sensor around the restricted process executor."""

    name = "sova-observed-restricted-local"

    def __init__(self, executable: Path) -> None:
        self._delegate = RestrictedLocalExecutor(executable_allowlist=(executable,))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self._delegate.close()

    def capabilities(self) -> tuple[Capability, ...]:
        return self._delegate.capabilities()

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        before = _snapshot_workspace(context.workspace)
        outcome = self._delegate.execute(request, context, cancellation)
        after = _snapshot_workspace(context.workspace)
        delta = _workspace_delta(before, after)
        encoded = canonical_json_bytes(delta)
        complete = before.complete and after.complete
        status = outcome.status
        error_code = outcome.error_code
        failure_cause = outcome.failure_cause
        if status == OutcomeStatus.SUCCEEDED and not complete:
            status = OutcomeStatus.PARTIAL
            error_code = "SOVA-SOFTWARE-SENSOR-PARTIAL"
        return ActionOutcome(
            request_id=outcome.request_id,
            status=status,
            side_effect=outcome.side_effect,
            output={**outcome.output, "workspaceDelta": delta},
            evidence=(
                *outcome.evidence,
                EvidenceReference(
                    "workspace-delta",
                    "application/json",
                    sha256_digest(encoded),
                    len(encoded),
                ),
            ),
            verification=(
                "process-exit-output-and-bounded-workspace-delta-observed"
                if complete
                else "process-observed-workspace-delta-incomplete"
            ),
            retryable=outcome.retryable,
            error_code=error_code,
            limitations=(
                *outcome.limitations,
                *before.limitations,
                *after.limitations,
                "Only regular-file state beneath the disposable workspace was hashed.",
                (
                    "Network, registry, kernel, child-process internals, and writes "
                    "outside the workspace were not observed."
                ),
            ),
            failure_cause=failure_cause,
        )


def _safe_file(path: Path, *, code: str, role: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise FormatError(code, f"{role} must be an existing regular non-symbolic-link file")
    return path.resolve()


def _safe_source_workspace(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise FormatError(
            "SOVA-SOFTWARE-WORKSPACE",
            "software workspace must be an existing regular directory",
        )
    resolved = path.resolve()
    if resolved in {Path(resolved.anchor).resolve(), Path.home().resolve()}:
        raise FormatError(
            "SOVA-SOFTWARE-WORKSPACE",
            "refusing a filesystem root or user home as a software workspace",
        )
    return resolved


def _snapshot_workspace(workspace: Path) -> _WorkspaceSnapshot:
    files: dict[str, tuple[str, int]] = {}
    limitations: list[str] = []
    total = 0
    for root, directories, names in os.walk(workspace, followlinks=False):
        root_path = Path(root)
        directories[:] = sorted(
            name
            for name in directories
            if name != ".sova-rehearsal" and not (root_path / name).is_symlink()
        )
        if any((root_path / name).is_symlink() for name in names):
            limitations.append("Symbolic-link files were omitted from the workspace sensor.")
        for name in sorted(names):
            path = root_path / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(workspace).as_posix()
            try:
                size = path.stat().st_size
                total += size
                if len(files) >= _MAX_SNAPSHOT_FILES or total > _MAX_SNAPSHOT_BYTES:
                    limitations.append("Workspace sensor file or byte budget was exceeded.")
                    return _WorkspaceSnapshot(
                        files=files,
                        complete=False,
                        limitations=tuple(sorted(set(limitations))),
                    )
                files[relative] = (sha256_digest(path.read_bytes()), size)
            except OSError:
                limitations.append(
                    "A workspace file changed or became unreadable during observation."
                )
    return _WorkspaceSnapshot(files, not limitations, tuple(sorted(set(limitations))))


def _workspace_delta(
    before: _WorkspaceSnapshot,
    after: _WorkspaceSnapshot,
) -> dict[str, Any]:
    created = sorted(set(after.files) - set(before.files))
    deleted = sorted(set(before.files) - set(after.files))
    modified = sorted(
        path
        for path in set(before.files) & set(after.files)
        if before.files[path] != after.files[path]
    )
    return {
        "complete": before.complete and after.complete,
        "created": [
            {"path": path, "digest": after.files[path][0], "size": after.files[path][1]}
            for path in created
        ],
        "modified": [
            {
                "path": path,
                "beforeDigest": before.files[path][0],
                "afterDigest": after.files[path][0],
                "afterSize": after.files[path][1],
            }
            for path in modified
        ],
        "deleted": [
            {"path": path, "digest": before.files[path][0], "size": before.files[path][1]}
            for path in deleted
        ],
        "limitations": sorted({*before.limitations, *after.limitations}),
    }


def _load_scenario(capsule: Path) -> dict[str, Any]:
    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    descriptor = next((item for item in descriptors if item.role == "scenario"), None)
    if descriptor is None:
        raise FormatError("SOVA-SOFTWARE-SCENARIO", "software capsule has no scenario")
    value = strict_json_loads(reader.read_object(descriptor))
    if not isinstance(value, dict):
        raise FormatError("SOVA-SOFTWARE-SCENARIO", "software scenario must be an object")
    validate_document(value, "sova.scenario")
    return value


def _validate_scenario(scenario: dict[str, Any], executable: Path) -> list[dict[str, Any]]:
    steps = expanded_steps(scenario)
    if not steps or len(steps) > _MAX_STEPS:
        raise FormatError(
            "SOVA-SOFTWARE-STEPS",
            f"software scenario must contain 1..{_MAX_STEPS} expanded steps",
        )
    for step in steps:
        if step["action"] != "process.exec":
            raise FormatError(
                "SOVA-SOFTWARE-ACTION",
                "bounded local software assessment accepts process.exec only",
            )
        inputs = step["inputs"]
        argv = inputs.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(item, str) for item in argv)
        ):
            raise FormatError("SOVA-SOFTWARE-ARGV", "every software step requires string argv")
        if not Path(argv[0]).is_absolute() or Path(argv[0]).resolve() != executable:
            raise FormatError(
                "SOVA-SOFTWARE-EXECUTABLE",
                "every software step must name the exact admitted absolute executable",
            )
        if inputs.get("secretEnv"):
            raise FormatError(
                "SOVA-SOFTWARE-SECRETS",
                "the clean-room software lane does not admit secret environment references",
            )
        if inputs.get("offensive") is True or inputs.get("irreversible") is True:
            raise FormatError(
                "SOVA-SOFTWARE-EFFECT",
                "offensive or irreversible software steps are not admitted",
            )
    return steps


def _fingerprint(value: str | None, *, status: str, method: str, source: str) -> dict[str, Any]:
    return {
        "value": value,
        "status": status,
        "method": method,
        "source": source,
        "version": "0.1.0",
    }


def _prepare_authorization(  # noqa: PLR0913
    target: TargetManifest,
    scenario: dict[str, Any],
    capabilities: tuple[Capability, ...],
    *,
    executable_digest: str,
    workspace_fingerprint: str,
    containment_digest: str,
    approval_prompt: SoftwareApprovalPrompt,
) -> tuple[
    tuple[AuthorizationSession, dict[str, ApprovalToken]],
    tuple[AuthorizationSession, dict[str, ApprovalToken]],
]:
    now = datetime.now(UTC)
    subject = f"sova:local-software:{target.digest[7:31]}"
    challenge_value = "sova-local-control:" + secrets.token_urlsafe(18)
    proof = ControlProof(
        ControlProofMethod.LOCAL_POSSESSION,
        subject,
        challenge_value,
        {
            "challenge": challenge_value,
            "operatorAssertion": True,
            "executableDigest": executable_digest,
            "workspaceFingerprint": workspace_fingerprint,
            "targetDigest": target.digest,
            "legalAuthorityIndependentlyVerified": False,
        },
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.local-software-control/0.1",
    )
    by_action = {item.name: item for item in capabilities}
    rows: list[tuple[str, str, ActionIntent]] = []
    for run_name in ("primary", "reproduction"):
        for step in expanded_steps(scenario):
            capability = by_action[step["action"]]
            rows.append(
                (
                    run_name,
                    step["id"],
                    action_intent_for_step(
                        scenario,
                        step,
                        side_effect=capability.side_effect,
                        evidence=capability.evidence,
                        target=subject,
                    ),
                )
            )
    scope = Scope(
        targets=frozenset({subject}),
        actions=frozenset(intent.action for _run, _step, intent in rows),
        tools=frozenset(intent.tool for _run, _step, intent in rows if intent.tool is not None),
    )
    authority = AuthorityEnvelope(
        id="sova:authorization:local-software:" + secrets.token_hex(12),
        issued_by=Principal("sova:principal:operator", PrincipalKind.HUMAN, "SOVA operator"),
        subject=Principal(
            "sova:principal:software-agent", PrincipalKind.AGENT, "SOVA software runner"
        ),
        scope=scope,
        max_effect=EffectClass.MUTATE,
        budget=EffectBudget(
            max_steps=len(rows),
            max_duration_ms=sum(intent.cost.duration_ms for _run, _step, intent in rows),
            max_mutations=sum(intent.cost.mutations for _run, _step, intent in rows),
            max_processes=sum(intent.cost.processes for _run, _step, intent in rows),
        ),
        valid_from=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
        single_use=True,
        ownership=str(target.configuration["authorityBasis"]),
        required_containment_digest=containment_digest,
    )
    approval_authority = InteractiveTerminalApprovalAuthority(secrets.token_bytes(32))
    batch = approval_authority.batch_challenge(
        authority,
        tuple((intent, ApprovalLevel.NORMAL) for _run, _step, intent in rows),
        now=now,
    )
    phrase = approval_prompt(batch, tuple(intent for _run, _step, intent in rows))
    tokens = approval_authority.approve_batch(
        batch,
        approver=Principal("sova:principal:reviewer", PrincipalKind.HUMAN, "SOVA reviewer"),
        exact_phrase=phrase,
        reviewed_effects=True,
    )
    approvals: dict[str, dict[str, ApprovalToken]] = {"primary": {}, "reproduction": {}}
    for (run_name, step_id, _intent), token in zip(rows, tokens, strict=True):
        approvals[run_name][step_id] = token

    def session() -> AuthorizationSession:
        return AuthorizationSession(
            authority=authority,
            proof=proof,
            containment_allowed=True,
            containment_digest=containment_digest,
            kernel=AuthorizationKernel(approval_authority),
        )

    return (session(), approvals["primary"]), (session(), approvals["reproduction"])


def _assert_target(target: TargetManifest) -> tuple[str, str]:
    if target.kind != TargetKind.LOCAL_PROCESS:
        raise FormatError("SOVA-SOFTWARE-TARGET", "software detonation requires local-process")
    if not validate_target_manifest(target)["accepted"]:
        raise FormatError("SOVA-SOFTWARE-TARGET", "software target manifest is not conformant")
    basis = target.configuration.get("authorityBasis")
    reference = target.configuration.get("authorityReference")
    if basis not in {"self", "explicit"} or not isinstance(reference, str) or not reference:
        raise FormatError(
            "SOVA-SOFTWARE-AUTHORITY",
            "target configuration requires self/explicit authorityBasis and a "
            "non-secret authorityReference",
        )
    return str(basis), reference


def _atomic_root(destination: Path) -> tuple[Path, Path]:
    resolved = destination.resolve()
    if resolved.exists():
        raise FormatError("SOVA-SOFTWARE-DESTINATION", "destination must not already exist")
    temporary = resolved.with_name(f".{resolved.name}.partial-{secrets.token_hex(8)}")
    temporary.mkdir(parents=True)
    return resolved, temporary


def run_live_software_assessment(  # noqa: PLR0913, PLR0915
    target: TargetManifest,
    source_capsule: Path,
    source_workspace: Path,
    destination: Path,
    *,
    executable: Path,
    approval_prompt: SoftwareApprovalPrompt,
    event_observer: SoftwareEventObserver | None = None,
) -> LiveSoftwareArtifacts:
    """Run one trusted local program twice in separate credential-stripped copies."""
    basis, authority_reference = _assert_target(target)
    capsule = _safe_file(
        source_capsule,
        code="SOVA-SOFTWARE-CAPSULE",
        role="source capsule",
    )
    admitted_executable = _safe_file(
        executable,
        code="SOVA-SOFTWARE-EXECUTABLE",
        role="executable",
    )
    workspace = _safe_source_workspace(source_workspace)
    if workspace == admitted_executable.parent or admitted_executable.is_relative_to(workspace):
        raise FormatError(
            "SOVA-SOFTWARE-EXECUTABLE",
            "admitted executable must be installed outside the disposable source workspace",
        )
    scenario = _load_scenario(capsule)
    _validate_scenario(scenario, admitted_executable)
    destination_resolved = destination.resolve()
    if destination_resolved == workspace or destination_resolved.is_relative_to(workspace):
        raise FormatError(
            "SOVA-SOFTWARE-DESTINATION",
            "evidence destination must be outside the source workspace",
        )
    root, temporary = _atomic_root(destination)
    try:
        source_copy = temporary / "source.sova"
        target_path = temporary / "target.json"
        shutil.copyfile(capsule, source_copy)
        target_path.write_bytes(canonical_json_bytes(target.to_mapping()) + b"\n")
        primary_workspace = temporary / "primary-workspace"
        reproduction_workspace = temporary / "reproduction-workspace"
        primary_preparation = prepare_rehearsal_environment(workspace, primary_workspace)
        reproduction_preparation = prepare_rehearsal_environment(workspace, reproduction_workspace)
        (temporary / "primary-preparation.json").write_bytes(
            canonical_json_bytes(primary_preparation.to_mapping()) + b"\n"
        )
        (temporary / "reproduction-preparation.json").write_bytes(
            canonical_json_bytes(reproduction_preparation.to_mapping()) + b"\n"
        )
        if primary_preparation.source_fingerprint != reproduction_preparation.source_fingerprint:
            raise FormatError(  # noqa: TRY301 - atomic cleanup is owned here
                "SOVA-SOFTWARE-PREPARATION",
                "clean-room workspace fingerprints did not match",
            )
        executable_digest = sha256_digest(admitted_executable.read_bytes())
        code_digest = sha256_digest(
            canonical_json_bytes(
                {
                    "sovaVersion": __version__,
                    "runner": sha256_digest(Path(__file__).read_bytes()),
                }
            )
        )
        environment: dict[str, Any] = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "codeDigest": code_digest,
            "model": None,
            "dependencies": [],
        }
        fingerprints = {
            "environment": _fingerprint(
                sha256_digest(canonical_json_bytes(environment)),
                status="recorded",
                method="canonical-runtime-environment-digest",
                source="sova.live.software",
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
                source="sova.live.software",
            ),
            "dependencies": _fingerprint(
                executable_digest,
                status="recorded",
                method="exact-admitted-executable-digest",
                source="operator-selected executable",
            ),
            "registry": _fingerprint(
                None,
                status="not-applicable",
                method="no-registry-used",
                source="local software runner",
            ),
            "model": _fingerprint(
                None,
                status="not-applicable",
                method="no-model-used",
                source="deterministic local process scenario",
            ),
        }
        containment = {
            "backend": "restricted-host-process",
            "workspace": "credential-stripped-disposable-copy",
            "originalWorkspaceMutationAllowed": False,
            "executableDigest": executable_digest,
            "networkIsolation": False,
            "filesystemIsolation": False,
            "securitySandbox": False,
        }
        containment_digest = sha256_digest(canonical_json_bytes(containment))
        with _ObservedLocalExecutor(admitted_executable) as executor:
            primary_auth, reproduction_auth = _prepare_authorization(
                target,
                scenario,
                executor.capabilities(),
                executable_digest=executable_digest,
                workspace_fingerprint=primary_preparation.source_fingerprint,
                containment_digest=containment_digest,
                approval_prompt=approval_prompt,
            )
            signing_key = generate_ed25519_keypair()
            trace = temporary / "primary.sova-trace"
            primary = run_capsule(
                source_copy,
                trace,
                executor=executor,
                workspace=primary_workspace,
                authorization_session=primary_auth[0],
                approvals=primary_auth[1],
                signing_key=signing_key,
                environment=environment,
                fingerprints=fingerprints,
                event_observer=_channel_observer(event_observer, "primary"),
            )
            reproduction = temporary / "reproduction.sova-trace"
            repeated = run_capsule(
                source_copy,
                reproduction,
                executor=executor,
                workspace=reproduction_workspace,
                authorization_session=reproduction_auth[0],
                approvals=reproduction_auth[1],
                source_trace_digest=sha256_digest(trace.read_bytes()),
                signing_key=signing_key,
                environment=environment,
                fingerprints=fingerprints,
                event_observer=_channel_observer(event_observer, "reproduction"),
            )
        trace_verification = TraceReader(trace).verify(require_signature=True)
        reproduction_verification = TraceReader(reproduction).verify(require_signature=True)
        comparison = compare_observable_outcomes(
            trace,
            reproduction,
            kinds=("tool.completed", "oracle.completed"),
        )
        successful = (
            primary.completion == repeated.completion == "completed"
            and primary.oracle_status == repeated.oracle_status == "pass"
            and trace_verification.signature_valid
            and reproduction_verification.signature_valid
            and comparison.equivalent
        )
        evidence_manifest = capsule_manifest_template(
            title="SOVA authorized local-software evidence capsule",
            summary=(
                "Observable process and clean-room workspace-delta evidence with "
                "controlled reproduction."
            ),
            author="SOVA operator",
            domain_profile=DomainProfile.EVALUATION,
        )
        evidence_manifest["license"] = "Apache-2.0"
        evidence_manifest["safety"]["impact"] = "low"
        evidence_manifest["methodology"] = {
            "id": "SOVA-LOCAL-SOFTWARE",
            "version": "0.1.0",
            "digest": code_digest,
        }
        evidence_manifest["taxonomy"] = {
            "id": "sova.local-software-observable-outcomes",
            "version": "0.1.0",
            "digest": sha256_digest(canonical_json_bytes(scenario["oracles"])),
        }
        evidence_manifest["relationships"] = [
            {
                "relationship": "derived-from",
                "artifactType": "sova.capsule",
                "digest": sha256_digest(source_copy.read_bytes()),
            },
            {
                "relationship": "derived-from",
                "artifactType": "sova.target-manifest",
                "digest": target.digest,
            },
        ]
        evidence_manifest["limitations"] = [
            "Restricted host-process execution is not a security sandbox.",
            (
                "Only process exit, bounded output, and regular-file changes inside "
                "clean-room copies were observed."
            ),
            (
                "The operator assertion and local possession proof do not independently "
                "establish legal authority."
            ),
            (
                "A reproduced declared outcome is not a claim that the software is safe "
                "or vulnerability-free."
            ),
        ]
        evidence_capsule = temporary / "evidence.sova"
        build_capsule(
            evidence_capsule,
            evidence_manifest,
            scenario=scenario,
            attachments={
                "target.json": canonical_json_bytes(target.to_mapping()),
                "containment.json": canonical_json_bytes(containment),
            },
            traces=[trace, reproduction],
        )
        verification = verify_artifact(evidence_capsule)
        if not verification.accepted:
            raise FormatError("SOVA-SOFTWARE-EVIDENCE", "evidence capsule verification failed")  # noqa: TRY301 - atomic cleanup is owned by this function
        status = "pass" if successful else "inconclusive"
        report_path = temporary / "report.json"
        report = {
            "artifactType": "sova.live-software-report",
            "schemaVersion": "0.1.0",
            "status": status,
            "targetDigest": target.digest,
            "sourceCapsuleDigest": sha256_digest(source_copy.read_bytes()),
            "executableDigest": executable_digest,
            "authorityBasis": basis,
            "authorityReferenceDigest": sha256_digest(authority_reference.encode("utf-8")),
            "legalAuthorityIndependentlyVerified": False,
            "liveTargetExecuted": True,
            "originalWorkspaceMutated": False,
            "credentialStrippedCopies": True,
            "primaryCompletion": primary.completion,
            "reproductionCompletion": repeated.completion,
            "primaryOracleStatus": primary.oracle_status,
            "reproductionOracleStatus": repeated.oracle_status,
            "traceSignatureValid": trace_verification.signature_valid,
            "reproductionSignatureValid": reproduction_verification.signature_valid,
            "semanticOutcomeEquivalent": comparison.equivalent,
            "capture": {
                "processExit": "direct",
                "stdoutStderr": "bounded-direct",
                "workspaceRegularFiles": "bounded-before-after-digest",
                "network": "not-observed",
                "registry": "not-observed",
                "kernel": "not-observed",
                "outsideWorkspace": "not-observed",
                "hiddenModelThoughts": "not-applicable",
            },
            "containment": containment,
            "safeOrCleanClaim": False,
            "limitations": evidence_manifest["limitations"],
        }
        report_path.write_bytes(canonical_json_bytes(report) + b"\n")
        temporary.rename(root)
        return LiveSoftwareArtifacts(
            root / target_path.name,
            root / source_copy.name,
            root / trace.name,
            root / reproduction.name,
            root / evidence_capsule.name,
            root / report_path.name,
            status,
        )
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


_OWNED_FIXTURE_APP = """from __future__ import annotations
import json
from pathlib import Path
import sys

sequence = sys.argv[1:]
behavior = "unexpected-action" if sequence == ["observe", "configure", "evaluate"] else "ordinary"
document = json.dumps({"behavior": behavior, "sequence": sequence}, sort_keys=True)
Path("state.json").write_text(document, encoding="utf-8")
print(json.dumps({"behavior": behavior, "observable": True}, sort_keys=True))
"""


def build_owned_software_capsule(path: Path, executable: Path) -> None:
    """Build the portable scenario used by the real owned-software acceptance lane."""
    scenario = scenario_template(
        title="SOVA owned local-software conditional behavior",
        purpose="Observe and reproduce one planted behavior in a disposable software workspace.",
    )
    scenario["procedure"]["steps"] = [
        {
            "id": "run-owned-software",
            "action": "process.exec",
            "inputs": {
                "argv": [
                    str(executable.resolve()),
                    "app.py",
                    "observe",
                    "configure",
                    "evaluate",
                ],
                "resources": {"maxOutputBytes": 65536},
            },
            "onFailure": "inconclusive",
            "requires": ["process.exec/0.1"],
        }
    ]
    scenario["oracles"] = [
        {"kind": "field-contains", "path": "$.stdout", "contains": "unexpected-action"},
        {
            "kind": "exact-field",
            "path": "$.workspaceDelta.complete",
            "equals": True,
        },
    ]
    scenario["expectedEffects"] = [
        {"kind": "observable-process-output", "value": "unexpected-action"},
        {"kind": "workspace-file-created", "path": "state.json"},
    ]
    scenario["limitations"] = [
        "The target is an inert bundled fixture, not evidence about third-party software."
    ]
    manifest = capsule_manifest_template(
        title="SOVA owned local-software fixture",
        summary="A safe conditional local-process behavior for end-to-end acceptance testing.",
        author="SOVA OSS contributors",
        domain_profile=DomainProfile.EVALUATION,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["limitations"] = scenario["limitations"]
    build_capsule(path, manifest, scenario=scenario)


def run_owned_software_vertical_slice(
    destination: Path,
    *,
    approval_prompt: SoftwareApprovalPrompt,
    event_observer: SoftwareEventObserver | None = None,
) -> LiveSoftwareArtifacts:
    """Run the real process/evidence path against SOVA's inert owned fixture."""
    executable = Path(sys.executable).resolve()
    fixture_root = destination.resolve().with_name(
        f".{destination.resolve().name}.owned-software-source-{secrets.token_hex(8)}"
    )
    fixture_root.mkdir(parents=True)
    source_root = fixture_root / "workspace"
    source_root.mkdir(parents=True)
    try:
        (source_root / "app.py").write_text(_OWNED_FIXTURE_APP, encoding="utf-8")
        capsule = fixture_root / "source.sova"
        build_owned_software_capsule(capsule, executable)
        target = TargetManifest(
            "sova:target:self-owned-live-software-fixture",
            TargetKind.LOCAL_PROCESS,
            "0.1.0",
            ("process.invoke", "process.observe"),
            "self-owned local inert fixture",
            {
                "interface": "argv-and-files",
                "workspaceMode": "credential-stripped-disposable-copy",
                "authorityBasis": "self",
                "authorityReference": "bundled-sova-owned-software-fixture",
            },
        )
        return run_live_software_assessment(
            target,
            capsule,
            source_root,
            destination,
            executable=executable,
            approval_prompt=approval_prompt,
            event_observer=event_observer,
        )
    finally:
        if fixture_root.exists():
            shutil.rmtree(fixture_root)


__all__ = [
    "LiveSoftwareArtifacts",
    "SoftwareApprovalPrompt",
    "SoftwareEventObserver",
    "build_owned_software_capsule",
    "run_live_software_assessment",
    "run_owned_software_vertical_slice",
]
