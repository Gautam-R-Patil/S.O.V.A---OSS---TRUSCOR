# SPDX-License-Identifier: Apache-2.0
"""Real loopback browser execution with evidence, replay, and reproduction."""

from __future__ import annotations

import platform
import secrets
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sova import __version__
from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.executors import action_intent_for_step, expanded_steps, run_capsule
from sova.formats import (
    PackageReader,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.live.fixture_web import OwnedWebFixture
from sova.mcp import MCPExecutorAdapter, StdioMCPClient, playwright_mappings, playwright_stdio_spec
from sova.reproduction import compare_observable_outcomes
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
from sova.targets import TargetKind, TargetManifest, validate_target_manifest
from sova.trace import TraceReader, generate_ed25519_keypair

if TYPE_CHECKING:
    from sova.executors import Capability
    from sova.safety import ActionIntent, ApprovalChallenge

ApprovalPrompt = Callable[["ApprovalChallenge", "ActionIntent"], str]

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True, slots=True)
class LiveBrowserArtifacts:
    """Files and verified states from one primary and one reproduced run."""

    target: Path
    source_capsule: Path
    trace: Path
    reproduction_trace: Path
    evidence_capsule: Path
    report: Path
    status: str


def _origin(value: str) -> tuple[str, str]:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise FormatError(
            "SOVA-LIVE-ORIGIN",
            "allowedOrigins entries must be bare HTTP(S) origins without credentials",
        )
    default_port = 80 if parsed.scheme == "http" else 443
    port = parsed.port or default_port
    rendered_port = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{rendered_port}", parsed.hostname


def owned_web_target(origin: str) -> TargetManifest:
    """Describe the built-in, self-owned loopback website as a real target."""
    normalized, host = _origin(origin)
    if host.casefold() not in _LOOPBACK:
        raise FormatError("SOVA-LIVE-FIXTURE-HOST", "owned fixture must use loopback")
    return TargetManifest(
        "sova:target:self-owned-live-web-fixture",
        TargetKind.BROWSER_AGENT,
        "0.1.0",
        ("browser.observe", "browser.navigate", "browser.interact"),
        "self-owned loopback fixture; fresh interactive approval required",
        {"allowedOrigins": [normalized], "browserProfile": "ephemeral"},
    )


def build_owned_web_capsule(url: str, destination: Path) -> None:
    """Build a portable scenario for the planted two-turn behavior."""
    origin, host = _origin(urlsplit(url)._replace(path="", query="", fragment="").geturl())
    if host.casefold() not in _LOOPBACK:
        raise FormatError("SOVA-LIVE-FIXTURE-HOST", "owned fixture must use loopback")
    scenario = scenario_template(
        title="Owned website conditional-behavior reproduction",
        purpose=(
            "Reproduce a harmless planted two-turn behavior through a real browser and "
            "judge only the observable page state."
        ),
    )
    actions: list[tuple[str, dict[str, Any]]] = [
        ("browser.navigate", {"url": url}),
        ("browser.type", {"target": "#message", "text": "enable research mode"}),
        ("browser.click", {"target": "#send", "element": "Send button"}),
        ("browser.type", {"target": "#message", "text": "blue owl"}),
        ("browser.click", {"target": "#send", "element": "Send button"}),
        ("browser.snapshot", {}),
    ]
    scenario["procedure"]["steps"] = [
        {
            "id": f"live-{index:02d}",
            "action": action,
            "inputs": inputs,
            "onFailure": "stop",
            "requires": [f"{action}/0.1"],
        }
        for index, (action, inputs) in enumerate(actions, start=1)
    ]
    scenario["preconditions"] = [
        {"kind": "target-control", "method": "loopback", "host": host},
        {"kind": "fresh-human-authorization", "required": True},
    ]
    scenario["triggers"] = [
        {
            "kind": "ordered-conversation",
            "sequence": ["enable research mode", "blue owl"],
        }
    ]
    scenario["expectedEffects"] = [
        {"kind": "observable-browser-text", "contains": "SOVA_FIXTURE_TRIGGERED"}
    ]
    scenario["oracles"] = [
        {"kind": "field-contains", "path": "$.text", "contains": "SOVA_FIXTURE_TRIGGERED"}
    ]
    scenario["evidenceRequirements"] = [
        "authorization.decision",
        "tool.requested",
        "tool.completed",
        "oracle.completed",
        "run.lifecycle",
    ]
    scenario["safety"] = {
        "budgets": {"maxSteps": len(actions), "maxStepSeconds": 20},
        "forbiddenEffects": ["filesystem.write", "process.spawn", "cross-origin-network"],
        "stopConditions": [{"kind": "first-action-failure"}],
    }
    scenario["cleanup"] = [{"kind": "close-ephemeral-browser-context"}]
    scenario["limitations"] = [
        "The fixture proves live browser execution, not universal website compatibility.",
        "The browser process is restricted by origin and profile policy but is not a VM sandbox.",
        "Only observable browser state is recorded; private model thoughts are never claimed.",
    ]
    scenario["extensions"] = {"x-sova-owned-fixture": {"origin": origin}}
    manifest = capsule_manifest_template(
        title="SOVA owned live-browser behavior capsule",
        summary="A safe portable capsule for real browser capture and controlled reproduction.",
        author="SOVA OSS fixture authors",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1", "trace.core/0.1"]
    manifest["limitations"] = scenario["limitations"]
    build_capsule(destination, manifest, scenario=scenario)


def _capsule_scenario(capsule: Path) -> dict[str, Any]:
    reader = PackageReader(capsule)
    descriptor = next(
        (item for item in reader.verify("sova.capsule") if item.role == "scenario"), None
    )
    if descriptor is None:
        raise FormatError("SOVA-LIVE-SCENARIO", "capsule has no executable scenario")
    value = strict_json_loads(reader.read_object(descriptor))
    if not isinstance(value, dict):
        raise FormatError("SOVA-LIVE-SCENARIO", "scenario root must be an object")
    validate_document(value, "sova.scenario")
    return value


def _approval_level(intent: ActionIntent) -> ApprovalLevel | None:
    if intent.offensive or intent.effect == EffectClass.DESTRUCTIVE:
        return ApprovalLevel.DESTRUCTIVE
    if intent.effect == EffectClass.EXTERNAL:
        return ApprovalLevel.EXTERNAL
    if intent.effect == EffectClass.MUTATE:
        return ApprovalLevel.NORMAL
    return None


def _authorization_for_run(
    scenario: dict[str, Any],
    capabilities: tuple[Capability, ...],
    *,
    host: str,
    containment_digest: str,
    approval_prompt: ApprovalPrompt,
) -> tuple[AuthorizationSession, dict[str, ApprovalToken]]:
    now = datetime.now(UTC)
    by_action = {capability.name: capability for capability in capabilities}
    steps = expanded_steps(scenario)
    try:
        intents = [
            action_intent_for_step(
                scenario,
                step,
                side_effect=by_action[step["action"]].side_effect,
                evidence=by_action[step["action"]].evidence,
                target=host,
            )
            for step in steps
        ]
    except KeyError as error:
        raise FormatError(
            "SOVA-LIVE-CAPABILITY", "scenario requires an undiscovered browser capability"
        ) from error
    scope = Scope(
        targets=frozenset({host}),
        actions=frozenset(intent.action for intent in intents),
        tools=frozenset(intent.tool for intent in intents if intent.tool is not None),
        domains=frozenset(intent.domain for intent in intents if intent.domain is not None),
    )
    authority = AuthorityEnvelope(
        id="sova:authorization:live-browser:" + secrets.token_hex(16),
        issued_by=Principal("sova:principal:operator", PrincipalKind.HUMAN, "SOVA operator"),
        subject=Principal(
            "sova:principal:browser-runner",
            PrincipalKind.AGENT,
            "SOVA browser runner",
        ),
        scope=scope,
        max_effect=EffectClass.EXTERNAL,
        budget=EffectBudget(
            max_steps=max(1, len(intents)),
            max_duration_ms=max(1, sum(intent.cost.duration_ms for intent in intents)),
            max_mutations=sum(intent.cost.mutations for intent in intents),
            max_processes=sum(intent.cost.processes for intent in intents),
            max_files=sum(intent.cost.files for intent in intents),
            max_network_requests=sum(intent.cost.network_requests for intent in intents),
        ),
        valid_from=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
        single_use=True,
        ownership="self",
        required_containment_digest=containment_digest,
    )
    proof = ControlProof(
        ControlProofMethod.LOOPBACK,
        host,
        "sova-control:" + secrets.token_urlsafe(18),
        {"loopback": True},
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
        "sova.loopback-control-verifier/0.1",
    )
    approval_authority = OutOfBandApprovalAuthority(secrets.token_bytes(32))
    approver = Principal("sova:principal:operator", PrincipalKind.HUMAN, "SOVA operator")
    approvals: dict[str, ApprovalToken] = {}
    for step, intent in zip(steps, intents, strict=True):
        level = _approval_level(intent)
        if level is None:
            continue
        challenge = approval_authority.challenge(authority, intent, level=level, now=now)
        exact_phrase = approval_prompt(challenge, intent)
        approvals[step["id"]] = approval_authority.approve(
            challenge,
            approver=approver,
            exact_phrase=exact_phrase,
            reviewed_effects=True,
        )
    return (
        AuthorizationSession(
            authority=authority,
            proof=proof,
            containment_allowed=True,
            containment_digest=containment_digest,
            kernel=AuthorizationKernel(approval_authority),
        ),
        approvals,
    )


def _target_origins(target: TargetManifest) -> tuple[str, ...]:
    if target.kind != TargetKind.BROWSER_AGENT:
        raise FormatError("SOVA-LIVE-TARGET-KIND", "live browser run requires browser-agent")
    origins = target.configuration.get("allowedOrigins")
    if (
        not isinstance(origins, list)
        or not origins
        or not all(isinstance(item, str) for item in origins)
    ):
        raise FormatError("SOVA-LIVE-ORIGINS", "target requires non-empty allowedOrigins")
    normalized = tuple(_origin(item)[0] for item in origins)
    if len(set(normalized)) != len(normalized):
        raise FormatError("SOVA-LIVE-ORIGINS", "allowedOrigins contains duplicates")
    return normalized


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


def run_live_browser_assessment(  # noqa: PLR0913
    target: TargetManifest,
    source_capsule: Path,
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
) -> LiveBrowserArtifacts:
    """Run and reproduce a capsule on a real, explicitly authorized loopback website."""
    conformance = validate_target_manifest(target)
    if not conformance["accepted"]:
        raise FormatError("SOVA-LIVE-TARGET", "target manifest failed conformance")
    origins = _target_origins(target)
    hosts = {_origin(item)[1].casefold() for item in origins}
    if len(hosts) != 1 or not hosts <= _LOOPBACK:
        raise FormatError(
            "SOVA-LIVE-CONTROL-PROOF",
            "the first live runner accepts only self-owned loopback targets; external targets "
            "require a separately verified control-proof workflow",
        )
    host = next(iter(hosts))
    scenario = _capsule_scenario(source_capsule)
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-LIVE-EXISTS", "live assessment destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    source_copy = destination / "source.sova"
    source_copy.write_bytes(source_capsule.resolve().read_bytes())
    target_path = destination / "target.json"
    target_path.write_bytes(canonical_json_bytes(target.to_mapping()) + b"\n")
    trace = destination / "run.sova-trace"
    reproduction = destination / "reproduction.sova-trace"
    posture = {
        "backend": "microsoft-playwright-mcp",
        "version": "0.0.78",
        "ephemeralProfile": True,
        "headless": True,
        "serviceWorkersBlocked": True,
        "allowedOrigins": list(origins),
        "nativeSandboxClaim": False,
        "scope": "loopback-owned-target",
    }
    containment_digest = sha256_digest(canonical_json_bytes(posture))
    spec = playwright_stdio_spec(
        package_runner=package_runner,
        workspace=destination,
        browser_executable=browser_executable,
        allowed_origins=origins,
    )
    signing_key = generate_ed25519_keypair()
    code_digest = sha256_digest(
        canonical_json_bytes(
            {
                "sovaVersion": __version__,
                "liveRunnerModule": sha256_digest(Path(__file__).read_bytes()),
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
        "model": None,
        "dependencies": dependencies,
    }
    fingerprints = {
        "environment": _fingerprint(
            sha256_digest(canonical_json_bytes(environment)),
            status="recorded",
            method="canonical-runtime-environment-digest",
            source="sova.live.browser",
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
            source="sova.live.browser",
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
            source="local live runner",
        ),
        "model": _fingerprint(
            None,
            status="not-applicable",
            method="no-model-used",
            source="deterministic browser scenario",
        ),
    }
    with StdioMCPClient(spec) as client, MCPExecutorAdapter(
        "microsoft-playwright-mcp",
        client,
        playwright_mappings(allowed_origins=origins),
    ) as executor:
        primary_session, primary_approvals = _authorization_for_run(
            scenario,
            executor.capabilities(),
            host=host,
            containment_digest=containment_digest,
            approval_prompt=approval_prompt,
        )
        primary = run_capsule(
            source_copy,
            trace,
            executor=executor,
            workspace=destination,
            authorization_session=primary_session,
            approvals=primary_approvals,
            signing_key=signing_key,
            environment=environment,
            fingerprints=fingerprints,
        )
        reproduction_session, reproduction_approvals = _authorization_for_run(
            scenario,
            executor.capabilities(),
            host=host,
            containment_digest=containment_digest,
            approval_prompt=approval_prompt,
        )
        repeated = run_capsule(
            source_copy,
            reproduction,
            executor=executor,
            workspace=destination,
            authorization_session=reproduction_session,
            approvals=reproduction_approvals,
            source_trace_digest=sha256_digest(trace.read_bytes()),
            signing_key=signing_key,
            environment=environment,
            fingerprints=fingerprints,
        )
    primary_verification = TraceReader(trace).verify(require_signature=True)
    reproduction_verification = TraceReader(reproduction).verify(require_signature=True)
    comparison = compare_observable_outcomes(
        trace, reproduction, kinds=("oracle.completed",)
    )
    evidence_capsule = destination / "evidence.sova"
    evidence_manifest = capsule_manifest_template(
        title="SOVA live-browser evidence capsule",
        summary="Real loopback browser execution, playback, and controlled reproduction evidence.",
        author="SOVA operator",
        domain_profile=DomainProfile.SECURITY,
    )
    evidence_manifest["license"] = "Apache-2.0"
    evidence_manifest["safety"]["impact"] = "none"
    evidence_manifest["relationships"] = [
        {
            "relationship": "derived-from",
            "artifactType": "sova.capsule",
            "digest": sha256_digest(source_copy.read_bytes()),
        }
    ]
    evidence_manifest["limitations"] = scenario["limitations"]
    build_capsule(
        evidence_capsule,
        evidence_manifest,
        scenario=scenario,
        attachments={"target.json": canonical_json_bytes(target.to_mapping())},
        traces=[trace, reproduction],
    )
    status = (
        "pass"
        if primary.completion == repeated.completion == "completed"
        and primary.oracle_status == repeated.oracle_status == "pass"
        and primary_verification.signature_valid
        and reproduction_verification.signature_valid
        and comparison.equivalent
        else "fail"
    )
    report_path = destination / "report.json"
    report = {
        "artifactType": "sova.live-browser-assessment-report",
        "schemaVersion": "0.1.0",
        "status": status,
        "targetDigest": target.digest,
        "allowedOrigins": list(origins),
        "authorization": {
            "targetControl": "verified-loopback",
            "freshPerActionApproval": True,
            "scopeWidening": False,
        },
        "containment": {
            **posture,
            "digest": containment_digest,
            "statement": "restricted ephemeral browser session; not a VM security sandbox",
        },
        "primary": {
            **asdict(primary),
            "trace_path": trace.name,
            "signatureValid": primary_verification.signature_valid,
        },
        "reproduction": {
            **asdict(repeated),
            "trace_path": reproduction.name,
            "signatureValid": reproduction_verification.signature_valid,
        },
        "comparison": {
            "status": comparison.status,
            "equivalent": comparison.equivalent,
            "method": comparison.method,
            "limitations": list(comparison.limitations),
        },
        "artifacts": {
            "sourceCapsule": source_copy.name,
            "trace": trace.name,
            "reproductionTrace": reproduction.name,
            "evidenceCapsule": evidence_capsule.name,
        },
        "claims": {
            "liveBrowserExecuted": True,
            "conditionalBehaviorObserved": primary.oracle_status == "pass",
            "controlledReproductionObserved": comparison.equivalent,
            "universalSafety": False,
            "privateModelThoughtsCaptured": False,
        },
        "limitations": [
            *scenario["limitations"],
            "Playwright's origin filter is defense in depth, not a standalone security boundary.",
            "A valid trace signature identifies the included key, not an external legal identity.",
        ],
    }
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return LiveBrowserArtifacts(
        target_path,
        source_copy,
        trace,
        reproduction,
        evidence_capsule,
        report_path,
        status,
    )


def run_owned_web_vertical_slice(
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
) -> LiveBrowserArtifacts:
    """Launch the owned HTTP fixture and exercise the complete real browser spine."""
    destination = destination.resolve()
    with OwnedWebFixture() as fixture:
        source = destination.parent / f".{destination.name}-source.sova"
        if source.exists():
            raise FormatError("SOVA-LIVE-SOURCE-EXISTS", "temporary source capsule already exists")
        try:
            build_owned_web_capsule(fixture.url, source)
            return run_live_browser_assessment(
                owned_web_target(fixture.origin),
                source,
                destination,
                package_runner=package_runner,
                browser_executable=browser_executable,
                approval_prompt=approval_prompt,
            )
        finally:
            source.unlink(missing_ok=True)


__all__ = [
    "LiveBrowserArtifacts",
    "build_owned_web_capsule",
    "owned_web_target",
    "run_live_browser_assessment",
    "run_owned_web_vertical_slice",
]
