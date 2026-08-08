# SPDX-License-Identifier: Apache-2.0
"""Portable authorized-target planning and deterministic reference assessments."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
    ScriptedAction,
    ScriptedExecutor,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.reproduction import compare_observable_outcomes
from sova.targets import TargetKind, TargetManifest, validate_target_manifest
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class AssessmentFixtureArtifacts:
    target: Path
    plan: Path
    scenario: Path
    trace: Path
    reproduction_trace: Path
    capsule: Path
    report: Path


def target_template(kind: TargetKind) -> dict[str, Any]:
    """Return a secret-free portable target template with no executor command line."""
    capabilities: dict[TargetKind, tuple[str, ...]] = {
        TargetKind.MCP_SERVER: ("protocol.mcp",),
        TargetKind.LOCAL_PROCESS: ("process.invoke", "process.observe"),
        TargetKind.REST_API: ("protocol.http", "api.observe"),
        TargetKind.BROWSER_AGENT: ("browser.observe", "browser.navigate"),
        TargetKind.COMPUTER_AGENT: ("computer.observe",),
        TargetKind.FRAMEWORK: ("manifest.inspect",),
        TargetKind.MULTI_AGENT: ("inter-agent.observe",),
        TargetKind.TRACE_ONLY: ("trace.import",),
    }
    configuration: dict[TargetKind, dict[str, Any]] = {
        TargetKind.MCP_SERVER: {"transport": "stdio", "mechanics": "executor-owned"},
        TargetKind.LOCAL_PROCESS: {
            "interface": "stdin-jsonl",
            "workspaceMode": "isolated-copy-required",
            "authorityBasis": "replace-with-self-or-explicit",
            "authorityReference": "replace-with-non-secret-reference",
        },
        TargetKind.REST_API: {
            "allowedOrigins": ["https://owned-target.example.invalid"],
            "redirects": "deny-cross-origin",
        },
        TargetKind.BROWSER_AGENT: {
            "allowedOrigins": ["https://owned-target.example.invalid"],
            "browserProfile": "ephemeral-by-default",
        },
        TargetKind.COMPUTER_AGENT: {
            "displayScope": "dedicated-test-session",
            "inputDefault": "disabled",
        },
        TargetKind.FRAMEWORK: {"inspection": "manifest-only"},
        TargetKind.MULTI_AGENT: {"sessionSharing": "opaque-runtime-handle-only"},
        TargetKind.TRACE_ONLY: {"execution": False},
    }
    return TargetManifest(
        identifier=f"sova:target:replace-me-{kind.value}",
        kind=kind,
        version="replace-with-exact-version",
        capabilities=capabilities[kind],
        authorization_scope="replace-with-self-owned-or-explicitly-authorized-scope",
        configuration=configuration[kind],
    ).to_mapping()


def build_assessment_plan(manifest: TargetManifest) -> dict[str, Any]:
    """Create an inert plan that keeps portable intent separate from adapter mechanics."""
    conformance = validate_target_manifest(manifest)
    if not conformance["accepted"]:
        raise FormatError(
            "SOVA-ASSESS-TARGET",
            "target manifest does not satisfy its required portable capability contract",
            details={"missing": conformance["missingCapabilities"]},
        )
    adapters: dict[TargetKind, tuple[str, ...]] = {
        TargetKind.MCP_SERVER: ("stdio-mcp",),
        TargetKind.LOCAL_PROCESS: ("restricted-local", "stronger-isolation-recommended"),
        TargetKind.REST_API: ("provider-extension-required",),
        TargetKind.BROWSER_AGENT: ("microsoft-playwright-mcp", "melra-optional"),
        TargetKind.COMPUTER_AGENT: ("windows-mcp-read-first", "melra-optional"),
        TargetKind.FRAMEWORK: ("static-manifest",),
        TargetKind.MULTI_AGENT: ("provider-extension-required",),
        TargetKind.TRACE_ONLY: ("offline-trace-import",),
    }
    authorization_required = manifest.kind not in {TargetKind.TRACE_ONLY, TargetKind.FRAMEWORK}
    document = {
        "artifactType": "sova.assessment-plan",
        "schemaVersion": "0.1.0",
        "target": manifest.to_mapping(),
        "targetDigest": manifest.digest,
        "portableRequirements": sorted(manifest.capabilities),
        "adapterCandidates": list(adapters[manifest.kind]),
        "authorization": {
            "requiredBeforeExecution": authorization_required,
            "declaredScope": manifest.authorization_scope,
            "freshPerRun": True,
            "scopeWideningAllowed": False,
            "promptOrModelMayApprove": False,
        },
        "stages": [
            "map-declared-surface",
            "negotiate-executor-capabilities",
            "verify-fresh-human-authorization",
            "prepare-containment-or-substitute",
            "execute-bounded-scenario",
            "observe-effects-independently",
            "evaluate-declared-oracles",
            "finalize-sova-trace",
            "package-sova-capsule",
            "verify-offline",
        ],
        "executionPerformed": False,
        "networkUsed": False,
        "limitations": [
            "A plan is not authorization and does not prove target ownership.",
            "Browser or computer execution requires an admitted optional executor.",
            "Ordinary host-process restriction is not a security sandbox.",
            "A bounded assessment cannot prove universal safety or absence of vulnerabilities.",
        ],
    }
    return {**document, "planDigest": sha256_digest(canonical_json_bytes(document))}


def create_browser_test_kit(origin: str, destination: Path) -> dict[str, Any]:
    """Write an inert, secret-free starter kit for one operator-controlled website."""
    parsed = urlsplit(origin)
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
            "SOVA-TARGET-KIT-ORIGIN",
            "origin must be one bare HTTP(S) origin without credentials, path, query, or fragment",
        )
    host = parsed.hostname.casefold()
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not loopback:
        raise FormatError(
            "SOVA-TARGET-KIT-TLS",
            "external website kits require HTTPS; HTTP is accepted only for loopback",
        )
    try:
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except ValueError as error:
        raise FormatError("SOVA-TARGET-KIT-ORIGIN", "origin port is invalid") from error
    default_port = 80 if parsed.scheme == "http" else 443
    rendered_host = f"[{host}]" if ":" in host else host
    normalized = f"{parsed.scheme}://{rendered_host}{'' if port == default_port else f':{port}'}"

    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-TARGET-KIT-EXISTS", "browser test kit destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    suffix = sha256_digest(normalized.encode("utf-8"))[-12:]
    target = TargetManifest(
        f"sova:target:browser-kit-{suffix}",
        TargetKind.BROWSER_AGENT,
        "replace-with-exact-target-version",
        ("browser.observe", "browser.navigate", "browser.interact"),
        "replace-with-self-owned-or-explicitly-authorized-scope-reference",
        {"allowedOrigins": [normalized], "browserProfile": "ephemeral-by-default"},
    )
    # Import locally so the target contract does not depend on a live executor at import time.
    from sova.live.campaign import BrowserCampaign  # noqa: PLC0415

    campaign = BrowserCampaign(
        f"sova:browser-campaign:kit-{suffix}",
        "Replace with the bounded behavior question",
        normalized + "/",
        "#replace-with-input-selector",
        "#replace-with-submit-selector",
        (("safe baseline",), ("safe alternate",), ("safe first turn", "safe second turn")),
        "REPLACE_WITH_OBSERVABLE_MARKER",
        3,
        300,
        offensive=False,
    )
    target_path = destination / "target.json"
    campaign_path = destination / "campaign.json"
    plan_path = destination / "assessment-plan.json"
    instructions_path = destination / "README.md"
    target_path.write_bytes(canonical_json_bytes(target.to_mapping()) + b"\n")
    campaign_path.write_bytes(canonical_json_bytes(campaign.to_mapping()) + b"\n")
    plan_path.write_bytes(canonical_json_bytes(build_assessment_plan(target)) + b"\n")
    control_step = (
        "Loopback control is verified locally; do not pass a control-proof file."
        if loopback
        else (
            "Run `sova target challenge target.json challenge.json`, host the exact token at "
            "the emitted HTTPS proof URL, then run `sova target prove target.json "
            "challenge.json control-proof.json`."
        )
    )
    instructions_path.write_text(
        "# Authorized SOVA browser test kit\n\n"
        f"Target origin: `{normalized}`\n\n"
        "This directory is an inert authoring kit. It does not prove ownership, connect to the "
        "target, or authorize execution.\n\n"
        "1. Replace the target version and authorization-scope reference in `target.json`.\n"
        "2. Replace selectors, finite candidate sequences, and the observable oracle marker in "
        "`campaign.json`; keep `offensive` false unless separately reviewed.\n"
        "3. Run `sova target validate target.json` and review `assessment-plan.json`.\n"
        f"4. {control_step}\n"
        "5. Use an isolated test account and data set. In a human-operated terminal, run "
        "`sova check standard --target target.json --destination result "
        "--browser-campaign campaign.json` and add `--control-proof control-proof.json` for an "
        "external origin.\n\n"
        "SOVA does not bypass CAPTCHA, acquire credentials, create unsolicited accounts, infer "
        "permission from a login, or prove universal safety. Browser execution is not a VM "
        "sandbox. Screenshots are reduced to digest/size evidence by the MCP adapter; raw pixels "
        "are not written into the trace.\n",
        encoding="utf-8",
        newline="\n",
    )
    report = {
        "artifactType": "sova.browser-test-kit-report",
        "schemaVersion": "0.1.0",
        "origin": normalized,
        "loopback": loopback,
        "targetDigest": target.digest,
        "campaignDigest": campaign.digest,
        "files": [
            "README.md",
            "assessment-plan.json",
            "campaign.json",
            "kit-report.json",
            "target.json",
        ],
        "readyForExecution": False,
        "networkUsed": False,
        "authorizationEstablished": False,
        "limitations": [
            "The operator must customize and review the finite scenario before execution.",
            "A target URL or login session is not proof of authorization.",
        ],
    }
    (destination / "kit-report.json").write_bytes(canonical_json_bytes(report) + b"\n")
    return report


def _fixture_target(kind: str) -> TargetManifest:
    if kind == "website":
        return TargetManifest(
            "sova:target:self-owned-website-fixture",
            TargetKind.BROWSER_AGENT,
            "0.1.0",
            ("browser.observe", "browser.navigate"),
            "self-owned local deterministic fixture",
            {
                "allowedOrigins": ["https://fixture.sova.invalid"],
                "browserProfile": "synthetic",
            },
        )
    if kind == "software":
        return TargetManifest(
            "sova:target:self-owned-software-fixture",
            TargetKind.LOCAL_PROCESS,
            "0.1.0",
            ("process.invoke", "process.observe"),
            "self-owned local deterministic fixture",
            {"interface": "stdin-jsonl", "workspaceMode": "synthetic"},
        )
    raise FormatError("SOVA-ASSESS-FIXTURE", "fixture kind must be website or software")


def _fixture_script(kind: str) -> list[ScriptedAction]:
    if kind == "website":
        return [
            ScriptedAction(
                "browser.navigate",
                {"url": "https://fixture.sova.invalid/test"},
                OutcomeStatus.SUCCEEDED,
                {"url": "https://fixture.sova.invalid/test", "title": "SOVA fixture"},
                SideEffect.MUTATE,
                (("aria-snapshot", "text/plain", b"heading SOVA fixture"),),
                "scripted-post-navigation-observation",
            ),
            ScriptedAction(
                "browser.snapshot",
                {},
                OutcomeStatus.SUCCEEDED,
                {"landmark": "SOVA fixture", "state": "ready"},
                SideEffect.READ,
                (("aria-snapshot", "text/plain", b"heading SOVA fixture\nstatus ready"),),
                "scripted-observation",
            ),
        ]
    return [
        ScriptedAction(
            "process.exec",
            {"argv": ["fixture-program", "--self-test"]},
            OutcomeStatus.SUCCEEDED,
            {"returncode": 0, "stdout": "SOVA_FIXTURE_READY", "stderr": ""},
            SideEffect.MUTATE,
            (("stdout", "text/plain", b"SOVA_FIXTURE_READY"),),
            "scripted-exit-and-output-observation",
        )
    ]


def _record_fixture_trace(path: Path, kind: str, target: TargetManifest) -> None:
    script = _fixture_script(kind)
    executor = ScriptedExecutor(script.copy())
    context = ExecutionContext(
        path.parent,
        {
            "decision": "allowed",
            "scopeDigest": target.digest,
            "decidedBy": "sova:principal:synthetic-fixture-authority",
        },
    )
    writer = TraceWriter(
        path,
        signing_key=generate_ed25519_keypair(),
        authorization=context.authorization,
    )
    run = writer.append(
        "run.started",
        {
            "targetDigest": target.digest,
            "fixtureKind": kind,
            "liveTarget": False,
            "hiddenModelThoughtsCaptured": False,
        },
    )
    writer.append(
        "authorization.decision",
        {
            "decision": "allowed",
            "scopeDigest": target.digest,
            "selfOwnedFixture": True,
            "freshHumanAuthorizationForLiveTargetStillRequired": True,
        },
        parents=[run] if run else [],
    )
    last = run
    for index, scripted in enumerate(script):
        request = ActionRequest(
            f"sova:request:fixture-{kind}-{index}",
            scripted.action,
            scripted.expected_inputs,
            5,
        )
        family = "browser" if kind == "website" else "process"
        requested = writer.append(
            f"{family}.action",
            {
                "requestId": request.id,
                "action": request.action,
                "inputs": request.inputs,
                "fixtureOnly": True,
            },
            parents=[last] if last else [],
        )
        outcome = executor.execute(request, context, CancellationToken())
        last = writer.append(
            "tool.result",
            {
                "requestId": outcome.request_id,
                "status": outcome.status.value,
                "sideEffect": outcome.side_effect.value,
                "output": outcome.output,
                "evidence": [asdict(item) for item in outcome.evidence],
                "verification": outcome.verification,
                "limitations": list(outcome.limitations),
            },
            parents=[requested] if requested else [],
        )
    if not executor.complete:
        raise FormatError("SOVA-ASSESS-FIXTURE", "fixture executor did not consume its script")
    oracle = writer.append(
        "oracle.completed",
        {
            "status": "pass",
            "results": [
                {
                    "status": "pass",
                    "expected": "observable fixture completion",
                    "observed": ["observable fixture completion"],
                    "evidence_event_ids": [last] if last else [],
                }
            ],
            "liveTargetClaim": False,
        },
        parents=[last] if last else [],
    )
    writer.append(
        "run.completed",
        {"completion": "completed", "fixtureOnly": True, "safeOrCleanClaim": False},
        parents=[oracle] if oracle else [],
    )
    writer.finalize()


def run_reference_assessment(kind: str, destination: Path) -> AssessmentFixtureArtifacts:
    """Prove the full target-to-capsule pipeline against a deterministic owned fixture."""
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-ASSESS-EXISTS", "assessment output directory is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    target = _fixture_target(kind)
    target_path = destination / "target.json"
    target_path.write_bytes(canonical_json_bytes(target.to_mapping()) + b"\n")
    plan = build_assessment_plan(target)
    plan_path = destination / "assessment-plan.json"
    plan_path.write_bytes(canonical_json_bytes(plan) + b"\n")
    scenario = scenario_template(
        title=f"Self-owned {kind} assessment fixture",
        purpose="Exercise target planning, observable execution, trace, capsule, and verification.",
    )
    scenario["procedure"]["steps"] = [
        {
            "id": f"fixture-{index}",
            "action": step.action,
            "inputs": step.expected_inputs,
            "onFailure": "inconclusive",
            "requires": [f"{step.action}/0.1"],
        }
        for index, step in enumerate(_fixture_script(kind))
    ]
    scenario["preconditions"] = [
        {"kind": "owned-target", "targetDigest": target.digest, "synthetic": True}
    ]
    scenario["expectedEffects"] = [{"kind": "observable-fixture-completion"}]
    scenario["oracles"] = [{"kind": "declared-outcome", "expected": "pass"}]
    scenario["limitations"] = [
        "This scenario exercises a deterministic fixture, not a live website or native program."
    ]
    scenario_path = destination / "scenario.json"
    scenario_path.write_bytes(canonical_json_bytes(scenario) + b"\n")
    trace = destination / "assessment.sova-trace"
    reproduction = destination / "assessment-reproduction.sova-trace"
    _record_fixture_trace(trace, kind, target)
    _record_fixture_trace(reproduction, kind, target)
    comparison = compare_observable_outcomes(trace, reproduction, kinds=("oracle.completed",))
    trace_verification = TraceReader(trace).verify(require_signature=True)
    reproduction_verification = TraceReader(reproduction).verify(require_signature=True)
    manifest = capsule_manifest_template(
        title=f"SOVA self-owned {kind} assessment fixture",
        summary="Portable deterministic evidence for the authorized-target assessment pipeline.",
        author="SOVA OSS synthetic fixture authors",
        domain_profile=DomainProfile.EVALUATION,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["limitations"] = scenario["limitations"]
    manifest["relationships"] = [
        {
            "relationship": "derived-from",
            "artifactType": "sova.target-manifest",
            "digest": target.digest,
        }
    ]
    capsule = destination / "assessment.sova"
    build_capsule(
        capsule,
        manifest,
        scenario=scenario,
        attachments={"target-manifest.json": canonical_json_bytes(target.to_mapping())},
        traces=[trace],
    )
    report_path = destination / "assessment-report.json"
    report = {
        "artifactType": "sova.assessment-report",
        "schemaVersion": "0.1.0",
        "fixtureKind": kind,
        "targetDigest": target.digest,
        "status": "pass"
        if trace_verification.signature_valid
        and reproduction_verification.signature_valid
        and comparison.equivalent
        else "fail",
        "pipeline": [
            "target",
            "plan",
            "scenario",
            "observable-execution",
            "sova-trace",
            "sova-capsule",
            "controlled-reproduction",
            "offline-verification",
        ],
        "traceSignatureValid": trace_verification.signature_valid,
        "reproductionSignatureValid": reproduction_verification.signature_valid,
        "semanticOutcomeEquivalent": comparison.equivalent,
        "liveTargetExecuted": False,
        "safeOrCleanClaim": False,
        "nextForLiveUse": (
            "Replace target template values, review the generated plan, provide exact target "
            "ownership/authorization, and admit a supported executor in an isolated test session."
        ),
        "limitations": [
            "Fixture evidence validates the SOVA measurement pipeline, not a live target.",
            "A website requires Playwright MCP or another admitted browser executor.",
            "A native software target requires stronger isolation than ordinary host restriction.",
        ],
    }
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return AssessmentFixtureArtifacts(
        target_path,
        plan_path,
        scenario_path,
        trace,
        reproduction,
        capsule,
        report_path,
    )


__all__ = [
    "AssessmentFixtureArtifacts",
    "build_assessment_plan",
    "create_browser_test_kit",
    "run_reference_assessment",
    "target_template",
]
