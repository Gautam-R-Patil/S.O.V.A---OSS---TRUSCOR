# SPDX-License-Identifier: Apache-2.0
"""Real process-restart proof for opaque persistent browser sessions."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.live.browser import verified_browser_control
from sova.live.fixture_web import OwnedWebFixture
from sova.live.startup import start_stdio_client
from sova.mcp import MCPExecutorAdapter, StdioMCPClient, playwright_mappings, playwright_stdio_spec
from sova.runtime import BrowserProfileLease, BrowserProfileVault
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from sova.safety import ControlProof
    from sova.targets import TargetManifest

BrowserHandoffPrompt = Callable[[str, str], str]


@dataclass(frozen=True, slots=True)
class PersistentSessionArtifacts:
    """Secret-free artifacts from one two-process persistence proof."""

    trace: Path
    report: Path
    status: str

    def to_mapping(self) -> dict[str, str]:
        return {"trace": str(self.trace), "report": str(self.report), "status": self.status}


@dataclass(frozen=True, slots=True)
class BrowserSessionHandoffArtifacts:
    """Secret-free evidence of one operator-controlled browser handoff."""

    trace: Path
    report: Path
    status: str

    def to_mapping(self) -> dict[str, str]:
        return {"trace": str(self.trace), "report": str(self.report), "status": self.status}


def _text(output: Mapping[str, Any]) -> str:
    items = output.get("text", [])
    return "\n".join(str(item) for item in items) if isinstance(items, list) else ""


def _execute_navigation(
    client: StdioMCPClient,
    *,
    origin: str,
    url: str,
    workspace: Path,
    request_id: str,
) -> tuple[int, str, tuple[str, ...]]:
    with MCPExecutorAdapter(
        "microsoft-playwright-mcp",
        client,
        playwright_mappings(allowed_origins=(origin,)),
    ) as executor:
        context = ExecutionContext(
            workspace,
            {
                "decision": "authorized",
                "basis": "self-owned-loopback-persistence-fixture",
                "offensive": False,
            },
        )
        outcome = executor.execute(
            ActionRequest(request_id, "browser.navigate", {"url": url}, 20),
            context,
            CancellationToken(),
        )
        if outcome.status != OutcomeStatus.SUCCEEDED:
            raise FormatError(
                "SOVA-PERSISTENT-SESSION-NAVIGATION",
                "persistent-session fixture navigation did not succeed",
            )
        snapshot = executor.execute(
            ActionRequest(f"{request_id}-snapshot", "browser.snapshot", {}, 20),
            context,
            CancellationToken(),
        )
        if snapshot.status != OutcomeStatus.SUCCEEDED:
            raise FormatError(
                "SOVA-PERSISTENT-SESSION-SNAPSHOT",
                "persistent-session fixture snapshot did not succeed",
            )
        evidence = tuple(item.digest for item in (*outcome.evidence, *snapshot.evidence))
        return client.process_id, _text(snapshot.output), evidence


def run_browser_profile_handoff(  # noqa: PLR0913
    target: TargetManifest,
    entry_url: str,
    destination: Path,
    *,
    profile_lease: BrowserProfileLease,
    package_runner: Path,
    browser_executable: Path,
    handoff_prompt: BrowserHandoffPrompt,
    control_proof: ControlProof | None = None,
) -> BrowserSessionHandoffArtifacts:
    """Let a human authenticate in a dedicated profile without exposing credentials.

    SOVA approves and observes navigation, then pauses while the operator acts
    directly in the browser window.  It does not type, read, log, export, or
    receive passwords, one-time codes, CAPTCHA answers, cookies, or tokens.
    """
    origins, _host, _proof, control_status = verified_browser_control(target, control_proof)
    parsed = urlsplit(entry_url)
    default_port = 80 if parsed.scheme == "http" else 443
    port = parsed.port or default_port
    rendered_port = "" if port == default_port else f":{port}"
    origin = (
        ""
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None
        else f"{parsed.scheme}://{parsed.hostname.casefold()}{rendered_port}"
    )
    if origin not in origins:
        raise FormatError(
            "SOVA-PROFILE-HANDOFF-SCOPE",
            "browser handoff entry URL is outside the target's admitted origins",
        )
    profile_lease.require_target(target.digest)
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-LIVE-EXISTS", "browser handoff destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    authorization_phrase = f"OPEN AUTHORIZED PROFILE {secrets.token_hex(8)}"
    supplied = handoff_prompt(
        authorization_phrase,
        "Authorize opening the target-bound profile. No credential material is captured.",
    )
    if not secrets.compare_digest(supplied, authorization_phrase):
        raise FormatError(
            "SOVA-PROFILE-HANDOFF-DENIED",
            "browser profile handoff authorization phrase did not match",
        )
    trace = destination / "browser-profile-handoff.sova-trace"
    report = destination / "report.json"
    profile_evidence = profile_lease.trace_mapping()
    writer = TraceWriter(
        trace,
        authorization={
            "decision": "allowed",
            "scopeDigest": target.digest,
            "decidedBy": "sova.browser-profile-handoff/0.1.0",
        },
        signing_key=generate_ed25519_keypair(),
    )
    writer.append(
        "run.started",
        {
            "runtime": "sova.browser-profile-handoff/0.1.0",
            "targetDigest": target.digest,
            "profile": profile_evidence,
            "manualOperatorChannel": True,
            "credentialCaptureEnabled": False,
        },
    )
    spec = playwright_stdio_spec(
        package_runner=package_runner,
        workspace=destination,
        browser_executable=browser_executable,
        allowed_origins=origins,
        profile_directory=profile_lease.path_for_executor(),
        profile_vault_root=profile_lease.root_for_executor(),
        headless=False,
    )
    client = start_stdio_client(spec, StdioMCPClient)
    with MCPExecutorAdapter(
        "microsoft-playwright-mcp",
        client,
        playwright_mappings(allowed_origins=origins),
    ) as executor:
        context = ExecutionContext(
            destination,
            {
                "decision": "allowed",
                "scopeDigest": target.digest,
                "decidedBy": "sova.browser-profile-handoff/0.1.0",
            },
        )
        navigation = executor.execute(
            ActionRequest("handoff-navigate", "browser.navigate", {"url": entry_url}, 30),
            context,
            CancellationToken(),
        )
        if navigation.status != OutcomeStatus.SUCCEEDED:
            raise FormatError(
                "SOVA-PROFILE-HANDOFF-NAVIGATION",
                "browser profile handoff navigation did not succeed",
            )
        writer.append(
            "browser.handoff.ready",
            {
                "processId": client.process_id,
                "entryOrigin": origin,
                "evidenceDigests": [item.digest for item in navigation.evidence],
                "contentCaptured": False,
            },
            phase="handoff",
        )
        ready_phrase = f"SESSION HANDOFF COMPLETE {secrets.token_hex(8)}"
        supplied_ready = handoff_prompt(
            ready_phrase,
            (
                "Complete login or CAPTCHA manually in the browser. Return here only when "
                "the intended session is ready. SOVA does not receive what you type."
            ),
        )
        if not secrets.compare_digest(supplied_ready, ready_phrase):
            raise FormatError(
                "SOVA-PROFILE-HANDOFF-INCOMPLETE",
                "operator did not confirm completion of the browser handoff",
            )
        snapshot = executor.execute(
            ActionRequest("handoff-snapshot", "browser.snapshot", {}, 30),
            context,
            CancellationToken(),
        )
        if snapshot.status != OutcomeStatus.SUCCEEDED:
            raise FormatError(
                "SOVA-PROFILE-HANDOFF-SNAPSHOT",
                "post-handoff browser snapshot did not succeed",
            )
        writer.append(
            "browser.handoff.completed",
            {
                "processId": client.process_id,
                "operatorConfirmed": True,
                "evidenceDigests": [item.digest for item in snapshot.evidence],
                "contentCaptured": False,
                "credentialValuesCaptured": False,
            },
            phase="handoff",
        )
    writer.append(
        "run.completed",
        {"completion": "completed", "status": "pass", "profileMaterialCaptured": False},
    )
    writer.finalize()
    verification = TraceReader(trace).verify(require_signature=True)
    document = {
        "artifactType": "sova.browser-profile-handoff-report",
        "schemaVersion": "0.1.0",
        "status": "pass",
        "targetDigest": target.digest,
        "targetControl": control_status,
        "entryOrigin": origin,
        "profile": profile_evidence,
        "integrity": {"signedTraceValid": verification.signature_valid},
        "privacy": {
            "profileHandleIncluded": False,
            "profilePathIncluded": False,
            "credentialsCaptured": False,
            "cookiesCaptured": False,
            "pageContentCaptured": False,
        },
        "operator": {
            "manualLoginOrCaptchaAllowed": True,
            "automatedCredentialEntry": False,
            "automatedCaptchaBypass": False,
            "completionSelfAttested": True,
        },
        "claims": {
            "operatorHandoffCompleted": True,
            "authenticatedStateIndependentlyVerified": False,
            "arbitrarySiteCompatibility": False,
            "profileEncryptedBySova": False,
        },
        "limitations": [
            "The operator's completion statement is not proof that a site accepted login.",
            "SOVA records evidence digests but deliberately omits page and credential content.",
            "The profile remains sensitive local executor state and is not a security sandbox.",
        ],
        "trace": trace.name,
    }
    rendered = canonical_json_bytes(document)
    forbidden = (profile_lease.handle, str(profile_lease.path_for_executor()))
    if any(value.encode() in rendered for value in forbidden):
        raise FormatError(
            "SOVA-PROFILE-HANDOFF-PRIVACY",
            "browser profile handoff report contains forbidden profile material",
        )
    report.write_bytes(rendered + b"\n")
    return BrowserSessionHandoffArtifacts(trace, report, "pass")


def run_owned_persistent_session_restart_probe(
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    package_cache: Path | None = None,
) -> PersistentSessionArtifacts:
    """Prove profile reuse across two real MCP processes on a loopback fixture.

    This is an executor capability probe, not a credential workflow.  It uses a
    harmless fixture cookie, performs no account creation or CAPTCHA handling,
    and never serializes the opaque handle, profile path, or cookie material.
    """
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-LIVE-EXISTS", "persistent-session destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    trace = destination / "persistent-session.sova-trace"
    report = destination / "report.json"
    writer = TraceWriter(
        trace,
        authorization={
            "decision": "allowed",
            "scopeDigest": sha256_digest(b"self-owned-loopback-persistence-fixture"),
            "decidedBy": "sova.persistent-browser-session-probe/0.1.0",
        },
        signing_key=generate_ed25519_keypair(),
    )
    with OwnedWebFixture() as fixture:
        vault = BrowserProfileVault(destination / ".sova" / "browser-profiles")
        record = vault.create(identity_id="fixture-operator", target=fixture.origin)
        with vault.acquire(record.handle, owner_id="persistent-session-probe") as lease:
            profile = lease.path_for_executor()
            profile_evidence = lease.trace_mapping()
            writer.append(
                "run.started",
                {
                    "runtime": "sova.persistent-browser-session-probe/0.1.0",
                    "target": "self-owned-loopback-fixture",
                    "profile": profile_evidence,
                    "profileMaterialCaptured": False,
                },
            )
            spec = playwright_stdio_spec(
                package_runner=package_runner,
                workspace=destination,
                browser_executable=browser_executable,
                allowed_origins=(fixture.origin,),
                package_cache=package_cache,
                profile_directory=profile,
            )
            first_client = start_stdio_client(spec, StdioMCPClient)
            first_pid, first_text, first_evidence = _execute_navigation(
                first_client,
                origin=fixture.origin,
                url=f"{fixture.origin}/session/set",
                workspace=destination,
                request_id="profile-prime",
            )
            if "SOVA_SESSION_MARKER_SET" not in first_text:
                raise FormatError(
                    "SOVA-PERSISTENT-SESSION-PRIME",
                    "fixture did not visibly confirm session priming",
                )
            writer.append(
                "browser.session.primed",
                {
                    "processId": first_pid,
                    "observableMarkerPresent": True,
                    "evidenceDigests": list(first_evidence),
                    "cookieValueCaptured": False,
                },
                phase="prime",
            )
            # MCPExecutorAdapter owns and closes the first client. A second
            # launch therefore proves persistence across a server/browser
            # process boundary rather than within one in-memory context.
            second_client = start_stdio_client(spec, StdioMCPClient)
            second_pid, second_text, second_evidence = _execute_navigation(
                second_client,
                origin=fixture.origin,
                url=f"{fixture.origin}/session/check",
                workspace=destination,
                request_id="profile-check",
            )
            persisted = "SOVA_SESSION_PRESENT" in second_text
            distinct_processes = first_pid != second_pid
            writer.append(
                "browser.session.recovered",
                {
                    "processId": second_pid,
                    "distinctMcpProcess": distinct_processes,
                    "observableSessionPresent": persisted,
                    "evidenceDigests": list(second_evidence),
                    "cookieValueCaptured": False,
                },
                phase="restart",
            )
            status = "pass" if persisted and distinct_processes else "fail"
            writer.append(
                "run.completed",
                {
                    "completion": "completed",
                    "status": status,
                    "profileMaterialCaptured": False,
                },
            )
            writer.finalize()
            verification = TraceReader(trace).verify(require_signature=True)
            document = {
                "artifactType": "sova.persistent-browser-session-probe",
                "schemaVersion": "0.1.0",
                "status": status,
                "backend": "microsoft-playwright-mcp",
                "backendVersion": "0.0.78",
                "profile": profile_evidence,
                "restart": {
                    "firstProcessId": first_pid,
                    "secondProcessId": second_pid,
                    "distinctMcpProcesses": distinct_processes,
                    "observableSessionPresentAfterRestart": persisted,
                },
                "integrity": {"signedTraceValid": verification.signature_valid},
                "privacy": {
                    "profileHandleIncluded": False,
                    "profilePathIncluded": False,
                    "cookieValueIncluded": False,
                    "credentialAutomationUsed": False,
                    "captchaBypassUsed": False,
                },
                "claims": {
                    "persistentFixtureSessionVerified": status == "pass",
                    "arbitraryProviderLoginVerified": False,
                    "profileEncryptedBySova": False,
                    "securitySandbox": False,
                },
                "limitations": [
                    "This probe uses a harmless cookie on a self-owned loopback fixture.",
                    "Authentication state may vary by site, browser, operating system, and policy.",
                    "The browser profile can contain sensitive material and must remain local.",
                ],
                "trace": trace.name,
            }
            rendered = canonical_json_bytes(document)
            forbidden = (record.handle, str(profile), "sova_owned_session=active")
            if any(value.encode() in rendered for value in forbidden):
                raise FormatError(
                    "SOVA-PERSISTENT-SESSION-PRIVACY",
                    "persistent-session report contains forbidden profile material",
                )
            report.write_bytes(rendered + b"\n")
    return PersistentSessionArtifacts(trace, report, status)


__all__ = [
    "BrowserHandoffPrompt",
    "BrowserSessionHandoffArtifacts",
    "PersistentSessionArtifacts",
    "run_browser_profile_handoff",
    "run_owned_persistent_session_restart_probe",
]
