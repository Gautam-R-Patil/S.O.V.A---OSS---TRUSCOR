# SPDX-License-Identifier: Apache-2.0
"""Bounded `sova check` workflow and machine-readable assurance states."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.campaign import BrowserCampaign, BrowserCampaignArtifacts, run_browser_campaign
from sova.mapping import build_capability_map, write_capability_map
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair
from sova.workflows.demo import CompleteDemoArtifacts, run_complete_demo

if TYPE_CHECKING:
    from collections.abc import Callable

    from sova.live.browser import ApprovalPrompt
    from sova.runtime import RunProfile
    from sova.safety import ControlProof
    from sova.targets import TargetManifest


@dataclass(frozen=True, slots=True)
class CheckResult:
    status: str
    exit_code: int
    report: Path
    trace: Path
    capsule: Path | None
    artifacts: CompleteDemoArtifacts | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "exitCode": self.exit_code,
            "report": str(self.report),
            "trace": str(self.trace),
            "capsule": str(self.capsule) if self.capsule is not None else None,
            "safeOrCleanClaim": False,
        }


@dataclass(frozen=True, slots=True)
class BrowserCheckResult:
    """One real-browser check over an exact, operator-declared candidate set."""

    status: str
    exit_code: int
    report: Path
    campaign_report: Path
    traces: tuple[Path, ...]
    reproduction_trace: Path | None
    capsule: Path | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "exitCode": self.exit_code,
            "mode": "authorized-live-browser",
            "report": str(self.report),
            "campaignReport": str(self.campaign_report),
            "traces": [str(path) for path in self.traces],
            "reproductionTrace": (
                None if self.reproduction_trace is None else str(self.reproduction_trace)
            ),
            "capsule": None if self.capsule is None else str(self.capsule),
            "safeOrCleanClaim": False,
        }


def _blocked_check(target: Path, destination: Path, profile: RunProfile) -> CheckResult:
    started_ns = time.perf_counter_ns()
    destination.mkdir(parents=True, exist_ok=True)
    map_report = build_capability_map(target)
    map_path = destination / "target.sova-map.json"
    write_capability_map(map_path, map_report)
    trace = destination / "check.sova-trace"
    writer = TraceWriter(trace, signing_key=generate_ed25519_keypair())
    started = writer.append(
        "run.started",
        {
            "targetMapDigest": map_report.to_mapping()["contentDigest"],
            "profile": profile.to_mapping(),
            "mode": "bounded-check",
        },
    )
    writer.append(
        "blocked.unsupported-target",
        {
            "reason": "No safe executable target adapter was selected for this local component.",
            "staticMapProduced": True,
            "nativeCodeExecuted": False,
        },
        parents=[started] if started else [],
    )
    writer.append(
        "run.failed",
        {"completion": "inconclusive", "safeOrCleanClaim": False},
    )
    writer.finalize(completion="failed")
    report = destination / "check-report.json"
    report.write_bytes(
        canonical_json_bytes(
            {
                "artifactType": "sova.check-report",
                "schemaVersion": "0.1.0",
                "status": "inconclusive",
                "profile": profile.to_mapping(),
                "conditions": {"staticMapOnly": True, "nativeCodeExecuted": False},
                "durationMs": max(
                    1,
                    (time.perf_counter_ns() - started_ns + 999_999) // 1_000_000,
                ),
                "attempts": 0,
                "coverage": map_report.to_mapping()["coverage"],
                "detectionFloor": "No dynamic target adapter was selected.",
                "safeOrCleanClaim": False,
                "nextStep": (
                    "Provide a supported authorized target adapter; use future Topic 14 trigger "
                    "hunting for dormancy testing."
                ),
                "artifacts": {"map": map_path.name, "trace": trace.name},
            }
        )
        + b"\n"
    )
    return CheckResult("inconclusive", 3, report, trace, None)


def run_check(target: str, destination: Path, *, profile: RunProfile) -> CheckResult:
    """Check one target and return explicit confirmed/inconclusive machine state."""
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FormatError("SOVA-CHECK-EXISTS", "check output directory is not empty")
    if target in {"sleeper", "synthetic-sleeper", "sova:target:sleeper"}:
        artifacts = run_complete_demo(destination, profile=profile)
        return CheckResult(
            "confirmed-behavior",
            1,
            artifacts.report,
            artifacts.trace,
            artifacts.capsule,
            artifacts,
        )
    path = Path(target).resolve()
    if not path.is_dir():
        raise FormatError(
            "SOVA-CHECK-TARGET",
            "target must be the bundled sleeper identifier or an existing local directory",
        )
    return _blocked_check(path, destination, profile)


def _campaign_report(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("artifactType") != (
        "sova.live-browser-campaign-report"
    ):
        raise FormatError("SOVA-CHECK-BROWSER-REPORT", "browser campaign report is invalid")
    return value


def _verify_browser_check_artifacts(artifacts: BrowserCampaignArtifacts) -> None:
    if not artifacts.traces:
        raise FormatError("SOVA-CHECK-BROWSER-EVIDENCE", "browser check produced no trace")
    for trace in artifacts.traces:
        verification = TraceReader(trace).verify(require_signature=True)
        if not verification.signature_valid or verification.completion != "completed":
            raise FormatError(
                "SOVA-CHECK-BROWSER-EVIDENCE",
                "browser check trace failed signed offline verification",
            )
    if artifacts.reproduction_trace is not None:
        verification = TraceReader(artifacts.reproduction_trace).verify(require_signature=True)
        if not verification.signature_valid or verification.completion != "completed":
            raise FormatError(
                "SOVA-CHECK-BROWSER-EVIDENCE",
                "browser check reproduction failed signed offline verification",
            )
    if artifacts.discovery_capsule is not None:
        PackageReader(artifacts.discovery_capsule).verify("sova.capsule")


def run_browser_check(  # noqa: PLR0913
    target: TargetManifest,
    campaign: BrowserCampaign,
    destination: Path,
    *,
    profile: RunProfile,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    control_proof: ControlProof | None = None,
    runner: Callable[..., BrowserCampaignArtifacts] = run_browser_campaign,
) -> BrowserCheckResult:
    """Execute a non-offensive dynamic check on one controlled browser target."""
    if campaign.offensive:
        raise FormatError(
            "SOVA-CHECK-BROWSER-OFFENSIVE",
            "sova check refuses offensive campaigns; use the separately gated hunt workflow",
        )
    artifacts = runner(
        target,
        campaign,
        destination,
        package_runner=package_runner,
        browser_executable=browser_executable,
        approval_prompt=approval_prompt,
        control_proof=control_proof,
    )
    _verify_browser_check_artifacts(artifacts)
    campaign_report = _campaign_report(artifacts.report)
    search = campaign_report.get("search")
    if not isinstance(search, dict):
        raise FormatError("SOVA-CHECK-BROWSER-REPORT", "browser search report is missing")
    stop_reason = search.get("stopReason")
    if artifacts.status == "pass":
        if artifacts.reproduction_trace is None or artifacts.discovery_capsule is None:
            raise FormatError(
                "SOVA-CHECK-BROWSER-EVIDENCE",
                "confirmed browser behavior lacks reproduction evidence",
            )
        status, exit_code = "confirmed-behavior", 1
    elif stop_reason == "candidate-source-exhausted":
        status, exit_code = "not-observed", 0
    else:
        status, exit_code = "inconclusive", 3
    check_report_path = destination.resolve() / "check-report.json"
    report = {
        "artifactType": "sova.check-report",
        "schemaVersion": "0.2.0",
        "status": status,
        "mode": "authorized-live-browser",
        "profile": profile.to_mapping(),
        "conditions": {
            "realBrowserExecuted": True,
            "declaredCandidateSetOnly": True,
            "offensiveCampaign": False,
            "signedTraceVerification": True,
            "controlledReproductionRequiredForConfirmation": True,
        },
        "attempts": search.get("attempts"),
        "coverage": search.get("coverage"),
        "stopReason": stop_reason,
        "detectionFloor": (
            "Only the exact declared candidates and observable text oracle were evaluated."
        ),
        "safeOrCleanClaim": False,
        "artifacts": {
            "campaignReport": artifacts.report.name,
            "campaignReportDigest": sha256_digest(artifacts.report.read_bytes()),
            "traces": [path.relative_to(destination).as_posix() for path in artifacts.traces],
            "reproductionTrace": (
                None
                if artifacts.reproduction_trace is None
                else artifacts.reproduction_trace.relative_to(destination).as_posix()
            ),
            "capsule": (
                None
                if artifacts.discovery_capsule is None
                else artifacts.discovery_capsule.relative_to(destination).as_posix()
            ),
        },
        "limitations": [
            "A not-observed result applies only to the declared finite candidate set.",
            "Browser and MCP sensors expose observable executor data, not hidden model state.",
            "The restricted browser session is not a VM security sandbox.",
            "This is operator-controlled self-assessment, not certification or attestation.",
        ],
    }
    check_report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return BrowserCheckResult(
        status,
        exit_code,
        check_report_path,
        artifacts.report,
        artifacts.traces,
        artifacts.reproduction_trace,
        artifacts.discovery_capsule,
    )


__all__ = ["BrowserCheckResult", "CheckResult", "run_browser_check", "run_check"]
