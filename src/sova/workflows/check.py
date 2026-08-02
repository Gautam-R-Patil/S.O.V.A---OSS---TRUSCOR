# SPDX-License-Identifier: Apache-2.0
"""Bounded `sova check` workflow and machine-readable assurance states."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.mapping import build_capability_map, write_capability_map
from sova.trace import TraceWriter, generate_ed25519_keypair
from sova.workflows.demo import CompleteDemoArtifacts, run_complete_demo

if TYPE_CHECKING:
    from sova.runtime import RunProfile


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


__all__ = ["CheckResult", "run_check"]
