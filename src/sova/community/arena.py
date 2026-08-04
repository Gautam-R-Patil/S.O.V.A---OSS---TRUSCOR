# SPDX-License-Identifier: Apache-2.0
"""Deterministic local Arena with trace-per-attempt evidence."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedModelError
from sova.trace import TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from sova.trace.integrity import Ed25519Keypair

_MAX_CASE_POINTS = 100


@dataclass(frozen=True, slots=True)
class ArenaProfile:
    identifier: str
    version: str
    standard: bool
    sensor_policy: str = "sova-standard-observable/0.1"

    @property
    def digest(self) -> str:
        return sha256_digest(
            canonical_json_bytes(
                {
                    "identifier": self.identifier,
                    "version": self.version,
                    "standard": self.standard,
                    "sensorPolicy": self.sensor_policy,
                }
            )
        )


STANDARD_ARENA_PROFILE = ArenaProfile("sova.arena.standard", "0.1.0", standard=True)


@dataclass(frozen=True, slots=True)
class ArenaCase:
    identifier: str
    attacker_prompt: str
    defender_prompt: str
    success_marker: str
    points: int = 1

    def __post_init__(self) -> None:
        if (
            not self.identifier
            or not self.success_marker
            or not 1 <= self.points <= _MAX_CASE_POINTS
        ):
            raise FormatError("SOVA-ARENA-CASE", "Arena case is invalid")


@dataclass(frozen=True, slots=True)
class ArenaMatch:
    attacker: str
    defender: str
    case: ArenaCase


def _writer(destination: Path, scope: dict[str, Any], signing_key: Ed25519Keypair) -> TraceWriter:
    return TraceWriter(
        destination,
        signing_key=signing_key,
        authorization={
            "decision": "allowed",
            "scopeDigest": sha256_digest(canonical_json_bytes(scope)),
            "decidedBy": "local-arena-self-owned-fixture",
        },
        environment={
            "platform": platform.platform(),
            "python": platform.python_version(),
            "codeDigest": None,
            "model": {"class": "deterministic-scripted-models"},
            "dependencies": [],
        },
        executor={
            "id": "sova:executor:local-arena",
            "name": "local-arena-scripted-only",
            "version": "0.1.0",
            "capabilityDigest": None,
        },
    )


def _validate_profile(profile: ArenaProfile) -> None:
    if profile.standard and profile != STANDARD_ARENA_PROFILE:
        raise FormatError(
            "SOVA-ARENA-STANDARD-PROFILE",
            "standard runs must use the exact pinned standard profile",
        )
    if not profile.standard and profile.identifier == STANDARD_ARENA_PROFILE.identifier:
        raise FormatError(
            "SOVA-ARENA-CUSTOM-PROFILE",
            "custom profiles cannot reuse the standard profile identifier",
        )


def run_local_arena(
    profile: ArenaProfile,
    matches: Sequence[ArenaMatch],
    models: Mapping[str, ScriptedModel],
    destination: Path,
) -> dict[str, Any]:
    """Run deterministic agents locally; no networking, uploads, or native target code."""
    if not matches:
        raise FormatError("SOVA-ARENA-MATCH", "Arena needs at least one match")
    _validate_profile(profile)
    destination.mkdir(parents=True, exist_ok=True)
    signing_key = generate_ed25519_keypair()
    attempts: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        if match.attacker == match.defender:
            raise FormatError("SOVA-ARENA-PARTICIPANT", "attacker and defender must differ")
        try:
            attacker = models[match.attacker]
            defender = models[match.defender]
        except KeyError as error:
            raise FormatError(
                "SOVA-ARENA-PARTICIPANT", "Arena participant is unavailable"
            ) from error
        if type(attacker) is not ScriptedModel or type(defender) is not ScriptedModel:
            raise FormatError(
                "SOVA-ARENA-PARTICIPANT",
                "reference Arena accepts exact deterministic ScriptedModel participants only",
            )
        trace_path = destination / f"attempt-{index:04d}.sova-trace"
        scope = {
            "profile": profile.digest,
            "case": match.case.identifier,
            "attacker": match.attacker,
            "defender": match.defender,
        }
        writer = _writer(trace_path, scope, signing_key)
        start = writer.append("attempt.started", scope)
        try:
            attack = attacker.respond(match.case.attacker_prompt).response_text
            attack_event = writer.append(
                "model.response",
                {"role": "attacker", "text": attack},
                parents=[start] if start else [],
            )
            defense_input = f"{match.case.defender_prompt}\nATTACK:\n{attack}"
            defense = defender.respond(defense_input).response_text
            defense_event = writer.append(
                "model.response",
                {"role": "defender", "text": defense},
                parents=[attack_event] if attack_event else [],
            )
            success = match.case.success_marker in defense
            writer.append(
                "oracle.result",
                {
                    "case": match.case.identifier,
                    "markerObserved": success,
                    "points": match.case.points if success else 0,
                    "possiblePoints": match.case.points,
                },
                parents=[defense_event] if defense_event else [],
            )
            completion = "completed"
            error_code = None
        except ScriptedModelError:
            success = False
            completion = "failed"
            error_code = "SOVA-ARENA-SCRIPT-MISMATCH"
            writer.append("error.recorded", {"code": error_code, "message": "script mismatch"})
        writer.finalize(completion=completion)
        capsule_path = destination / f"attempt-{index:04d}.sova"
        manifest = capsule_manifest_template(
            title=f"Local Arena {match.case.identifier}",
            summary="A deterministic local Arena attempt with replayable evidence.",
            author="SOVA OSS contributors",
        )
        manifest["license"] = "Apache-2.0"
        manifest["disclosure"] = {
            "classification": "private",
            "sharing": "Local output; review explicitly before any submission.",
        }
        manifest["methodology"]["digest"] = profile.digest
        scenario = scenario_template(
            title=f"Arena case {match.case.identifier}",
            purpose="Reproduce one deterministic standard-profile Arena attempt.",
        )
        scenario["parameters"] = {
            "profileDigest": profile.digest,
            "caseId": match.case.identifier,
            "attacker": match.attacker,
            "defender": match.defender,
            "attackerPrompt": match.case.attacker_prompt,
            "defenderPrompt": match.case.defender_prompt,
            "successMarker": match.case.success_marker,
            "points": match.case.points,
        }
        scenario["procedure"]["steps"][0] = {
            "id": "scripted-arena-attempt",
            "action": "sova.arena.scripted",
            "inputs": {"caseId": match.case.identifier},
            "onFailure": "inconclusive",
            "requires": ["arena.scripted/0.1"],
        }
        artifact_digest = build_capsule(
            capsule_path, manifest, scenario=scenario, traces=[trace_path]
        )
        attempts.append(
            {
                "attemptId": f"attempt-{index:04d}",
                "caseId": match.case.identifier,
                "attacker": match.attacker,
                "defender": match.defender,
                "success": success,
                "points": match.case.points if success else 0,
                "trace": trace_path.as_posix(),
                "traceDigest": sha256_digest(trace_path.read_bytes()),
                "artifact": capsule_path.as_posix(),
                "artifactDigest": artifact_digest,
                "traceCompletion": completion,
                "error": error_code,
            }
        )
    report = {
        "artifactType": "sova.local-arena-report",
        "schemaVersion": "0.1.0",
        "profile": {
            "id": profile.identifier,
            "version": profile.version,
            "digest": profile.digest,
            "class": "standard" if profile.standard else "custom-noncomparable",
        },
        "attempts": attempts,
        "score": sum(item["points"] for item in attempts),
        "possibleScore": sum(match.case.points for match in matches),
        "execution": "local-scripted-only",
        "submission": "none-local-output-only",
        "telemetry": "none",
        "signingKeyId": signing_key.key_id,
        "limitations": [
            "The reference Arena runs deterministic scripted participants only.",
            "A score is comparable only under an identical standard profile digest.",
        ],
    }
    report_path = destination / "arena-report.json"
    report_path.write_bytes(canonical_json_bytes(report) + b"\n")
    return report
