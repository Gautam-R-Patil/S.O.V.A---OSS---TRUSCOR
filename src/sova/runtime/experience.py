# SPDX-License-Identifier: Apache-2.0
"""Local, content-addressed attempt history without prompts or secret material."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_ALLOWED_OUTCOMES = {"confirmed", "not-confirmed", "inconclusive", "failed"}


@dataclass(frozen=True, slots=True)
class ExperienceRecord:
    """Privacy-minimized search result suitable for an owner-local store."""

    scenario_digest: str
    candidate_digest: str
    outcome: str
    attempts: int
    turns: int
    mutations: int
    duration_ms: int
    trace_digest: str
    near_miss: bool = False

    def __post_init__(self) -> None:
        digests = (self.scenario_digest, self.candidate_digest, self.trace_digest)
        if not all(value.startswith("sha256:") for value in digests):
            raise FormatError("SOVA-EXPERIENCE-DIGEST", "experience digests require sha256")
        if self.outcome not in _ALLOWED_OUTCOMES:
            raise FormatError("SOVA-EXPERIENCE-OUTCOME", "unsupported experience outcome")
        if min(self.attempts, self.turns, self.mutations, self.duration_ms) < 0:
            raise FormatError("SOVA-EXPERIENCE-EFFORT", "effort measurements cannot be negative")

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.experience",
            "schemaVersion": "0.1.0",
            "scenarioDigest": self.scenario_digest,
            "candidateDigest": self.candidate_digest,
            "outcome": self.outcome,
            "nearMiss": self.near_miss,
            "effort": {
                "attempts": self.attempts,
                "turns": self.turns,
                "mutations": self.mutations,
                "durationMs": self.duration_ms,
            },
            "traceDigest": self.trace_digest,
            "rawPromptsStored": False,
            "rawModelOutputsStored": False,
            "secretValuesStored": False,
            "remoteSynchronization": False,
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


class LocalExperienceStore:
    """Explicit local-only store; it has no transport or private-corpus integration."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def add(self, record: ExperienceRecord) -> Path:
        document = record.to_mapping()
        digest = str(document["contentDigest"])
        destination = self.root / f"{digest.removeprefix('sha256:')}.json"
        encoded = canonical_json_bytes(document) + b"\n"
        self.root.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != encoded:
                raise FormatError(
                    "SOVA-EXPERIENCE-COLLISION",
                    "existing experience does not match its content address",
                )
            return destination
        temporary = destination.with_suffix(".tmp")
        if temporary.exists():
            raise FormatError("SOVA-EXPERIENCE-TEMP", "temporary experience path exists")
        temporary.write_bytes(encoded)
        temporary.replace(destination)
        return destination

    def records(self, *, outcome: str | None = None) -> tuple[dict[str, Any], ...]:
        if outcome is not None and outcome not in _ALLOWED_OUTCOMES:
            raise FormatError("SOVA-EXPERIENCE-OUTCOME", "unsupported experience outcome")
        if not self.root.exists():
            return ()
        records: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("*.json")):
            value = strict_json_loads(path.read_bytes())
            if not isinstance(value, dict) or value.get("artifactType") != "sova.experience":
                raise FormatError("SOVA-EXPERIENCE-RECORD", "malformed local experience record")
            claimed = value.get("contentDigest")
            unsigned = dict(value)
            unsigned.pop("contentDigest", None)
            if claimed != sha256_digest(canonical_json_bytes(unsigned)):
                raise FormatError("SOVA-EXPERIENCE-INTEGRITY", "experience digest mismatch")
            if outcome is None or value.get("outcome") == outcome:
                records.append(value)
        return tuple(records)


__all__ = ["ExperienceRecord", "LocalExperienceStore"]
