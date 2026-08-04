# SPDX-License-Identifier: Apache-2.0
"""Static, reproducible leaderboard generation from verified local evidence."""

from __future__ import annotations

import html
from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import TYPE_CHECKING, Any

from sova.community.arena import STANDARD_ARENA_PROFILE
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import TraceReader

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

_ALLOWED_CATEGORIES = {"building-block", "framework", "component", "model"}
_MIN_RECOMMENDED_SAMPLE = 10


@dataclass(frozen=True, slots=True)
class LeaderboardSubmission:
    category: str
    component: str
    version: str
    profile_id: str
    profile_digest: str
    score: int
    possible_score: int
    artifact: Path
    trace: Path
    required_key_id: str

    def __post_init__(self) -> None:
        if self.category not in _ALLOWED_CATEGORIES:
            raise FormatError(
                "SOVA-LEADERBOARD-CATEGORY",
                "leaderboard ranks technical building blocks, not people or organizations",
            )
        if (
            not self.component
            or not self.version
            or not self.profile_id
            or not self.required_key_id
        ):
            raise FormatError("SOVA-LEADERBOARD-IDENTITY", "submission identity is incomplete")
        if not 0 <= self.score <= self.possible_score or self.possible_score < 1:
            raise FormatError("SOVA-LEADERBOARD-SCORE", "submission score is invalid")


def _interval(successes: int, attempts: int) -> tuple[str, str]:
    """Wilson 95 percent interval as decimal strings (no binary floats in artifacts)."""
    with localcontext() as context:
        context.prec = 28
        z = Decimal("1.959963984540054")
        count = Decimal(attempts)
        rate = Decimal(successes) / count
        denominator = Decimal(1) + z * z / count
        center = (rate + z * z / (Decimal(2) * count)) / denominator
        margin = (
            z
            * (rate * (Decimal(1) - rate) / count + z * z / (Decimal(4) * count * count)).sqrt()
            / denominator
        )
        return (str(max(Decimal(0), center - margin)), str(min(Decimal(1), center + margin)))


def _verify(submission: LeaderboardSubmission) -> dict[str, Any]:
    descriptors = PackageReader(submission.artifact).verify("sova.capsule")
    manifest = PackageReader(submission.artifact).manifest("sova.capsule")
    if manifest["methodology"]["digest"] != submission.profile_digest:
        raise FormatError(
            "SOVA-LEADERBOARD-PROFILE",
            "artifact methodology digest does not match the standard profile",
        )
    trace_reader = TraceReader(submission.trace)
    trace_report = trace_reader.verify(
        require_signature=True, required_key_id=submission.required_key_id
    )
    if trace_report.completion != "completed":
        raise FormatError("SOVA-LEADERBOARD-TRACE", "leaderboard trace is not complete")
    trace_digest = sha256_digest(submission.trace.read_bytes())
    embedded = {item.digest for item in descriptors if item.role == "trace"}
    if trace_digest not in embedded:
        raise FormatError(
            "SOVA-LEADERBOARD-ARTIFACT-TRACE",
            "the submitted trace is not embedded in the submitted capsule",
        )
    oracle_events = [item for item in trace_reader.events() if item.get("kind") == "oracle.result"]
    if len(oracle_events) != 1:
        raise FormatError(
            "SOVA-LEADERBOARD-SCORE-EVIDENCE",
            "leaderboard trace must contain exactly one scoring oracle result",
        )
    payload = oracle_events[0].get("payload")
    if (
        not isinstance(payload, dict)
        or payload.get("points") != submission.score
        or payload.get("possiblePoints") != submission.possible_score
    ):
        raise FormatError(
            "SOVA-LEADERBOARD-SCORE-EVIDENCE",
            "declared score does not match signed trace evidence",
        )
    return {
        "artifactDigest": sha256_digest(submission.artifact.read_bytes()),
        "traceDigest": trace_digest,
        "traceTrustPolicy": trace_report.trust_policy,
        "requiredKeyId": submission.required_key_id,
    }


def build_static_leaderboard(
    submissions: Sequence[LeaderboardSubmission],
    destination: Path,
    *,
    methodology_snapshot: str,
) -> dict[str, Any]:
    """Write a local JSON + HTML snapshot; this function performs no upload or telemetry."""
    if not submissions or not methodology_snapshot:
        raise FormatError("SOVA-LEADERBOARD-SUBMISSION", "submissions and methodology are required")
    seen_artifacts: set[str] = set()
    seen_traces: set[str] = set()
    rows: list[dict[str, Any]] = []
    expected_profile: tuple[str, str] | None = None
    for item in submissions:
        if (item.profile_id, item.profile_digest) != (
            STANDARD_ARENA_PROFILE.identifier,
            STANDARD_ARENA_PROFILE.digest,
        ):
            raise FormatError(
                "SOVA-LEADERBOARD-STANDARD-PROFILE",
                "leaderboard accepts only the pinned standard Arena profile",
            )
        current_profile = (item.profile_id, item.profile_digest)
        if expected_profile is None:
            expected_profile = current_profile
        elif current_profile != expected_profile:
            raise FormatError(
                "SOVA-LEADERBOARD-COMPARABILITY",
                "one snapshot cannot mix standard profile identities or digests",
            )
        evidence = _verify(item)
        if evidence["artifactDigest"] in seen_artifacts or evidence["traceDigest"] in seen_traces:
            raise FormatError("SOVA-LEADERBOARD-DUPLICATE", "duplicate evidence submission")
        seen_artifacts.add(evidence["artifactDigest"])
        seen_traces.add(evidence["traceDigest"])
        lower, upper = _interval(item.score, item.possible_score)
        rows.append(
            {
                "category": item.category,
                "component": item.component,
                "version": item.version,
                "score": item.score,
                "possibleScore": item.possible_score,
                "rate": f"{item.score}/{item.possible_score}",
                "uncertainty95": {"lower": lower, "upper": upper, "method": "wilson"},
                "evidence": evidence,
                "gamingChecks": {
                    "duplicateArtifact": False,
                    "duplicateTrace": False,
                    "minimumSampleWarning": item.possible_score < _MIN_RECOMMENDED_SAMPLE,
                },
            }
        )
    if expected_profile is None:
        raise FormatError("SOVA-LEADERBOARD-PROFILE", "standard profile is unavailable")
    profile_id, profile_digest = expected_profile
    rows.sort(
        key=lambda row: (
            -(Decimal(row["score"]) / Decimal(row["possibleScore"])),
            row["component"],
            row["version"],
        )
    )
    for rank, row in enumerate(rows, 1):
        row["rank"] = rank
    document = {
        "artifactType": "sova.leaderboard-snapshot",
        "schemaVersion": "0.1.0",
        "profile": {"id": profile_id, "digest": profile_digest},
        "methodology": {
            "snapshot": methodology_snapshot,
            "digest": sha256_digest(methodology_snapshot.encode()),
            "ranking": "observed-score-rate-descending-then-stable-identity",
            "uncertainty": "Wilson 95 percent interval",
        },
        "entries": rows,
        "publication": "local-static-output-not-uploaded",
        "telemetry": "none",
        "limitations": [
            "Ranks apply only to the exact standard profile and component versions shown.",
            "Included-key signatures provide integrity, not independent publisher identity.",
        ],
    }
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "leaderboard.json").write_bytes(canonical_json_bytes(document) + b"\n")
    table = "".join(
        "<tr>"
        f"<td>{row['rank']}</td><td>{html.escape(row['category'])}</td>"
        f"<td>{html.escape(row['component'])}</td><td>{html.escape(row['version'])}</td>"
        f"<td>{row['score']}/{row['possibleScore']}</td>"
        f"<td>{html.escape(row['uncertainty95']['lower'])}-"
        f"{html.escape(row['uncertainty95']['upper'])}</td></tr>"
        for row in rows
    )
    page = (
        "<!doctype html><meta charset=utf-8><title>SOVA local leaderboard</title>"
        "<h1>SOVA local reproducible leaderboard</h1>"
        f"<p>Profile: {html.escape(profile_id)} / "
        f"{html.escape(profile_digest)}</p>"
        "<table><thead><tr><th>Rank</th><th>Category</th><th>Component</th>"
        "<th>Version</th><th>Score</th><th>95% interval</th></tr></thead>"
        f"<tbody>{table}</tbody></table>"
        "<p>Local static output. Verify the linked artifacts before interpreting ranks.</p>"
    )
    (destination / "index.html").write_text(page, encoding="utf-8", newline="\n")
    return document
