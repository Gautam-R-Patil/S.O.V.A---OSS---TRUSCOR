# SPDX-License-Identifier: Apache-2.0
"""Privacy-minimized bridge from trigger search to the owner-local experience store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.runtime import ExperienceRecord, LocalExperienceStore

if TYPE_CHECKING:
    from pathlib import Path

    from sova.search.model import SearchReport


def persist_search_experience(
    report: SearchReport,
    store: LocalExperienceStore,
    *,
    scenario_digest: str,
    trace_digest: str,
) -> Path:
    """Persist only digests and effort metrics; raw candidates and outputs stay absent."""
    if report.success is None:
        candidate_digest = sha256_digest(b"sova:no-successful-candidate")
        outcome = "not-confirmed"
        near_miss = any(item.observation.score > 0 for item in report.attempts)
    else:
        candidate_digest = report.success.digest
        outcome = "confirmed"
        near_miss = False
    if not scenario_digest.startswith("sha256:") or not trace_digest.startswith("sha256:"):
        raise FormatError("SOVA-SEARCH-EXPERIENCE", "scenario and trace digests are required")
    return store.add(
        ExperienceRecord(
            scenario_digest,
            candidate_digest,
            outcome,
            len(report.attempts),
            sum(item.observation.turns for item in report.attempts),
            sum(item.candidate.mutations for item in report.attempts),
            report.duration_ms,
            trace_digest,
            near_miss,
        )
    )


__all__ = ["persist_search_experience"]
