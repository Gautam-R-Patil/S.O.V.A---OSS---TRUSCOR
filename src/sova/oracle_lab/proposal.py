# SPDX-License-Identifier: Apache-2.0
"""Deterministic derivation of typed, non-authorizing oracle proposals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.oracle_lab.contracts import OracleProposal, OracleSource

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from sova.intake import TargetProfile


@dataclass(frozen=True, slots=True)
class ProposalSeed:
    """Reviewed derivation input; text is data and never becomes executable code."""

    identifier: str
    source: OracleSource
    statement: str
    positive_signal: str
    negative_signal: str
    ambiguous_state: str
    source_references: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    known_blind_spots: tuple[str, ...]
    evaluator_id: str = "sova.oracle.deterministic-observable"
    evaluator_version: str = "0.1.0"
    evaluator_config: Mapping[str, Any] | None = None


def derive_oracle_proposals(
    profile: TargetProfile,
    seeds: Sequence[ProposalSeed],
) -> tuple[OracleProposal, ...]:
    """Bind reviewed proposal seeds to one exact target profile generation.

    SOVA intentionally does not generate an oracle when the caller supplies no
    defensible seed. A model suggestion may be represented as a source reference,
    but it receives no special trust or authority.
    """
    if not seeds:
        return ()
    identifiers = [seed.identifier for seed in seeds]
    if len(identifiers) != len(set(identifiers)):
        raise FormatError("SOVA-ORACLE-LAB-SEED", "proposal seed IDs must be unique")
    proposals = []
    for seed in sorted(seeds, key=lambda item: item.identifier):
        config = dict(seed.evaluator_config or {})
        config_digest = sha256_digest(canonical_json_bytes(config))
        proposals.append(
            OracleProposal(
                identifier=seed.identifier,
                target_profile_digest=profile.digest,
                source=seed.source,
                statement=seed.statement,
                evaluator_id=seed.evaluator_id,
                evaluator_version=seed.evaluator_version,
                evaluator_config_digest=config_digest,
                positive_signal=seed.positive_signal,
                negative_signal=seed.negative_signal,
                ambiguous_state=seed.ambiguous_state,
                source_references=seed.source_references,
                evidence_requirements=seed.evidence_requirements,
                known_blind_spots=seed.known_blind_spots,
            )
        )
    return tuple(proposals)


__all__ = ["ProposalSeed", "derive_oracle_proposals"]
