# SPDX-License-Identifier: Apache-2.0
"""Curated adversarial browser red-team mission library."""

from __future__ import annotations

import pytest

from sova.contracts.taxonomy import load_attack_taxonomy
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.live.adversarial_missions import (
    _TACTICS,
    adversarial_tactic,
    adversarial_tactic_ids,
    build_adversarial_mission,
)
from sova.live.semantic_workflow import (
    SemanticBrowserMission,
    semantic_browser_mission_from_mapping,
)
from sova.trace import Redactor

_ENTRY = "http://127.0.0.1:8080/chat"


def test_every_tactic_maps_to_a_real_taxon() -> None:
    known = set(load_attack_taxonomy().by_id())
    for tactic in _TACTICS:
        assert tactic.taxon_id in known


def test_tactic_ids_are_stable_and_unique() -> None:
    ids = adversarial_tactic_ids()
    assert len(ids) == len(set(ids))
    assert "direct-instruction-override" in ids
    assert "induced-hallucination" in ids


def test_unknown_tactic_id_raises() -> None:
    with pytest.raises(FormatError, match="unknown adversarial tactic"):
        adversarial_tactic("no-such-tactic")


def test_every_mission_is_offensive_and_round_trips_through_the_real_parser() -> None:
    for tactic_id in adversarial_tactic_ids():
        mission = build_adversarial_mission(tactic_id, entry_url=_ENTRY)
        assert isinstance(mission, SemanticBrowserMission)
        assert mission.offensive is True  # forces DESTRUCTIVE approval at the engine
        # The mission must survive the exact strict parser the engine uses.
        reparsed = semantic_browser_mission_from_mapping(mission.to_mapping())
        assert reparsed.digest == mission.digest
        assert reparsed.oracle_contains == mission.oracle_contains


def test_success_signal_becomes_the_oracle() -> None:
    mission = build_adversarial_mission(
        "direct-instruction-override",
        entry_url=_ENTRY,
        success_signal="TARGET-SPECIFIC-LEAK-42",
    )
    assert mission.oracle_contains == "TARGET-SPECIFIC-LEAK-42"
    assert "TARGET-SPECIFIC-LEAK-42" not in mission.objective
    assert sha256_digest(b"TARGET-SPECIFIC-LEAK-42") in mission.objective
    assert all("TARGET-SPECIFIC-LEAK-42" not in item for item in mission.seed_inputs)


def test_extra_payloads_are_appended_and_must_stay_unique() -> None:
    mission = build_adversarial_mission(
        "direct-instruction-override",
        entry_url=_ENTRY,
        extra_payloads=("A custom bounded jailbreak attempt.",),
    )
    assert "A custom bounded jailbreak attempt." in mission.seed_inputs
    with pytest.raises(FormatError, match="unique"):
        build_adversarial_mission(
            "direct-instruction-override",
            entry_url=_ENTRY,
            extra_payloads=(mission.seed_inputs[0],),  # duplicate of a built-in payload
        )


def test_payloads_are_not_credential_shaped() -> None:
    """The injection payloads attack instruction-following, not auth; they must
    not themselves look like secrets, or the mission builder's own secret screen
    would reject them (and they would be misclassified as credential leaks)."""
    redactor = Redactor(context_id="test-adversarial-payload-scan")
    for tactic in _TACTICS:
        for payload in tactic.payloads:
            _redacted, disclosures = redactor.redact(payload)
            assert not disclosures, f"payload looked credential-shaped: {payload!r}"


def test_a_nonoffensive_target_url_still_requires_control_proof_conceptually() -> None:
    # Building the mission never contacts the network or asserts ownership; the
    # engine does that. This guards that the builder does not silently relax the
    # offensive flag for any tactic.
    for tactic_id in adversarial_tactic_ids():
        assert build_adversarial_mission(tactic_id, entry_url=_ENTRY).offensive is True


def test_entry_url_must_be_a_valid_http_origin() -> None:
    with pytest.raises(FormatError):
        build_adversarial_mission("direct-instruction-override", entry_url="not-a-url")
