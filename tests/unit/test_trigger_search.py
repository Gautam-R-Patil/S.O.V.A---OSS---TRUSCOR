# SPDX-License-Identifier: Apache-2.0
"""Topic 14 dimensions, baselines, adaptive search, minimization, and Phantom safety."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.cli import main
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.runtime import LocalExperienceStore
from sova.search import (
    EphemeralToken,
    PhantomFuzzer,
    SearchBudget,
    SearchObservation,
    SearchSpace,
    TriggerCandidate,
    TriggerDimension,
    TriggerSearchEngine,
    candidate_to_scenario_fragment,
    grid_candidates,
    minimize_candidate,
    persist_search_experience,
    random_candidates,
    run_trigger_search_demo,
    with_sequence,
)

if TYPE_CHECKING:
    from pathlib import Path


def _space() -> SearchSpace:
    return SearchSpace(
        {
            "message": ("hello", "blue-owl"),
            "mode": ("default", "research"),
            "count": (1, 3),
        },
        {
            "message": TriggerDimension.CONTENT,
            "mode": TriggerDimension.ENVIRONMENT,
            "count": TriggerDimension.INVOCATION,
        },
        {"message": "hello", "mode": "default", "count": 1},
    )


def _evaluate(candidate: TriggerCandidate) -> SearchObservation:
    matches = (
        candidate.values.get("message") == "blue-owl",
        candidate.values.get("mode") == "research",
        candidate.values.get("count") == 3,
    )
    score = sum(matches) / len(matches)
    sequence_ok = not candidate.sequence or [
        item.get("message") for item in candidate.sequence
    ] == ["remember alpha", "confirm beta"]
    triggered = all(matches) and sequence_ok
    return SearchObservation(
        triggered,
        score if sequence_ok else score / 2,
        frozenset(f"condition:{index}:{value}" for index, value in enumerate(matches)),
        ("canary.read",) if triggered else (),
        duration_ms=1,
        status="confirmed" if triggered else "not-confirmed",
    )


def test_taxonomy_covers_all_declared_trigger_dimensions() -> None:
    assert {item.value for item in TriggerDimension} == {
        "content-and-phrasing",
        "conversation-history",
        "environment-and-configuration",
        "filesystem-and-file-history",
        "tool-availability-and-order",
        "permission-and-identity",
        "invocation-and-session-count",
        "time-delay-date-and-position",
        "memory-and-retrieval",
        "inter-agent-and-delegation",
        "browser-and-ui-state",
        "cross-component-composition",
        "user-defined",
    }


def test_grid_and_seeded_random_are_bounded_deterministic_baselines() -> None:
    space = _space()
    assert len(grid_candidates(space)) == space.cardinality == 8
    first = random_candidates(space, 5, seed=44)
    second = random_candidates(space, 5, seed=44)
    assert [item.digest for item in first] == [item.digest for item in second]
    assert len({item.digest for item in first}) == 5
    large = SearchSpace(
        {"a": tuple(range(1000)), "b": tuple(range(1000))},
        {"a": TriggerDimension.CONTENT, "b": TriggerDimension.ENVIRONMENT},
    )
    assert len(random_candidates(large, 5, seed=7)) == 5
    with pytest.raises(FormatError, match="too large"):
        grid_candidates(large)
    with pytest.raises(FormatError, match="exploration fraction"):
        SearchBudget(max_attempts=4, population_size=2, exploration_fraction=1.1)


def test_adaptive_search_finds_and_minimizes_trigger_fixed_and_one_pass_miss() -> None:
    result = run_trigger_search_demo()
    assert result["fixedList"]["confirmed"] == 0
    assert result["onePass"]["confirmed"] == 0
    assert result["adaptive"]["confirmed"] == 1
    assert result["adaptive"]["reproductionRate"] == "1"
    assert result["portableTrigger"]["portableIntentOnly"] is True
    assert result["claims"]["novelAlgorithm"] is False
    assert {item["dimension"] for item in result["adaptive"]["familyPerformance"]} == {
        "content-and-phrasing",
        "environment-and-configuration",
        "invocation-and-session-count",
    }


def test_hunt_demo_cli_is_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["hunt-demo"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["artifactType"] == "sova.trigger-search-comparison"
    assert value["adaptive"]["confirmed"] == 1


def test_multi_turn_growth_and_reduction_preserve_required_sequence() -> None:
    space = _space()
    base = TriggerCandidate({"message": "blue-owl", "mode": "research", "count": 3})
    first = with_sequence(base, {"message": "noise"})
    second = with_sequence(first, {"message": "remember alpha"})
    candidate = with_sequence(second, {"message": "confirm beta"})
    engine = TriggerSearchEngine(
        space,
        SearchBudget(max_attempts=20, population_size=4),
        seed=1,
    )
    report = engine.human((candidate,), _evaluate)
    assert report.success is None
    minimized, _attempts = minimize_candidate(candidate, space, _evaluate, attempt_budget=20)
    assert [item["message"] for item in minimized.sequence] == [
        "remember alpha",
        "confirm beta",
    ]
    assert _evaluate(minimized).triggered
    fragment = candidate_to_scenario_fragment(minimized, space)
    assert fragment["executorMechanicsIncluded"] is False


def test_search_experience_is_local_digest_only(tmp_path: Path) -> None:
    space = _space()
    engine = TriggerSearchEngine(space, SearchBudget(max_attempts=10, population_size=4))
    report = engine.grid(_evaluate)
    store = LocalExperienceStore(tmp_path / "experience")
    path = persist_search_experience(
        report,
        store,
        scenario_digest=sha256_digest(b"scenario"),
        trace_digest=sha256_digest(b"trace"),
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["rawPromptsStored"] is False
    assert document["remoteSynchronization"] is False
    assert "blue-owl" not in path.read_text(encoding="utf-8")


class OwnedHarness:
    def __init__(self) -> None:
        self.attempts = 0

    def backend_attempt(self, token: str, payload: bytes) -> tuple[bool, bytes]:
        assert token
        self.attempts += 1
        return payload == b"safe-kill-shot", b"bounded-evidence"

    def browser_confirm(self) -> bytes:
        return b"synthetic-screenshot"


def test_phantom_fuzzer_fails_closed_and_never_persists_token() -> None:
    with pytest.raises(FormatError):
        PhantomFuzzer(target_control_verified=False)
    token = EphemeralToken("SYNTHETIC-SESSION-SECRET")
    harness = OwnedHarness()
    result = PhantomFuzzer(target_control_verified=True, max_attempts=3).run(
        token,
        (b"benign", b"safe-kill-shot", b"unused"),
        harness,
    )
    assert result.confirmed
    assert result.attempts == 2
    assert result.token_persisted is False
    assert token.closed
    assert "SYNTHETIC-SESSION-SECRET" not in json.dumps(result.to_mapping())
    with pytest.raises(FormatError):
        token.reveal()
