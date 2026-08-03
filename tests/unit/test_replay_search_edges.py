# SPDX-License-Identifier: Apache-2.0
"""Uncertainty, budget, malformed-input, and cleanup edges for Topics 12 and 14."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.executors import ScriptedExecutor
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.replay import (
    ReproductionClass,
    VerificationState,
    calibrate_judge,
    controlled_reexecute,
    semantic_reproduction_study,
    verify_artifact,
)
from sova.runtime import LocalExperienceStore
from sova.search import (
    CandidateEvaluator,
    EphemeralToken,
    PhantomFuzzer,
    SearchAttempt,
    SearchBudget,
    SearchObservation,
    SearchReport,
    SearchSpace,
    SearchStrategy,
    TriggerCandidate,
    TriggerDimension,
    TriggerFamilyMetric,
    TriggerSearchEngine,
    grid_candidates,
    minimize_candidate,
    persist_search_experience,
    random_candidates,
)
from sova.trace import TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path


def _fingerprints(*, unknown: bool = False) -> dict[str, dict[str, str | None]]:
    return {
        name: {
            "value": None,
            "status": "unknown" if unknown and name == "model" else "not-applicable",
            "method": "fixture",
            "source": "fixture",
            "version": "0.1",
        }
        for name in ("environment", "target", "code", "dependencies", "registry", "model")
    }


def _trace(path: Path, status: str | None, *, signed: bool = True, unknown: bool = False) -> None:
    writer = TraceWriter(
        path,
        signing_key=generate_ed25519_keypair() if signed else None,
        fingerprints=_fingerprints(unknown=unknown),
    )
    if status is not None:
        writer.append("oracle.completed", {"status": status, "results": [{"status": status}]})
    writer.finalize()


def test_replay_verifier_signature_fingerprint_io_and_capsule_partial(tmp_path: Path) -> None:
    unsigned = tmp_path / "unsigned.sova-trace"
    _trace(unsigned, "pass", signed=False, unknown=True)
    result = verify_artifact(unsigned, require_signature=True)
    assert result.state == VerificationState.INVALID
    assert result.error_code is not None

    absent = verify_artifact(tmp_path / "absent.sova-trace")
    assert absent.state == VerificationState.INVALID
    assert absent.error_code is not None

    manifest = capsule_manifest_template(title="Partial", summary="Fixture", author="Tests")
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "partial.sova"
    build_capsule(capsule, manifest)
    capsule_result = verify_artifact(capsule)
    assert capsule_result.state == VerificationState.PARTIAL
    assert {check.name for check in capsule_result.checks} >= {"methodology", "taxonomy"}


def test_controlled_reexecution_refuses_invalid_source_and_capsule(tmp_path: Path) -> None:
    invalid_source = tmp_path / "bad.sova-trace"
    invalid_source.write_bytes(b"bad")
    with pytest.raises(FormatError, match="source trace"):
        controlled_reexecute(
            tmp_path / "bad.sova",
            invalid_source,
            tmp_path / "new.sova-trace",
            executor=ScriptedExecutor([]),
            workspace=tmp_path,
        )

    valid_source = tmp_path / "valid.sova-trace"
    _trace(valid_source, "pass")
    invalid_capsule = tmp_path / "bad.sova"
    invalid_capsule.write_bytes(b"bad")
    with pytest.raises(FormatError, match="capsule"):
        controlled_reexecute(
            invalid_capsule,
            valid_source,
            tmp_path / "new.sova-trace",
            executor=ScriptedExecutor([]),
            workspace=tmp_path,
        )


def test_semantic_not_reproduced_inconclusive_and_optional_judge(tmp_path: Path) -> None:
    reference = tmp_path / "reference.sova-trace"
    divergent = tmp_path / "divergent.sova-trace"
    empty = tmp_path / "empty.sova-trace"
    _trace(reference, "pass")
    _trace(divergent, "fail")
    _trace(empty, None)

    not_reproduced = semantic_reproduction_study(reference, (divergent, divergent))
    assert not_reproduced.classification == ReproductionClass.NOT_REPRODUCED
    assert not_reproduced.to_mapping()["rate"] == "0"

    inconclusive = semantic_reproduction_study(reference, (empty,))
    assert inconclusive.classification == ReproductionClass.INCONCLUSIVE
    assert inconclusive.to_mapping()["rate"] is None

    abstained = semantic_reproduction_study(reference, (empty,), judge=lambda _a, _b: None)
    assert abstained.trials[0].method == "isolated-model-judge"
    accepted = semantic_reproduction_study(reference, (empty,), judge=lambda _a, _b: True)
    assert accepted.classification == ReproductionClass.FLAKY
    rejected = semantic_reproduction_study(reference, (empty,), judge=lambda _a, _b: False)
    assert rejected.classification == ReproductionClass.NOT_REPRODUCED

    for candidates, conditions in (((), None), ((empty,), ("",))):
        with pytest.raises(FormatError):
            semantic_reproduction_study(reference, candidates, conditions=conditions)
    defaulted = semantic_reproduction_study(reference, (empty,), conditions=())
    assert defaulted.sensitivity[0].condition == "declared-baseline"

    calibration = calibrate_judge((True, False), (False, True))
    assert calibration.false_negative == 1 and calibration.false_positive == 1
    assert calibration.to_mapping()["agreement"] == "0"


def _space() -> SearchSpace:
    return SearchSpace(
        {"message": ("plain", "OWL"), "mode": ("safe", "research")},
        {"message": TriggerDimension.CONTENT, "mode": TriggerDimension.ENVIRONMENT},
        {"message": "plain", "mode": "safe"},
    )


def _observation(candidate: TriggerCandidate) -> SearchObservation:
    triggered = candidate.values == {"message": "OWL", "mode": "research"}
    score = (
        sum(
            (
                candidate.values.get("message") == "OWL",
                candidate.values.get("mode") == "research",
            )
        )
        / 2
    )
    return SearchObservation(
        triggered,
        score,
        frozenset({f"score:{score}"}),
        ("oracle",) if triggered else (),
        status="confirmed" if triggered else "not-confirmed",
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: TriggerCandidate({}, generation=-1),
        lambda: TriggerCandidate({"value": "x" * (1024 * 1024)}),
        lambda: SearchSpace({}, {}),
        lambda: SearchSpace({"a": ()}, {"a": TriggerDimension.CUSTOM}),
        lambda: SearchSpace({"a": (1,)}, {"a": TriggerDimension.CUSTOM}, {"unknown": 1}),
        lambda: SearchBudget(max_attempts=0),
        lambda: SearchBudget(max_attempts=2, population_size=3),
        lambda: SearchObservation(triggered=False, score=1.1, coverage=frozenset(), effects=()),
        lambda: SearchObservation(
            triggered=False, score=0.1, coverage=frozenset(), effects=(), turns=-1
        ),
        lambda: SearchObservation(
            triggered=False,
            score=0.1,
            coverage=frozenset(),
            effects=(),
            status="unknown",
        ),
    ],
)
def test_search_typed_contracts_fail_closed(factory: Any) -> None:
    with pytest.raises(FormatError):
        factory()


def test_search_budget_and_minimization_edges() -> None:
    space = _space()
    with pytest.raises(FormatError):
        random_candidates(space, 0, seed=1)
    with pytest.raises(FormatError):
        minimize_candidate(TriggerCandidate({}), space, _observation, attempt_budget=0)

    candidate = TriggerCandidate(
        {"message": "OWL", "mode": "research"},
        ({"message": "noise"}, {"message": "required"}),
    )

    def sequence_sensitive(value: TriggerCandidate) -> SearchObservation:
        triggered = bool(value.sequence) and value.sequence[-1].get("message") == "required"
        return SearchObservation(
            triggered,
            1.0 if triggered else 0.0,
            frozenset(),
            (),
            status="confirmed" if triggered else "not-confirmed",
        )

    minimized, attempts = minimize_candidate(
        candidate,
        space,
        cast("CandidateEvaluator", sequence_sensitive),
        attempt_budget=1,
    )
    assert attempts == 1 and len(minimized.sequence) == 1


def test_search_stop_reasons_coverage_mutations_and_adaptive_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    space = _space()
    attempt_limited = TriggerSearchEngine(
        space, SearchBudget(max_attempts=1, population_size=1)
    ).signature(grid_candidates(space), _observation)
    assert attempt_limited.stop_reason == "attempt-budget"

    clock = iter((0.0, 2.0, 2.0))
    monkeypatch.setattr("sova.search.engine.time.monotonic", lambda: next(clock))
    duration_limited = TriggerSearchEngine(
        space,
        SearchBudget(max_attempts=2, population_size=1, max_duration_ms=1),
    ).human((TriggerCandidate(space.defaults),), _observation)
    assert duration_limited.stop_reason == "duration-budget"

    monkeypatch.undo()
    coverage = TriggerSearchEngine(
        space, SearchBudget(max_attempts=10, population_size=2), seed=4
    ).coverage_guided((TriggerCandidate(space.defaults),), _observation)
    assert coverage.success is not None
    assert coverage.minimized is not None

    with pytest.raises(FormatError, match="at least one seed"):
        TriggerSearchEngine(space, SearchBudget(max_attempts=4, population_size=2)).adaptive(
            (), _observation
        )

    stagnant = TriggerSearchEngine(
        space,
        SearchBudget(
            max_attempts=8,
            population_size=2,
            max_generations=5,
            stagnation_generations=1,
            exploration_fraction=1,
        ),
        seed=2,
    ).adaptive(
        (TriggerCandidate(space.defaults),),
        lambda _item: SearchObservation(
            triggered=False,
            score=0,
            coverage=frozenset(),
            effects=(),
            status="not-confirmed",
        ),
    )
    assert stagnant.stop_reason in {"diminishing-returns", "search-space-exhausted"}


def test_search_report_metrics_and_no_success_experience(tmp_path: Path) -> None:
    candidate = TriggerCandidate({"message": "plain", "mode": "safe"})
    observation = SearchObservation(
        triggered=False,
        score=0.5,
        coverage=frozenset(),
        effects=(),
        turns=2,
        tokens=3,
        status="inconclusive",
        false_positive=True,
    )
    report = SearchReport(
        SearchStrategy.HUMAN,
        (SearchAttempt(0, candidate, observation, frozenset()),),
        None,
        None,
        "candidate-source-exhausted",
        frozenset(),
        1,
        None,
        (TriggerFamilyMetric(TriggerDimension.CONTENT, 0, 0, None),),
        (),
        0,
    )
    mapping = report.to_mapping()
    assert mapping["falsePositiveRate"] is None
    assert mapping["attemptCoverageFraction"] is None
    assert mapping["familyPerformance"][0]["bestScore"] is None
    store = LocalExperienceStore(tmp_path / "experience")
    path = persist_search_experience(
        report,
        store,
        scenario_digest=sha256_digest(b"scenario"),
        trace_digest=sha256_digest(b"trace"),
    )
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["outcome"] == "not-confirmed" and saved["nearMiss"] is True
    with pytest.raises(FormatError):
        persist_search_experience(report, store, scenario_digest="bad", trace_digest="bad")


class NeverTriggerHarness:
    def backend_attempt(self, token: str, payload: bytes) -> tuple[bool, bytes]:
        assert token and payload
        return False, b"none"

    def browser_confirm(self) -> bytes:
        return b"screen"


class FixtureError(RuntimeError):
    """Synthetic harness failure."""


class RaisingHarness(NeverTriggerHarness):
    def backend_attempt(self, token: str, payload: bytes) -> tuple[bool, bytes]:
        del token, payload
        raise FixtureError


class OversizedEvidenceHarness(NeverTriggerHarness):
    def backend_attempt(self, token: str, payload: bytes) -> tuple[bool, bytes]:
        del token, payload
        return False, b"x" * (16 * 1024 * 1024 + 1)


def test_phantom_no_trigger_budgets_empty_inputs_and_exception_cleanup() -> None:
    for budget in (0, 1001):
        with pytest.raises(FormatError):
            PhantomFuzzer(target_control_verified=True, max_attempts=budget)
    with pytest.raises(FormatError):
        EphemeralToken("")

    empty_token = EphemeralToken("secret")
    with pytest.raises(FormatError):
        PhantomFuzzer(target_control_verified=True).run(empty_token, (), NeverTriggerHarness())
    assert empty_token.closed

    oversized_payload_token = EphemeralToken("secret")
    with pytest.raises(FormatError, match="at most 1 MiB"):
        PhantomFuzzer(target_control_verified=True).run(
            oversized_payload_token,
            (b"x" * (1024 * 1024 + 1),),
            NeverTriggerHarness(),
        )
    assert oversized_payload_token.closed

    oversized_evidence_token = EphemeralToken("secret")
    with pytest.raises(FormatError, match="evidence"):
        PhantomFuzzer(target_control_verified=True).run(
            oversized_evidence_token,
            (b"one",),
            OversizedEvidenceHarness(),
        )
    assert oversized_evidence_token.closed

    token = EphemeralToken("secret")
    result = PhantomFuzzer(target_control_verified=True, max_attempts=1).run(
        token, (b"one", b"two"), NeverTriggerHarness()
    )
    assert not result.confirmed and result.attempts == 1 and result.payload_digest is None

    failing = EphemeralToken("secret")
    with pytest.raises(FixtureError):
        PhantomFuzzer(target_control_verified=True).run(failing, (b"one",), RaisingHarness())
    assert failing.closed


def test_phantom_records_digest_only_trace_events(tmp_path: Path) -> None:
    trace = tmp_path / "phantom.sova-trace"
    writer = TraceWriter(trace)
    token = EphemeralToken("TRACE-MUST-NOT-CONTAIN-THIS-SESSION-SECRET")
    result = PhantomFuzzer(target_control_verified=True, max_attempts=1).run(
        token,
        (b"payload-must-not-appear",),
        NeverTriggerHarness(),
        trace_writer=writer,
    )
    writer.finalize()
    events = TraceReader(trace).events()
    assert [event["kind"] for event in events] == [
        "attempt.completed",
        "oracle.completed",
    ]
    serialized = trace.read_bytes()
    assert b"TRACE-MUST-NOT-CONTAIN-THIS-SESSION-SECRET" not in serialized
    assert b"payload-must-not-appear" not in serialized
    assert result.browser_confirmation_digest.startswith("sha256:")
