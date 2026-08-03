# SPDX-License-Identifier: Apache-2.0
"""Seeded baselines, coverage guidance, evolutionary search, and minimization."""

from __future__ import annotations

import itertools
import time
from dataclasses import replace
from random import Random
from typing import TYPE_CHECKING, Protocol

from sova.formats.errors import FormatError
from sova.search.model import (
    SearchAttempt,
    SearchBudget,
    SearchObservation,
    SearchReport,
    SearchSpace,
    SearchStrategy,
    TriggerCandidate,
    TriggerFamilyMetric,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_CROSSOVER_PROBABILITY = 0.5
_MAX_MATERIALIZED_GRID = 100_000


class CandidateEvaluator(Protocol):
    def __call__(self, candidate: TriggerCandidate) -> SearchObservation: ...


def grid_candidates(space: SearchSpace) -> tuple[TriggerCandidate, ...]:
    """Enumerate the declared finite grid in stable key and value order."""
    if space.cardinality > _MAX_MATERIALIZED_GRID:
        raise FormatError(
            "SOVA-SEARCH-GRID-LIMIT",
            "declared grid is too large to materialize safely",
        )
    names = tuple(sorted(space.domains))
    return tuple(
        TriggerCandidate(dict(zip(names, values, strict=True)))
        for values in itertools.product(*(space.domains[name] for name in names))
    )


def random_candidates(
    space: SearchSpace,
    count: int,
    *,
    seed: int,
) -> tuple[TriggerCandidate, ...]:
    """Sample without replacement when the declared grid fits the budget."""
    if count <= 0:
        raise FormatError("SOVA-SEARCH-RANDOM", "random count must be positive")
    rng = Random(seed)  # noqa: S311 - seeded reproducible test strategy, not cryptography
    target = min(count, space.cardinality)
    if space.cardinality <= _MAX_MATERIALIZED_GRID and target * 2 >= space.cardinality:
        grid = list(grid_candidates(space))
        rng.shuffle(grid)
        return tuple(grid[:target])
    names = tuple(sorted(space.domains))
    selected: list[TriggerCandidate] = []
    seen: set[str] = set()
    while len(selected) < target:
        candidate = TriggerCandidate({name: rng.choice(space.domains[name]) for name in names})
        if candidate.digest not in seen:
            seen.add(candidate.digest)
            selected.append(candidate)
    return tuple(selected)


def _sequence_variants(candidate: TriggerCandidate) -> tuple[TriggerCandidate, ...]:
    variants: list[TriggerCandidate] = []
    for index in range(len(candidate.sequence)):
        sequence = (*candidate.sequence[:index], *candidate.sequence[index + 1 :])
        variants.append(
            TriggerCandidate(
                dict(candidate.values),
                sequence,
                (candidate.digest,),
                candidate.generation + 1,
                candidate.mutations + 1,
            )
        )
    return tuple(variants)


def minimize_candidate(
    candidate: TriggerCandidate,
    space: SearchSpace,
    evaluator: CandidateEvaluator,
    *,
    attempt_budget: int = 100,
) -> tuple[TriggerCandidate, int]:
    """Deterministically reduce sequence steps and reset dimensions while preserving effect."""
    if attempt_budget <= 0:
        raise FormatError("SOVA-SEARCH-MINIMIZE", "minimization budget must be positive")
    current = candidate
    attempts = 0
    changed = True
    while changed and attempts < attempt_budget:
        changed = False
        for variant in _sequence_variants(current):
            attempts += 1
            if evaluator(variant).triggered:
                current = variant
                changed = True
                break
            if attempts >= attempt_budget:
                break
        if changed:
            continue
        for name in sorted(space.domains):
            default = space.defaults.get(name, space.domains[name][0])
            if current.values.get(name) == default:
                continue
            values = dict(current.values)
            values[name] = default
            variant = TriggerCandidate(
                values,
                current.sequence,
                (current.digest,),
                current.generation + 1,
                current.mutations + 1,
            )
            attempts += 1
            if evaluator(variant).triggered:
                current = variant
                changed = True
                break
            if attempts >= attempt_budget:
                break
    return current, attempts


class TriggerSearchEngine:
    """Budgeted, seedable engine whose every baseline remains separately measurable."""

    def __init__(self, space: SearchSpace, budget: SearchBudget, *, seed: int = 0) -> None:
        self.space = space
        self.budget = budget
        self.seed = seed

    def _evaluate(
        self,
        candidates: Iterable[TriggerCandidate],
        evaluator: CandidateEvaluator,
        *,
        strategy: SearchStrategy,
        minimize: bool,
    ) -> SearchReport:
        started = time.monotonic()
        attempts: list[SearchAttempt] = []
        coverage: set[str] = set()
        success: TriggerCandidate | None = None
        stop_reason = "candidate-source-exhausted"
        for candidate in candidates:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            if len(attempts) >= self.budget.max_attempts:
                stop_reason = "attempt-budget"
                break
            if elapsed_ms >= self.budget.max_duration_ms:
                stop_reason = "duration-budget"
                break
            observation = evaluator(candidate)
            new_coverage = observation.coverage - coverage
            coverage.update(observation.coverage)
            attempts.append(SearchAttempt(len(attempts), candidate, observation, new_coverage))
            if observation.triggered:
                success = candidate
                stop_reason = "confirmed-trigger"
                break
        minimized = None
        if success is not None and minimize:
            remaining = max(1, self.budget.max_attempts - len(attempts))
            minimized, _used = minimize_candidate(
                success, self.space, evaluator, attempt_budget=remaining
            )
        return SearchReport(
            strategy,
            tuple(attempts),
            success,
            minimized,
            stop_reason,
            frozenset(coverage),
            int((time.monotonic() - started) * 1000),
            None,
            self._family_performance(attempts),
            (
                "Search success is limited to the declared target, oracle, and budget.",
                "A missed trigger is not evidence that no dormant behavior exists.",
            ),
            self.space.cardinality,
        )

    def _family_performance(
        self,
        attempts: Sequence[SearchAttempt],
    ) -> tuple[TriggerFamilyMetric, ...]:
        metrics: list[TriggerFamilyMetric] = []
        for dimension in sorted(set(self.space.dimensions.values()), key=lambda item: item.value):
            names = {
                name
                for name, candidate_dimension in self.space.dimensions.items()
                if candidate_dimension == dimension
            }
            changed = [
                attempt
                for attempt in attempts
                if any(
                    attempt.candidate.values.get(name)
                    != self.space.defaults.get(name, self.space.domains[name][0])
                    for name in names
                )
            ]
            metrics.append(
                TriggerFamilyMetric(
                    dimension,
                    len(changed),
                    sum(attempt.observation.triggered for attempt in changed),
                    max(
                        (attempt.observation.score for attempt in changed),
                        default=None,
                    ),
                )
            )
        return tuple(metrics)

    def signature(
        self,
        signatures: Sequence[TriggerCandidate],
        evaluator: CandidateEvaluator,
    ) -> SearchReport:
        return self._evaluate(
            signatures, evaluator, strategy=SearchStrategy.SIGNATURE, minimize=False
        )

    def human(
        self,
        heuristics: Sequence[TriggerCandidate],
        evaluator: CandidateEvaluator,
    ) -> SearchReport:
        return self._evaluate(heuristics, evaluator, strategy=SearchStrategy.HUMAN, minimize=False)

    def random(self, evaluator: CandidateEvaluator) -> SearchReport:
        return self._evaluate(
            random_candidates(self.space, self.budget.max_attempts, seed=self.seed),
            evaluator,
            strategy=SearchStrategy.RANDOM,
            minimize=False,
        )

    def grid(self, evaluator: CandidateEvaluator) -> SearchReport:
        return self._evaluate(
            grid_candidates(self.space),
            evaluator,
            strategy=SearchStrategy.GRID,
            minimize=False,
        )

    def coverage_guided(
        self,
        seeds: Sequence[TriggerCandidate],
        evaluator: CandidateEvaluator,
    ) -> SearchReport:
        """Prioritize candidates that add evaluator-declared coverage."""
        queue = list(seeds)
        seen = {candidate.digest for candidate in queue}

        def candidates() -> Iterable[TriggerCandidate]:
            index = 0
            while index < len(queue):
                candidate = queue[index]
                index += 1
                yield candidate
                rng = Random(  # noqa: S311 - deterministic coverage-search scheduling
                    self.seed + index
                )
                for variant in self._mutations(candidate, rng):
                    if variant.digest not in seen:
                        seen.add(variant.digest)
                        queue.append(variant)

        return self._evaluate(
            candidates(), evaluator, strategy=SearchStrategy.COVERAGE, minimize=True
        )

    def _mutations(
        self,
        candidate: TriggerCandidate,
        rng: Random,
    ) -> tuple[TriggerCandidate, ...]:
        variants: list[TriggerCandidate] = []
        for name in sorted(self.space.domains):
            current = candidate.values.get(name)
            choices = [value for value in self.space.domains[name] if value != current]
            rng.shuffle(choices)
            for value in choices[:3]:
                values = dict(candidate.values)
                values[name] = value
                variants.append(
                    TriggerCandidate(
                        values,
                        candidate.sequence,
                        (candidate.digest,),
                        candidate.generation + 1,
                        candidate.mutations + 1,
                    )
                )
            if isinstance(current, str) and current:
                typed = {current.casefold(), current.upper(), current.replace("-", " ")}
                for value in sorted(typed - {current}):
                    values = dict(candidate.values)
                    values[name] = value
                    variants.append(
                        TriggerCandidate(
                            values,
                            candidate.sequence,
                            (candidate.digest,),
                            candidate.generation + 1,
                            candidate.mutations + 1,
                        )
                    )
        return tuple(variants)

    @staticmethod
    def _crossover(
        left: TriggerCandidate,
        right: TriggerCandidate,
        rng: Random,
    ) -> TriggerCandidate:
        names = sorted(set(left.values) | set(right.values))
        values = {
            name: (left.values if rng.random() < _CROSSOVER_PROBABILITY else right.values).get(name)
            for name in names
        }
        split_left = rng.randrange(len(left.sequence) + 1)
        split_right = rng.randrange(len(right.sequence) + 1)
        sequence = (*left.sequence[:split_left], *right.sequence[split_right:])
        return TriggerCandidate(
            values,
            sequence,
            (left.digest, right.digest),
            max(left.generation, right.generation) + 1,
            max(left.mutations, right.mutations) + 1,
        )

    def adaptive(  # noqa: PLR0912, PLR0915 - explicit bounded search state machine
        self,
        seeds: Sequence[TriggerCandidate],
        evaluator: CandidateEvaluator,
    ) -> SearchReport:
        """Evolutionary exploration/exploitation with near-miss and coverage fitness."""
        if not seeds:
            raise FormatError("SOVA-SEARCH-SEEDS", "adaptive search requires at least one seed")
        started = time.monotonic()
        rng = Random(self.seed)  # noqa: S311 - deterministic experiment reproducibility
        population = list(seeds[: self.budget.population_size])
        attempts: list[SearchAttempt] = []
        coverage: set[str] = set()
        seen: set[str] = set()
        success: TriggerCandidate | None = None
        mutation_count = 0
        best_score = -1.0
        stagnant = 0
        stop_reason = "generation-budget"
        for _generation in range(self.budget.max_generations):
            scored: list[tuple[float, TriggerCandidate, SearchObservation]] = []
            for candidate in population:
                if candidate.digest in seen:
                    continue
                elapsed_ms = int((time.monotonic() - started) * 1000)
                if len(attempts) >= self.budget.max_attempts:
                    stop_reason = "attempt-budget"
                    break
                if elapsed_ms >= self.budget.max_duration_ms:
                    stop_reason = "duration-budget"
                    break
                seen.add(candidate.digest)
                observation = evaluator(candidate)
                new_coverage = observation.coverage - coverage
                coverage.update(observation.coverage)
                attempts.append(SearchAttempt(len(attempts), candidate, observation, new_coverage))
                fitness = observation.score + min(0.25, len(new_coverage) * 0.05)
                scored.append((fitness, candidate, observation))
                if observation.triggered:
                    success = candidate
                    stop_reason = "confirmed-trigger"
                    break
            if success is not None or stop_reason in {"attempt-budget", "duration-budget"}:
                break
            if not scored:
                stop_reason = "search-space-exhausted"
                break
            scored.sort(key=lambda item: (-item[0], item[1].digest))
            current_best = scored[0][0]
            if current_best <= best_score:
                stagnant += 1
            else:
                best_score = current_best
                stagnant = 0
            if stagnant >= self.budget.stagnation_generations:
                stop_reason = "diminishing-returns"
                break
            elite = [item[1] for item in scored[: max(1, len(scored) // 2)]]
            next_population: list[TriggerCandidate] = list(elite)
            while len(next_population) < self.budget.population_size:
                parent = rng.choice(elite)
                if rng.random() < self.budget.exploration_fraction:
                    child = TriggerCandidate(
                        {
                            name: rng.choice(self.space.domains[name])
                            for name in sorted(self.space.domains)
                        },
                        parent_digests=(parent.digest,),
                        generation=parent.generation + 1,
                        mutations=parent.mutations + 1,
                    )
                else:
                    variants = self._mutations(parent, rng)
                    if (
                        variants
                        and mutation_count < self.budget.max_mutations
                        and rng.random() >= _CROSSOVER_PROBABILITY
                    ):
                        child = rng.choice(variants)
                        mutation_count += 1
                    else:
                        other = rng.choice(elite)
                        child = self._crossover(parent, other, rng)
                next_population.append(child)
            population = next_population
        minimized = None
        if success is not None:
            minimized, _used = minimize_candidate(
                success,
                self.space,
                evaluator,
                attempt_budget=max(1, self.budget.max_attempts - len(attempts)),
            )
        return SearchReport(
            SearchStrategy.ADAPTIVE,
            tuple(attempts),
            success,
            minimized,
            stop_reason,
            frozenset(coverage),
            int((time.monotonic() - started) * 1000),
            None,
            self._family_performance(attempts),
            (
                "This is a generic established evolutionary baseline, not a novelty claim.",
                "Near-miss scores must come from declared observable instrumentation.",
                "Local experience does not synchronize to a private or hosted corpus.",
            ),
            self.space.cardinality,
        )


def with_sequence(
    candidate: TriggerCandidate,
    step: dict[str, object],
) -> TriggerCandidate:
    """Grow a multi-turn sequence without mutating the source candidate."""
    return replace(
        candidate,
        sequence=(*candidate.sequence, step),
        parent_digests=(candidate.digest,),
        generation=candidate.generation + 1,
        mutations=candidate.mutations + 1,
    )


__all__ = [
    "CandidateEvaluator",
    "TriggerSearchEngine",
    "grid_candidates",
    "minimize_candidate",
    "random_candidates",
    "with_sequence",
]
