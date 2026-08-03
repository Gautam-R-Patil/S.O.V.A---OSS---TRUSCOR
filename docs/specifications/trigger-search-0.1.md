<!-- status: implemented -->

# Trigger search 0.1

## Search-space contract

A `SearchSpace` declares finite named domains, one typed trigger dimension per
domain, and optional defaults. The registry covers content, conversation
history, environment, filesystem history, tool order, permission/identity,
invocation count, time/position, memory/retrieval, inter-agent delegation,
browser/UI state, cross-component composition, and user-defined dimensions.

A `TriggerCandidate` contains portable values and an ordered interaction
sequence. Parent digests, generation, and mutation counts provide search
lineage but do not alter its content identity.

## Strategies

Each strategy emits an independent `SearchReport`:

- known-signature;
- seeded random without replacement where the finite grid fits;
- stable grid enumeration;
- evaluator-declared coverage guidance;
- human-authored heuristic candidates; and
- adaptive evolutionary search.

Adaptive fitness combines a bounded observable near-miss score with new
coverage. Typed value mutation, sequence growth/shrinkage, crossover, elite
selection, deterministic seeds, stagnation detection, and candidate
deduplication are explicit. The public implementation is a generic baseline,
not a novelty claim.

## Budgets and metrics

Hard ceilings cover attempts, mutations, generations, population, duration,
and stagnant generations. Reports include attempts, confirmed/inconclusive
counts, false-positive rate, turns, tokens, duration, mutations, declared space
cardinality, attempt coverage fraction, minimized trigger, and repeated
reproduction rate. Results are scoped to the declared target, instrumentation,
oracle, search space, seed, and budget.

## Multi-turn and minimization

Sequences may represent persistent conversation, cross-session state, delayed
activation, benign setup, hostile condition, or tool-mediated state. Search may
grow sequences; deterministic reduction removes steps and restores default
dimensions one at a time while rechecking the effect. The final portable
fragment contains intent, dimension labels, ancestry, and no executor-specific
mechanics.

## Phantom Fuzzer boundary

`PhantomFuzzer` requires a prior owned-target control decision. It accepts an
ephemeral in-memory token, executes only a bounded payload sequence, records a
digest of non-destructive evidence, returns to a browser confirmer, and
zeroizes the token buffer. It records no token value and rejects third-party
targets. When supplied a trace writer, every backend attempt emits only the
attempt number, outcome, payload digest, and evidence digest; browser
confirmation emits an oracle event containing only a screenshot digest. Raw
payloads, screenshots, and session material are explicitly marked absent.
Payloads are limited to 1 MiB each; backend evidence and browser confirmation
are limited to 16 MiB each. The token is zeroized on success, validation
failure, or harness failure.

Known unresolved barriers include HttpOnly or proof-of-possession credentials,
CSRF, WebSockets, bot defenses, third-party components, and irreversible
transactions. No bypass is implied.

## Acceptance fixture

`sova hunt-demo` uses an owned inert three-dimension target. Its fixed list and
one-pass baseline miss; the seeded adaptive baseline finds the planted
condition, reproduces it five times, and emits a portable minimized fragment.
This is a deterministic engineering acceptance fixture, not evidence of
real-system superiority.

## Gates

Patent Gate 14-A is **HOLD** for any future genuinely novel adaptive method; the
public generic baseline required no novelty disclosure. Paper Gate 14-B is
**HOLD** until a predeclared dataset, ethics protocol, repeated real-system
results, baselines, and false-positive analysis exist. Research Gate 14-C is
enforced by separating taxonomy, public generic search, and any later private
tuning. Claim Gate 14-D allows only fixture-scoped wording today.
