<!-- status: implemented -->

# Cross-provider and cross-model experiment matrix 0.1

The matrix runner accepts a preregistered plan containing case identifiers,
prompt digests, exact observable text predicates, model identities,
repetitions, a seeded randomized schedule, and a bounded total run count. The
runtime model set must exactly match preregistration.

Observations retain schedule position, model, case, repetition, completion,
oracle outcome, response digest/size, token count when supplied, and a bounded
failure class. Raw prompts, raw responses, credentials, provider error text,
and hidden chain-of-thought are absent. Aggregates report completion and oracle
rates; paired comparisons report both-pass, left-only, right-only and both-fail
counts without inventing statistical significance.

`ScriptedModel` is the mandatory offline lane. Credential-late provider models
can implement the same protocol, but provider calls require explicit operator
authorization and budgets. Provider labels remain declarations until bound to
provider receipts. A matrix does not by itself establish oracle validity,
independence, representativeness, causal explanation, or benchmark advantage.
