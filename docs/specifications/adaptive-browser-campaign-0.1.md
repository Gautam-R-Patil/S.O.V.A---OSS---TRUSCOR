<!-- status: implemented -->

# Adaptive browser campaign 0.1

## Purpose

The adaptive browser campaign adds a bounded feedback loop to SOVA's
authorized trigger-hunting workflow. It does not give a model an unrestricted
browser. Instead, it repeats this sequence:

1. tool-isolated roles receive the declared target contract, campaign policy,
   and a sanitized summary of earlier rounds;
2. the roles propose one finite candidate batch as strict JSON;
3. SOVA validates the batch and shows its complete derived browser action set;
4. a human approves that exact batch;
5. SOVA executes it inside the admitted Playwright boundary;
6. deterministic sensors and the declared oracle score the attempt;
7. a fresh reproduction is required before confirmation; and
8. only candidate sequences, scores, and coverage labels flow to the next
   planning round.

Every round has a separate signed orchestration trace and browser traces. The
coordinator emits another signed trace that binds the target, base campaign,
policy, round report digests, stop reason, token accounting, candidate
accounting, and final status.

## Hard policy

The policy is a strict `sova.adaptive-browser-policy` document. Version 0.1
permits at most eight rounds, 64 generated candidates, and one hour. The
provider runtime must reserve five model turns per declared round: recon,
explorer, strategist, attacker, and evidence-bounded judge. A global token
budget is enforced when provider usage is available. Missing usage fails closed
when a token ceiling was requested.

Campaign candidates still pass the credential-shaped-data rejection used by
the finite browser campaign. URLs remain exact-origin bound by the separately
verified target-control proof. A model cannot expand origins, selectors,
effects, duration, candidate count, or authorization. CAPTCHA bypass, account
creation, and credential collection are not part of this workflow.

## Adaptation boundary

The next round sees its own previously proposed candidate sequences and only
deterministic outcome fields: trigger state, score, coverage labels, and stop
reason. It does not receive raw target responses, hidden model state, cookies,
credentials, screenshots, console text, or network bodies through the adaptive
prompt. Repeated executed candidate digests count as stagnation. Confirmation
still requires the deterministic oracle and a fresh controlled reproduction;
the model judge is advisory and cannot override either.

This is adaptive candidate-batch search, not a general web-navigation agent.
Each round currently uses an ephemeral browser context. Persistent authenticated
sessions and arbitrary action planning have separate acceptance gates.

## Interoperability and prior work

[WebArena](https://arxiv.org/abs/2307.13854) established realistic,
reproducible self-hosted web environments and execution-based task evaluation.
[BrowserGym](https://arxiv.org/abs/2412.05467) standardized observation and
action spaces across browser benchmarks. [OSWorld](https://arxiv.org/abs/2404.07972)
extended execution-based evaluation to real computer environments, while
[AgentDojo](https://papers.neurips.cc/paper_files/paper/2024/file/97091a5177d8dc64b1da8bf3e1f6fb54-Paper-Datasets_and_Benchmarks_Track.pdf)
made dynamic prompt-injection security evaluation reproducible.

SOVA 0.1 reuses none of those systems as an authority boundary. Its narrower
engineering contribution in this release is the explicit separation of
untrusted adaptive planning, exact round-level human authorization,
deterministic evidence, fresh reproduction, and portable signed artifacts. No
novelty or benchmark-superiority claim is made without comparative experiments.

## Verification

Mandatory tests use `ScriptedModel` and a protocol-compatible deterministic
browser. The two-round fixture proves that an inert first round can feed only
safe evidence into a second planner round, that every batch is approved, and
that the planted two-message behavior must reproduce before the adaptive run
passes. Parser tests reject unknown fields, booleans as integers, excessive
rounds, and inconsistent stagnation budgets.

The optional installed-Chrome two-round lane also passes on SOVA's self-owned
loopback fixture. A founder-selected external site is not claimed tested until
its control proof and exact campaign have been reviewed and executed.
