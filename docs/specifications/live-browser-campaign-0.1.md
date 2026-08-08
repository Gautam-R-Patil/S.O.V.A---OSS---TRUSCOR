<!-- status: implemented-experimental -->

# Live browser campaign 0.1

## Purpose

The live browser campaign is SOVA's first real-target behavior-search path. It
is distinct from `detonate browser`: detonation executes a known portable
recipe, while `hunt browser` evaluates a closed candidate set and returns the
first behavior that satisfies an observable oracle.

It currently targets a declared single-input/single-submit conversational UI.
This is a real, useful integration slice, not a claim that every website layout
or every jailbreak family is already supported.

## Contract

A campaign declares:

- one exact entry URL inside the target manifest's admitted origin;
- input and submit targets;
- one to 32 unique ordered message sequences, with at most six messages each;
- one deterministic observable text-containment oracle;
- exact attempt, duration, and derived action ceilings; and
- whether the interactions are offensive, which raises the approval level.

Unknown fields, credentials in URLs, duplicate candidates, booleans disguised
as integer budgets, inconsistent action counts, and out-of-origin entry URLs
fail closed.

## Execution and authorization

Before any browser action, SOVA:

1. validates the target manifest and current loopback or HTTPS well-known
   control proof;
2. expands every selected candidate into its exact browser actions;
3. displays the entire closed action batch to the human operator;
4. binds one exact phrase to that batch;
5. creates a distinct signed, scope-bound, one-use token for every effectful
   action; and
6. applies one monotone budget across all attempts.

The campaign authority may span multiple candidate runs, but it cannot add or
substitute an action after approval. A winning candidate receives a separate
fresh approval before controlled reproduction.

## Observations and output

Each attempt reloads the entry URL, performs its ordered messages, and records:

- accessibility snapshots and post-action observations;
- screenshot digest, media type, and byte-size evidence without durable raw pixels;
- browser console messages exposed by Playwright MCP;
- browser network requests exposed by Playwright MCP;
- authorization decisions and normalized tool outcomes;
- deterministic oracle status and observed near-miss state; and
- a signed `.sova-trace` with environment, target, code, and dependency
  fingerprints.

On success, SOVA reruns the winning recipe, compares the two observable oracle
events, and creates `discovery.sova` containing the winning scenario, the
signed discovery and reproduction traces, target/campaign material, and the
search report. Methodology and campaign-taxonomy snapshots are digest pinned,
so the capsule passes offline structural verification.

## Honest limits

- Candidates are operator-authored in 0.1; model-assisted generation is a
  separate provider layer and never bypasses human review.
- The first success is locally minimal only in the declared candidate order.
- A miss means only that the bounded candidate set did not satisfy the oracle.
- Console and network capture is limited to observable data returned by the
  executor.
- Screenshot hashing minimizes durable disclosure but is not pixel redaction;
  SOVA cannot prove that an external executor retained no copy.
- An ephemeral origin-restricted browser is not a VM security sandbox.
- SOVA does not capture private model thoughts or hidden chain-of-thought.
