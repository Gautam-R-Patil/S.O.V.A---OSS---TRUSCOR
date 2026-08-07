<!-- status: implemented-experimental -->

# Provider-assisted browser campaign 0.1

## Purpose

`sova hunt agent-browser` lets independently configured model roles propose a
finite browser campaign for a system the operator controls. Models plan; they
never receive the browser, credentials, cookies, approval tokens, or other
target tools. SOVA validates the proposed campaign, displays every resulting
browser action to a human, and executes nothing until the exact closed batch is
approved.

This is a provider-assisted extension of the live browser campaign, not an
autonomous permission boundary and not evidence that model prose is correct.

## Roles and information flow

The runtime invokes five bounded roles in order:

1. recon describes declared observable target facts;
2. explorer proposes bounded behavior families;
3. strategist proposes candidate-design rules;
4. attacker returns exact finite message sequences; and
5. judge receives only a bounded deterministic evidence summary.

Every role must return one strict JSON object matching its role schema. Unknown
fields, wrapped Markdown, arrays at the root, tool calls, oversized output,
invalid token usage, exhausted budgets, and excess candidates fail closed.
Target and prior-role strings are explicitly untrusted data.

Only the target identifier, kind, version, declared capabilities, allowed
origins, browser profile, and a digest of the complete target configuration are
shown to planning roles. The planning trace and report retain provider/model
identity, prompt/response digests, byte and token accounting, and fallback
errors. They do not copy the provider's structured prose. The generated
candidate set is necessarily retained in the reviewed browser campaign.

## Authority boundary

Provider calls require the explicit `--allow-provider-calls` flag because they
may send declared metadata to a configured service and may incur cost. The
secret-free runtime document contains no credentials. SOVA resolves an
allowlisted provider credential immediately before an HTTPS request; the local
Ollama route uses loopback HTTP. Redirects and unpinned origins are refused.

Model planning itself has no target tools. After planning, the existing live
browser authority performs proof-of-control checks, exact batch review,
scope-bound one-use action authorization, effect budgeting, origin enforcement,
and a separately approved controlled reproduction. A provider cannot widen the
operator-declared attempt, action, duration, or origin ceilings.

## Evidence and verdict

The signed orchestration trace links by digest to the browser report, every
attempt trace, and the discovery capsule. Deterministic observable oracle
results control the final status. The model judge is advisory; disagreement is
recorded and cannot change that status.

The deterministic mandatory test lane uses `ScriptedModel` and a simulated MCP
transport with no network or credentials. The optional installed-browser lane
uses real Chrome and pinned Playwright MCP. A real provider run is intentionally
optional and must be operator-authorized; absence of a provider credential is
not a SOVA core failure.

## Limits

- Candidate quality depends on the configured model and prompt budget.
- Version 0.1 targets the declared single-input/single-submit browser contract.
- The planner does not obtain accounts, solve CAPTCHAs, or create sessions.
- Browser sensors record only data exposed by the executor.
- No component captures hidden chain-of-thought or private model thoughts.
- An ephemeral origin-restricted browser is not a VM security sandbox.
