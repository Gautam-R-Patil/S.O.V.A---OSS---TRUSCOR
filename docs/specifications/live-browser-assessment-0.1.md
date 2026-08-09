<!-- status: implemented-experimental -->

# Authorization-gated live browser assessment 0.1

## Scope

This specification defines the first non-scripted SOVA website execution path.
It supports SOVA's self-owned loopback target and one exact operator-owned HTTPS
origin after short-lived well-known control verification. Account, privacy,
scenario, oracle, and stronger-isolation decisions remain explicit operator
gates.

The accepted flow is:

```text
owned loopback HTTP target
  -> exact target manifest and origin set
  -> fresh exact-batch human review + one-use token per action
  -> pinned Playwright MCP 0.0.78
  -> ephemeral headless Chrome context
  -> portable .sova procedure
  -> observable accessibility snapshot oracle
  -> signed .sova-trace
  -> fresh controlled reproduction
  -> declared-outcome comparison
  -> .sova evidence capsule
  -> offline verification and inert playback
```

## Portable intent and executor mechanics

The `.sova` scenario contains portable actions such as `browser.navigate`,
`browser.type`, `browser.click`, and `browser.snapshot`. CSS targets in the
built-in fixture are stable semantic mechanics for that fixture, not a promise
that all browser adapters accept the same selector language. `requires` binds
each step to an exact SOVA capability version. Playwright-specific tool names,
launch arguments, cache paths, and process transport remain in the adapter.

## Authorization and target control

- A URL or login is never authorization.
- Loopback fixtures use the built-in proof. External runs require exactly one
  bare HTTPS origin and an unexpired well-known proof.
- Loopback control proof, exact action/tool/domain scope, effect and duration
  budgets, and a fresh approval token are checked before every action.
- The CLI refuses non-interactive approval. One phrase authorizes only the
  complete displayed intent set; each intent receives a distinct, signed,
  one-use token and no new intent may be added after review.
- Any redirect or explicit navigation outside the admitted origin is a failed
  run. Playwright's own origin filter is an additional control, not the trust
  boundary.

The implemented external proof is one bounded HTTPS GET with ordinary
certificate validation, no redirects, a 16 KiB body limit, an exact final URL,
and an exact challenge token. DNS and signed-scope proof collectors are not yet
implemented. Target-specific data/account policy is never inferred from proof
of origin control.

## Capture and verification

Each run records authorization decisions, requested actions, normalized tool
outcomes, deterministic oracle results, lifecycle state, exact dependency and
target fingerprints, the executor capability digest, and an included-key
Ed25519 signature. The recorder captures only observable results. It never
claims access to hidden chain-of-thought.

The signature and event hash chain provide tamper evidence and included-key
provenance. They do not prove recorder honesty, legal identity, target safety,
or non-repudiation. Evidence capsules remain drafts until a human reviews them
for disclosure.

## Containment statement

The default browser uses an ephemeral profile, headless mode, a workspace-local
data directory, blocked service workers, and a declared request-origin filter.
An operator may instead supply an exclusively leased, exact-target-bound local
profile under the [persistent-session contract](./persistent-browser-sessions-0.1.md).
That profile is executor state, never capsule or trace content. Either mode is a
restricted browser session, not a VM or complete security sandbox. The built-in
target has no credentials, user data, external services, native code, or
destructive behavior.

## Acceptance

The deterministic mandatory lane substitutes only the MCP process while
exercising the real authorization, adapter, trace, signing, capsule,
reproduction, comparison, and verification code. The optional installed lane
uses the real pinned Playwright MCP and Chrome against the real loopback server.

On 2026-08-07 the installed lane completed two six-step runs, both observable
oracles passed, both trace signatures verified offline, declared outcomes were
equivalent, and the evidence capsule verified structurally. This is a narrow
engineering acceptance result, not a benchmark or field study.
