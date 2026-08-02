<!-- status: experimental-implemented -->

# Authorization and safety contract 0.1

This specification is normative for the reference Topic 07 implementation.
It is a technical safety boundary, not legal authorization advice.

## Principals and ownership

Principals are `human`, `service`, or `agent`. An agent cannot issue authority
or approve an action. Ownership is one of `self`, `explicit`, or
`legal-offline`. Self-owned synthetic targets are the default. Legal acquisition
permits offline analysis only and never authorizes external effects.

## Exact scope

An authority envelope contains exact target and action sets plus optional path,
tool, identity, and domain sets. Paths are normalized, parent traversal and NUL
bytes are refused, and `/work` does not authorize `/work-evil`. Domains are
exact unless an explicit child-only wildcard is declared. Wildcards never match
the apex.

The authority also binds:

- a validity window and single-use policy;
- maximum consequence (`observe`, `read`, `mutate`, `external`, `destructive`);
- the digest of the admitted containment backend; and
- independent ceilings for steps, duration, tokens, mutations, processes,
  files, network requests, and transaction value.

Budget consumption is monotone and atomic. A rejected action consumes nothing.

## Proof of control

Collectors may supply the following typed proof results. The authorization
kernel validates their captured semantics without making a hidden network
request:

| Method | Minimum evidence |
|---|---|
| loopback | exact loopback identity |
| sandbox | `sova:sandbox:` identity plus bound challenge |
| signed manifest | trusted key id, verified signature result, bound challenge |
| `.well-known` | HTTPS, status 200, unchanged final host, no redirect, exact body |
| DNS | challenge in the captured TXT set |
| scoped document | trusted key id, verified signature result, bound challenge |
| legal acquisition | named source, licence/authority, offline-only flag |

A URL alone is never proof. Expired, mismatched, ambiguous, or untrusted proof
fails closed. The current `signatureValid` field is the output of a trusted
proof collector; this module does not itself fetch or validate deployment
signatures.

## Human approval

Mutation, external, destructive, and offensive operations require increasingly
strong approval. A challenge binds authority id, exact intent digest, level,
nonce, expiration, and an exact phrase. A token binds a human approver and is
single use. Destructive approval requires a separately asserted effect review.

The reference local HMAC channel is suitable for tests and local composition.
It proves possession of the channel key, not human comprehension or external
identity. It must not be called non-repudiation.

## Safe execution rule

Before an effectful executor receives a request, SOVA creates an `ActionIntent`
from portable action semantics and the executor capability's declared side
effect. Browser, computer, network, and MCP actions are at least `external`.
Every intent declares required post-action evidence. A denial emits
`authorization.decision` and `blocked.authorization`; the adapter is not called.

Only the inert `ScriptedExecutor` and genuine read-only executor paths accept a
compact precomputed authorization assertion. This compatibility path cannot
perform a real mutation.

## Emergency stop and cleanup

Cancellation is shared with the executor contract. Executors must bound time,
output, and retries, terminate owned child processes, report cancellation and
timeout, and expose cleanup limitations. Ordinary host-process supervision is
not a security sandbox. A hardened detonation backend must satisfy the separate
containment admission contract.

## Privacy and misuse defaults

- No telemetry or account is required.
- Raw environment capture and contribution are off.
- Provider secrets use opaque references and ephemeral in-memory resolution.
- Export is local and each contribution item needs explicit consent.
- Retention deletion operates only on individual ordinary files inside one
  explicit root.
- Public release refuses organization/victim ranking, working unpatched
  payloads, missing disclosure references, secrets, unreviewed authorization
  material, missing human review, and missing limitations.

## Trace obligations

Allow and deny events record authority id and digest, issuer id/kind, subject
id/kind, ownership basis, independent scope/intent/proof and containment
digests, required evidence, budget before/after, approval-token digest where
present, reasons, decision time, and kernel version. These identifiers are
audit references, not proof of a person's real-world identity. Raw approval
keys, phrases, secrets, private identity attributes, and control documents are
never placed in the trace.
