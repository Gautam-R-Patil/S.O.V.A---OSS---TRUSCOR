<!-- status: implemented -->

# Experimental executor capability contract 0.1

Status: experimental

Contract version: `0.1`

Reference implementation: `sova.executors`

## Scope

The executor contract is the narrow boundary between a portable SOVA scenario
and a provider that can perform an action. It carries abstract actions into a
backend and normalizes observable outcomes back into SOVA. Authorization,
containment policy, judging, oracles, redaction, signing, and threat-model
claims remain in SOVA orchestration and evidence layers.

An executor is not trusted merely because it implements this interface. Its
capability report is an input to negotiation, not an attestation.

## Exact capability identifiers

A capability identifier is:

```text
<reverse-domain-or-sova-name>/<major.minor>
```

Examples include:

- `artifact.read/0.1`
- `process.exec/0.1`
- `browser.navigate/0.1`
- `browser.inspect/0.1`
- `browser.act/0.1`
- `browser.screenshot/0.1`
- `browser.upload/0.1`
- `browser.download/0.1`
- `browser.tab/0.1`
- `computer.screenshot/0.1`
- `computer.input/0.1`

Negotiation is exact. A backend advertising `artifact.read/0.1` does not
silently satisfy `artifact.read/0.2`, and an unversioned capability is not
portable. A scenario must fail visibly before execution when a required
capability is missing.

Each advertised capability declares:

- a name and version;
- its maximum side-effect class: `read`, `mutate`, or `destructive`;
- whether exact retry is intended to be idempotent;
- the evidence kinds the backend can return.

## Requests, context, cancellation, and budgets

An `ActionRequest` contains a stable request ID, abstract action name, typed
inputs, a positive timeout of at most one hour, and a retry-attempt counter.
Provider-specific mechanics belong in explicitly namespaced optional data; they
must not replace the portable action.

An `ExecutionContext` contains:

- an already-created workspace directory;
- the current explicit authorization decision;
- content-addressed capsule artifacts;
- a secret-free allowlisted environment map;
- an optional secret provider that resolves opaque references only for one
  action.

Capsules and traces may contain only references matching
`sova-secret:<opaque-reference>`, never resolved secret values. Packaging
rejects malformed or plaintext `secretEnv` values before writing the capsule.
The
restricted-local backend may place a resolved value into an allowlisted child
environment just in time. Provider failures and durable outcomes must not
contain the value. The value may still exist transiently in process memory, so
this mechanism is not a hardware-backed secret boundary.

Cancellation is cooperative at the contract boundary and enforced by the
backend where possible. Timeout, cancellation, output truncation, and process
termination are terminal outcomes, not Python exceptions hidden from the trace.
The orchestration layer owns whole-run and whole-scenario budgets.

If a provider nevertheless raises an exception across the adapter boundary,
the runner records `SOVA-EXECUTOR-EXCEPTION`, the exception type, and a
`crashed` run. It deliberately omits the exception message because provider
messages may contain credentials, target data, or other sensitive values.

## Normalized outcome

Every attempted action returns one status:

- `succeeded`
- `failed`
- `timeout`
- `cancelled`
- `denied`
- `unsupported`
- `partial`

The outcome also declares the observed side-effect class, structured output,
content-addressed evidence references, post-action verification state,
retryability, a stable error code where applicable, limitations, and a bounded
failure-cause category.

The categories are `none`, `target`, `executor`, `policy`, `environment`,
`evidence`, `timeout`, `cancellation`, `unsupported`, and `unknown`. Terminal
states infer only conservative causes. In particular, a generic failure stays
`unknown` unless independent evidence supports a narrower category; provider
exceptions are `executor`. A succeeded outcome cannot carry a failure cause.

`partial` means the observable result is incomplete—for example, bounded output
was exceeded. It must never be upgraded silently to success. A verification
string describes an observation method; it is not an assurance claim.

## Reference backends

### `ScriptedExecutor`

The deterministic backend consumes an exact ordered script. It compares
canonical input bytes, emits scripted evidence digests, supports every
normalized terminal status, and fails on missing, extra, or reordered actions.
It is the mandatory offline conformance and fault-injection backend.

### `RestrictedLocalExecutor`

The local backend currently implements:

- `artifact.read/0.1`, which reads only bytes already extracted from the
  content-addressed capsule;
- optional `process.exec/0.1`, exposed only when the constructor receives an
  explicit absolute executable allowlist;
- `process.spawn/0.1`, `process.status/0.1`, and `process.stop/0.1` for
  supervised children owned by one executor instance.

Process execution uses an argv array with `shell=False`, an existing confined
working directory, an environment allowlist that rejects secret-shaped keys,
bounded stdout/stderr capture, timeout and cancellation polling, process-tree
termination where the operating system permits it, and explicit cleanup of
supervised children. On Windows, a failed or timed-out `taskkill /T` attempt
falls back immediately to terminating and waiting for the owned root process;
temporary I/O cleanup retries bounded transient handle-release failures.
Path-like arguments outside the workspace are denied. This fallback does not
guarantee termination of independently surviving descendants without a
job-object or stronger containment backend.

Per-action duration and output limits are enforced. Requested CPU, memory, or
process-count limits are rejected as `unsupported` before process creation
because this host-process backend cannot enforce them portably. A stronger
container, VM, or operating-system isolation backend is required for those
guarantees. Unsupported protection is never silently accepted.

This is restricted host-process execution. It is **not** a security sandbox and
does not claim operating-system isolation, syscall filtering, network
containment, filesystem virtualization, or protection from a malicious
allowlisted executable. High-risk actions require a later true containment
backend and Topic 07 authorization controls.

Browser and computer capabilities are deliberately unsupported by the local
backend. Atlas MCP or another provider may implement those capabilities later
without changing `.sova`, `.sova-trace`, or SOVA's security logic.

## Conformance

The public conformance suite checks:

- exact capability discovery and version negotiation;
- every normalized outcome state;
- side-effect, idempotency, retry, denial, and error semantics;
- artifact digest and evidence preservation;
- workspace, executable, argument, environment, output, and time boundaries;
- strict opaque `sova-secret:` reference validation and resolution without
  durable secret output;
- pre-execution refusal of unenforceable CPU, memory, and process-count quotas;
- supervised background status, timeout, stop, owned-root cleanup, and bounded
  temporary-handle cleanup;
- cancellation and best-effort process-tree termination with a tested
  Windows owned-root fallback;
- unsupported browser/computer actions;
- post-action verification fields;
- the same `.sova` capsule producing the same material observation through
  `ScriptedExecutor` and `RestrictedLocalExecutor`.

The semantic-equivalence test compares normalized material observations, not
timestamps, event IDs, provider-internal mechanics, or hidden model reasoning.
The public comparator verifies both source traces first and returns
`inconclusive` rather than equivalent when either recorder reports dropped
events, non-full content capture, or an absent selected event family.
The complete no-Atlas fixture additionally performs capsule inspection, inert
playback, controlled execution through both backends, declared-outcome
comparison, explicit unsigned disclosure-view generation, capsule repackaging
with both traces, and dependency-free offline verification.
