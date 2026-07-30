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
- a secret-free allowlisted environment map.

Cancellation is cooperative at the contract boundary and enforced by the
backend where possible. Timeout, cancellation, output truncation, and process
termination are terminal outcomes, not Python exceptions hidden from the trace.
The orchestration layer owns whole-run and whole-scenario budgets.

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
retryability, a stable error code where applicable, and limitations.

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
  explicit absolute executable allowlist.

Process execution uses an argv array with `shell=False`, an existing confined
working directory, an environment allowlist that rejects secret-shaped keys,
bounded stdout/stderr capture, timeout and cancellation polling, and process
tree termination. Path-like arguments outside the workspace are denied.

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
- cancellation and process-tree termination;
- unsupported browser/computer actions;
- post-action verification fields;
- the same `.sova` capsule producing the same material observation through
  `ScriptedExecutor` and `RestrictedLocalExecutor`.

The semantic-equivalence test compares normalized material observations, not
timestamps, event IDs, provider-internal mechanics, or hidden model reasoning.
