<!-- status: decision -->

# ADR-0022: Substitute-only rehearsal and selective promotion

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 18 safe real-task rehearsal

## Decision

`sova rehearse` runs a user's declared agent task against a bounded,
credential-stripped copy and inert service substitutes. The user agent and any
SOVA attacker remain separate trace actors. File changes occur only inside the
prepared workspace; database, API, network, process, browser, and computer
effects are ledgered substitutes in the built-in backend. Every run requires
explicit authorization and emits a signed trace. Runtime failure also finalizes
a failed trace without recording raw exception text.

Review and production change are deliberately separate. SOVA reports each
proposed change by content digest, records deletions as requests, and exports
only explicitly selected, digest-stable file changes to a new staging tree. It
never patches or deletes production content automatically.

Isolation preparation is pluggable behind `RehearsalIsolationBackend`. The
built-in filesystem backend is not called a security sandbox. Stronger
container, gVisor, or microVM implementations may be admitted later under the
existing containment contract; policy, evidence, review, and judging remain in
SOVA.

## Alternatives rejected

- Copy credentials into the clone: creates unnecessary exposure and live reach.
- Let substitutes silently fall through to production: violates rehearsal.
- Apply all changes after a successful task: removes per-change human review.
- Build a new microVM platform in SOVA: duplicates mature isolation projects.
- Treat simulated fidelity as proven: the built-in backend has no field-validity result.

## Consequences

The implementation proves a safe, deterministic developer workflow for files
and inert service effects. It does not prove production-equivalent substitute
fidelity, contain untrusted native code, or implement a full database/browser
digital twin. Those are explicit limitations and research questions.
