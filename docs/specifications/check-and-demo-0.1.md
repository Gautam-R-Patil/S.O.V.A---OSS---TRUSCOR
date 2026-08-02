<!-- status: implemented -->

# `sova check` and `sova demo` 0.1

These commands expose the first bounded no-MELRA workflow. They return evidence
about a declared run; they never return a universal `safe` or `clean` verdict.

## `sova demo sleeper OUTPUT`

An installation must include the `signing` extra because this workflow promises
an Ed25519-signed trace. The locked repository development environment already
includes that dependency; a minimal source install uses
`pip install ".[signing]"`. Missing signing support fails visibly and preserves
the partial output directory.

The zero-configuration demo:

1. maps an owned synthetic target without executing native code;
2. runs deterministic recon, exploration, planning, attack, and isolated judge
   roles;
3. compares a minimal known-signature static rule, a one-pass dynamic run, and
   passive recording against a planted two-factor condition;
4. searches the four combinations of message and `SOVA_MODE`;
5. observes an inert canary read and sink-only egress attempt;
6. blocks real delivery, evaluates deterministic oracles, and verifies cleanup;
7. emits a `.sova` capsule and an Ed25519-signed `.sova-trace`;
8. repeats the run fresh and compares declared observable outcomes;
9. writes a machine-readable report and independent offline-verification
   command.

The bundled “static baseline” is deliberately only a named minimal
known-signature rule. It is not a comparison with a mature external scanner.
The demo therefore proves the measurement pipeline, not superior discovery on
real agents.

## `sova check TARGET OUTPUT`

The current executable target is `synthetic-sleeper`. A confirmed planted
behavior returns exit code `1`, reserving `0` for a future completed run with no
confirmed result. Input or contract failure returns `2`. A local directory with
no selected safe target adapter is mapped statically, emits a signed blocked
trace and `inconclusive` report, executes no native code, and returns `3`.

The default is the standard profile. `--custom-profile FILE` binds a canonical
configuration digest, marks the result non-standard, and excludes it from
shared comparisons.

Reports contain conditions, measured duration, attempts, coverage, detection
floor, artifact paths, explicit limitations, and a trigger-hunting next step.
Partial and failed output directories are preserved rather than silently
deleted, supporting flakiness and failure review.

## Threat and trust boundaries

- Synthetic authorization, credentials, canaries, and sink-only endpoints are
  inert and self-owned.
- The synthetic backend executes no target-native code and is not evidence
  about a host, container, model, or third-party service.
- Included ephemeral signing keys establish covered-byte integrity, not a
  verified signer identity.
- Fresh deterministic reproduction is not a claim that hosted stochastic
  inference replays exactly.
- SOVA output is operator-controlled self-assessment, never TRUSCOR attestation
  or a financial/compliance certificate.
- MELRA/Atlas is not installed, invoked, or trusted by this workflow.
