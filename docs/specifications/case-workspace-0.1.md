<!-- status: implemented -->

# Offline case workspace 0.1

`sova case build TRACE CAPSULE OUTPUT` converts one already-recorded behavior
into a reviewable local case directory. It does not connect to a target,
re-execute an action, call a provider, upload evidence, or clear a disclosure
gate.

## Admission contract

The command fails closed unless:

- both inputs are regular files rather than symbolic links;
- `TRACE` is a complete, loss-free `.sova-trace` with a valid included-key
  signature and fully recorded or explicitly not-applicable fingerprints;
- `CAPSULE` is a fully verified `.sova` capsule with digest-pinned methodology
  and taxonomy identities;
- the capsule object index contains the exact SHA-256 digest of the supplied
  trace bytes; and
- `OUTPUT` does not already exist.

These checks prove package consistency and recorder provenance inside the
published threat model. They do not prove that the recorder, target, sensors,
or stated finding was truthful.

## Generated workspace

The output is assembled in a temporary sibling directory and renamed only
after every component succeeds. `case.json` indexes the following artifacts by
path, media type, byte length, and digest:

- exact trace and capsule copies plus an offline verification record;
- a payload-omitting selective-disclosure view;
- an uncertainty-preserving forensic reconstruction;
- an inert local HTML timeline that may display the trace's already-redacted
  payloads;
- a metadata-caption-only Y4M replay clip and sidecar that never include event
  payloads;
- watermarked evidence JSON, SARIF, and technical, executive, reproduction,
  and methodology reports;
- a multi-axis behavior snapshot for later drift comparison; and
- a registry contribution template and safety preview with every human gate
  false.

The workspace distinguishes trace playback from controlled re-execution and
semantic reproduction. Building it performs playback preparation only.

## Disclosure states

The default `bundled-target` and `simulation` classes are suitable for local
fixture evidence. `real-disclosed-finding` is refused unless all of these are
true:

1. the immutable trace says it was reviewed for export at recording time;
2. the operator passes `--reviewed-for-export`; and
3. the operator passes `--disclosure-cleared`.

Even then, contribution staging is not automatic. The generated template keeps
human review, authorization redaction, provenance, and public-disclosure gates
false. A later `sova contribute` invocation is a separate local operation; it
still never uploads or opens a pull request.

## Privacy and limitations

The exact trace and capsule remain local and may contain sensitive information
that survived capture-time policy. The HTML timeline is therefore local-only.
The selective view and replay clip omit payloads, but neither is a
cryptographic selective-disclosure proof. Operators must review all files
before sharing.

The command makes no safe-or-clean verdict, no independent-attestation claim,
no hidden-chain-of-thought claim, and no statement about behavior that was not
recorded.

## Validation

Mandatory no-network tests cover the complete build, CLI route, exact
capsule-to-trace binding, replay payload exclusion, blocked contribution state,
and disclosure refusal. The optional installed-browser lane feeds a signed
trace and capsule from the self-owned loopback Chrome campaign into the same
workflow.
