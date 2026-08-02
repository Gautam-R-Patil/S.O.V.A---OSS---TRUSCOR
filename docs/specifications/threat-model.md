<!-- status: implemented -->

# SOVA format threat model 0.1

## Assets

- operator host and credentials;
- target and authorization scope;
- capsule and trace integrity;
- confidential prompts, outputs, tools, artifacts, and identities;
- signer private keys and trust policy;
- historical meaning across migrations.

## Adversaries

1. A malicious capsule author controls all package bytes.
2. A distributor modifies, inserts, deletes, reorders, or substitutes content.
3. A curious recipient attempts to recover redacted low-entropy values.
4. A compromised recorder emits false but internally consistent observations.
5. A valid signer signs misleading or unauthorized evidence.
6. A hostile extension attempts parser confusion, resource exhaustion, path
   traversal, active-content execution, or capability acquisition.
7. An agent or malicious capsule attempts to forge, broaden, replay, or
   self-approve authority.
8. A target-control collector is confused by redirects, DNS changes, ambiguous
   scope, or a public URL.
9. A detonation target attempts real egress, child-process escape, persistent
   state, cleanup failure, or anti-sandbox behavior.
10. A missing, degraded, dishonest, or contradictory sensor creates false
    confidence about an effect or attribution.

## Defended properties

- bounded parsing and decompression;
- normalized relative paths and ordinary-file entries only;
- unique JSON keys, strict UTF-8, finite bounded structures;
- descriptor verification before object parsing;
- event modification/insertion/deletion/reordering detection for covered bytes;
- manifest/signature binding;
- capture-time structural secret omission;
- rejection of unkeyed or short-key secret commitments;
- unknown required feature rejection;
- inert inspection and explicit re-execution boundary;
- migration provenance and non-overwrite.
- explicit recovered-prefix semantics after an interrupted writer;
- redaction-placeholder and redaction-record consistency checks.
- strict opaque secret-reference syntax in capsules and just-in-time provider
  resolution without writing the resolved value into normal outcomes;
- provider exceptions converted into crash evidence without retaining the
  potentially sensitive exception message;
- declared-outcome comparison becomes inconclusive on recorder-reported loss,
  non-full content capture, or absent selected evidence families.
- exact per-action scope, consequence ceiling, monotone effect budget, bound
  containment digest, expiring proof, and required-evidence checks;
- agent self-approval refusal and fresh single-use human approval for effectful
  and offensive actions;
- caller assertions cannot authorize real effectful executor paths;
- synthetic-world network attempts terminate in an in-memory sink that never
  opens a socket;
- claim-conditioned evidence closure reports missing, degraded, and
  contradictory sensor coverage instead of silently inferring safety.

## Out of scope or not guaranteed

- truthfulness or completeness of the recorder;
- model, provider, operating-system, firmware, or hardware integrity;
- authorization merely because a signed trace says `allowed`;
- correctness of an oracle, judge, finding, hypothesis, or attribution;
- signer identity from an included key;
- trusted time without an external timestamp authority;
- replay or freshness detection without trusted external state;
- detection of a valid signer's conflicting traces without a trusted
  transparency or consistency service;
- confidentiality of unencrypted bytes;
- recovery of a trace never flushed to durable storage;
- power-loss durability on filesystems/platforms that do not honor the
  requested flush or sync operation;
- perfect secret detection;
- protection of a resolved secret from the explicitly allowlisted child
  process, operating system, debugger, or memory inspection;
- deterministic behavior across stochastic or changed runtimes;
- non-repudiation, unforgeability, causality proof, or hidden-thought capture.
- truth of a claimed human identity, comprehension of an approval challenge,
  or honesty of the trusted approval/control-proof collector;
- containment against a compromised host, kernel, hypervisor, executor binary,
  or malicious runtime administrator;
- native-code isolation from the in-memory synthetic world, which executes no
  target-native code and is not an OS sandbox;
- complete observability, anti-sandbox fidelity, or real-world equivalence of
  synthetic services;
- prevention of deliberate code modification by a trusted local operator.

## Security language

Allowed claims are:

- content-addressed;
- integrity-checked;
- tamper-evident for covered bytes under this threat model;
- signature-valid under a named trust policy;
- offline-verifiable for included material.
- externally timestamped only under a named TSA/log policy and verifier.

Do not use "tamper-proof," "forensically proven," "unforgeable,"
"non-repudiable," "perfectly reproducible," or "cryptographically proves
causality."

## Tests

The conformance suite covers duplicate JSON keys, invalid UTF-8, binary floats,
UTF-16 ordering, I-JSON integer bounds, lone surrogates,
path traversal, undeclared members, byte substitution, sequence reordering,
event-chain mismatch, signature substitution, unknown required features,
secret omission, environment allowlisting, partial/recovered states,
redaction-record mismatch, and required-key verification.
Short commitment keys fail before capture. Negative controls confirm that a
byte-identical replay and two different traces signed by the same valid key
remain individually valid offline; SOVA does not misrepresent those cases as
detectable without an external freshness/transparency policy.
Authorization tests mutate every scope dimension, proof freshness, containment
binding, effect ceiling, approval level/signature/use count, and budget. The
detonation suite verifies run-unique canaries, declared transforms, sink-only
egress, reset, nine labeled target families, missing sensors, degraded coverage,
contradictory observations, and containment-descriptor binding.

Still required before `1.0`: fuzzing at scale, independent parser agreement,
cross-language canonical digests, zip-bomb corpus review, encryption/selective
disclosure review, external cryptographic review, and malicious-renderer tests.
