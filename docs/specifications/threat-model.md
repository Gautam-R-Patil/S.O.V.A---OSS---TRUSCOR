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

## Defended properties

- bounded parsing and decompression;
- normalized relative paths and ordinary-file entries only;
- unique JSON keys, strict UTF-8, finite bounded structures;
- descriptor verification before object parsing;
- event modification/insertion/deletion/reordering detection for covered bytes;
- manifest/signature binding;
- capture-time structural secret omission;
- unknown required feature rejection;
- inert inspection and explicit re-execution boundary;
- migration provenance and non-overwrite.
- explicit recovered-prefix semantics after an interrupted writer;
- redaction-placeholder and redaction-record consistency checks.

## Out of scope or not guaranteed

- truthfulness or completeness of the recorder;
- model, provider, operating-system, firmware, or hardware integrity;
- authorization merely because a signed trace says `allowed`;
- correctness of an oracle, judge, finding, hypothesis, or attribution;
- signer identity from an included key;
- trusted time without an external timestamp authority;
- confidentiality of unencrypted bytes;
- recovery of a trace never flushed to durable storage;
- power-loss durability on filesystems/platforms that do not honor the
  requested flush or sync operation;
- perfect secret detection;
- deterministic behavior across stochastic or changed runtimes;
- non-repudiation, unforgeability, causality proof, or hidden-thought capture.

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

Still required before `1.0`: fuzzing at scale, independent parser agreement,
cross-language canonical digests, zip-bomb corpus review, encryption/selective
disclosure review, external cryptographic review, and malicious-renderer tests.
