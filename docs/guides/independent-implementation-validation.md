<!-- status: implemented -->

# Independent implementation validation

SOVA ships dependency-free Python and Node.js verification programs so two
language runtimes can check the same canonical `.sova` and `.sova-trace` bytes.
They reject malformed ZIP structure, path substitution, manifest and object digest
drift, event-chain mutations, malformed DSSE envelopes, and required-key mismatch.
The conformance tests compare their package digest, content digest, event count,
and signature-policy result.

Run the verifiers offline:

```text
python scripts/sova_independent_verify.py artifact.sova
node scripts/sova_independent_verify.mjs artifact.sova-trace --require-signature
```

These are independently written code paths, not independently owned products.
They therefore demonstrate cross-language implementation feasibility but do not
satisfy the stable-release requirement for an implementation maintained by an
organization outside the SOVA team.

An external implementation owner should:

1. implement from the normative specifications and schemas rather than importing
   the Python package;
2. run the public valid, invalid, hostile-input, migration, canonicalization, DSSE,
   and ZIP-structure corpus without network access;
3. publish the exact implementation version, runtime, platform, corpus digest, and
   complete result set;
4. compare canonical bytes and error classes with the reference implementation;
5. disclose unsupported fields, extensions, algorithms, and migrations;
6. submit an acceptance receipt without claiming organizational independence unless
   that fact is externally checkable.

Passing the corpus proves agreement on the tested cases only. It does not prove the
absence of parser differentials, universal compatibility, trust in embedded keys,
or correctness of the behavior described by an artifact.
