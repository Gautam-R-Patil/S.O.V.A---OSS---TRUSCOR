<!-- status: implemented -->

# Final-mile acceptance and stable-release gates 0.1

SOVA separates engineering evidence from facts that the SOVA team cannot
truthfully self-issue. `sova acceptance run DEST` executes the credential-free
capsule, signed-trace, oracle, evidence-closure, cleanup, sensor-ledger, and
offline-verification path. `sova acceptance evaluate RECEIPTS` evaluates twelve
named gates without turning a signature, download, or self-authored receipt
into independence or adoption.

The gates cover held-out authorized websites, Windows/macOS/Linux desktop
drivers, user-kernel or microVM isolation, declared sensor coverage, blinded
causal validation, provider/model studies, hosted community operation,
acknowledged monitoring, independent implementations, signed stable release,
comparative benchmark evidence, and external user workflows. Strict receipt
fields include producer, organization, environment, labels, artifact digests,
result, timestamp, limitations, and an explicit independence declaration.

Templates are always `inconclusive`. External gates require evidence from the
declared number of distinct environments and organizations. Receipt signatures
can protect bytes but do not establish that the named reviewer is real,
independent, qualified, or authorized. Stable `1.0` remains blocked while any
gate is blocked; the implemented formats remain experimental `0.1.0`.

The release-candidate workflow runs the complete suite, offline acceptance,
wheel/sdist build, CycloneDX generation, checksum verification, keyless
Sigstore signing, and GitHub build-provenance attestation. It deliberately
produces an experimental candidate and cannot publish or label a stable 1.0.

Primary references: [Sigstore bundles](https://docs.sigstore.dev/about/bundle/),
[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
and [in-toto Statement v1](https://github.com/in-toto/attestation/tree/main/spec/v1).
