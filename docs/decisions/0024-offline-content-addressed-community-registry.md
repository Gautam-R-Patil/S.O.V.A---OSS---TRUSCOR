<!-- status: decision -->

# ADR-0024: Offline content-addressed community registry

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 20 registry, sync, adapters, taxonomy, and contributions

## Decision

The SOVA public registry is a cloneable repository of files. Disclosed payloads
are addressed by SHA-256, releases and taxonomies are versioned, and the
canonical index is wrapped in a DSSE-compatible Ed25519 envelope. An included
key proves integrity continuity only. Publisher identity is trusted only when
the operator pins an expected key identifier.

`sova sync` is pull-only: it selects the first supplied local mirror that
passes complete offline verification, copies a bounded immutable snapshot, and
atomically replaces a local pointer. It sends no target, finding, trace,
credential, or usage data.

`sova contribute` previews and stages allowed, bounded, non-executable items
after schema, secret, disclosure, provenance, license, identity, and explicit
confirmation gates. It never creates a pull request, sends a message, uploads,
or transfers public material into a private corpus. External adapters retain
source identity, version, license, digest, and fidelity limitations.

## Alternatives rejected

- Mandatory hosted API or account: breaks offline use and creates telemetry pressure.
- Trust an index merely because it carries its own key: allows key substitution.
- Hide embargoed payloads behind guessable object paths: leaks restricted content.
- Auto-submit after local validation: bypasses human disclosure review.
- Reimplement OCI, TUF, in-toto, or SARIF as a proprietary protocol: unnecessary.

## Consequences

The first implementation is intentionally repository-of-files and local-mirror
only. Git, static hosting, OCI-compatible distribution, TUF-style root rotation,
and transparency services can be layered later without changing artifact
identity. This registry is community infrastructure, not TRUSCOR attestation
and not the private SOVA Engine corpus.
