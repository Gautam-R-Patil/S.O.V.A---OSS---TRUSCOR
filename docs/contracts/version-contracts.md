<!-- status: implemented -->

# Identity and version contracts

## Identity layers

SOVA keeps three identities separate:

1. Logical ID: stable across revisions, `sova:<kind>:<UUIDv7>`.
2. Declared version: the author's or specification owner's semantic revision.
3. Content digest: immutable identity of exact bytes,
   `sha256:<lowercase-hex>`.

Names and URLs are locators. Consumers verify content digests before expensive
parsing. UUIDv7 ordering is operational convenience, not trusted event time.

## Exact version axes

| Axis | Required identity |
|---|---|
| Schema | Artifact kind, exact `specVersion`, immutable schema identity |
| Taxonomy | Taxonomy name and exact version |
| Methodology | Method ID and exact version |
| Executor | Implementation name and exact adapter-facing contract version |
| Adapter | Adapter name and exact contract version, or explicit absence |
| Model/provider | Provider, model, provider revision, secret-free configuration fingerprint |
| Target | Target snapshot fingerprint |
| Environment | Environment snapshot fingerprint |
| Judge | Judge name and exact version, or explicit absence |
| Oracle | Oracle name and exact version |
| Registry | Snapshot name and fingerprint, or explicit absence |

Package, schema, taxonomy, methodology, oracle, adapter, model, target, and
registry versions are independent. Updating one never silently updates another.

## Explicit absence

`null`, empty string, omission, and “unknown” are not interchangeable. A
context slot that lacks a concrete value uses exactly one reason:

- `not-applicable`: the run did not use that kind of component;
- `not-recorded`: a source failed to capture it;
- `unknown-after-migration`: the source representation could not know it.

Every absence includes an explanation. A future schema decides which absences
are permitted for that artifact and operation. Required unknown behavior fails
closed for execution and verification claims.

## Model configuration fingerprint

The fingerprint commits to security-relevant, secret-free configuration:

- provider and model identifiers;
- provider revision when supplied;
- decoding and sampling parameters;
- system/developer prompt digests rather than protected prompt text;
- tool/interface declarations;
- safety and policy configuration;
- seed support and value when meaningful.

API keys, tokens, credentials, private prompt bodies, and personal data are
never placed in the fingerprint input record. The future artifact schema must
define canonical bytes for this record before the digest is interoperable.

## External identifiers

An external reference records system, catalog version, identifier,
relationship, and HTTPS locator. SOVA preserves its own stable ID.

CVE syntax is `CVE-YYYY-NNNN` with four or more sequence digits. A SOVA finding
may cite a reserved or published CVE only under the disclosure policy. CWE,
CAPEC, OWASP, ATLAS, vendor advisory, paper DOI, and registry identifiers are
handled the same way: they are qualified links, not native identity.

## Compatibility

Semantic versions follow ADR-0002:

- PATCH clarifies without changing accepted meaning;
- MINOR adds backward-compatible meaning that old consumers can safely
  preserve or explicitly decline;
- MAJOR changes existing meaning or required behavior.

No consumer may infer compatibility from a matching package version. Unknown
major versions and unknown required behavior fail closed. Stable old
representations remain inspectable and migratable.
