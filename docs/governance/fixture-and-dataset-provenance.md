<!-- status: implemented -->

# Fixture and dataset provenance

Every tracked fixture, benchmark input, dataset, model artifact, payload,
screenshot, trace, and generated sample must have a machine-checkable entry in
the nearest provenance manifest.

## Accepted provenance classes

| Class | Requirement |
|---|---|
| `synthetic` | Created from first principles solely for the public repository |
| `public-source` | Exact source, version/digest, author, licence, and redistribution terms |
| `consented-publication` | Written authority, scope, date, and disclosure status |
| `generated-from-public-inputs` | Every public input plus deterministic generation method and seed |

“Anonymized client data” and “scraped from the internet” are not accepted
classes.

## Required entry

Each entry records:

- repository-relative path;
- provenance class;
- author or source;
- licence and required notice;
- purpose and expected test result;
- SHA-256 digest;
- generator version and seed when generated;
- safety and disclosure state when relevant.

The repository checker fails on undeclared fixture files and digest drift.
Changing fixture bytes requires a new digest and review; published stable
conformance fixtures receive a new version rather than an in-place rewrite.

## Public trace exception

Raw `.sova-trace` files are private and ignored by default. The only tracked
exception is a deliberately synthetic, provenance-recorded golden fixture under
`tests/fixtures/golden/trace/`. It must contain no credential, target, browser
profile, client, private corpus, or confidential Atlas material.

## Dataset intake

Before adding a dataset:

1. identify the legal source and responsible owner;
2. review licence compatibility, privacy, consent, security, and terms of use;
3. inspect nested files and metadata;
4. pin immutable source and content digests;
5. document sampling, filtering, transformations, and exclusions;
6. isolate any active content and test parsing as hostile input;
7. run the publication/IP and coordinated-disclosure gates;
8. add deterministic acquisition and integrity verification.

Remote data is never downloaded merely by importing SOVA or running an
unrelated test. Acquisition is explicit and offline use remains possible.
