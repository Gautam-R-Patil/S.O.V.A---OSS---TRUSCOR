<!-- status: implemented -->

# Registry, synchronization, and contributions 0.1

## Registry layout

```text
index.json
objects/sha256/<hex-digest>
taxonomy/<version>.md
```

The signed index binds registry and taxonomy versions, taxonomy digest,
artifact digest/size, component/version, taxonomy IDs, disclosure state,
reproduction metadata, provenance, license, lifecycle, and verification tier.
Embargoed and withdrawn entries contain metadata only and cannot expose an
object path or digest. Superseded entries remain addressable.

Verification tiers are submitted, schema/safety validated, safely reproduced
by CI, independently reproduced, embargoed, withdrawn, and superseded. None is
a TRUSCOR attestation. Included-key verification establishes integrity, not
publisher identity; `--trusted-key-id` is required for that local trust choice.

## Offline synchronization

`sova sync MIRROR... --cache CACHE` verifies each supplied local mirror in
order, selects the first valid source, enforces file/byte/symlink limits, copies
to an immutable snapshot, re-verifies the copy, and atomically updates
`current.json`. Existing cached snapshots are re-verified before reuse. The
command is pull-only and has no network, telemetry, or upload code path.

A registry can therefore be distributed by Git, static files, removable media,
or a separate downloader. Network transport and root-key rotation are not
silently invented by this 0.1 implementation.

## Contributions

`sova contribute SPEC STAGING --confirm` is a local PR-preparation step. It
requires contributor name/identity, license, provenance, human review,
public-disclosure permission, redacted authorization, and explicit per-run
confirmation. `.sova`, JSON, TOML, and Markdown are allowed under bounds;
executable magic, symlinks, unsupported types, oversized items, credential
patterns, and invalid capsules fail closed.

The staging result states that no upload, pull request, message, submission, or
private-corpus reuse occurred. Separate consent is recorded but is never acted
on by OSS contribution code. A human maintainer must review and create the PR.

## Adapters and taxonomy

Adapters import benchmark intent, passive trace events, scanner/SARIF findings,
and external taxonomy mappings without claiming stronger evidence than the
source. Every conversion retains source format, URI, version/license where
applicable, digest, integrity state, unmapped values, and fidelity limits.

The complete experimental standard attack taxonomy remains versioned under
`src/sova/contracts/data/attack-taxonomy-0.1.0.toml`. Additions use reviewed
proposals; removed IDs remain reserved, and historical results are not
rewritten. Public payload aging and benchmark contamination are expected and
must be recorded in reproduction metadata.
