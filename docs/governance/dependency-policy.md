<!-- status: implemented -->

# Dependency and supply-chain policy

## Default

Prefer the standard library and small, replaceable interfaces. A dependency is
accepted only when its maintained implementation meaningfully reduces risk or
work compared with owning the code.

The Topic 02 CLI has zero runtime dependencies. Development and build
dependencies are declared in `pyproject.toml`, resolved in `uv.lock`, and
listed in `THIRD_PARTY_NOTICES.md`.

## Intake checklist

Before adding or upgrading a dependency:

- define the capability and why the standard library or existing dependency is
  insufficient;
- verify the canonical source, maintainer, release, signatures/checksums where
  available, and package-index ownership;
- review licence, notice, patent, export, data, and redistribution terms;
- examine transitive dependencies, install/build hooks, native code, network
  behavior, telemetry, and credential access;
- pin or constrain the version, regenerate the universal lockfile, and inspect
  the complete diff;
- run dependency audit, tests, build, provenance, and public-boundary checks;
- add an adapter boundary for providers, model SDKs, executors, telemetry, and
  other replaceable ecosystems.

Dependencies from Git branches, mutable URLs, unverified archives, or private
indexes are prohibited in public release manifests.

## Updating

Dependabot proposes weekly Python and GitHub Actions updates. Updates remain
manual-review pull requests; auto-merge is disabled for security-sensitive
code. Action references are pinned to full commit SHAs and their human-readable
release versions are kept in comments.

Emergency security updates may use the administrator bypass only after a
documented advisory review and the full test/boundary suite.

## Build and release

- CI installs from the checked-in lockfile using `uv --locked`.
- Release artifacts are built in CI from the tagged source.
- Package-index publication will use short-lived OIDC Trusted Publishing, not a
  long-lived API token.
- Release artifacts will carry provenance attestations when publishing is
  enabled.
- An SBOM is generated for promoted releases.

No setup step may silently contact a SOVA, TRUSCOR, Atlas, model, telemetry, or
registry service.
