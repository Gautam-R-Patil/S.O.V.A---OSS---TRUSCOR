<!-- status: implemented -->

# Dependency and supply-chain policy

## Default

Prefer the standard library and small, replaceable interfaces. A dependency is
accepted only when its maintained implementation meaningfully reduces risk or
work compared with owning the code.

The Topic 02 CLI began with zero runtime dependencies. The implemented capsule
and trace formats now use the `jsonschema` reference validator and a
parity-tested `jsonschema-rs` runtime validator. Development, build, and runtime
dependencies are declared in `pyproject.toml`, resolved in `uv.lock`, and
listed in `THIRD_PARTY_NOTICES.md`.

The separately shipped Linux worker mediator is a Rust crate under
`deploy/worker/network-mediator`. Its small direct dependency set is exact-version
pinned, the complete graph is committed in `Cargo.lock`, and CI applies formatting,
Clippy, unit/interop tests, a release build, and RustSec audit before admission.

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

An audit exception is allowed only when the advisory is verified against the
upstream record, no fixed compatible release exists, the affected API is not
reachable from SOVA, an automated guard preserves that fact, an owner and
removal condition are recorded, and the exception remains visible in CI. The
exception must be removed or the dependency replaced before the affected API is
introduced. See the [advisory register](./dependency-advisory-register.md).

## Build and release

- CI installs from the checked-in lockfile using `uv --locked`.
- CI builds the mediator from its checked-in `Cargo.lock` using Rust 1.88.0,
  runs pinned `cargo-audit` 0.22.2, and rejects
  formatting, Clippy, test, or RustSec failures.
- Release artifacts are built in CI from the tagged source.
- Package-index publication will use short-lived OIDC Trusted Publishing, not a
  long-lived API token.
- Release artifacts will carry provenance attestations when publishing is
  enabled.
- Separate deterministic SBOMs are generated for the Python and mediator Cargo
  dependency closures in promoted releases.

No setup step may silently contact a SOVA, TRUSCOR, Atlas, model, telemetry, or
registry service.
