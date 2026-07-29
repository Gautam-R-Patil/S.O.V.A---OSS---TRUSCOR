<!-- status: decision -->

# ADR-0007: Topic 02 engineering foundation

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Roadmap scope:** Topics 02.1 through 02.5 and Topic 02 exit
- **Decision owner:** Gautam R. Patil

## Context

SOVA needs a contributor-friendly research stack, a trustworthy local CLI,
strong safety controls, and portable execution adapters. The foundation must
run on Windows, macOS, and Linux, must not require a SOVA-hosted service, and
must not define Topic 03–05 artifact semantics prematurely.

The PyPI distribution name `sova` is already used by an unrelated project. The
name `sova-oss` returned unclaimed on 2026-07-29; this check is not a
reservation and publication requires the release gate.

## Language decision

Python is the first production language because it offers:

- direct access to agent, model, security-research, data, and MCP ecosystems;
- a portable CLI and mature packaging on the three target platforms;
- approachable contribution and experimentation;
- strong subprocess, async, telemetry, schema, and test ecosystems;
- a low-friction path from reproducible experiment to maintained implementation.

The public package uses:

- **distribution:** `sova-oss`;
- **import namespace:** `sova`;
- **command:** `sova`;
- **initial version:** `0.1.0a0`;
- **runtime:** CPython `>=3.11,<3.15`;
- **runtime dependencies:** none at the Topic 02 boundary.

Python 3.10 is excluded because it reaches end of life in October 2026. CI
tests CPython 3.11, 3.12, 3.13, and 3.14. The supported operating-system
families are 64-bit Windows, macOS, and Linux, represented by GitHub-hosted
`windows-latest`, `macos-latest`, and `ubuntu-latest` runners. An exact release
records the concrete runner images it passed.

## Production and research languages

Research prototypes may use Python, notebooks, Rust, or another justified
language under a clearly labelled prototype area. A prototype:

- is not imported by the production package;
- cannot carry private data or cleared invention-hold material into Git;
- must record environment, seed, inputs, provenance, and limitations;
- must be ported, typed, tested, threat-reviewed, and documented before release.

Rust is permitted for a measured isolation, parser-hardening, cryptographic, or
performance need after an ADR demonstrates the need and defines FFI, build,
platform, and memory-safety boundaries. It is not a mandatory second runtime.
TypeScript may later serve a browser UI or extension, not duplicate the core.

## Packaging and environment decision

The package uses:

- standard `pyproject.toml` metadata and a `src/` layout;
- Hatchling as the PEP 517 build backend;
- a standard `console_scripts` entry point;
- `uv` for contributor environments, universal locking, and builds;
- a checked-in `uv.lock`;
- a pure-Python wheel while no native component is justified.

End users may install through a standards-compatible installer such as
`pipx install sova-oss` or `uv tool install sova-oss`. Using `uv` is a
contributor convention, not a runtime dependency or service dependency.

No command requires a TRUSCOR account, hosted SOVA API, network connection,
telemetry, or remote schema lookup. Networked model, registry, and executor
adapters are optional capabilities selected by the user.

## Quality decision

Required gates are:

- Ruff formatting and linting, including Python security rules;
- strict mypy type checking;
- pytest unit, integration, compatibility, failure, and performance suites;
- branch coverage of at least 95% for the initial package;
- deterministic test seeds and explicit test clocks in later time-dependent code;
- golden fixture provenance and immutable digests;
- `pip-audit`, CodeQL, dependency review, Gitleaks, and the SOVA public-boundary
  scanner;
- build and CLI smoke tests across all supported platform families;
- a source-distribution and wheel build before release.

Topic 02 creates `.sova` and `.sova-trace` **rejection sentinels**, not valid
schemas. Valid golden artifacts can only begin when Topics 04 and 05 publish
their experimental contracts. This prevents a fixture from becoming an
accidental de facto specification.

## Repository-control decision

`main` is releasable and protected by convention:

- contributors work on branches and merge through pull requests;
- required CI, public-boundary, secret, dependency, and code-scanning checks
  must pass;
- CODEOWNERS review is required for governance, schemas, evidence, execution,
  security, and release surfaces;
- force pushes and branch deletion are prohibited;
- DCO sign-off, resolved review conversations, linear history, and one approving
  review are the intended GitHub protection settings;
- the project lead may use an administrator bypass only for a documented
  emergency or the current founder-operated bootstrap flow and must still run
  every local and remote check.

Checked-in controls are authoritative. Hosting settings are defense in depth
and are audited before a promoted release.

## Documentation and release decision

Public documentation labels content as `implemented`, `planned`, `experiment`,
`claim`, or `decision`. The generated glossary is controlled by
`docs/glossary.toml`; Topic 03 must reconcile all data-model terminology through
that source.

Releases use:

- SemVer for the CLI package;
- independent versions for artifact schemas, methodologies, taxonomies, and
  adapters;
- a changelog and methodology ledger;
- signed, immutable Git tags after all safety/publication gates;
- CI-built wheel and source distribution;
- a dry-run release-candidate artifact before any package-index publication;
- Trusted Publishing and provenance attestations when PyPI release authority is
  configured.

No package has been published by Topic 02.

## Safety and provenance decision

Private invention details live only in the ignored private ledger. Public
issues provide public feature, defect, and research forms; security reports use
GitHub private vulnerability reporting or the private email in `SECURITY.md`;
invention disclosures use a private intake route, never a public issue body.

Every fixture or dataset has a provenance class, licence, purpose, expected use,
and content digest. Only declared synthetic traces may be tracked. Client data,
private corpus material, browser profiles, credentials, live tokens, and the
confidential Atlas report remain blocked.

## Alternatives rejected

- **TypeScript-first:** attractive for `npx`, but less direct for the scientific
  and agent-security core and would still need native/process boundaries.
- **Rust-first:** strong isolation and distribution, but higher contribution and
  research iteration cost before a measured hotspot exists.
- **Python plus mandatory hosted orchestration:** conflicts with the local-first
  constitution.
- **Use the `sova` PyPI name:** conflicts with an existing unrelated package.
- **Publish valid artifact goldens now:** would bypass the ordered Topic 03–05
  design and version gates.

## Decision basis

The foundation was checked against current primary documentation on
2026-07-29:

- the [CPython support lifecycle](https://devguide.python.org/versions/);
- the [Python Packaging User Guide](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
  for `pyproject.toml`, supported Python, licence metadata, and console scripts;
- pytest's [recommended `src/` and importlib test layout](https://docs.pytest.org/en/stable/explanation/goodpractices.html);
- uv's [universal lockfile and locked-sync behavior](https://docs.astral.sh/uv/concepts/projects/sync/);
- GitHub's [secure Actions guidance](https://docs.github.com/en/actions/reference/security/secure-use),
  [protected-branch controls](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
  [supply-chain controls](https://docs.github.com/en/code-security/concepts/supply-chain-security/supply-chain-security),
  and [private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository);
- the existing unrelated [`sova` PyPI distribution](https://pypi.org/project/sova/).

These sources support the engineering choices. They do not validate SOVA's
planned security capabilities or comparative claims.

## Consequences

The repository now builds a small honest CLI rather than presenting planned
security commands as implemented. Contributors have one reproducible workflow
and every later artifact, adapter, dataset, method, and release has a permanent
control location.

The cost is a deliberate quality burden. New code must pass multiple platforms,
strict typing, tests, provenance, supply-chain review, and public/private
screening. Native components require a separate decision and build matrix.

## Topic 02 closure

- [x] Repository, review, issue-routing, decision, invention, research,
      changelog, and methodology controls exist.
- [x] Python, prototype-language, runtime, platform, package, command, and
      local-only packaging decisions are accepted.
- [x] Formatting, linting, typing, tests, deterministic seeds, compatibility,
      performance-budget, fault-injection, coverage, and cross-platform CI exist.
- [x] Contributor, security, conduct, development, glossary, and documentation
      state controls exist.
- [x] Secret, confidential-file, licence, dependency, fixture, raw-trace,
      credential, profile, and Atlas-report controls exist.
- [x] The placeholder CLI builds and tests on each supported platform family.
- [x] Topic 01 publication controls remain intact and no non-trivial mechanism
      or private material was published.

## Next

Begin Topic 03 with the shared data model and vocabulary. Update the generated
glossary source as Topic 03 terms become normative.
