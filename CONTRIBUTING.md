# Contributing to SOVA OSS

Thank you for helping build SOVA OSS.

## Before contributing

Read:

- [the public repository boundary](docs/governance/public-repository-boundary.md);
- [the dual-use policy](DUAL_USE_POLICY.md);
- [the security and coordinated-disclosure policy](SECURITY.md);
- [the trademark policy](TRADEMARKS.md);
- [the controlling project decisions](docs/decisions/0005-topic-00-project-constitution.md).
- [the development environment](docs/engineering/development.md);
- [the testing strategy](docs/engineering/testing.md);
- [the repository controls](docs/governance/repository-controls.md).

Do not submit credentials, private traces, client data, confidential target details, unpatched exploit payloads, restricted proprietary methods, or material you do not have the right to publish.

Security vulnerabilities must be reported privately as described in `SECURITY.md`, not opened as public issues.

## Licence

SOVA OSS is licensed under the [Apache License 2.0](LICENSE).

Unless you state otherwise, a contribution intentionally submitted for inclusion is provided under Apache-2.0 without additional terms, consistent with Section 5 of the licence.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a contributor copyright assignment.

Sign off each commit:

```bash
git commit -s -m "describe the change"
```

The sign-off certifies that you created the contribution or have the right to submit it under the project's licence and understand that the contribution and sign-off record are public.

Do not sign off for another person.

## Public provenance

Every fixture, scenario, benchmark, or dataset contribution must declare one of:

- `synthetic`;
- `public-source`, with source and licence;
- `consented-publication`, with disclosure status;
- `generated-from-public-inputs`, with inputs and method.

Anonymized client data is not accepted.

## Safety requirements

Contributions involving offensive behavior must:

- operate against a deliberately vulnerable fixture or a system the contributor is authorized to test;
- use non-destructive proof by default;
- declare blast-radius and cleanup behavior;
- never contain live credentials or named production targets;
- respect coordinated disclosure;
- preserve the explicit human-authorization gate;
- include tests for refusal and failure paths;
- avoid automatic target modification or remediation.

The official registry does not accept an exploit for an unpatched vulnerability.

## Pull requests

Keep pull requests narrow and include:

- the problem and intended outcome;
- tests or reproducible validation;
- safety and privacy impact;
- artifact/schema compatibility impact;
- public provenance;
- paper, patent, licence, and disclosure status when applicable.

Complete the pull-request boundary checklist. Maintainers may ask for a change to be split, withheld pending disclosure, or recreated with synthetic data.

## Development workflow

SOVA uses CPython 3.11–3.14, a `src/` package layout, `uv`, and a checked-in
universal lockfile:

```bash
uv sync --locked
uv run sova --version
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest --cov=sova --cov-branch
uv export --locked --quiet --format requirements.txt --all-groups --no-emit-project --output-file audit-requirements.txt
uv run pip-audit --strict --cache-dir .cache/pip-audit --requirement audit-requirements.txt --no-deps --disable-pip
uv run python scripts/generate_glossary.py --check
uv run python scripts/generate_taxonomy.py --check
uv run python scripts/check_repository.py
```

Run the public-boundary script using the command for your platform in the
[development guide](docs/engineering/development.md). CI is the authoritative
Windows, macOS, Linux, and supported-Python result.

New runtime or build dependencies require the
[dependency and supply-chain review](docs/governance/dependency-policy.md).
Every fixture or dataset requires the
[provenance record](docs/governance/fixture-and-dataset-provenance.md).

Install the local checks:

```bash
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

The placeholder CLI and Topic 03 domain-contract library are the only
implemented product code. Do not represent planned security commands, artifact
schemas, execution, or evidence capabilities as shipped.

## Research and citation

Research contributions are welcome. Methods and claims must include:

- a reproducible protocol;
- suitable baselines;
- uncertainty and limitations;
- ethics and authorization context;
- versioned `.sova` and `.sova-trace` artifacts where safe;
- paper/patent review before irreversible disclosure.

If you use SOVA OSS in research or publication, cite the release or commit using [`CITATION.cff`](CITATION.cff).

## Attribution and forks

Distributed derivatives must comply with Apache-2.0, including its licence, modified-file, notice-retention, and `NOTICE` requirements.

Modified forks must follow [`TRADEMARKS.md`](TRADEMARKS.md), use a distinct primary name, and may truthfully describe themselves as based on SOVA-OSS.
