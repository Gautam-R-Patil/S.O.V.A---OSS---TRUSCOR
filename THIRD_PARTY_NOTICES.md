# Third-party dependency and tool notices

SOVA OSS `0.1.0a0` has **no runtime Python dependencies**. The following
third-party projects are used only to build, test, review, or automate the
repository and are not bundled into the pure-Python wheel.

| Project | Role | Licence | Source |
|---|---|---|---|
| `hatchling` | PEP 517 build backend | MIT | [PyPA Hatch](https://github.com/pypa/hatch) |
| `mypy` | Static type checking | MIT | [python/mypy](https://github.com/python/mypy) |
| `pip-audit` | Python dependency vulnerability audit | Apache-2.0 | [pypa/pip-audit](https://github.com/pypa/pip-audit) |
| `pre-commit` | Local quality-hook runner | MIT | [pre-commit/pre-commit](https://github.com/pre-commit/pre-commit) |
| `pytest` | Test runner | MIT | [pytest-dev/pytest](https://github.com/pytest-dev/pytest) |
| `pytest-cov` | Coverage integration | MIT | [pytest-dev/pytest-cov](https://github.com/pytest-dev/pytest-cov) |
| `ruff` | Formatting, linting, and Python security rules | MIT | [astral-sh/ruff](https://github.com/astral-sh/ruff) |
| `uv` | Contributor environment, lockfile, and build runner | Apache-2.0 or MIT | [astral-sh/uv](https://github.com/astral-sh/uv) |
| `actions/checkout` | GitHub Actions checkout | MIT | [actions/checkout](https://github.com/actions/checkout) |
| `actions/dependency-review-action` | Pull-request dependency review | MIT | [actions/dependency-review-action](https://github.com/actions/dependency-review-action) |
| `actions/upload-artifact` | Release-candidate artifact retention | MIT | [actions/upload-artifact](https://github.com/actions/upload-artifact) |
| `astral-sh/setup-uv` | Reproducible CI toolchain setup | MIT | [astral-sh/setup-uv](https://github.com/astral-sh/setup-uv) |
| `github/codeql-action` | GitHub code scanning | MIT | [github/codeql-action](https://github.com/github/codeql-action) |
| `gitleaks/gitleaks-action` | CI secret scanning | Gitleaks Action licence | [gitleaks/gitleaks-action](https://github.com/gitleaks/gitleaks-action) |
| Contributor Covenant 2.1 | Community code-of-conduct text | CC BY 4.0 | [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct.html) |

Transitive development dependencies and exact versions are recorded in
`uv.lock`. GitHub Actions are pinned to immutable full commit SHAs and are
updated through reviewed Dependabot pull requests.

Before adding a runtime dependency, contributor tooling, fixture, copied code,
model, dataset, binary, or action:

1. verify its source, licence, authorship, redistribution terms, and security
   posture;
2. record it here or in the fixture/dataset provenance ledger;
3. regenerate and review `uv.lock`;
4. run the dependency, secret, licence, and public-boundary checks;
5. preserve any required licence or notice text in the distributed artifact.

This ledger is an engineering record, not legal advice. Unclear or incompatible
terms block the dependency until qualified review resolves them.
