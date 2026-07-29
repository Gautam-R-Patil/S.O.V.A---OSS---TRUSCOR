<!-- status: implemented -->

# Development environment

## Supported foundation

SOVA OSS currently supports CPython 3.11–3.14 on 64-bit Windows, macOS, and
Linux. CI records the concrete GitHub-hosted images used for each commit.

Install [uv](https://docs.astral.sh/uv/) and clone the repository. No model API
key, SOVA account, TRUSCOR service, Atlas runtime, Docker daemon, or telemetry
opt-in is required for current foundation and contract development.

## Bootstrap

```bash
uv sync --locked
uv run sova --version
uv run pytest
```

`uv` creates the project environment and installs exact versions from
`uv.lock`. `.python-version` selects Python 3.11 as the contributor default;
CI also tests later supported versions.

## Quality commands

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest --cov=sova --cov-branch --cov-report=term-missing
uv export --locked --quiet --format requirements.txt --all-groups --no-emit-project --output-file audit-requirements.txt
uv run pip-audit --strict --cache-dir .cache/pip-audit --requirement audit-requirements.txt --no-deps --disable-pip
uv run python scripts/generate_glossary.py --check
uv run python scripts/generate_taxonomy.py --check
uv run python scripts/check_repository.py
```

Run the confidential/public boundary on Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-public-boundary.ps1
```

Or with PowerShell 7:

```bash
pwsh ./scripts/check-public-boundary.ps1
```

Run everything before requesting review. CI is the authoritative
cross-platform result.

## Local hooks

```bash
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
uv run pre-commit run --all-files
git commit -s
```

The hooks use only the locked local environment. They do not fetch independent
hook repositories.

## Build

```bash
uv build
```

The result is a pure-Python wheel and source distribution under `dist/`. Build
outputs are ignored. The pre-alpha package has not been published to PyPI.

## Platform notes

- Use UTF-8 and LF line endings; `.editorconfig` and `.gitattributes` control
  repository text.
- Use `Path` instead of string-built paths.
- Tests must not rely on shell-specific behavior unless they are explicitly
  platform-scoped.
- Tests requiring Docker, a model, network, browser, computer control, or Atlas
  must be opt-in and capability-probed when those layers are introduced.
- Never place real credentials in `.env` for tests; use synthetic placeholders
  that cannot authenticate.

## Adding a dependency

Follow [the dependency policy](../governance/dependency-policy.md), then update
`pyproject.toml`, regenerate `uv.lock`, update `THIRD_PARTY_NOTICES.md`, and
review every transitive change.
