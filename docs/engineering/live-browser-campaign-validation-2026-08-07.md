<!-- status: experiment -->

# Live browser campaign validation — 2026-08-07

## Scope

This record covers the first real-target SOVA trigger-hunt implementation:
closed candidate authorization, Playwright/Chrome execution, snapshot/console/
network observation, deterministic oracle evaluation, near-miss scoring,
controlled reproduction, signed `.sova-trace` output, and a digest-pinned
`discovery.sova` capsule.

## Installed-browser acceptance

Command:

```powershell
$env:SOVA_RUN_REAL_BROWSER='1'
.\.venv\Scripts\python.exe -m pytest -q tests/integration/test_live_browser_vertical_slice.py
```

Current result after provider-role integration and startup recovery:
`7 passed in 68.31s`.

The test started SOVA's real loopback HTTP fixture, launched pinned
`@playwright/mcp@0.0.78` with installed Google Chrome, exercised the known
detonation, four-candidate hunt, and provider-shaped isolated-role hunt paths,
observed the planted two-turn behavior, reran the winning sequence under fresh
authorization, and verified the emitted evidence. The role lane used
deterministic `ScriptedModel` inputs, demonstrating real browser execution
without making or paying for an external provider call. A real external-
provider result remains explicitly unclaimed.

## Repository validation

Commands:

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe
.\.venv\Scripts\python.exe -m pytest -q
```

Result:

- Ruff: all checks passed.
- mypy: no issues in 256 source files.
- pytest: 786 passed, 3 skipped in 96.80 seconds.

The skipped default-suite lanes were explicit opt-ins: official Codex testing
was unavailable because Codex was not logged in, and the two installed-browser
tests require `SOVA_RUN_REAL_BROWSER=1`. Both browser tests were run separately
and passed as recorded above.

## What this proves

- The browser campaign is not merely a schema or protocol double.
- One human-reviewed closed campaign can safely authorize multiple exact
  attempts while retaining a distinct signed one-use token per action.
- The real Playwright MCP exposes the snapshot, console, and network tools used
  by the runner.
- The owned target's planted behavior is found on the fourth candidate and is
  reproduced in a fresh run.
- Attempt and reproduction traces pass required-signature verification.
- The discovery capsule passes offline structural and content-addressed
  integrity verification.

## What this does not prove

- compatibility with arbitrary UI structures, authenticated accounts, CAPTCHA,
  native desktop software, or every browser executor;
- model-generated candidate quality or jailbreak superiority;
- containment equivalent to a VM or browser-process honesty;
- complete network/console observability beyond what the executor returns; or
- capture of private model thoughts or hidden chain-of-thought.
