<!-- status: experiment -->

# Executor-backed browser swarm validation - 2026-08-09

## Result

The bounded browser-swarm implementation passes its mandatory deterministic,
hostile-input, parser, CLI, evidence, and privacy tests. The optional
installed-browser lane also passed against SOVA's self-owned loopback fixture.

## Real-runtime procedure

- Browser: installed Google Chrome on Windows.
- Executor: pinned `@playwright/mcp` `0.0.78` through the cached package runner.
- Roles: two deterministic `ScriptedModel` participants with distinct grants.
- State: one target-digest-bound profile under one exclusive lease.
- Execution: baseline candidate in one MCP process, planted ordered trigger and
  fresh reproduction in subsequent MCP processes.
- Authorization: exact fresh SOVA approval for every browser action batch.

Command:

```powershell
$env:SOVA_RUN_REAL_BROWSER='1'
python -m pytest tests/integration/test_live_browser_vertical_slice.py::test_optional_real_executor_backed_browser_swarm -q -s
```

Observed result: **1 passed in 26.93 seconds**.

The result proves that this implementation can coordinate two bounded roles,
reuse one opaque profile across executor restarts, discover the planted
conditional behavior, reproduce it, stream canonical trace channels, sign all
traces, and build an offline-verifiable aggregate capsule on this fixture. It
does not prove arbitrary-site compatibility, provider-model quality, parallel
swarm safety, total observability, or independent causal accuracy.
