# Live browser validation - 2026-08-07

## Result

The first real-browser acceptance slice passed on Windows using Chrome and
`@playwright/mcp@0.0.78`. It used no model API, provider account, MELRA, target
credential, or external website.

## Verified path

- real loopback HTTP server;
- real Playwright MCP stdio process;
- real headless Chrome navigation, typing, clicks, and accessibility snapshot;
- six authorized actions per run;
- planted ordered trigger `enable research mode` then `blue owl`;
- observable `SOVA_FIXTURE_TRIGGERED` oracle;
- fresh primary and controlled-reproduction executions;
- 21 events in each signed trace;
- valid package hashes, event ordering, causal links, redaction structure,
  event chain, manifest digest, and included-key signature;
- equivalent declared oracle outcomes; and
- one content-addressed evidence capsule containing the target, scenario, and
  both traces.

## Test separation

The mandatory CI test uses a deterministic MCP protocol double and requires no
network or browser installation. The optional installed-browser test runs only
when `SOVA_RUN_REAL_BROWSER=1`. Both exercise the same public coordinator. The
installed lane was run explicitly during this validation and passed.

## Limits

This validates SOVA's own loopback fixture. It does not establish arbitrary
website support, automated vulnerability discovery, CAPTCHA handling, account
creation, multi-agent swarms, production-grade containment, or model-backed
judgment. Those remain separate product acceptance gates.
