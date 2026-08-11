<!-- status: implemented -->

# Browser adapters and held-out website matrix 0.1

SOVA has two independent MCP browser mappings:

- Microsoft Playwright MCP `0.0.78` is the primary deterministic automation
  adapter used by the live assessment and trigger-campaign workflows.
- Chrome DevTools MCP `1.6.0` is a second protocol adapter for navigation,
  accessibility snapshots, interaction, console, network, screenshots, and
  performance evidence.

Both are exact-version launch receipts. SOVA supplies the browser executable,
workspace, cache/log paths, origin allowlist, and profile mode; disables
optional telemetry/update/CrUX lookups; rejects credentials in URLs and
headers; bounds requests and responses; and verifies observed page origins
after calls. Neither MCP is SOVA's policy, judge, evidence root, or security
sandbox. Capability probing prevents silent fallback when tools differ.

The self-owned held-out matrix contains four application shapes with the same
harmless two-message conditional behavior:

1. server-rendered static UI;
2. client-state SPA launch flow;
3. cookie-bound login using inert fixture credentials; and
4. modal/popup interruption requiring an explicit consent action.

Each class produces a portable capsule, signed primary trace, fresh controlled
reproduction trace, evidence capsule, and offline verification result. The
matrix is representative engineering coverage, not universal website
compatibility. CAPTCHA bypass, third-party account creation, arbitrary consent,
and unreviewed cross-origin navigation remain excluded.

Primary references: [Playwright MCP](https://github.com/microsoft/playwright-mcp),
[Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp),
and [Chrome DevTools MCP tools](https://github.com/ChromeDevTools/chrome-devtools-mcp/blob/main/docs/tool-reference.md).
