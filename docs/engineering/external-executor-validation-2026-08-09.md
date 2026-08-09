<!-- status: implemented -->

# External executor validation — 2026-08-09

This record separates source claims, upstream test claims, SOVA unit evidence,
and live behavior observed on the current Windows runner. An upstream badge or
provider receipt is never promoted to SOVA verification.

## MELRA 0.3.0-alpha.10

Public source: [XAGI-Lab/melra](https://github.com/XAGI-Lab/melra).

| Property | Pinned value |
|---|---|
| Public HEAD tested | `b9edeb35b3749de029386c929fbe8a21cc666a08` |
| Package version | `0.3.0-alpha.10` |
| `pnpm-lock.yaml` SHA-256 | `0c85260bc26947ac834ad2202d8c1ecb345cce245fac00e72393c9b064a17fc0` |
| Licence | Apache-2.0 |
| SOVA role | Optional browser/computer/terminal executor |

The lockfile-pinned dependency installation completed. All TypeScript packages
compiled, but MELRA's aggregate Windows build command returned failure after
compilation because the CLI script invokes Unix `chmod`. SOVA did not patch or
silently reinterpret that upstream result.

The opt-in SOVA-to-MELRA live test passed against the exact commit:

- MCP initialization and tool discovery;
- Windows computer capability inspection;
- an allowlisted `node` terminal command with exact SOVA authorization and the
  MELRA approval challenge;
- navigation to a self-owned loopback HTTP fixture in installed Chrome; and
- same-process browser-session cookie reuse through a SOVA-owned opaque profile
  handle.

Cross-process profile persistence did not pass the earlier validation attempt;
the current admitted claim is same-process reuse only. MELRA's own policy,
receipt, certificate, focus report, and task state remain provider input.
SOVA accepts only a matching planned task whose internal status is exactly
`verified_success`, and even that is labelled defense-in-depth rather than
independent evidence.

## CUA Driver 0.12.6

Public source: [trycua/cua](https://github.com/trycua/cua).

| Property | Pinned value |
|---|---|
| Release tag commit | `9eb1f481b8a12cd6ffda2ad5af21653a9e5aa9e5` |
| Windows x86_64 archive SHA-256 | `d18a0ca02314c6dc7dfdfbb20aac8f52c7b1547308f182546a9252a991d4d0dd` |
| Licence | MIT |
| SOVA role | Optional bounded Windows computer executor |

The official archive digest matched its published checksum. A source build was
also attempted from the exact tag and stopped because the host Visual Studio
installation lacks Spectre-mitigated C++ libraries. SOVA did not disable that
mitigation.

SOVA launches a private named-pipe service generation with:

- bounded mode and an approved deny-by-default session manifest;
- unrestricted mode disabled;
- permissions-gate bypass disabled at the SOVA authorization layer (the CUA
  interactive gate is suppressed only after the exact SOVA launch decision);
- telemetry forced off and its state redirected inside the admitted workspace;
- a hidden argv-only process with no shell; and
- deterministic service readiness and shutdown.

Live read-only conformance passed for discovery, session start/end, screen
dimensions, application inventory, and window inventory. Effectful conformance
did not pass on this runner:

- CUA's UI Automation provider timed out on a fixture-owned Windows Forms
  window and on Notepad;
- a later top-level enumeration stalled instead of returning a bounded result;
- the current runner returned no independently verifiable foreground window;
  therefore SOVA refused to count pixel/global-input fallback as success; and
- the opt-in mutation test reports a visible skip for that runner condition.

`CuaDriverExecutorAdapter` nevertheless freezes the safe contract for a runner
that can satisfy it: exact positive PID/HWND binding for mutations, background
delivery first, a foreground retry only after CUA returns the typed
`background_unavailable` condition and a separate SOVA approval is present,
post-action provider observation, bounded text, and no desktop capture unless
explicitly enabled. CUA's post-observation is labelled provider evidence and is
not accepted by the broker as independent verification.

## Backend decision

No single open-source executor passed every required path. SOVA therefore uses
a capability broker rather than replacing one dependency with another:

| Need | Current first choice | Fallback / status |
|---|---|---|
| Browser semantics and exact-origin fixtures | Microsoft Playwright MCP | MELRA for its passing public interface |
| Terminal execution | RestrictedLocalExecutor for trusted allowlisted fixtures | MELRA optional |
| Windows computer reads | CUA Driver or restricted Windows-MCP surface | Provider observations remain untrusted |
| Windows computer mutations | No default backend admitted | CUA only after a live fixture-owned mutation conformance pass |
| Untrusted desktop applications/agents | Separately admitted VM backend | Host automation is not isolation |

This result is not “MELRA failed” or “CUA passed.” It is an evidence-based
capability split with visible downgrades and no silent substitution.
