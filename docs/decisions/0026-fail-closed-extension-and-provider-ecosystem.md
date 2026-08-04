<!-- status: decision -->

# ADR-0026: Fail-closed extension and provider ecosystem

- **Status:** Accepted
- **Date:** 2026-08-04
- **Owner:** Gautam R. Patil
- **Scope:** Topic 22 extensions, providers, targets, and benchmark interoperability

## Decision

Extensions declare one of eight kinds, a SOVA extension API version,
capabilities, side effects, isolation, trust, version, and optional distribution
digest. PyPA entry-point discovery reads metadata only; it does not import
plugin code. Untrusted extensions run through an exact-executable-allowlisted,
shell-free JSONL subprocess with time and output limits. This is process
isolation, not a security sandbox. In-process execution is reserved for
explicitly pinned first-party code.

OpenAI, Anthropic, OpenRouter, and loopback Ollama use one observable request
and result contract. Credentials resolve only at call time from an injected
resolver, environment reference, or optional OS keyring; they never enter
artifacts. Remote adapters pin HTTPS origins, disable redirects, bound replies,
surface rate limits, report token usage, and refuse to invent costs when a
pricing snapshot is absent. Provider roles and model swaps are explicit.

Target manifests cover MCP, local process, REST, browser, computer, framework,
multi-agent, and trace-only surfaces without embedding executor mechanics.
Inspect AI Sample JSON/JSONL import preserves identifiers, metadata, source
digest, URL, and licence. Setup, files, and sandbox declarations remain inert;
every conversion reports semantic loss.

## Alternatives rejected

- Import every discovered plugin: turns discovery into code execution.
- Claim subprocesses are sandboxes: ordinary host processes do not provide that boundary.
- Store API keys in SOVA configuration: risks artifact and log leakage.
- One “OpenAI-compatible” adapter for every service: erases divergent semantics.
- Silently flatten external scenarios: corrupts provenance and comparability.

## Consequences

The compatibility kit proves a SOVA-authored external-process fixture and a
real documented scenario format. It is not independent third-party adoption.
Real-provider transferability remains a research HOLD until authorized repeated
trials control model, prompt, tools, environment, and budget.
