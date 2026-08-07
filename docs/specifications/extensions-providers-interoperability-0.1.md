<!-- status: implemented -->

# Extensions, model providers, targets, and interoperability 0.1

## Extension contract

The API version is `0.1`. An extension manifest declares identity, distribution
version, kind, capabilities, side effects, trust, isolation, and optional
distribution digest. Kinds are attacker, judge, mutator, oracle, executor,
target, sandbox, and report.

Installed extensions advertise through the `sova.extensions` PyPA entry-point
group. Discovery returns metadata without calling `EntryPoint.load()`. The
reference third-party path is a newline-delimited JSON protocol in an exact
allowlisted subprocess with a sanitized environment, no shell, a maximum
60-second call, and a 2 MiB response. This is **not** a security sandbox.
Untrusted or verified-publisher code cannot select in-process isolation.

### Operator workflow

The public workflow has three distinct operations:

1. `sova extension discover` reads installed PyPA entry-point metadata without
   importing extension code and explicitly establishes no trust.
2. `sova extension prepare` parses an exact-field manifest, resolves an
   absolute executable and working directory, hashes the executable, hashes
   every command argument that resolves to an existing regular file, rejects
   symbolic files and inline interpreter code, and writes a machine-local
   `sova.extension-launch` document without starting a process.
3. `sova extension run` requires a human-operated terminal, displays the
   complete manifest, command, payload, resolved files, hashes, effects, and
   non-sandbox warning, and accepts only the exact digest-derived phrase. It
   rechecks every file after approval and immediately before process creation.

Launch documents are deliberately machine-local. Absolute paths and exact
SHA-256 pins prevent PATH or current-directory substitution; they do not make
the selected code trustworthy. A response must bind the protocol, manifest
digest, requested operation, and boolean acceptance. Credential-shaped request
payloads are rejected, and credential-shaped response fields are redacted
before signed evidence and the local report are written.

`conform` performs `describe` and `self-test` in separate fresh processes. A
successful run produces a DSSE-compatible Ed25519-signed `.sova-trace` and a
canonical report. The signature proves only integrity under the included-key
verification model. Manifest capabilities and side effects remain publisher
assertions; the subprocess receives no SOVA authorization, target authority,
or inherited approval.

The safe worked example is in
[`examples/extensions`](../../examples/extensions/README.md).

## Providers

The common observable envelope supports messages, model, temperature, output
budget, timeout, response text, finish reason, response ID, and token usage.

| Provider | Endpoint family | Credential |
|---|---|---|
| OpenAI | `/v1/responses`, `/v1/models` | `OPENAI_API_KEY` |
| Anthropic | `/v1/messages`, `/v1/models` | `ANTHROPIC_API_KEY` |
| OpenRouter | `/api/v1/chat/completions`, `/api/v1/models` | `OPENROUTER_API_KEY` |
| Ollama | loopback `/api/chat`, `/api/tags` | none |

Remote requests require a pinned HTTPS origin, reject redirects, and cap the
response at 8 MiB. Ollama permits HTTP only on loopback. Secrets resolve at call
time from an injected resolver, environment reference, or optional OS keyring
and are never serialized into a SOVA result. Pricing is `not-pinned` unless an
experiment explicitly freezes it; no cost is invented. HTTP 429 preserves the
provider's retry-after value as an optional operational hint.

Role routing configures attacker, judge, mutator, oracle, and target model
separately. A model-swap run reuses the same request envelope, but exact text
agreement is not called semantic equivalence.

Normative upstream API references: [OpenAI](https://platform.openai.com/docs/api-reference),
[Anthropic](https://docs.anthropic.com/en/api/overview),
[OpenRouter](https://openrouter.ai/docs/quickstart), and
[Ollama](https://docs.ollama.com/api/chat).

## Target and benchmark bridges

Target manifests cover MCP server, local process, REST API, browser agent,
computer agent, framework, multi-agent, and trace-only import. Each kind has a
minimum observation capability and fresh authorization statement. Executor
commands do not belong in the portable target contract.

Inspect AI Sample JSON or JSONL is the first external scenario bridge. Import:

- preserves original IDs, input, target, choices, metadata, unknown fields,
  source URL, licence, and source digest;
- retains `setup`, `files`, and `sandbox` declarations inert;
- never runs or materializes external content;
- emits a conversion record that names every semantic loss; and
- exports preserved fields back to JSONL while reporting the SOVA envelope that
  cannot transfer.

Upstream format: [Inspect sample datasets](https://inspect.aisi.org.uk/datasets.html#sample-json).

## Research state

The no-network test lane validates adapters with injected transports and runs
the external-process operator workflow against a real local process. It does
not establish provider equivalence or vulnerability transfer. P5 remains HOLD
until authorized real-model trials run identical artifacts across multiple
providers with controlled tools, prompts, environments, budgets, repeated
trials, and blinded outcome adjudication.
