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

The no-network test lane validates adapters with injected transports. It does
not establish provider equivalence or vulnerability transfer. P5 remains HOLD
until authorized real-model trials run identical artifacts across multiple
providers with controlled tools, prompts, environments, budgets, repeated
trials, and blinded outcome adjudication.
