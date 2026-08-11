<!-- status: implemented -->

# Topics 21-23 validation record

Checked on 2026-08-04 against the public working tree before publication.

## Implemented inventory

- Local MCP `2025-11-25` stdio server, stable manifest, five safe tools, three
  exact-gated tools, separate-terminal HMAC approval, single-use expiry, traces,
  `sova check --self`, and release-manifest drift pin.
- Eight-kind extension manifest, import-free PyPA metadata discovery,
  shell-free bounded subprocess protocol, compatibility fixture, and explicit
  non-sandbox trust policy.
- OpenAI, Anthropic, OpenRouter, and loopback Ollama adapters behind an injected
  transport; role routing, discovery, model-swap envelope, usage/rate-limit
  normalization, and optional OS-keyring resolution.
- Eight executor-independent target-manifest kinds and an inert Inspect AI
  Sample JSON/JSONL provenance-preserving bridge.
- Signed nonce/scope/freshness-bound probe evidence, deterministic local Arena,
  signature-pinned standard-profile static leaderboard, inert CTF catalog, and
  bounded metadata-only Y4M replay renderer.
- Strict CLI documents for `probe verify`, `arena run`, `leaderboard build`,
  `ctf build`, and `replay clip`.

## Validation result

```text
723 passed, 1 skipped
branch coverage: 95.11% (required: 95%)
ruff format: pass
ruff lint: pass
mypy strict: pass
repository policy: pass
glossary/taxonomy generation checks: pass
dependency audit: pass with one scoped non-applicable advisory exception
```

The dependency exception is `GHSA-g6cj-pr64-35w5`: the current stable
`cryptography` release is affected only through three PKCS#7 decryption APIs
that SOVA never imports or invokes, while the named fixed version `50.0.0` is
not available on PyPI as of this validation. A source guard fails if that
module or any affected function name enters `src/sova`; the exception expires
as soon as a compatible fixed release is available. This is an applicability
decision, not a claim that the installed dependency contains no known issue.

**Resolution (2026-08-11):** stable `cryptography 50.0.0` is now available.
SOVA upgraded its runtime constraint and lock, removed the CI audit exception,
and re-ran the complete compatibility and dependency-audit gates. The paragraph
above remains as the historical record of the earlier validation.

The skipped test is the optional official Codex subscription lane. Its visible
reason was `Not logged in`; it is not a mandatory product dependency. No live
provider call, paid service, account creation, credential inspection, or model
comparison was performed.

The deterministic lane found and fixed one Windows defect: `os.open` needed
binary mode for control-key creation, otherwise a random newline could be
translated to CRLF. The regression test now requires exactly 32 bytes.

## Research and claim result

- Broad novelty/patent claims for out-of-band authorization, plugin discovery,
  provider routing, signed responses, or static leaderboards are **NO-GO** due
  to strong prior art.
- Exact invocation-bound local approval under adversarial agent prompting is a
  **HOLD** research candidate pending a predeclared operator study, baselines,
  ablations, and independent reproduction.
- Artifact-gated benchmark falsifiability is a **HOLD** research candidate
  pending comparative correction/dispute data.
- Model-swap transferability (P5) remains **HOLD / NOT RUN** until identical
  artifacts run across authorized real providers with controlled variables,
  repeated trials, and blinded adjudication.

No paper or patent is publication-ready from these internal fixtures. No
novelty-bearing material was published as a novelty claim.

## Honest remaining gates

- Topic 21: issue and independently verify an actual signed/checksum-pinned
  release candidate.
- Topic 22: run a compatible external benchmark through SOVA, compare an
  independently authored extension with its baseline, and run authorized real
  provider/model transfer experiments.
- Topic 23: admit a genuinely isolating arbitrary-agent backend, integrate
  reviewed beginner/intermediate/advanced vulnerable-agent scenarios, and
  reproduce a public comparison independently.
- Earlier topics: this work does not close cross-machine/third-party/blinded
  validation (4-6), real-provider comparison (12), or the larger empirical
  research datasets and nondeterministic studies (15-17).

The current Arena is deterministic scripted evidence-path validation. It is not
a security sandbox and not evidence of model or component superiority.
