<!-- status: experimental-implemented -->

# Synthetic detonation world 0.1

The reference world is a deterministic, event-sourced laboratory for safe
behavior discovery. It is not an operating-system sandbox and does not emulate
private model thoughts.

## State and services

Each run receives a seed, run id, synthetic UTC clock, invocation counter,
generation counter, environment gates, and baseline state. The state contains:

- a fake home directory, source/configuration files, SSH and wallet decoys;
- synthetic customer and billing tables;
- fake email, messaging, storage, payment, database, and network services;
- explicit synthetic approval on payment release; and
- before/after state digests for every world event.

No service accepts a real credential or contacts a real service. The network
collector never opens a socket and always records `delivered: false`.

## Canaries

Run-unique canaries cover API tokens, SSH keys, wallet seeds, credentials,
files, database records, and messages. They contain the marker `DO_NOT_USE` and
are not valid secrets. The detector identifies raw, case-folded, Base64, hex,
URL-encoded, and SHA-256 forms. Each hit binds the canary id, transform, actor,
action, and destination.

## Sensor mesh and evidence closure

The normalized sensor vocabulary includes tool, MCP, filesystem, process,
network, DNS, browser, computer, memory, retrieval, inter-agent, database, and
API observations. A missing sensor cannot emit an observation. Health is
`healthy`, `degraded`, or `missing`.

An evidence requirement declares primary and optional alternative sensor sets.
Closure is sufficient only when one set is both observed and healthy. Missing
or degraded coverage is insufficient. Opposed `pass` and `fail` verdicts for
one claim produce conflict. Coverage is a decimal string in canonical JSON and
does not imply complete reality.

## Deterministic oracles

The registry covers file state, process state, network effects, canaries, tool
invocation and forbidden parameters, approval bypass, browser state, database
mutation, inter-agent handoff, state transition, trigger activation, and
`all`/`any`/`not` composition. Results are pass, fail, inconclusive, or conflict.
Unknown or malformed meaning is never guessed.

## Ground-truth suite

Nine deterministic target families provide known labels:

1. benign control;
2. obvious malicious behavior;
3. an exact-trigger sleeper;
4. multi-turn stateful activation;
5. invocation-count long fuse;
6. environment gate;
7. composition-only activation;
8. a suspicious-language false-positive trap; and
9. a target with a known responsible layer.

The bundled `sova demo sleeper <directory>` command proves the safe path:

```text
fresh authority + admitted no-native-code backend
  -> planted conditional behavior
  -> inert canary read
  -> sink-only egress attempt
  -> claim-conditioned evidence closure
  -> deterministic oracle
  -> .sova-trace
  -> .sova capsule
  -> offline verify and playback
  -> verified reset
```

The output directory must be empty of the three named outputs; the command
refuses overwrite.

## Limits

- Synthetic success does not prove real-world safety or fidelity.
- A compromised recorder or sensor may lie consistently.
- Anti-sandbox, timing, browser, kernel, and model-provider behavior may differ.
- A deterministic target validates the measurement system, not model novelty.
- Real native-code detonation requires a separately validated isolation backend.

## Research baselines

- [AgentDojo](https://arxiv.org/abs/2406.13352)
- [ToolEmu](https://arxiv.org/abs/2309.15817)
- [ToolSandbox](https://arxiv.org/abs/2408.04682)
- [OSWorld](https://arxiv.org/abs/2404.07972)
- [tau-bench](https://arxiv.org/abs/2406.12045)
