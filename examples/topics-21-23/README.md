# Topics 21-23 safe local examples

These examples execute deterministic `ScriptedModel` fixtures only. They do
not contact a provider, target a third party, upload results, or run untrusted
agent code.

From the repository root:

```console
uv run sova arena run examples/topics-21-23/arena.json examples/topics-21-23/out
uv run sova verify examples/topics-21-23/out/attempt-0000.sova-trace --require-signature
uv run sova replay clip examples/topics-21-23/clip.json examples/topics-21-23/out/replay.y4m
```

The Arena report records the generated signing key identifier. A leaderboard
submission must copy that identifier into `requiredKeyId`, name the exact
standard profile digest, and link the generated capsule and trace. The static
leaderboard builder then verifies the capsule, complete signature-pinned trace,
embedded trace digest, methodology digest, and oracle score before ranking it.

```console
uv run sova leaderboard build leaderboard.json leaderboard-output
uv run sova ctf build ctf.json ctf-catalog.json
```

Both builders are local-only. The CTF builder creates an inert provenance
catalog and never clones, installs, or starts a referenced project. Public
upload is a separate human action outside these commands.

`agent-arena.json` is a secret-free provider configuration for the
provider-capable multi-round Arena. Replace its placeholder model names, then
run it only when you have authorized the resulting provider use:

```console
uv run sova arena agent-run examples/topics-21-23/agent-arena.json \
  examples/topics-21-23/agent-arena-output --allow-provider-calls
```

The flag permits configured provider calls; it does not grant browser,
terminal, filesystem, credential, or other target access. Outputs are custom,
non-comparable, local-only artifacts and are not leaderboard eligible.
