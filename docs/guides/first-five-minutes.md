<!-- status: implemented -->

# First five minutes

After [installation](installation.md):

```console
uv run sova init .sova-local --provider none
uv run sova doctor .sova-local
uv run sova demo sleeper ./sova-demo
uv run sova verify --require-signature ./sova-demo/discovery/synthetic-sleeper.sova-trace
uv run sova playback ./sova-demo/discovery/synthetic-sleeper.sova-trace
```

The demo maps a self-owned synthetic target, discovers a planted conditional
behavior, records observable canary and sink-only egress evidence, creates a
signed trace and capsule, performs a fresh reproduction, compares declared
outcomes, and verifies the artifacts offline. It does not run native target
code or establish detection accuracy on a real system.

Prove the authorized-target pipeline for either target class:

```console
uv run sova target fixture website ./website-fixture
uv run sova target fixture software ./software-fixture
```

These are deterministic fixtures, not claims about a live website or native
program. For a real self-owned target, follow the
[authorized-target guide](authorized-target-testing.md).

Every failing CLI operation prints a stable `SOVA-*` error code. Exit `0` means
the requested operation completed, not that a target is safe. Commands with a
meaningful negative or inconclusive result use their documented nonzero code.
