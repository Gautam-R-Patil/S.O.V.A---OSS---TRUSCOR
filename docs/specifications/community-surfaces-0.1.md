<!-- status: implemented -->

# Probe, local Arena, leaderboard, CTF, and replay media 0.1

## Probe

A signed probe response binds a subject, unpredictable request nonce, exact
scope, issued/expiry window (maximum 15 minutes), conformance state,
third-party assertions, SOVA observations, and optional revocation-list digest.
States are `passed`, `failed`, `unsupported`, and `inconclusive`.

Verification checks the DSSE signature, payload type, key identifier, nonce,
scope, freshness, optional pinned key, and a locally supplied revoked-key set.
The included public key provides integrity only. Without a pinned key,
`identityTrust` is `not-established`. A passing response is limited protocol
conformance, never “instant trust”.

## Local Arena

The reference Arena accepts only deterministic `ScriptedModel` participants.
It records attacker and defender observable responses and the deterministic
oracle result. Each attempt becomes a signed trace embedded in a portable
capsule. Standard profile identity/version/digest is separate from custom
non-comparable runs. The runner has no network, upload, account, or telemetry
path.

This implementation proves the evidence path. It is not yet a containment
backend for arbitrary untrusted agents and does not establish model superiority.

The provider-capable extension, `sova arena agent-run`, adds bounded multi-round
challenger/defender interaction and an isolated advisory judge inside a
synthetic message-only environment. It captures observable prompts, responses,
inter-agent communication, environment state, oracle decisions, budgets, and
failures in signed traces. It never exposes target tools, and deterministic
signal membership—not model self-grading—controls the score. These runs are
custom, non-comparable, and excluded from the standard leaderboard. See the
[Agent Arena specification](./agent-arena-0.1.md).

## Static leaderboard

A snapshot accepts building blocks, frameworks, components, and models—not
people, organizations, or victims. All entries share one standard profile
digest and include an exact component version, verified `.sova`, complete signed
`.sova-trace` embedded in that capsule, score denominator, Wilson 95 percent
interval, stable ranking rule, methodology snapshot, and duplicate-evidence
checks. Fewer than ten observations produces a visible sample-size warning.

Output is local `leaderboard.json` plus static `index.html`. Public upload is a
separate human action outside this API.

## CTF

The catalog is inert. It records difficulty, source project URL and licence,
setup mode, educational explanation, verified SOVA artifact, and reviewed
registry contribution path. It never clones, installs, starts, or copies assets
from referenced vulnerable-agent projects. External setup remains governed by
the source project's instructions and licence.

## Replay clips

The dependency-free renderer produces bounded YUV4MPEG (`.y4m`) clips from at
most 12 event metadata captions. Event payloads are never rendered. Secret-like
captions become `REDACTED`; unknown characters become visible placeholder
glyphs. A canonical sidecar records the media digest, artifact and verification
links, simulation/bundled/real-disclosed classification, and clearance status.
Naming a real component requires explicit disclosure clearance.

## Claims and safety

- No rank is meaningful without its exact artifacts and methodology.
- Included-key signatures are tamper evidence, not non-repudiation.
- Arena and CTF operations produce no silent telemetry or private corpus input.
- Real-system probes and Arena execution require a separately admitted
  containment backend and fresh human authorization.

## Local commands

The public CLI accepts strict JSON documents and rejects unknown fields:

```console
sova probe verify response.json --nonce REQUEST_NONCE --scope manifest --key-id sha256:...
sova arena run arena.json arena-output
sova arena agent-run agent-arena.json agent-arena-output --allow-provider-calls
sova leaderboard build leaderboard.json leaderboard-output
sova ctf build ctf.json ctf-catalog.json
sova replay clip clip.json replay.y4m
```

Paths inside leaderboard and CTF specifications resolve relative to that
specification and cannot escape its directory. The safe deterministic example
is in [`examples/topics-21-23`](../../examples/topics-21-23/README.md).
