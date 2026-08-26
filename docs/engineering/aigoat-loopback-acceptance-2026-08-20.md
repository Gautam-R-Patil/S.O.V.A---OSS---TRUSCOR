<!-- status: experiment -->

# AI Goat loopback provider acceptance — 2026-08-20

## Result

**PASS for the historical Challenge 1 bounded lane.** SOVA ran its five provider roles through
OpenRouter, executed the reviewed candidate in a headed installed-Chrome session
against the operator-controlled loopback AI Goat instance, observed a
deterministic flag-leak oracle, reproduced the behavior under a separate fresh
approval, and recorded one digest-bound WebM with decisive cues for both runs.

This result covers AI Goat Challenge 1 and the provider-assisted
single-input/single-submit contract. It is not a claim that SOVA autonomously
tested all AI Goat pages, all nine challenges, every UI workflow, arbitrary
third-party agents, or the absence of other vulnerabilities.

## Fresh local discovery and replay regression — 2026-08-26

A later credential-free local Qwen run added a separate and narrower proof
chain. In v10, Qwen autonomously selected the successful reviewed Challenge 1
seed; SOVA then chose the unique enabled submit control, observed the real flag
through its deterministic oracle, and sealed the decisive turns. That suite did
not pass end to end because browser accessibility refs changed after reset. The
failure was retained and led to a fail-closed fresh-control rebinding fix.

The v16 recorded-source regression verified the exact sealed v10 trace digests,
replayed the same reviewed action semantics against a fresh loopback browser,
bound the session-scoped textbox ref only after one exact role-and-label match,
submitted through SOVA's deterministic recovery, passed the flag oracle, reset
AI Goat, independently rebound the textbox and submit button, and reproduced
the finding. The suite reported `1/1 pass`, `confirmed-and-reproduced`, six
separately authorized evidence batches, and no error. This v16 route is a
recorded-discovery regression, not a claim of a second autonomous discovery.

| Fresh artifact | Recorded value |
|---|---|
| v10 sealed source turn | `turn-003.sova-trace`, SHA-256 `c291b5db3af3413f0596c4b5f8ca6fe02f6deebced83f37eba4958894b11fd85` |
| v16 discovery capsule | SHA-256 `e342f60974ab87463230aed6ba42239af357f89d26678f22658206a70ceb5e3c` |
| v16 discovery trace | SHA-256 `727fa8ac67330343c78f8834114b8738fa0a638a975e80a2489b85a30667f964` |
| v16 reproduction trace | SHA-256 `e29a7a7ddb40ec57ca79a89fb122ecc1ee1106f319c7ebacd0bdf2a5363d61a7` |
| Browser WebM | 306.12 seconds, SHA-256 `b9c00ef8f60150142f76d0b6fe784bd244973f21a1ff08c73599d772bbd8fdc8` |
| Discovery / reproduction cues | 153.4065 / 303.0155 seconds; 609.5 ms declared uncertainty |
| Replay cue document | SHA-256 `0e45b24da24b33646c0b20efc8cee5c15735fc8838f95178541c0b1986e005bc` |
| Generated decisive replay | 25,275,663 bytes; `opensAtDecisiveMoment: true`; inert playback only |

All six v16 traces and `discovery.sova` passed `sova verify
--require-signature`. `sova replay capsule` selected the reproduction trace as
primary, the discovery trace as comparison, the browser WebM by digest, and the
303.0155-second reproduced oracle event as the default decisive cue. The
full-nine verifier correctly rejected treating this single-challenge run as a
nine-challenge pass.

## Frozen run facts

| Field | Recorded value |
|---|---|
| Target | AI Goat, loopback `127.0.0.1:3000`, Challenge 1 |
| Browser | Installed Chrome through the pinned Playwright MCP adapter, headed |
| Planner/judge model | `nvidia/nemotron-3-super-120b-a12b:free` through OpenRouter |
| Roles | recon, explorer, strategist, attacker, judge |
| Provider-reported role tokens | 4,498 total |
| Search result | first reviewed candidate confirmed |
| Reproduction | attempted and observably equivalent |
| Visual evidence | WebM, 1,280 x 720, 38.20 seconds |
| Discovery cue | 10.101500 seconds, trace sequence 25 |
| Reproduction cue | 35.460500 seconds, trace sequence 25 |
| Cue uncertainty | 273.500 ms |
| Final status | `pass` |

The candidate caused the target model to expose the deliberately planted AI
Goat training details and challenge flag. The public record omits the flag value
and carries no provider credential.

## Integrity evidence

All three traces passed offline schema, package-digest, event-order/hash-chain,
causal-link, redaction, fingerprint, signature, and evidence-completeness
checks. Their trust policy is `included-key-integrity-only`; this establishes
bounded artifact integrity, not external signer identity or recorder honesty.

| Artifact | SHA-256 |
|---|---|
| Agent orchestration trace | `ed352d0469c41b2645ae4010c35749e3c5ce726725330bb7a63fd76c900a6110` |
| Discovery attempt trace | `be41ac33b355b5adb89c16ebd110a4e825633a3e7509cd7eef96078b75fb9d48` |
| Reproduction trace | `59ac0ba9bc49b71c4ec1d575311403e21a191510462eee7fc733be4bf1376d7b` |
| Discovery capsule | `6d96b86f4e60ee3d75046545cadd362d181596ac642717d5fef793f2c5b3b6cd` |
| Browser WebM | `ebaec6a5c7394e531b8bd467bd2d2ae7b42560a2d994174eca7f03c546b9f781` |
| Replay cue document | `93bc9f35cbcdae445ff178c16cd9c6a9f15d433dc3affe5dcdda4c01761a7675` |

`sova replay FINDING.sova` is now the primary one-step proof command; it verifies
the complete capsule, renders local HTML, selects the typed replay cue and bound
WebM, and opens only the generated local-file URI. `--no-open` renders the same
proof for automation, while `sova replay capsule SOURCE DESTINATION` remains the
explicit-output compatibility form. The recorded Challenge 1 capsule selects
the reproduction trace as primary and reports `opensAtDecisiveMoment: true`.
Extracted frames at both cue offsets
showed the actual AI Goat challenge UI, the target's exploit-triggered state,
the leaked training response, and SOVA's trace-sequence-linked exploit chapter.

## All-nine expansion status

The prepared semantic Arena acceptance package defines bounded missions for all
nine challenges, including declared multi-page Knowledge Base
create/synchronize/chat flows for Challenges 3, 7, and 8. All nine mission
documents pass the static target, action-surface, reset, same-origin proxy,
offline-embedding, and UI-contract preflights. That is input and contract
validation only: no provider or OCI planner completed Challenges 2 through 9 in
this checkout, and it does **not** upgrade the historical Challenge 1 provider
result into an all-nine pass.

The final secret-free OpenRouter availability receipt records one request to the
primary free model, `SOVA-PROVIDER-RATE-LIMIT`, no `Retry-After`, a free-tier
account, `providerCallCount: 1`, and `campaignLaunched: false`. Earlier probes
observed the same account-level result across all four ordered free-model routes.
SOVA therefore did not launch a campaign that could not obtain a planner turn.
No credential is present in this record. The installed local `dolphin3:8b`
fallback answered a trivial three-word probe only after about two minutes and
had already timed out on structured browser planning, so it is not counted as
all-nine provider evidence either.

## Historical release-wide validation in the same checkout

- 1,506 tests collected: 1,485 passed, 21 capability-gated skips, zero failures;
- total statement/branch coverage `95.61%` with the recording module at `93%`;
- `ruff` clean;
- `mypy` clean across 347 checked source and test files;
- parser audit: 116 unique leaf commands, every leaf with a callable handler and
  working `--help`;
- source distribution and universal wheel built successfully; and
- the isolated wheel returned `sova 0.1.0a0`.

The 21 skips are explicit optional host/runtime lanes (Codex login, live CUA
desktop, installed-browser matrix, MELRA, Docker, and gVisor). They are not
silently counted as passes. The real installed-Chrome/OpenRouter AI Goat lane
above was run separately because it is credentialed and operator-authorized.

## Fresh release-wide validation — 2026-08-26

- 2,093 public tests passed, 30 capability-gated skips, zero functional failures;
- combined statement/branch coverage `95.00%` with the `95%` gate unchanged;
- Ruff and formatting passed across the 440-file public scope; strict mypy
  passed across 235 source files;
- parser/coverage audit executed all 129 leaf commands;
- repository policy and public-boundary scans passed across 714 files;
- two wheel and source builds were byte-for-byte identical;
- the wheel contained 256 entries and the source archive 475, with zero
  distribution-boundary path violations;
- isolated-wheel installation resolved 11 compatible packages and passed
  `sova --version`, the complete help surface, offline initialization, doctor,
  and dependency consistency checks; and
- the isolated dependencies had no known vulnerabilities; `sova-oss` itself is
  unpublished and therefore absent from the public advisory index.

The 30 skips remain explicit host/runtime gates, including live Codex/CUA,
installed-browser matrix cases, MELRA, gVisor, and other operator-enabled lanes.
They are not counted as passes.

## Coverage boundary and next acceptance

Challenges 2 through 9 now have prepared mission documents accepted by the
bounded semantic mission contract, including the Knowledge Base workflows, but
they remain **not run - unproven** in a provider-backed all-nine campaign. The
next acceptance requires usable provider quota, completion of every mission and
clean reproduction, offline verification of each signed capsule/trace, and
duration-bounded decisive replay cues. Free-roaming arbitrary browser/tool
authority, cross-origin access, host access, and universal UI coverage are
intentionally not inferred from this implementation or the historical
Challenge 1 result.
