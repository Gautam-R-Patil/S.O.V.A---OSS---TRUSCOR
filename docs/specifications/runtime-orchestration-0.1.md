<!-- status: implemented -->

# Runtime orchestration and evidence firewall 0.1

The SOVA Runtime is the public, provider-neutral loop that turns a mapped,
authorized target into attempts and evidence. It is not the proprietary SOVA
Engine corpus or operating service.

## Pipeline and role isolation

The reference pipeline has recon, surface mapping, attack planning, execution
and mutation, then evidence/result assembly phases. Recon, explorer,
strategist, attacker, judge, mutator, refiner, and attribution are typed roles.
Only bound roles run.

Each role receives a canonical prompt with an explicit trust contract. Before
execution, a role may see the map summary and prior structured role outputs.
The judge receives neither attacker prose nor attacker/model chain of thought.
It has no target tools. Refiner and attribution roles receive the admitted
evidence packet and adjudicated verdict, not the target transcript.

The orchestration trace records role, model identifier, prompt/response digest,
content-capture decision, tool-call count, provider fallback classes, byte
usage, limits, attempts, and phases. Raw content is off by default. SOVA does
not claim to capture hidden model reasoning.

## Model routing and budgets

Models are selected per role behind a small `RoleModel` contract. Provider
errors, over-budget responses, and forbidden tool calls cause bounded fallback
to the next configured model. Model swapping does not modify scenario intent.
The runtime enforces model-turn, output-byte, attempt, elapsed-time, mutation,
and admitted-effect ceilings. A token ceiling can be configured only when the
adapter reports token usage; if a bounded run receives no such usage, it fails
visibly instead of pretending the ceiling was enforced. Cost values remain
explicitly unavailable unless an adapter supplies authorized usage metadata.
The elapsed-time check detects an overrun before and after an adapter call; the
adapter or executor must separately enforce an interrupting timeout. Effect
prevention remains the authorization ledger's job—the runtime's effect-atom
ceiling bounds admitted evidence after capture and is not a containment claim.

The mandatory lane uses `ScriptedModel` and requires no network or credential.
Local or hosted models are optional adapters and never a core dependency.

## Standard and custom profiles

`standard` binds a versioned taxonomy and methodology and is comparison
eligible. `custom` requires the canonical digest of its configuration, carries
the watermark `CUSTOM / NON-STANDARD`, and is excluded from shared comparison.
Both remain fully inspectable and useful to the owner.

## Evidence-firewalled adjudication

Target execution writes the canonical `.sova-trace`. The evidence firewall
first verifies trace integrity, then performs a one-way allowlisted projection
into typed atoms. Attacker/model response events are excluded. Tool outputs are
reduced to normalized outcome metadata, and every atom retains event and
projection digests.

Adjudication order is:

1. deterministic oracle;
2. deterministic policy rule over admitted fields;
3. evidence-referenced model interpretation only when needed;
4. `inconclusive` and human review when evidence is insufficient or judges
   disagree.

Every model proposition must cite admitted evidence identifiers. The verifier
rejects missing identifiers mechanically. Citation proves linkage, not semantic
truth, sensor truth, or causal correctness. Ensemble agreement is not promoted
to independent ground truth. Calibration utilities score frozen predictions
against labeled ground truth and count abstentions separately.

This one-way typed projection is a research candidate, not a public novelty or
robustness claim. Adaptive attack, clean-utility, ablation, calibration, and
independent-case experiments remain required.

## Search records, sessions, and reliability

Attempts preserve candidate digests, near misses, outcomes, and effort. The
owner-local content-addressed experience store records only digests, outcome,
attempts, turns, mutations, duration, and trace digest. It stores no prompts,
model output, secret values, or remote synchronization and has no connection to
a TRUSCOR private corpus.

The session broker leases pre-provisioned authorized identities through opaque
`sova-secret:` references. It enforces target, agent, scope, TTL, concurrency,
and explicit shared-state permission. Passwords, cookies, tokens, and browser
profile material are not placed in role prompts or trace mappings.

The reliability plane selects compatible executors, normalizes failures,
requires SOVA-owned post-action verification, and permits fallback only for
safe retry classes. An unverified non-idempotent action is never retried.
Checkpoints omit action inputs and session material. This is resilient workflow
engineering, not a security-sandbox claim.
