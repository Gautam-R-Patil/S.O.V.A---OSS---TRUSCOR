<!-- status: implemented -->

# Replay application and blinded causal validation - 2026-08-09

## Delivered inventory

- `sova replay timeline` now emits the evidence-native interactive application.
- `sova replay serve` tails a sealed trace or validated writer prefix through a
  bounded loopback capability URL and finite SSE responses.
- `sova forensics blind-fixture`, `blind-run`, `blind-score`, `blind-keygen`,
  and `blind-sign-key` implement the separated causal-study workflow.
- Four JSON Schema 2020-12 documents cover study, answer key, predictions, and
  score artifacts.
- Public specifications define replay security and causal-study semantics;
  private prior-art/gate decisions remain under `private/research/`.

## Deterministic acceptance

The final offline repository run reports **1,160 passed**, **13 expected
optional skips**, and **95.23% branch coverage** against a 95% minimum. The CLI
coverage audit reports **106/106 registered leaf commands** with no unexecuted
handler. Ruff formatting/linting, strict mypy, glossary generation, taxonomy
generation, and repository-policy checks pass.

The lockfile check passes. The strict locked dependency audit against OSV
reports no known vulnerability and uses no advisory ignore. The runtime is
locked to fixed `cryptography 50.0.0`; no dependency was added for this
milestone.

The source distribution and universal wheel build successfully. A clean Python
3.11 environment resolved the wheel's declared dependencies, then passed
installed-entrypoint version, blinded fixture/run/score, complete sleeper demo,
bounded replay-service startup, and static replay export. Release checksums are
generated from the final immutable candidate rather than embedded recursively
inside the source archive.

The focused suite covers:

- static and live replay, play controls, sensor lanes, recorded links,
  comparison, hostile HTML/script strings, CSP, and no action execution;
- partial lines, malformed objects, sequence gaps, duplicate identifiers,
  unavailable parents, residual secret fields, hash tampering, symlinks, source
  limits, event limits, and sealed transition;
- capability and bad routes, exact Host headers, GET/HEAD/POST policy, SSE event
  IDs, `Last-Event-ID`, keepalive, client limits, and service lifecycle;
- exact task/key/prediction/score schemas, malformed trials and labels,
  committed-answer substitution, frozen-prediction binding, incorrect and
  abstained decisions, declared gates, and output overwrite refusal; and
- DSSE signing and key pins, tampering, missing/wrong keys, partial-key rollback,
  and binary-exact raw key persistence on Windows.

The default synthetic stochastic study (`seed=20260809`) produces 16 cases,
three predeclared abstentions, decision accuracy `1` (Wilson 95% interval
`[0.806392, 1]`), coverage `0.8125`, selective accuracy `1`, false-attribution
rate `0`, macro F1 `1`, supported-prediction Brier score `0.092449`, and all
four predeclared gates passing. These are fixture-scoped software results, not
real-agent performance.

## Real browser interaction check

A local 17-event trace was served to installed Chrome through the loopback
reference service. The rendered application showed eight sensor-family lanes
and three actors. The acceptance operator observed event navigation advancing
from 1/17 to 2/17 under playback, selected 4x speed, filtered to the network
lane, and followed the recorded relation from network egress sequence 13 to
tool request sequence 11. Link navigation cleared the obstructing filter as
designed. Browser console warnings and errors were empty.

This is interaction evidence on one local Chrome/runtime combination, not an
accessibility, performance, cross-browser, or independent security review.

## Security conclusions

- Trace-controlled content remains text; it is not HTML, CSS, URL, or code.
- Live prefixes are visibly unsealed and rechecked at every snapshot. Only a
  finalized package that passes `TraceReader` verification becomes sealed.
- The service is local reference transport, not production HTTP. Capability
  URL secrecy does not resist a compromised host, browser history disclosure,
  screenshots, or local administrators.
- Answer commitments detect post-freeze replacement but do not establish label
  truth. DSSE plus a key pin establishes payload/key binding but not reviewer
  identity, independence, or qualification.
- A hash chain provides tested tamper evidence, never unforgeability,
  non-repudiation, recorder honesty, or causal truth.

## Research and IP gates

- Evidence replay paper/patent: **NO-GO now**. The product result is useful but
  uses mature trace-UI, content-security, and SSE concepts.
- Blinded causal-validation paper: **HOLD** until a real nondeterministic study,
  strongest-baseline comparison, ablations, external review, limitations, and
  replication exist.
- Blinded protocol patent: **NO-GO now** unless later work identifies a precise
  non-obvious mechanism beyond known commitments, signing, blinding, paired
  interventions, and statistical scoring.

No publication, upload, filing, novelty claim, or external reviewer identity is
created by this milestone.

## External-only gates

An independent causal result still requires a separately governed reviewer,
preregistered real-agent dataset, concealed answer key, intervention-fidelity
audit, frozen predictions, signed unblinding, and transparent failures. Large-
trace usability, accessibility, cross-browser coverage, and independent replay
security review also remain external validation work.
