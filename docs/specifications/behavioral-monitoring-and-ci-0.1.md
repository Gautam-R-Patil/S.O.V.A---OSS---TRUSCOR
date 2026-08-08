<!-- status: implemented -->

# Behavioral monitoring and CI 0.1

## Recorder

`sova trace run SPEC TRACE` executes exactly one argument-vector command. The
executable must resolve to an exact allowlisted path, shell invocation is not
used, the working directory must exist, authorization must be explicit, and
the timeout is bounded. The process request/result and any adapter-supplied
registered observable events stream into a signed trace. Capture profiles are
`lite`, `standard`, `forensic`, and `interpretability`; they retain the privacy
semantics of `.sova-trace` 0.1.

`sova trace command TRACE --working-directory DIR -- EXECUTABLE ARG...` builds
the same strict specification only after a human-operated terminal reviews a
canonical digest of the resolved executable, full secret-screened argument
vector, working directory, timeout, and capture profile. It refuses secret-like
option names and values, invokes no shell, and adds a digest-bound authorization
event. This convenience front door does not strengthen host isolation.

The recorder separately measures process elapsed time, total recorder elapsed
time, and their non-negative difference as instrumentation-path time. The ratio
is a per-run engineering measurement, not a causal or cross-machine benchmark.
Existing trace recovery handles interrupted package segments. A process timeout
or failure receives a terminal trace state.

## Snapshot and diff

`sova trace snapshot SPEC --output SNAPSHOT` canonicalizes these axes:

- environment: target, model, tool schemas, permissions, dependencies,
  environment, registry snapshot, and approval surface;
- behavior: observed effects, reproduction rates, and findings;
- methodology: method, capture profile, and taxonomy.

Every axis receives its own digest. Missing axes are explicit
`not-recorded`. `sova diff LEFT RIGHT` reports changes by axis and links any
trace references. Methodology drift makes results non-comparable. Environment
or behavior drift alone does not establish causation or new security evidence.

## Sentinel, CI, and self-check

`sova sentinel` runs one local comparison, applies separate thresholds, alerts
on approval-surface changes, and appends local JSONL history with methodology
and policy digests. It does not upload and is self-monitoring only.

`sova ci` applies deterministic environment, behavior, methodology, and
flakiness policy. It emits a machine report, SARIF 2.1.0, and annotation rows.
Standard/custom profile labels and operator-controlled retention are explicit;
SOVA never patches. The reusable workflow in
`.github/workflows/sova-behavioral-ci.yml` is manually or caller invoked and
must receive explicit artifact paths.

`sova self-check create` builds a versionable file-hash baseline.
`sova self-check verify` reports changed/missing files. The baseline is unsigned
and must be protected by version control or a separately trusted signature.
