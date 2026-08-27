# Bundled SOVA schemas

These JSON Schema 2020-12 documents are the normative structural contracts for
the experimental SOVA `0.1.0` artifact family:

The family also includes `map-report-0.1.0.schema.json`, the distinct
evidence-aware capability-map report contract.

- `capsule-manifest-0.1.0.schema.json` — `.sova` behavior-capsule manifest
- `scenario-0.1.0.schema.json` — portable scenario/replay recipe
- `trace-manifest-0.1.0.schema.json` — `.sova-trace` manifest
- `event-0.1.0.schema.json` — canonical observable trace event
- `forensic-reconstruction-0.1.0.schema.json` — uncertainty-preserving forensic timeline
- `evidence-0.1.0.schema.json` — bounded self-assessment evidence bundle
- `composition-report-0.1.0.schema.json` — composition-search evidence and attribution
- `playbook-0.1.0.schema.json` — complete native or community security playbook contract
- `playbook-library-0.1.0.schema.json` — versioned, provenance-separated playbook catalog
- `methodology-policy-0.1.0.schema.json` — budget, scheduler, and allowed-effect policy
- `methodology-observations-0.1.0.schema.json` — evidence-bound replanning observations
- `methodology-plan-0.1.0.schema.json` — deterministic six-phase methodology plan
- `playbook-submission-0.1.0.schema.json` — DSSE-signed local contribution envelope
- `adapter-descriptor-0.1.0.schema.json` — pinned external-tool admission contract
- `normalized-observation-0.1.0.schema.json` — unverified, evidence-bound tool assertion
- `adapter-run-report-0.1.0.schema.json` — authorization, execution, cleanup, and trace result
- `oracle-proposal-0.1.0.schema.json` — typed non-authorizing oracle hypothesis
- `oracle-calibration-0.1.0.schema.json` — blinded false-positive/miss calibration and promotion
- `oracle-comparison-0.1.0.schema.json` — differential or metamorphic relation result
- `decisive-evidence-set-0.1.0.schema.json` — digest-bound cue/raw/media/trace/capsule set
- `fresh-reproduction-0.1.0.schema.json` — independent fresh-generation reproduction record
- `assessment-coverage-0.1.0.schema.json` — eight-dimensional non-exhaustive coverage report
- `blinded-oracle-study-0.1.0.schema.json` — label-free seeded or external calibration task
- `blinded-oracle-predictions-0.1.0.schema.json` — predictions frozen before unblinding
- `blinded-oracle-answer-key-0.1.0.schema.json` — separately committed calibration labels

- `blinded-causal-study-0.1.0.schema.json` — label-free randomized intervention task
- `blinded-causal-answer-key-0.1.0.schema.json` — committed, optionally DSSE-signed labels
- `blinded-causal-predictions-0.1.0.schema.json` — pre-unblinding attribution output
- `blinded-causal-score-0.1.0.schema.json` — post-unblinding metrics and declared gates
- `worker-job-manifest-0.1.0.schema.json` — immutable controller-authorized worker job
- `worker-attestation-0.1.0.schema.json` — exact worker host, binary, image, and policy measurements
- `worker-protocol-message-0.1.0.schema.json` — signed peer-bound controller/worker message
- `worker-network-receipt-0.1.0.schema.json` — allowed or denied broker flow evidence
- `worker-secret-receipt-0.1.0.schema.json` — redacted scoped-capability use evidence
- `worker-evidence-report-0.1.0.schema.json` — controller-validated hostile-output report
- `worker-cleanup-receipt-0.1.0.schema.json` — exact-job teardown verification
- `firecracker-launch-plan-0.1.0.schema.json` — jailer, cgroup, drive, device, and watchdog plan

Schema files are versioned and immutable after a tagged release. Semantics,
canonicalization, migrations, threat boundaries, and interoperability rules
are specified in [`docs/specifications`](../../../docs/specifications/README.md).
