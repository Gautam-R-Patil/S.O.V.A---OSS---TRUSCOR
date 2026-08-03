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

Schema files are versioned and immutable after a tagged release. Semantics,
canonicalization, migrations, threat boundaries, and interoperability rules
are specified in [`docs/specifications`](../../../docs/specifications/README.md).
