<!-- status: implemented -->

# Capsule migration and compatibility

ADR-0002 is normative. The reference implementation currently demonstrates a
two-step experimental chain:

```text
0.0.1 -> 0.0.2 -> 0.1.0
```

The migrator:

- never overwrites the source;
- applies one deterministic edge at a time;
- preserves source values and unknown optional values;
- moves legacy unknowns into `x-sova-legacy`;
- retains source digest, source version, and the complete path;
- distinguishes canonical source-manifest identity from exact source-package
  identity;
- embeds the exact historical `manifest.json` as a
  `migration-source-manifest` object during package migration;
- emits a machine-readable preflight classification, preserved-unknown list,
  assumptions, and blockers;
- records transformations in provenance;
- sets conservative safety and fresh-authorization requirements when older
  versions omitted them;
- records unavailable historical context as unknown;
- rejects unknown required behavior;
- refuses unknown legacy values when mapping them would invent meaning;
- does not copy a signature onto changed bytes.

"Lossless" means no information present in the source was silently lost and no
execution meaning was weakened. It does not mean that a migrator invented
information the source never recorded. Compatible downgrade is allowed only
when the newer artifact uses no feature unavailable in the older schema.

Stable `1.0` remains blocked until real-scenario pressure, three experimental
revisions, hostile-input testing, independent implementations, cross-language
canonical digests, and migration-corpus evidence satisfy ADR-0002.

`sova compat` performs this analysis without writing. Migration refuses an
existing destination and failed conversion emits no destination package.
