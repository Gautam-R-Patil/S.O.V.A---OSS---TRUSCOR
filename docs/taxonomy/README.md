<!-- status: implemented -->

# SOVA attack taxonomy

The native attack taxonomy is packaged with the CLI so classification and
validation work offline.

- Machine source:
  `src/sova/contracts/data/attack-taxonomy-0.1.0.toml`
- Generated reference: [SOVA attack taxonomy 0.1.0](sova-attack-taxonomy.md)
- Validator: `sova.contracts.taxonomy`
- Controlling decision:
  [ADR-0008](../decisions/0008-topic-03-domain-contracts.md)

## Governance

SOVA OSS maintainers own the native taxonomy. Taxon IDs and published versions
are permanent:

- PATCH clarifies wording without changing classification;
- MINOR adds compatible taxa or mappings;
- MAJOR changes existing classification meaning;
- deprecated and retired IDs remain reserved forever;
- retired entries remain present and may name a replacement;
- external mappings always pin the external catalog version.

The `standard` profile contains every active native taxon exactly once.
`custom` profiles may select a subset or namespaced additions but are
non-standard and not leaderboard-comparable.

External framework names and identifiers are factual interoperability
references. A mapping states the native SOVA taxon's relationship to the
external entry; it does not claim endorsement or exact equivalence.
