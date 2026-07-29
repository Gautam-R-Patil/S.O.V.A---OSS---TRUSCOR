<!-- status: implemented -->

# Shared domain contracts

Topic 03 defines the language and validation primitives used by every later
SOVA artifact. The controlling decision is
[ADR-0008](../decisions/0008-topic-03-domain-contracts.md).

| Contract | Human specification | Executable source |
|---|---|---|
| Vocabulary | [Generated glossary](../glossary.md) | `docs/glossary.toml` and `sova.contracts.vocabulary` |
| Finding lifecycle | [Finding lifecycle](finding-lifecycle.md) | `sova.contracts.lifecycle` |
| Stable identities | [Version contracts](version-contracts.md) | `sova.contracts.identifiers` |
| Attack taxonomy | [Attack taxonomy](../taxonomy/sova-attack-taxonomy.md) | `sova.contracts.data/attack-taxonomy-0.1.0.toml` |
| Observed coverage | [Coverage model](coverage-model.md) | `sova.contracts.coverage` |
| Historical context | [Version contracts](version-contracts.md) | `sova.contracts.versions` |
| Vision examples | [Source-example reconciliation](source-example-reconciliation.md) | Contract tests |

These are experimental `0.x` contracts. They may change before `1.0.0` under
ADR-0002. Published versions are never silently rewritten.

They do not define valid `.sova` or `.sova-trace` fields, execute a target, or
make a security claim.
