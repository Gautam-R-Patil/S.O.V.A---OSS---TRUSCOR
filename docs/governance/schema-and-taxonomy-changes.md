<!-- status: implemented -->

# Schema and taxonomy change process

Every change declares its artifact family, old/new versions, stable invariants,
migration effect, unknown-extension behavior, downgrade/rollback behavior,
methodology/taxonomy coupling, and conformance vectors. A compatible change
must preserve the meaning present in the source. A migration that lacks needed
source information must refuse visibly rather than invent it.

Experimental `0.x` permits change but not silent breakage. Stable `1.x` cannot
be declared until multiple independent real scenarios, chained migrations,
cross-machine readers, and external implementation feedback have tested the
invariants. Taxonomy additions require definitions, examples, exclusions,
mapping effects, and versioned denominators.
