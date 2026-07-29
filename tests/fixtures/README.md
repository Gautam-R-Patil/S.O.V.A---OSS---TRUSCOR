<!-- status: implemented -->

# Public test-fixture policy

Every public fixture is synthetic or has explicit, redistributable public
provenance in `provenance.toml`. Anonymized client or private-corpus data is not
accepted.

The files under `golden/` are deliberate **rejection sentinels**. They reserve
the fixture and digest workflow without pretending that Topics 04 and 05 have
already defined valid `.sova` or `.sova-trace` schemas. Future valid goldens
will be added beside—not substituted for—these immutable negative cases.
