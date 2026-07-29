<!-- status: implemented -->

# Compatibility test suites

This directory is the permanent home for compatibility contracts.

- `schemas/` retains readers, validation cases, and migrations for every published stable schema.
- `adapters/` retains executor and importer contract suites by adapter-version range.
- `golden/` is sourced from the provenance-controlled artifact fixtures.

Topic 02 creates and tests the structure. Topic 03 adds shared vocabulary,
identity, lifecycle, taxonomy, coverage, and historical-version contracts but
does not create an artifact schema. Topics 04 and 05 add `.sova` and
`.sova-trace` compatibility cases. No experimental fixture may be represented
as stable.
