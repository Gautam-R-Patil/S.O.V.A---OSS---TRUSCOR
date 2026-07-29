<!-- status: implemented -->

# Compatibility test suites

This directory is the permanent home for compatibility contracts.

- `schemas/` retains readers, validation cases, and migrations for every published stable schema.
- `adapters/` retains executor and importer contract suites by adapter-version range.
- `golden/` is sourced from the provenance-controlled artifact fixtures.

Topic 02 creates and tests the structure. Topics 03–05 add the first real data
model, `.sova`, and `.sova-trace` compatibility cases. No experimental fixture
may be represented as stable.
