<!-- status: implemented -->

# Schema compatibility

Add one immutable directory per released artifact schema version. Stable
schemas, readers, migrators, and conformance fixtures are never rewritten;
corrections receive a new version.

Valid `.sova` and `.sova-trace` goldens now cover the experimental schemas,
migrations, hostile inputs, public scenario corpus, and validator parity.
Topic 02 intentionally did not invent those schemas early.
