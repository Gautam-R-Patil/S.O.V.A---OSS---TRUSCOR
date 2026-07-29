<!-- status: planned -->

# Schema compatibility

Add one immutable directory per released artifact schema version. Stable
schemas, readers, migrators, and conformance fixtures are never rewritten;
corrections receive a new version.

Valid `.sova` and `.sova-trace` goldens begin only after Topics 04 and 05 define
their experimental schemas. Topic 02 intentionally does not invent those
schemas early.
