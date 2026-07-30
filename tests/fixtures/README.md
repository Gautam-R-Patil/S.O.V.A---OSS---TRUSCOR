<!-- status: implemented -->

# Public test-fixture policy

Every public fixture is synthetic or has explicit, redistributable public
provenance in `provenance.toml`. Anonymized client or private-corpus data is not
accepted.

The `unsupported-pre-schema` files are immutable **rejection sentinels**. Valid
goldens live beside them and are checked for exact canonical bytes, schema
validity, and integrity. A golden fixture demonstrates compatibility with the
declared experimental version; it is not real user evidence.

`golden/trace/all-event-families-0.1.0.jsonl` is generated deterministically by
`scripts/generate_trace_goldens.py`. Run the script without flags to check exact
bytes; use `--write` only when intentionally versioning the event registry.
