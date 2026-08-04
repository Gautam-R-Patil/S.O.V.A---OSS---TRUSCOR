<!-- status: implemented -->

# Conformance kit 0.1

`sova conformance export` creates a byte-reproducible ZIP containing every
packaged experimental JSON Schema, canonical-JSON vectors, unknown-extension
preservation vectors, and a content-addressed manifest. ZIP timestamps,
permissions, order, and compression settings are fixed.

`sova conformance verify` rejects traversal, backslashes, absolute paths,
symlinks, duplicate/directory entries, undeclared entries, digest/size changes,
entry-count and total-size excess, and unsafe compression ratios.

Passing establishes only the included schema and vector contracts. It does not
establish executor, behavioral, security, or semantic-reproduction equivalence.
