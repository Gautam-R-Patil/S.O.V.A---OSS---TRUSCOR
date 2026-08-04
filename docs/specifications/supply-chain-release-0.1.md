<!-- status: implemented -->

# Supply-chain and release metadata 0.1

`sova release sbom uv.lock DEST --scope runtime` emits timestamp-free canonical
CycloneDX 1.6 JSON for the transitive runtime closure. `--scope all` includes
development-only locked packages. The lockfile digest and no-network status are
recorded.

`sova release checksums DIST DIST/SHA256SUMS` writes a sorted SHA-256 manifest.
Verification rejects malformed/duplicate/traversing rows, changed or missing
files, undeclared additions, symlinks, and resource-limit excess.

GitHub build provenance is complementary: a checksum detects changed bytes,
the SBOM describes locked components, and an attestation relates an artifact to
a workflow identity. None proves source correctness or eliminates review.
