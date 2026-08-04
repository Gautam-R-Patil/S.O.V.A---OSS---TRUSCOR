<!-- status: implemented -->

# Air-gapped use

The parser, schemas, capsule/trace verifier, playback, mapper, deterministic
fixtures, conformance kit, registry verifier, and release-metadata tools have no
required network call. Prepare the exact source/wheel, lockfile artifacts,
checksums, SBOM, and any registry snapshot on a connected staging machine, then
transfer them under the organization's media-control process.

In the disconnected environment:

```console
sova doctor LOCAL_STATE
sova conformance verify sova-conformance.zip
sova release verify-checksums RELEASE_DIRECTORY RELEASE_DIRECTORY/SHA256SUMS
sova registry verify LOCAL_REGISTRY
sova verify ARTIFACT
```

Provider APIs, remote registries, external timestamp authorities, online
Sigstore identity verification, and optional MCP package acquisition do not work
offline. Their absence must be reported as a visible capability limitation,
never silently substituted.
