<!-- status: decision -->

# Ecosystem durability, archival, and benchmark aging

Every stable release should retain source, wheel/sdist, checksums, SBOM,
provenance, conformance kit, schemas, migrations, methodology versions, and
security advisories in at least two independently controlled archives.

Benchmark snapshots record creation date, source/licence, model/provider
versions, disclosure status, contamination risk, known leakage, deprecated
cases, and replacement rationale. A result expires from current comparison when
its target, dependency, model, or methodology can no longer be reproduced. Old
results remain archived and visibly stale rather than rewritten.

External registries, authors, verifiers, and independent implementations are
desired evidence, not current claims. A mirror must verify the same immutable
index and cannot acquire TRUSCOR authority by mirroring public files.
