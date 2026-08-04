<!-- status: implemented -->

# Topics 24-27 validation

Implemented work includes private research/IP disposition ledgers, publication
package validation, onboarding and diagnostics, safe managed-data removal,
first-run documentation, deterministic release SBOM/checksums, public
governance, a neutral conformance kit, authorized-target planning, and signed
website/software fixture pipelines.

Focused tests cover secret-free initialization, credential non-disclosure,
deletion identity/preview/unknown-file refusal, SBOM determinism/transitive
closure, checksum tampering/traversal/extra-file detection, conformance ZIP
reproducibility and hostile membership, nested target secrets, inert planning,
and repeated trace/capsule fixture verification.

The final Windows/Python 3.11 run collected 769 tests: 768 passed, the optional
official Codex lane skipped because Codex was not logged in, and branch-aware
coverage reached 95.31%. Strict typing passed for 248 files, Ruff passed for
371 files, all 67 registered CLI command handlers executed, repository and
public-boundary checks passed, and the dependency audit found no known
non-waived vulnerability.

Two source and wheel builds were byte-identical; their artifact digests belong
in the release checksum manifest rather than inside the source archive itself.
A clean wheel environment passed initialization, diagnostics, previewed and
identity-confirmed deletion, mapping, signed website/software fixture flows,
conformance export/verification, the sleeper demo, trace verification, capsule
inspection, and MCP manifest generation.

After publication, commit `6f70420` passed the quality and DCO jobs, Linux
Python 3.11-3.14, Windows 3.11/3.14, macOS 3.11/3.14, the aggregate CI gate,
CodeQL, secret scanning, and the public-repository boundary workflow.

The complete evidence and remaining external boundaries are recorded in the
[whole-repository validation report](./final-validation-2026-08-04.md).

External reviews, actual signed public releases, real provider comparisons,
independent adapters/readers, live target runs, and promoted-launch founder
approval remain explicit external gates. Topic 27 remains open-ended by design.
