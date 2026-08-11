<!-- status: implemented -->

# Last-mile engineering validation — 2026-08-11

This record separates code and local runtime evidence from external launch
facts. It does not declare SOVA stable, universal, independently validated, or
adopted.

## Implemented in this pass

- second browser executor mapping for pinned Chrome DevTools MCP 1.6.0;
- four-class self-owned website matrix;
- Windows and macOS Appium adapters plus Linux AT-SPI adapter;
- gVisor `runsc` OCI backend and opt-in live lane;
- claim-conditioned sensor coverage ledger;
- preregistered cross-provider/model experiment matrix;
- strict twelve-gate acceptance receipt and stable-readiness evaluator;
- authenticated acknowledged monitoring webhook;
- service-supervision and community TLS deployment blueprints; and
- candidate-only Sigstore signing and GitHub provenance workflow.

## Real browser execution

On this Windows workstation, Chrome and pinned Playwright MCP executed all four
matrix classes. The static class passed separately in 27.35 seconds; SPA,
authenticated-session, and popup-interrupted classes then passed in 51.69
seconds. Every case performed a primary run and fresh controlled reproduction,
verified signed traces, and verified the evidence capsule. These are local
self-owned results, not an external website field study.

## Unavailable live infrastructure

Docker Desktop's client was installed but its engine was not running, and no
`runsc` runtime was registered; therefore gVisor live execution remains
unperformed on this host. Appium Windows/Mac2 and Linux AT-SPI real-native
fixtures require their respective operating-system runners and drivers. The
optional cloud/self-hosted workflow exposes these lanes without making them
mandatory offline tests.

## Stable-release boundary

Stable 1.0 remains blocked until the external acceptance gates have genuine
receipts: independent causal review, multiple providers/models, a production
community deployment, supervised monitoring and real acknowledgements,
independent implementations, benchmark comparison, and external users on
environments outside SOVA fixtures. Self-generated placeholders cannot satisfy
those gates.

## Final local validation gate

The combined Windows run completed with 1,232 passing tests and 18 explicitly
optional infrastructure skips. Combined line-and-branch coverage was 95.17%; all
109 registered CLI handlers executed. Ruff formatting/lint, strict mypy, generated
glossary/taxonomy checks, the repository-policy scan, and the public-boundary scan
passed. The locked runtime dependency export had no known OSV vulnerabilities.

The source and wheel distributions built successfully. A fresh isolated environment
installed the built wheel and returned `sova 0.1.0a0`. CycloneDX 1.6 SBOM creation,
four-file checksumming, and offline checksum verification passed. The credential-free
acceptance lab passed its core workflow and correctly kept `readyForStable1` false.

The 18 skipped lanes were not silently accepted: they require Codex authentication,
an interactive checksum-pinned desktop driver, the real-browser opt-in environment,
MELRA source admission, a reachable digest-pinned Docker backend, or a registered
gVisor `runsc` runtime. The four new held-out browser classes were run separately
through installed Chrome as recorded above.
