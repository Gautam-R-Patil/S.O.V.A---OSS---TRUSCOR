<!-- status: implemented -->

# Dependency advisory register

This register contains narrow, time-bounded dependency-audit applicability
decisions. Entries do not state that an affected package is safe in general.
An exception permits only the reviewed SOVA usage and remains a visible audit
argument rather than suppressing all advisories for a package.

## GHSA-g6cj-pr64-35w5 / CVE-2026-69247

| Field | Decision |
|---|---|
| Package | `cryptography==49.0.0` through the locked `signing`/development dependency |
| Upstream effect | A Bleichenbacher oracle can arise when an application adaptively decrypts attacker-supplied PKCS#7 `EnvelopedData` through `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, or `pkcs7_decrypt_smime` |
| Affected range | Introduced in `44.0.0`; upstream names `50.0.0` as fixed |
| Release status checked | `49.0.0` is the latest stable PyPI release and `50.0.0`/`50.0.0.dev1` is unavailable as of 2026-08-04 |
| SOVA use | Raw Ed25519 signing/verification and AES-256-GCM placeholders only |
| Applicability | The three affected PKCS#7 APIs and their module are absent from `src/sova` |
| Guard | `tests/unit/test_dependency_advisory_scope.py` scans every shipped Python source and fails on the affected module or API names |
| Audit behavior | CI passes the exact advisory ID to `pip-audit --ignore-vuln`; all other advisories still fail the audit |
| Owner | SOVA OSS security maintainers |
| Removal condition | Upgrade to a compatible fixed stable release and remove the exception, or replace the dependency; re-review immediately if SOVA needs any PKCS#7 decryption |

The exception does not apply to third-party extension code. Extensions run as
separate, explicitly untrusted subprocesses and remain responsible for their
own dependencies. SOVA must not expose the affected functions through an
extension helper or provider adapter.

Sources: the official [PyPI 49.0.0 metadata](https://pypi.org/pypi/cryptography/49.0.0/json),
[OSV advisory](https://osv.dev/vulnerability/GHSA-g6cj-pr64-35w5), and
[`cryptography` release history](https://cryptography.io/en/stable/changelog/),
plus the repository's locked dependency manifest. The advisory's cryptographic
impact is not reinterpreted or downgraded here; only reachability in the shipped
SOVA source is assessed.
