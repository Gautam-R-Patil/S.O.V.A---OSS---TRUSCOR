<!-- status: implemented -->

# Dependency advisory register

This register contains narrow, time-bounded dependency-audit applicability
decisions and their resolution. Entries do not state that an affected package
is safe in general. An active exception permits only the reviewed SOVA usage
and remains a visible audit argument rather than suppressing all advisories for
a package.

## GHSA-g6cj-pr64-35w5 / CVE-2026-69247

| Field | Decision |
|---|---|
| Status | **Resolved 2026-08-11; exception removed** |
| Former package | `cryptography==49.0.0` through the locked runtime/development dependency |
| Upstream effect | A Bleichenbacher oracle can arise when an application adaptively decrypts attacker-supplied PKCS#7 `EnvelopedData` through `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, or `pkcs7_decrypt_smime` |
| Affected range | Introduced in `44.0.0`; upstream names `50.0.0` as fixed |
| Release status | Stable `50.0.0` became available on PyPI and was verified on 2026-08-11 |
| SOVA use | Raw Ed25519 signing/verification and AES-256-GCM placeholders only |
| Applicability | The three affected PKCS#7 APIs and their module are absent from `src/sova` |
| Guard | `tests/unit/test_dependency_advisory_scope.py` scans every shipped Python source and fails on the affected module or API names |
| Resolution | Runtime constraint and lock upgraded to `cryptography>=50,<51`; CI no longer ignores this or any other advisory |
| Audit behavior | Strict locked dependency audit fails on every reported advisory |
| Owner | SOVA OSS security maintainers |
| Re-review condition | Re-review immediately if SOVA needs any PKCS#7 decryption |

The retired exception never applied to third-party extension code. Extensions
run as separate, explicitly untrusted subprocesses and remain responsible for
their own dependencies. SOVA must not expose the affected functions through an
extension helper or provider adapter.

Sources: the official [PyPI 50.0.0 metadata](https://pypi.org/pypi/cryptography/50.0.0/json),
[PyPA advisory](https://github.com/pypa/advisory-database/blob/main/vulns/cryptography/PYSEC-2026-3552.yaml), and
[`cryptography` release history](https://cryptography.io/en/stable/changelog/),
plus the repository's locked dependency manifest. The advisory's cryptographic
impact is not reinterpreted or downgraded here; only reachability in the shipped
SOVA source was assessed while a fixed stable release was unavailable.
