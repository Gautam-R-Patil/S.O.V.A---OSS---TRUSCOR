<!-- status: implemented -->

# P0 foundation baseline — 2026-08-26

This record closes P0 of the
[universal-security launch checklist](./universal-security-launch-checklist-2026-08-26.md).
It preserves the inherited implementation before universal-intake work begins. It
does not claim that P1–P6 are implemented.

## Preservation identity

| Field | Value |
|---|---|
| Preservation branch | `codex/universal-target-foundation` |
| Inherited HEAD | `e98546706f05e0abd33e88da065fec549ebe323a` |
| Public upstream observed at preservation | `origin/main` at `cae9ea1` |
| Pre-P0 working snapshot digest | `65753976fc8c483278b1a99ad61dfb2ec08215fb` |
| Tracked patch SHA-1 | `d55efdf67aa2fe66709c551c710991ec398de704` |
| Untracked public manifest SHA-1 | `edce3b62298d6c84cb7fcce5b1189896a47b8580` |

The snapshot digest is a preservation receipt over the captured tracked/untracked
state, not a Git object or a cryptographic signature. The preservation commit that
contains this document is the authoritative P0 repository state.

## Inherited-change classification

The pre-P0 inventory contained 52 modified tracked files and 89 untracked public
files: 141 unique paths. The largest groups were 61 under `src/sova`, 56 under
`tests/unit`, nine under `tests/integration`, five under `docs/engineering`, and
three under `docs/specifications`. The remaining files were public root metadata,
guides, research records, and supporting tests.

All 141 paths were retained because they form one coupled implementation: executor
chamber and full-capability engine, runtime surfaces, browser/computer/workspace/
process execution, swarms, replay, Registry contribution, safety profiles, CLI
wiring, documentation, and their tests. No ignored `private/`, environment, browser
profile, raw trace, receipt, build, cache, coverage, or temporary path was admitted.

## Secret and public-boundary result

- Repository and staged-candidate scans found no provider credential or private-key
  material in public paths.
- The only secret-shaped examples identified by the supplementary pattern scan are
  deliberate synthetic negative-test values in
  `tests/unit/test_community_service_edges.py`.
- `.gitignore` excludes local secrets, key containers, private/confidential trees,
  browser profiles, receipts, raw traces, operator deployment state, build output,
  caches, and local test artifacts.
- The operator reports the provider credential previously disclosed in conversation
  has been revoked. Provider-side revocation cannot be proved from this repository;
  a fresh credential requires the normal scoped secret broker before any later live
  provider study.
- Gitleaks is not installed on this host. The repository's own public-boundary check
  and supplementary staged-content pattern scan are the P0 controls; Gitleaks remains
  a mandatory release/adaptor gate before P6.

## Compatibility evidence

The focused P0 gate exercised the CLI surface audit, full-capability authority,
Registry index edges, trace handling, and executor vertical slice:

```text
64 passed in 23.37s
```

The initial invocation failed before test execution because the default Windows
temporary directory was inaccessible. The same tests passed with an isolated,
workspace-local base temporary directory and Pytest cache disabled. This is recorded
as an environment failure, not a product failure.

`git diff --check` reported no whitespace errors or merge-conflict markers. The
broader inherited release evidence remains recorded in the founder acceptance matrix
and claims register; P0 does not relabel that older evidence as a new full-suite run.

The ignored local distribution candidates present at P0 were content-addressed. They
are evidence inputs, not tracked release artifacts and not proof of P1–P6:

| Candidate | SHA-256 |
|---|---|
| `sova_oss-0.1.0a0-py3-none-any.whl` | `74e363f60050d83c7fe67e9b0275e6d0554ffffd18da03e1b28e501dbf28e106` |
| `sova_oss-0.1.0a0.tar.gz` | `0ec6171ac9d988d586a1089ebe085fed5f247a3c08d5c7e770b5930e6943bbfa` |
| `sova-oss.cdx.json` | `4187e8fa711c0c1429979851a69409c159e05db550e9aa983778ce4e5ef0cd14` |
| `SHA256SUMS` | `1e76d84ea5b3c6a1c3402824b18c72aaa4e1c5ed9cd6f928917d0014beafbab6` |

After adding the P0 control records, `scripts/check_repository.py` passed and the
public-boundary scanner passed over 718 tracked or unignored files.

## P0 architecture decisions

- [ADR-0028](../decisions/0028-universal-security-extension-boundary.md) freezes the
  SOVA-owned authority, executor, target, trace, capsule, replay, Registry, and
  provider seams.
- The [OSS adoption ledger](../research/oss-architecture-adoption-ledger-2026-08-26.md)
  selects adapters and narrow file-level study candidates and records rejected
  wholesale replacements.
- No third-party source code, prompt corpus, playbook prose, test template, or
  dataset was copied into SOVA during P0.
- P1 begins from this commit and may add extensions only through the frozen seams or
  a superseding ADR with compatibility evidence.
