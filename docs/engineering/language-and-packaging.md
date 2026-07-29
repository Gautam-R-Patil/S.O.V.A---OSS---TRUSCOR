<!-- status: decision -->

# Language, runtime, and packaging support

The controlling decision is
[ADR-0007](../decisions/0007-topic-02-engineering-foundation.md).

| Surface | Decision |
|---|---|
| Production core | Typed Python |
| Distribution | `sova-oss` |
| Import | `sova` |
| Command | `sova` |
| Python | CPython 3.11–3.14 |
| OS families | 64-bit Windows, macOS, Linux |
| Build | PEP 517 through Hatchling |
| Contributor environment | `uv` plus checked-in universal lockfile |
| Runtime dependencies at Topic 02 | None |
| Hosted SOVA service | Never required |

## Why not one language forever?

The evidence core benefits from one readable implementation now. Sandboxing and
host control may later expose a measured case for a small Rust component.
Interfaces—not language loyalty—must keep that component replaceable and
testable. A new production language requires an ADR, cross-platform builds,
supply-chain review, failure semantics, and contributor documentation.

## Distribution boundary

`sova-oss` is the canonical install identity even though the command remains
`sova`. The unrelated `sova` PyPI project is not a dependency, predecessor, or
part of SOVA OSS.

The package contains only the public instrument. It cannot download or unlock a
private SOVA Engine, private model, proprietary corpus, or hosted feature tier.
