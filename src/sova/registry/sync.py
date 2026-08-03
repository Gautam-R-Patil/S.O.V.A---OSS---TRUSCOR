# SPDX-License-Identifier: Apache-2.0
"""Pull-only atomic registry snapshot synchronization."""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.registry.index import verify_registry

if TYPE_CHECKING:
    from pathlib import Path

_MAX_FILES = 8192
_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def _select_mirror(sources: tuple[Path, ...]) -> tuple[Path, dict[str, object]]:
    failures: list[str] = []
    for source in sources:
        resolved = source.resolve()
        try:
            report = verify_registry(resolved)
        except (FormatError, OSError) as error:
            failures.append(f"{resolved.name}:{type(error).__name__}")
            continue
        return resolved, report
    raise FormatError(
        "SOVA-SYNC-MIRROR",
        "no supplied local mirror passed offline verification",
        details={"failures": failures},
    )


def _copy_snapshot(source: Path, destination: Path) -> None:
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if len(files) > _MAX_FILES:
        raise FormatError("SOVA-SYNC-LIMIT", "registry exceeds file-count limit")
    total = sum(path.stat().st_size for path in files)
    if total > _MAX_TOTAL_BYTES:
        raise FormatError("SOVA-SYNC-LIMIT", "registry exceeds byte limit")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise FormatError("SOVA-SYNC-SYMLINK", "registry mirrors cannot contain symlinks")
    for source_file in files:
        relative = source_file.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, target)


def sync_registry(sources: tuple[Path, ...], cache_root: Path) -> dict[str, object]:
    """Verify one local mirror and atomically point the cache at an immutable snapshot."""
    if not sources:
        raise FormatError("SOVA-SYNC-SOURCE", "at least one mirror is required")
    source, source_report = _select_mirror(sources)
    cache_root = cache_root.resolve()
    cache_root.mkdir(parents=True, exist_ok=True)
    snapshot_digest = sha256_digest((source / "index.json").read_bytes())
    snapshots = cache_root / "snapshots"
    snapshots.mkdir(exist_ok=True)
    destination = snapshots / snapshot_digest[7:]
    reused = destination.exists()
    if not reused:
        temporary = snapshots / f".{snapshot_digest[7:]}.{os.getpid()}.tmp"
        if temporary.exists():
            raise FormatError("SOVA-SYNC-TEMP", "stale synchronization directory exists")
        temporary.mkdir()
        try:
            _copy_snapshot(source, temporary)
            verify_registry(temporary)
            temporary.replace(destination)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    verify_registry(destination)
    pointer = {
        "artifactType": "sova.registry-cache-pointer",
        "schemaVersion": "0.1.0",
        "snapshotDigest": snapshot_digest,
        "snapshotPath": f"snapshots/{snapshot_digest[7:]}",
        "sourceKind": "local-mirror",
        "sourceName": source.name,
        "uploadPerformed": False,
        "telemetrySent": False,
    }
    temporary_pointer = cache_root / f".current.{os.getpid()}.tmp"
    temporary_pointer.write_bytes(canonical_json_bytes(pointer) + b"\n")
    temporary_pointer.replace(cache_root / "current.json")
    return {
        **pointer,
        "snapshotReused": reused,
        "verification": source_report,
        "offlineCachedOperationAvailable": True,
    }


__all__ = ["sync_registry"]
