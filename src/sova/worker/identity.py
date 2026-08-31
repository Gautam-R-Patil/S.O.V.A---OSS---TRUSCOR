# SPDX-License-Identifier: Apache-2.0
"""Persistent exclusive leases for Firecracker UID/GID and network identity slots."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_SLOT = 500_000
_MAX_LEASE_BYTES = 4_096


@dataclass(frozen=True, slots=True)
class IdentitySlotLease:
    slot: int
    job_id: str
    manifest_digest: str

    def __post_init__(self) -> None:
        if not 0 <= self.slot <= _MAX_SLOT:
            raise FormatError("SOVA-WORKER-LEASE-SLOT", "identity slot is outside policy")
        if not self.job_id or _DIGEST.fullmatch(self.manifest_digest) is None:
            raise FormatError("SOVA-WORKER-LEASE-BINDING", "lease job binding is invalid")

    def to_mapping(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "artifactType": "sova.worker-identity-slot-lease",
            "schemaVersion": "0.1.0",
            "slot": self.slot,
            "jobId": self.job_id,
            "manifestDigest": self.manifest_digest,
        }
        body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
        return body


class IdentitySlotLeaseTable:
    """Reserve slots with O_EXCL files; stale leases require explicit operator recovery."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute() or ".." in root.parts:
            raise FormatError(
                "SOVA-WORKER-LEASE-PATH", "lease root must be absolute and normalized"
            )
        self.root = root
        self._lock = Lock()

    def _path(self, slot: int) -> Path:
        if not 0 <= slot <= _MAX_SLOT:
            raise FormatError("SOVA-WORKER-LEASE-SLOT", "identity slot is outside policy")
        return self.root / f"{slot:06d}.lease"

    def _require_root_controlled(self) -> None:
        if os.name != "posix":
            return
        current = self.root
        while True:
            metadata = current.lstat()
            if (
                current.is_symlink()
                or metadata.st_uid != 0
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise FormatError(
                    "SOVA-WORKER-LEASE-PATH", "identity lease root is not root controlled"
                )
            if current.parent == current:
                return
            current = current.parent

    def _sync_root(self) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise OSError
            remaining = remaining[written:]

    def acquire(self, lease: IdentitySlotLease) -> None:
        path = self._path(lease.slot)
        payload = canonical_json_bytes(lease.to_mapping()) + b"\n"
        if len(payload) > _MAX_LEASE_BYTES:
            raise FormatError("SOVA-WORKER-LEASE-SIZE", "identity lease exceeds policy")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with self._lock:
            if self.root.is_symlink() or not self.root.is_dir():
                raise FormatError("SOVA-WORKER-LEASE-PATH", "identity lease root is unavailable")
            self._require_root_controlled()
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError as error:
                raise FormatError(
                    "SOVA-WORKER-LEASE-CONFLICT", "identity slot is already reserved"
                ) from error
            try:
                self._write_all(descriptor, payload)
                os.fsync(descriptor)
            except Exception:
                os.close(descriptor)
                path.unlink(missing_ok=True)
                raise
            os.close(descriptor)
            self._sync_root()

    def _read(self, path: Path) -> IdentitySlotLease:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise FormatError("SOVA-WORKER-LEASE-FILE", "identity lease file is unsafe")
        if os.name == "posix" and (
            metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise FormatError("SOVA-WORKER-LEASE-FILE", "identity lease file is mutable")
        payload = path.read_bytes()
        if not payload or len(payload) > _MAX_LEASE_BYTES:
            raise FormatError("SOVA-WORKER-LEASE-SIZE", "identity lease file is invalid")
        value = strict_json_loads(payload, max_bytes=_MAX_LEASE_BYTES)
        expected = {
            "artifactType",
            "schemaVersion",
            "slot",
            "jobId",
            "manifestDigest",
            "contentDigest",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise FormatError("SOVA-WORKER-LEASE-FILE", "identity lease fields are invalid")
        if payload != canonical_json_bytes(value) + b"\n":
            raise FormatError("SOVA-WORKER-LEASE-FILE", "identity lease is not canonical JSON")
        body = dict(value)
        claimed = body.pop("contentDigest", None)
        if (
            value.get("artifactType") != "sova.worker-identity-slot-lease"
            or value.get("schemaVersion") != "0.1.0"
            or claimed != sha256_digest(canonical_json_bytes(body))
            or isinstance(value.get("slot"), bool)
            or not isinstance(value.get("slot"), int)
            or not isinstance(value.get("jobId"), str)
            or not isinstance(value.get("manifestDigest"), str)
        ):
            raise FormatError("SOVA-WORKER-LEASE-FILE", "identity lease content is invalid")
        return IdentitySlotLease(
            slot=value["slot"],
            job_id=value["jobId"],
            manifest_digest=value["manifestDigest"],
        )

    def release(self, lease: IdentitySlotLease, *, cleanup_complete: bool) -> bool:
        """Release only the exact lease after complete cleanup; otherwise retain it."""
        if not cleanup_complete:
            return False
        path = self._path(lease.slot)
        with self._lock:
            try:
                observed = self._read(path)
            except FileNotFoundError as error:
                raise FormatError(
                    "SOVA-WORKER-LEASE-MISSING", "identity lease is missing"
                ) from error
            if observed != lease:
                raise FormatError("SOVA-WORKER-LEASE-BINDING", "identity lease binding drifted")
            path.unlink()
            self._sync_root()
        return True


__all__ = ["IdentitySlotLease", "IdentitySlotLeaseTable"]
