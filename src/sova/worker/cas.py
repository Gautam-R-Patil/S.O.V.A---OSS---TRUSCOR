# SPDX-License-Identifier: Apache-2.0
"""Root-scoped immutable content-addressed storage for worker inputs and outputs."""

from __future__ import annotations

import hashlib
import os
import tempfile
from contextlib import suppress
from pathlib import Path

from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.worker.contracts import ContentReference

SHA256_HEX_LENGTH = 64


class ContentAddressedStore:
    """Store bytes by digest and reject links, mutations, truncation, and path authority."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise FormatError("SOVA-WORKER-CAS-ROOT", "CAS root must be absolute")
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise FormatError("SOVA-WORKER-CAS-ROOT", "CAS root must be a real directory")
        self._root = root.resolve(strict=True)

    @property
    def root(self) -> Path:
        return self._root

    def _path(self, digest: str) -> Path:
        try:
            algorithm, value = digest.split(":", maxsplit=1)
        except ValueError as error:
            raise FormatError("SOVA-WORKER-CAS-DIGEST", "CAS digest is malformed") from error
        if algorithm != "sha256" or len(value) != SHA256_HEX_LENGTH or not value.isascii():
            raise FormatError("SOVA-WORKER-CAS-DIGEST", "CAS digest is malformed")
        try:
            int(value, 16)
        except ValueError as error:
            raise FormatError("SOVA-WORKER-CAS-DIGEST", "CAS digest is malformed") from error
        return self._root / algorithm / value[:2] / value

    def put(self, *, name: str, media_type: str, data: bytes) -> ContentReference:
        """Atomically publish immutable bytes and return their typed reference."""
        reference = ContentReference(name, sha256_digest(data), len(data), media_type)
        destination = self._path(reference.digest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            self.verify(reference)
            return reference
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=destination.parent, prefix=".sova-cas-", delete=False
            ) as temporary:
                temporary_name = temporary.name
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
            with suppress(FileExistsError):
                os.link(temporary_name, destination)
        finally:
            if temporary_name is not None:
                Path(temporary_name).unlink(missing_ok=True)
        destination.chmod(0o444)
        self.verify(reference)
        return reference

    def verify(self, reference: ContentReference) -> Path:
        """Verify size and digest before any worker materialization."""
        path = self._path(reference.digest)
        if path.is_symlink() or not path.is_file():
            raise FormatError("SOVA-WORKER-CAS-MISSING", "CAS object is missing or not regular")
        stat_result = path.stat()
        if stat_result.st_size != reference.size:
            raise FormatError("SOVA-WORKER-CAS-SIZE", "CAS object size does not match reference")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if f"sha256:{digest.hexdigest()}" != reference.digest:
            raise FormatError(
                "SOVA-WORKER-CAS-MUTATION", "CAS object digest does not match reference"
            )
        return path

    def read(self, reference: ContentReference, *, maximum_bytes: int) -> bytes:
        if reference.size > maximum_bytes:
            raise FormatError("SOVA-WORKER-CAS-READ-LIMIT", "CAS read exceeds caller limit")
        return self.verify(reference).read_bytes()


__all__ = ["ContentAddressedStore"]
