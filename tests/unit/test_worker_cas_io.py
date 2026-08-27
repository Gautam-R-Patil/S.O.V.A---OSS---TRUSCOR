# SPDX-License-Identifier: Apache-2.0
"""Immutable CAS and strict job-manifest parsing tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from sova.formats import FormatError, canonical_json_bytes
from sova.worker.cas import ContentAddressedStore
from sova.worker.io import job_manifest_from_mapping, read_worker_job_manifest
from tests.support.worker import guest_keypair, worker_manifest


def test_cas_round_trip_is_content_addressed_and_bounded(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    store = ContentAddressedStore(root)
    reference = store.put(name="fixture", media_type="application/octet-stream", data=b"abc")
    assert store.read(reference, maximum_bytes=3) == b"abc"
    with pytest.raises(FormatError, match="caller limit"):
        store.read(reference, maximum_bytes=2)


def test_cas_detects_post_publish_mutation(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    store = ContentAddressedStore(root)
    reference = store.put(name="fixture", media_type="application/octet-stream", data=b"abc")
    path = store.verify(reference)
    path.chmod(0o644)
    path.write_bytes(b"abd")
    with pytest.raises(FormatError, match="digest"):
        store.verify(reference)


def test_worker_manifest_round_trip_rechecks_content_digest() -> None:
    manifest = worker_manifest(guest_keypair())
    raw = canonical_json_bytes(manifest.to_mapping())
    assert read_worker_job_manifest(raw) == manifest
    mutated = manifest.to_mapping()
    mutated["jobId"] = "job:mutation"
    with pytest.raises(FormatError, match="content digest"):
        read_worker_job_manifest(canonical_json_bytes(mutated))


def test_worker_manifest_rejects_schema_invalid_input() -> None:
    manifest = worker_manifest(guest_keypair())
    with pytest.raises(FormatError, match="at least one output"):
        replace(manifest, output_schema_ids=())


def test_cas_rejects_relative_or_file_root(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="absolute"):
        ContentAddressedStore(Path("relative"))
    file_root = tmp_path / "file"
    file_root.write_text("not-directory", encoding="utf-8")
    with pytest.raises((FormatError, FileExistsError)):
        ContentAddressedStore(file_root)


@pytest.mark.parametrize("digest", ["bad", "md5:" + "0" * 32, "sha256:xyz"])
def test_cas_rejects_malformed_digest(tmp_path: Path, digest: str) -> None:
    store = ContentAddressedStore((tmp_path / "cas").resolve())
    with pytest.raises(FormatError, match="malformed"):
        store._path(digest)


def test_cas_existing_object_is_verified_and_missing_object_fails(tmp_path: Path) -> None:
    store = ContentAddressedStore((tmp_path / "cas").resolve())
    reference = store.put(name="fixture", media_type="application/octet-stream", data=b"abc")
    second = store.put(name="fixture", media_type="application/octet-stream", data=b"abc")
    assert second == reference
    missing = replace(reference, digest="sha256:" + "0" * 64)
    with pytest.raises(FormatError, match="missing"):
        store.verify(missing)


def test_cas_detects_size_change(tmp_path: Path) -> None:
    store = ContentAddressedStore((tmp_path / "cas").resolve())
    reference = store.put(name="fixture", media_type="application/octet-stream", data=b"abc")
    with pytest.raises(FormatError, match="size"):
        store.verify(replace(reference, size=4))


def test_manifest_reader_rejects_nonobject_invalid_json_and_wrong_field_types() -> None:
    with pytest.raises(FormatError, match="must be an object"):
        read_worker_job_manifest(b"[]")
    with pytest.raises(FormatError):
        read_worker_job_manifest(b"not-json")
    manifest = worker_manifest(guest_keypair()).to_mapping()
    manifest["limits"]["vcpuCount"] = True
    with pytest.raises(FormatError):
        job_manifest_from_mapping(manifest)


def test_manifest_reader_rejects_unknown_enum_and_bad_nested_types() -> None:
    document = worker_manifest(guest_keypair()).to_mapping()
    document["secretGrants"][0]["kind"] = "unknown"
    with pytest.raises(FormatError):
        job_manifest_from_mapping(document)
    document = worker_manifest(guest_keypair()).to_mapping()
    document["inputs"] = {}
    with pytest.raises(FormatError):
        job_manifest_from_mapping(document)
