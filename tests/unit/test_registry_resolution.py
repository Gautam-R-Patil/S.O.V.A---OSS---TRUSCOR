# SPDX-License-Identifier: Apache-2.0
"""Trusted offline Registry to capsule resolution."""

from pathlib import Path

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.registry import (
    RegistryEntry,
    VerificationTier,
    build_registry,
    resolve_registry_capsule,
)


def test_exact_trusted_registry_capsule_resolves_and_rechecks(tmp_path: Path) -> None:
    capsule = tmp_path / "finding.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(title="finding", summary="fixture", author="test"),
    )
    data = capsule.read_bytes()
    digest = sha256_digest(data)
    entry = RegistryEntry(
        "finding",
        "1.0.0",
        f"objects/sha256/{digest[7:]}",
        digest,
        len(data),
        "fixture",
        "1",
        ("fixture",),
        "public",
        {"state": "not-run"},
        {"source": "unit-test"},
        "Apache-2.0",
        VerificationTier.VALIDATED,
    )
    root = tmp_path / "registry"
    verified = build_registry(
        root,
        registry_version="1.0.0",
        taxonomy_version="1.0.0",
        taxonomy_bytes=b"fixture taxonomy",
        artifacts=((capsule, entry),),
    )
    path, report = resolve_registry_capsule(
        root,
        entry_id="finding",
        version="1.0.0",
        trusted_key_ids=frozenset({verified["keyId"]}),
    )
    assert path.read_bytes() == data
    assert report["registryIdentityTrusted"] is True
    with pytest.raises(FormatError, match="trusted"):
        resolve_registry_capsule(
            root,
            entry_id="finding",
            version="1.0.0",
            trusted_key_ids=frozenset({"sha256:" + "0" * 64}),
        )
