# SPDX-License-Identifier: Apache-2.0
"""Adversarial signed-index and exact-resolution registry tests."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

import sova.registry.index as registry_index
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.registry import RegistryEntry, VerificationTier, build_registry

if TYPE_CHECKING:
    from pathlib import Path


def _entry(path: Path, *, tier: VerificationTier = VerificationTier.SUBMITTED) -> RegistryEntry:
    if tier in {VerificationTier.EMBARGOED, VerificationTier.WITHDRAWN}:
        return RegistryEntry(
            "fixture",
            "1",
            None,
            None,
            0,
            "component",
            "1",
            (),
            "private",
            {},
            {},
            "Apache-2.0",
            tier,
        )
    data = path.read_bytes()
    digest = sha256_digest(data)
    return RegistryEntry(
        "fixture",
        "1",
        f"objects/sha256/{digest[7:]}",
        digest,
        len(data),
        "component",
        "1",
        (),
        "public",
        {},
        {},
        "Apache-2.0",
        tier,
    )


def _build(
    tmp_path: Path,
    *,
    tier: VerificationTier = VerificationTier.SUBMITTED,
) -> tuple[Path, dict[str, Any]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(b"{}")
    root = tmp_path / "registry"
    report = build_registry(
        root,
        registry_version="1",
        taxonomy_version="1",
        taxonomy_bytes=b"taxonomy",
        artifacts=((artifact, _entry(artifact, tier=tier)),),
    )
    return root, report


def test_registry_mapping_decoder_rejects_ambiguous_taxonomy_entries_and_identity() -> None:
    with pytest.raises(FormatError, match="taxonomy or entries"):
        registry_index._index_from_mapping({"taxonomy": [], "entries": []})
    with pytest.raises(FormatError, match="contain objects"):
        registry_index._index_from_mapping(
            {"registryVersion": "1", "taxonomy": {"version": "1", "digest": "x"}, "entries": [1]}
        )
    with pytest.raises(FormatError, match="identity"):
        registry_index._index_from_mapping(
            {"registryVersion": "", "taxonomy": {"version": "1", "digest": "x"}, "entries": []}
        )


def test_registry_signature_material_key_binding_and_payload_type_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _report = _build(tmp_path)
    index_path = root / "index.json"
    original = json.loads(index_path.read_text(encoding="utf-8"))

    malformed = json.loads(json.dumps(original))
    malformed["publicKey"] = []
    index_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
    with pytest.raises(FormatError, match="signature material"):
        registry_index.verify_registry(root)

    malformed = json.loads(json.dumps(original))
    malformed["publicKey"]["keyid"] = "sha256:" + "0" * 64
    index_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
    with pytest.raises(FormatError, match="key identifiers"):
        registry_index.verify_registry(root)

    public_bytes = b"fixture-public-key"
    key_id = sha256_digest(public_bytes)
    array_payload = b"[]"
    non_object = {
        "envelope": {
            "payloadType": registry_index._PAYLOAD_TYPE,
            "payload": base64.b64encode(array_payload).decode("ascii"),
            "signatures": [{"keyid": key_id, "sig": base64.b64encode(b"sig").decode("ascii")}],
        },
        "publicKey": {
            "algorithm": "ed25519",
            "keyid": key_id,
            "raw": base64.b64encode(public_bytes).decode("ascii"),
        },
        "index": [],
    }

    class _Public:
        @classmethod
        def from_public_bytes(cls, _value: bytes) -> _Public:
            return cls()

        def verify(self, _signature: bytes, _payload: bytes) -> None:
            return None

    monkeypatch.setattr(registry_index, "_crypto", lambda: (SimpleNamespace(), _Public))
    index_path.write_bytes(canonical_json_bytes(non_object) + b"\n")
    with pytest.raises(FormatError, match="payload must be an object"):
        registry_index.verify_registry(root)


def test_registry_verification_rejects_signed_index_substitution_and_unsafe_object(
    tmp_path: Path,
) -> None:
    root, _report = _build(tmp_path)
    index_path = root / "index.json"
    original = json.loads(index_path.read_text(encoding="utf-8"))
    substituted = json.loads(json.dumps(original))
    substituted["index"]["registryVersion"] = "2"
    index_path.write_bytes(canonical_json_bytes(substituted) + b"\n")
    with pytest.raises(FormatError, match="payload and index differ"):
        registry_index.verify_registry(root)

    index_path.write_bytes(canonical_json_bytes(original) + b"\n")
    object_path = root / original["index"]["entries"][0]["objectPath"]
    object_path.unlink()
    with pytest.raises(FormatError, match="missing or unsafe"):
        registry_index.verify_registry(root)


def test_exact_registry_resolution_rejects_missing_scope_lifecycle_and_postcheck_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, report = _build(tmp_path / "public")
    trusted = frozenset({report["keyId"]})
    invalid_scopes: tuple[tuple[str, str, frozenset[str]], ...] = (
        ("", "1", trusted),
        ("fixture", "", trusted),
        ("fixture", "1", frozenset()),
    )
    for entry_id, version, keys in invalid_scopes:
        with pytest.raises(FormatError, match="exact entry"):
            registry_index.resolve_registry_capsule(
                root, entry_id=entry_id, version=version, trusted_key_ids=keys
            )
    with pytest.raises(FormatError, match="did not resolve uniquely"):
        registry_index.resolve_registry_capsule(
            root, entry_id="missing", version="1", trusted_key_ids=trusted
        )

    hidden_root, hidden_report = _build(tmp_path / "hidden", tier=VerificationTier.EMBARGOED)
    with pytest.raises(FormatError, match="cannot be replayed"):
        registry_index.resolve_registry_capsule(
            hidden_root,
            entry_id="fixture",
            version="1",
            trusted_key_ids=frozenset({hidden_report["keyId"]}),
        )

    monkeypatch.setattr(
        registry_index,
        "verify_registry",
        lambda _root, **_kwargs: {"identityTrusted": True, "keyId": report["keyId"]},
    )
    raw = json.loads((root / "index.json").read_text(encoding="utf-8"))
    object_path = root / raw["index"]["entries"][0]["objectPath"]
    object_path.write_bytes(b"changed")
    with pytest.raises(FormatError, match="changed after verification"):
        registry_index.resolve_registry_capsule(
            root, entry_id="fixture", version="1", trusted_key_ids=trusted
        )
