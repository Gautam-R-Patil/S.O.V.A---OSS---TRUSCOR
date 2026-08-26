# SPDX-License-Identifier: Apache-2.0
"""DSSE-wrapped included-key registry indexes and content verification."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.registry.model import RegistryEntry, RegistryIndex, VerificationTier, entry_from_mapping
from sova.trace import generate_ed25519_keypair

if TYPE_CHECKING:
    from sova.trace.integrity import Ed25519Keypair

_PAYLOAD_TYPE = "application/vnd.sova.registry-index+json"


def _crypto() -> tuple[Any, Any]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as error:  # pragma: no cover - mandatory test extras provide dependency
        raise FormatError(
            "SOVA-REGISTRY-SIGNING-UNAVAILABLE",
            "registry signing requires the signing dependency",
        ) from error
    return Ed25519PrivateKey, Ed25519PublicKey


def _pae(payload: bytes) -> bytes:
    media = _PAYLOAD_TYPE.encode("ascii")
    return (
        b"DSSEv1 "
        + str(len(media)).encode()
        + b" "
        + media
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def _signed_index(index: RegistryIndex, key: Ed25519Keypair) -> dict[str, Any]:
    private_cls, _public_cls = _crypto()
    document = index.to_mapping()
    payload = canonical_json_bytes(document)
    signature = private_cls.from_private_bytes(key.private_key).sign(_pae(payload))
    return {
        "artifactType": "sova.registry-signed-index",
        "schemaVersion": "0.1.0",
        "index": document,
        "envelope": {
            "payloadType": _PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {"keyid": key.key_id, "sig": base64.b64encode(signature).decode("ascii")}
            ],
        },
        "publicKey": {
            "algorithm": "ed25519",
            "keyid": key.key_id,
            "raw": base64.b64encode(key.public_key).decode("ascii"),
        },
        "trustPolicy": "included-key-integrity-only",
        "identityVerified": False,
    }


def build_registry(  # noqa: PLR0913 - exact registry identity is deliberately explicit
    destination: Path,
    *,
    registry_version: str,
    taxonomy_version: str,
    taxonomy_bytes: bytes,
    artifacts: tuple[tuple[Path, RegistryEntry], ...],
    signing_key: Ed25519Keypair | None = None,
) -> dict[str, Any]:
    """Build a cloneable repository-of-files registry without a hosted service."""
    destination = destination.resolve()
    if destination.exists():
        raise FormatError("SOVA-REGISTRY-DESTINATION", "registry destination must not exist")
    destination.mkdir(parents=True)
    objects = destination / "objects" / "sha256"
    objects.mkdir(parents=True)
    entries: list[RegistryEntry] = []
    hidden_tiers = {VerificationTier.EMBARGOED, VerificationTier.WITHDRAWN}
    for source, declared in artifacts:
        if declared.verification_tier in hidden_tiers:
            entries.append(declared)
            continue
        data = source.read_bytes()
        digest = sha256_digest(data)
        if digest != declared.digest or len(data) != declared.size:
            raise FormatError(
                "SOVA-REGISTRY-DIGEST",
                "declared artifact digest or size does not match source",
            )
        if source.suffix == ".sova":
            PackageReader(source).verify("sova.capsule")
        target = objects / digest[7:]
        if target.exists() and target.read_bytes() != data:
            raise FormatError("SOVA-REGISTRY-COLLISION", "content address collision detected")
        target.write_bytes(data)
        entries.append(declared)
    taxonomy_digest = sha256_digest(taxonomy_bytes)
    taxonomy_dir = destination / "taxonomy"
    taxonomy_dir.mkdir()
    (taxonomy_dir / f"{taxonomy_version}.md").write_bytes(taxonomy_bytes)
    index = RegistryIndex(
        registry_version,
        taxonomy_version,
        taxonomy_digest,
        tuple(entries),
    )
    signed = _signed_index(index, signing_key or generate_ed25519_keypair())
    (destination / "index.json").write_bytes(canonical_json_bytes(signed) + b"\n")
    return verify_registry(destination)


def _decode(value: Any) -> bytes:
    if not isinstance(value, str):
        raise FormatError("SOVA-REGISTRY-SIGNATURE", "signature field must be a string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FormatError("SOVA-REGISTRY-SIGNATURE", "signature field is invalid base64") from error


def _index_from_mapping(value: Mapping[str, Any]) -> RegistryIndex:
    taxonomy = value.get("taxonomy")
    raw_entries = value.get("entries")
    if not isinstance(taxonomy, Mapping) or not isinstance(raw_entries, list):
        raise FormatError("SOVA-REGISTRY-INDEX", "index taxonomy or entries are malformed")
    if any(not isinstance(item, Mapping) for item in raw_entries):
        raise FormatError("SOVA-REGISTRY-INDEX", "entries must contain objects")
    registry_version = value.get("registryVersion")
    taxonomy_version = taxonomy.get("version")
    taxonomy_digest = taxonomy.get("digest")
    if not all(
        isinstance(item, str) and item
        for item in (registry_version, taxonomy_version, taxonomy_digest)
    ):
        raise FormatError("SOVA-REGISTRY-INDEX", "registry identity is malformed")
    return RegistryIndex(
        cast("str", registry_version),
        cast("str", taxonomy_version),
        cast("str", taxonomy_digest),
        tuple(entry_from_mapping(item) for item in raw_entries),
    )


def verify_registry(root: Path, *, trusted_key_ids: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Verify the signed index and every disclosed object entirely offline."""
    root = root.resolve()
    raw = strict_json_loads((root / "index.json").read_bytes())
    if not isinstance(raw, Mapping):
        raise FormatError("SOVA-REGISTRY-INDEX", "signed index must be an object")
    try:
        envelope = raw["envelope"]
        public = raw["publicKey"]
        declared_index = raw["index"]
        signature_row = envelope["signatures"][0]
    except (KeyError, IndexError, TypeError) as error:
        raise FormatError("SOVA-REGISTRY-SIGNATURE", "signed index is malformed") from error
    if not isinstance(envelope, Mapping) or not isinstance(public, Mapping):
        raise FormatError("SOVA-REGISTRY-SIGNATURE", "signature material is malformed")
    payload = _decode(envelope.get("payload"))
    public_bytes = _decode(public.get("raw"))
    signature = _decode(signature_row.get("sig"))
    key_id = sha256_digest(public_bytes)
    if (
        envelope.get("payloadType") != _PAYLOAD_TYPE
        or public.get("algorithm") != "ed25519"
        or public.get("keyid") != key_id
        or signature_row.get("keyid") != key_id
    ):
        raise FormatError("SOVA-REGISTRY-KEY", "registry key identifiers do not match")
    _private_cls, public_cls = _crypto()
    try:
        public_cls.from_public_bytes(public_bytes).verify(signature, _pae(payload))
    except Exception as error:
        raise FormatError(
            "SOVA-REGISTRY-SIGNATURE",
            "registry signature verification failed",
        ) from error
    parsed_payload = strict_json_loads(payload)
    if parsed_payload != declared_index:
        raise FormatError("SOVA-REGISTRY-SUBSTITUTION", "signed payload and index differ")
    if not isinstance(parsed_payload, Mapping):
        raise FormatError("SOVA-REGISTRY-INDEX", "registry index payload must be an object")
    index = _index_from_mapping(parsed_payload)
    taxonomy_path = root / "taxonomy" / f"{index.taxonomy_version}.md"
    if sha256_digest(taxonomy_path.read_bytes()) != index.taxonomy_digest:
        raise FormatError("SOVA-REGISTRY-TAXONOMY", "taxonomy snapshot digest mismatch")
    verified_objects = 0
    for entry in index.entries:
        if entry.object_path is None or entry.digest is None:
            continue
        object_path = root / Path(entry.object_path)
        resolved = object_path.resolve()
        if root not in resolved.parents or not resolved.is_file() or resolved.is_symlink():
            raise FormatError("SOVA-REGISTRY-OBJECT", "registry object path is missing or unsafe")
        data = resolved.read_bytes()
        if len(data) != entry.size or sha256_digest(data) != entry.digest:
            raise FormatError("SOVA-REGISTRY-DIGEST", "registry object digest or size mismatch")
        verified_objects += 1
    identity_trusted = bool(trusted_key_ids) and key_id in trusted_key_ids
    return {
        "artifactType": "sova.registry-verification",
        "schemaVersion": "0.1.0",
        "accepted": True,
        "registryVersion": index.registry_version,
        "entryCount": len(index.entries),
        "verifiedObjectCount": verified_objects,
        "keyId": key_id,
        "signatureValid": True,
        "trustPolicy": (
            "explicit-trusted-key" if identity_trusted else "included-key-integrity-only"
        ),
        "identityTrusted": identity_trusted,
        "offline": True,
        "truscorAttestation": False,
    }


def resolve_registry_capsule(
    root: Path,
    *,
    entry_id: str,
    version: str,
    trusted_key_ids: frozenset[str],
) -> tuple[Path, dict[str, Any]]:
    """Resolve one exact trusted registry entry as a verified SOVA capsule.

    Registry objects are content-addressed and intentionally have no filename
    extension. Resolution therefore verifies the signed index, requires an
    out-of-band trusted signing key, rechecks the selected object after lookup,
    and validates the bytes as a capsule before returning the inert local path.
    """
    if not entry_id or not version or not trusted_key_ids:
        raise FormatError(
            "SOVA-REGISTRY-RESOLVE",
            "registry replay requires an exact entry id/version and trusted signing key",
        )
    root = root.resolve()
    verification = verify_registry(root, trusted_key_ids=trusted_key_ids)
    if verification["identityTrusted"] is not True:
        raise FormatError(
            "SOVA-REGISTRY-UNTRUSTED",
            "registry replay requires an explicitly trusted index signing key",
        )
    raw = strict_json_loads((root / "index.json").read_bytes())
    if not isinstance(raw, Mapping) or not isinstance(raw.get("index"), Mapping):
        raise FormatError("SOVA-REGISTRY-INDEX", "signed index is malformed")
    index = _index_from_mapping(cast("Mapping[str, Any]", raw["index"]))
    matches = [
        item for item in index.entries if item.entry_id == entry_id and item.version == version
    ]
    if len(matches) != 1:
        raise FormatError(
            "SOVA-REGISTRY-RESOLVE",
            "registry entry id/version did not resolve uniquely",
        )
    entry = matches[0]
    if entry.object_path is None or entry.digest is None:
        raise FormatError(
            "SOVA-REGISTRY-LIFECYCLE",
            "embargoed or withdrawn registry entries cannot be replayed",
        )
    path = (root / entry.object_path).resolve()
    if root not in path.parents or not path.is_file() or path.is_symlink():
        raise FormatError("SOVA-REGISTRY-OBJECT", "registry object path is missing or unsafe")
    data = path.read_bytes()
    if len(data) != entry.size or sha256_digest(data) != entry.digest:
        raise FormatError("SOVA-REGISTRY-DIGEST", "registry object changed after verification")
    PackageReader(path).verify("sova.capsule")
    return path, {
        "artifactType": "sova.registry-capsule-resolution",
        "schemaVersion": "0.1.0",
        "entryId": entry.entry_id,
        "version": entry.version,
        "capsule": str(path),
        "capsuleDigest": entry.digest,
        "verificationTier": entry.verification_tier.value,
        "registryKeyId": verification["keyId"],
        "registryIdentityTrusted": True,
    }


__all__ = ["build_registry", "resolve_registry_capsule", "verify_registry"]
