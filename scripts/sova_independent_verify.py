#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: TRY003
"""Small verifier implemented independently from `sova`.

This intentionally validates a strict portable subset: archive/object
integrity, canonical manifest identity, event order/hash chain, and structural
redaction records. Its core is standard-library-only. Optional Ed25519/DSSE
verification uses ``cryptography`` when explicitly requested.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import math
import re
import sys
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ENTRIES = 4096
MAX_ENTRY_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_RATIO = 200
MIN_RATIO_CHECK_BYTES = 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_IJSON_INTEGER = (1 << 53) - 1
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REDACTION_METHODS = {"omitted", "keyed-commitment", "encrypted", "masked"}
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://sova-oss.org/attestation/trace/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


class VerificationError(ValueError):
    """One bounded independent-verifier failure."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def strict_loads(raw: bytes) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise VerificationError("JSON byte limit exceeded")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                VerificationError(f"non-finite number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("invalid UTF-8 JSON") from error


def _key(value: str) -> bytes:
    try:
        return value.encode("utf-16-be", errors="strict")
    except UnicodeEncodeError as error:
        raise VerificationError("lone surrogate in canonical JSON") from error


def canonical(value: Any) -> bytes:
    def render(item: Any) -> str:
        if item is None or isinstance(item, bool):
            return json.dumps(item)
        if isinstance(item, int):
            if not -MAX_IJSON_INTEGER <= item <= MAX_IJSON_INTEGER:
                raise VerificationError("integer outside I-JSON exact range")
            return str(item)
        if isinstance(item, float):
            if not math.isfinite(item):
                raise VerificationError("non-finite number")
            raise VerificationError("binary float outside SOVA canonical subset")
        if isinstance(item, str):
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise VerificationError("lone surrogate in canonical JSON") from error
            return json.dumps(item, ensure_ascii=False)
        if isinstance(item, list):
            return "[" + ",".join(render(child) for child in item) + "]"
        if isinstance(item, Mapping):
            if not all(isinstance(name, str) for name in item):
                raise VerificationError("non-string JSON member name")
            return (
                "{"
                + ",".join(
                    f"{render(name)}:{render(item[name])}" for name in sorted(item, key=_key)
                )
                + "}"
            )
        raise VerificationError("non-JSON canonical value")

    return render(value).encode("utf-8")


def digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _decode_base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise VerificationError("signature base64 value is not a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise VerificationError("signature value is not valid base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise VerificationError("signature value is not canonical base64")
    return decoded


def _pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _unsigned_manifest_digest(manifest: dict[str, Any]) -> str:
    value = json.loads(json.dumps(manifest))
    value["integrity"]["manifestDigest"] = None
    value["integrity"]["signature"] = None
    return digest(canonical(value))


def _signature_material(
    manifest: dict[str, Any],
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    material = manifest["integrity"].get("signature")
    if not isinstance(material, dict):
        raise VerificationError("trace signature is required but absent")
    envelope = material.get("envelope")
    public = material.get("publicKey")
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"payloadType", "payload", "signatures"}
        or not isinstance(public, dict)
        or set(public) != {"algorithm", "keyid", "raw"}
    ):
        raise VerificationError("unsupported or malformed DSSE envelope")
    signatures = envelope["signatures"]
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or envelope["payloadType"] != PAYLOAD_TYPE
        or public.get("algorithm") != "ed25519"
    ):
        raise VerificationError("unsupported or malformed DSSE envelope")
    signature_item = signatures[0]
    if not isinstance(signature_item, dict) or set(signature_item) != {"keyid", "sig"}:
        raise VerificationError("unsupported or malformed DSSE signature")
    return envelope["payloadType"], envelope, public, signature_item


def _verify_signature(
    manifest: dict[str, Any],
    *,
    required_key_id: str | None,
) -> dict[str, Any]:
    payload_type, envelope, public, signature_item = _signature_material(manifest)
    material = manifest["integrity"]["signature"]
    payload = _decode_base64(envelope["payload"])
    signature = _decode_base64(signature_item["sig"])
    public_raw = _decode_base64(public["raw"])
    key_id = digest(public_raw)
    if key_id != public.get("keyid") or key_id != signature_item.get("keyid"):
        raise VerificationError("signature key identifier mismatch")
    if required_key_id is not None and key_id != required_key_id:
        raise VerificationError("signature does not match the required key")
    try:
        ed25519 = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ed25519")
    except ImportError as error:
        raise VerificationError(
            "signature verification requires the optional cryptography dependency"
        ) from error
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature,
            _pae(payload_type, payload),
        )
    except Exception as error:
        raise VerificationError("Ed25519 signature verification failed") from error
    statement = strict_loads(payload)
    if not isinstance(statement, dict):
        raise VerificationError("signed statement is not an object")
    if canonical(statement) != payload:
        raise VerificationError("signed statement is not canonical SOVA JSON")
    subject = statement.get("subject")
    predicate = statement.get("predicate")
    if (
        not isinstance(subject, list)
        or len(subject) != 1
        or not isinstance(subject[0], dict)
        or not isinstance(subject[0].get("digest"), dict)
        or not isinstance(predicate, dict)
    ):
        raise VerificationError("signed statement is malformed")
    subject_digest = subject[0]["digest"].get("sha256")
    verification_material = material.get("verificationMaterial")
    expected_material_digest = (
        digest(canonical(verification_material)) if verification_material is not None else None
    )
    if (
        statement.get("_type") != STATEMENT_TYPE
        or statement.get("predicateType") != PREDICATE_TYPE
        or subject[0].get("name") != "sova.trace.manifest"
        or subject_digest != _unsigned_manifest_digest(manifest)[7:]
        or predicate.get("traceId") != manifest.get("id")
        or predicate.get("runId") != manifest.get("runId")
        or predicate.get("eventCount") != manifest.get("eventCount")
        or predicate.get("chainRoot") != manifest.get("chainRoot")
        or predicate.get("verificationMaterialDigest") != expected_material_digest
    ):
        raise VerificationError("signed statement does not match the trace manifest")
    return {
        "signaturePresent": True,
        "signatureChecked": True,
        "signatureKeyId": key_id,
        "trustPolicy": (
            "required-key" if required_key_id is not None else "included-key-integrity-only"
        ),
        "verificationMaterialPresent": verification_material is not None,
        "verificationMaterialVerified": False,
    }


def _safe_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise VerificationError(f"unsafe package path: {value!r}")


def _archive(path: Path) -> tuple[dict[str, bytes], bytes]:
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        raise VerificationError("invalid ZIP package") from error
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ENTRIES:
            raise VerificationError("invalid archive entry count")
        result: dict[str, bytes] = {}
        total = 0
        for info in infos:
            _safe_path(info.filename)
            if info.filename in result:
                raise VerificationError("duplicate archive member")
            mode = info.external_attr >> 16
            if info.is_dir() or (mode & 0o170000) not in {0, 0o100000}:
                raise VerificationError("special archive member")
            if info.file_size > MAX_ENTRY_BYTES:
                raise VerificationError("archive member too large")
            if info.file_size > MIN_RATIO_CHECK_BYTES and (
                info.compress_size == 0 or info.file_size / info.compress_size > MAX_RATIO
            ):
                raise VerificationError("unsafe compression ratio")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise VerificationError("archive total size exceeded")
            try:
                result[info.filename] = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise VerificationError("archive member integrity check failed") from error
    if "manifest.json" not in result:
        raise VerificationError("manifest.json missing")
    return result, result["manifest.json"]


def _descriptors(manifest: dict[str, Any], members: dict[str, bytes]) -> list[dict[str, Any]]:
    objects = manifest.get("objects")
    if not isinstance(objects, list):
        raise VerificationError("manifest object index is not an array")
    declared: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in objects:
        if not isinstance(item, dict) or set(item) != {
            "role",
            "path",
            "mediaType",
            "digest",
            "size",
        }:
            raise VerificationError("malformed object descriptor")
        object_path = item["path"]
        if not isinstance(object_path, str):
            raise VerificationError("descriptor path is not a string")
        _safe_path(object_path)
        if object_path in declared:
            raise VerificationError("duplicate descriptor path")
        declared.add(object_path)
        data = members.get(object_path)
        if (
            data is None
            or not isinstance(item["size"], int)
            or isinstance(item["size"], bool)
            or len(data) != item["size"]
            or not isinstance(item["digest"], str)
            or SHA256.fullmatch(item["digest"]) is None
            or digest(data) != item["digest"]
        ):
            raise VerificationError("object descriptor integrity mismatch")
        result.append(item)
    if declared != set(members) - {"manifest.json"}:
        raise VerificationError("manifest/archive object-index mismatch")
    return result


def _redactions(value: Any, path: str = "$") -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    if isinstance(value, dict):
        if "$redacted" in value:
            marker = value["$redacted"]
            if (
                not isinstance(marker, dict)
                or marker.get("present") is not True
                or not all(
                    isinstance(marker.get(field), str) for field in ("class", "method", "encoding")
                )
            ):
                raise VerificationError("malformed redaction placeholder")
            return [(path, marker["class"], marker["method"])]
        for name, child in value.items():
            found.extend(_redactions(child, f"{path}.{name}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_redactions(child, f"{path}[{index}]"))
    return found


def _redaction_records(event: dict[str, Any]) -> list[tuple[str, str, str]]:
    records = event.get("redactions")
    if not isinstance(records, list):
        raise VerificationError("event redactions are not an array")
    result: list[tuple[str, str, str]] = []
    for item in records:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "class", "method"}
            or not isinstance(item["path"], str)
            or not item["path"]
            or not isinstance(item["class"], str)
            or not item["class"]
            or item["method"] not in REDACTION_METHODS
        ):
            raise VerificationError("malformed redaction record")
        result.append((item["path"], item["class"], item["method"]))
    return sorted(result)


def _trace(
    manifest: dict[str, Any],
    descriptors: list[dict[str, Any]],
    members: dict[str, bytes],
) -> int:
    sequence = 0
    previous: str | None = None
    for descriptor in sorted(
        (item for item in descriptors if item["role"] == "event-segment"),
        key=lambda item: item["path"],
    ):
        segment = members[descriptor["path"]]
        if segment and not segment.endswith(b"\n"):
            raise VerificationError("event segment lacks final newline")
        for raw in segment.splitlines():
            event = strict_loads(raw)
            if not isinstance(event, dict):
                raise VerificationError("event root is not an object")
            if event.get("sequence") != sequence or event.get("previousHash") != previous:
                raise VerificationError("event sequence/hash-chain link mismatch")
            claimed = event.get("eventHash")
            unsigned = dict(event)
            unsigned.pop("eventHash", None)
            if not isinstance(claimed, str) or digest(canonical(unsigned)) != claimed:
                raise VerificationError("event hash mismatch")
            records = _redaction_records(event)
            if records != sorted(_redactions(event.get("payload"))):
                raise VerificationError("redaction record/placeholder mismatch")
            previous = claimed
            sequence += 1
    if manifest.get("eventCount") != sequence or manifest.get("chainRoot") != previous:
        raise VerificationError("trace manifest chain root/count mismatch")
    integrity = manifest.get("integrity")
    if not isinstance(integrity, dict):
        raise VerificationError("trace integrity object missing")
    expected = integrity.get("manifestDigest")
    unsigned_manifest = json.loads(json.dumps(manifest))
    unsigned_manifest["integrity"]["manifestDigest"] = None
    unsigned_manifest["integrity"]["signature"] = None
    if expected != digest(canonical(unsigned_manifest)):
        raise VerificationError("trace manifest digest mismatch")
    return sequence


def verify(
    path: Path,
    *,
    require_signature: bool = False,
    required_key_id: str | None = None,
) -> dict[str, Any]:
    members, manifest_bytes = _archive(path)
    manifest = strict_loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise VerificationError("manifest root is not an object")
    artifact_type = manifest.get("artifactType")
    if artifact_type not in {"sova.capsule", "sova.trace"}:
        raise VerificationError("unsupported artifact type")
    if manifest.get("schemaVersion") != "0.1.0":
        raise VerificationError("unsupported schema version")
    descriptors = _descriptors(manifest, members)
    event_count = _trace(manifest, descriptors, members) if artifact_type == "sova.trace" else 0
    result = {
        "artifactType": artifact_type,
        "contentDigest": digest(canonical(manifest)),
        "eventCount": event_count,
        "objectCount": len(descriptors),
        "packageDigest": digest(path.read_bytes()),
        "signaturePresent": False,
        "signatureChecked": False,
        "valid": True,
    }
    if artifact_type == "sova.trace":
        signature = manifest.get("integrity", {}).get("signature")
        result["signaturePresent"] = signature is not None
        if required_key_id is not None:
            require_signature = True
        if require_signature:
            result.update(
                _verify_signature(
                    manifest,
                    required_key_id=required_key_id,
                )
            )
    elif require_signature or required_key_id is not None:
        raise VerificationError("signature policy is supported only for sova.trace")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sova-independent-verify")
    parser.add_argument("path", type=Path)
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--required-key-id")
    args = parser.parse_args(argv)
    try:
        report = verify(
            args.path,
            require_signature=args.require_signature,
            required_key_id=args.required_key_id,
        )
    except (OSError, VerificationError) as error:
        sys.stderr.write(f"INDEPENDENT-VERIFY-FAILED: {error}\n")
        return 2
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
