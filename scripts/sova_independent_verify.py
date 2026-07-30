#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: TRY003
"""Small dependency-free verifier implemented independently from `sova`.

This intentionally validates a strict portable subset: archive/object
integrity, canonical manifest identity, event order/hash chain, and structural
redaction records. It does not execute content or verify Ed25519 signatures.
"""

from __future__ import annotations

import argparse
import hashlib
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
            result[info.filename] = archive.read(info)
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
        for raw in members[descriptor["path"]].splitlines():
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
            records = sorted(
                (item["path"], item["class"], item["method"])
                for item in event.get("redactions", [])
                if isinstance(item, dict)
            )
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


def verify(path: Path) -> dict[str, Any]:
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
    return {
        "artifactType": artifact_type,
        "contentDigest": digest(canonical(manifest)),
        "eventCount": event_count,
        "objectCount": len(descriptors),
        "packageDigest": digest(path.read_bytes()),
        "signatureChecked": False,
        "valid": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sova-independent-verify")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify(args.path)
    except (OSError, VerificationError) as error:
        sys.stderr.write(f"INDEPENDENT-VERIFY-FAILED: {error}\n")
        return 2
    sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
