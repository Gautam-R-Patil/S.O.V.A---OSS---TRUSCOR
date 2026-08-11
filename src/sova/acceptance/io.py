# SPDX-License-Identifier: Apache-2.0
"""Strict acceptance-receipt I/O."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.acceptance.model import AcceptanceReceipt
from sova.formats import strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_FIELDS = {
    "artifactType",
    "schemaVersion",
    "gateId",
    "evidenceType",
    "runId",
    "result",
    "producer",
    "organization",
    "environmentId",
    "labels",
    "artifactDigests",
    "independentOfSovaTeam",
    "observedAt",
    "limitations",
}


def receipt_from_mapping(value: Mapping[str, Any]) -> AcceptanceReceipt:
    if set(value) != _FIELDS:
        raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt fields must be exact")
    if (
        value.get("artifactType") != "sova.acceptance-receipt"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt type is unsupported")
    labels = value.get("labels")
    digests = value.get("artifactDigests")
    limitations = value.get("limitations")
    if not isinstance(labels, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in labels.items()
    ):
        raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt labels are malformed")
    if not isinstance(digests, list) or not all(isinstance(item, str) for item in digests):
        raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt digests are malformed")
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt limitations are malformed")
    strings = (
        "gateId",
        "evidenceType",
        "runId",
        "result",
        "producer",
        "organization",
        "environmentId",
        "observedAt",
    )
    if not all(isinstance(value.get(name), str) for name in strings) or not isinstance(
        value.get("independentOfSovaTeam"), bool
    ):
        raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt scalar fields are malformed")
    return AcceptanceReceipt(
        str(value["gateId"]),
        str(value["evidenceType"]),
        str(value["runId"]),
        str(value["result"]),
        str(value["producer"]),
        str(value["organization"]),
        str(value["environmentId"]),
        tuple(sorted((str(key), str(item)) for key, item in labels.items())),
        tuple(str(item) for item in digests),
        bool(value["independentOfSovaTeam"]),
        str(value["observedAt"]),
        tuple(str(item) for item in limitations),
    )


def load_receipts(directory: Path) -> tuple[AcceptanceReceipt, ...]:
    root = directory.resolve()
    if not root.is_dir():
        raise FormatError("SOVA-ACCEPTANCE-DIRECTORY", "receipt directory does not exist")
    receipts: list[AcceptanceReceipt] = []
    for path in sorted(root.glob("*.json")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise FormatError("SOVA-ACCEPTANCE-FILE", "receipt must be a bounded regular file")
        value = strict_json_loads(path.read_bytes())
        if not isinstance(value, dict):
            raise FormatError("SOVA-ACCEPTANCE-RECEIPT", "receipt root must be an object")
        receipts.append(receipt_from_mapping(value))
    return tuple(receipts)


__all__ = ["load_receipts", "receipt_from_mapping"]
