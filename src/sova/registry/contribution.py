# SPDX-License-Identifier: Apache-2.0
"""Explicit, local contribution preview and staging with no upload side effect."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_ALLOWED_SUFFIXES = frozenset({".sova", ".json", ".toml", ".md"})
_SECRET = re.compile(
    rb"(?i)[\"']?(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    rb"[\"']?\s*[:=]\s*[\"']?[^\s,;\"']{8,}"
)
_EXECUTABLE_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe")
_MAX_ITEM_BYTES = 256 * 1024 * 1024


def _review_item(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.suffix not in _ALLOWED_SUFFIXES:
        raise FormatError("SOVA-CONTRIBUTE-TYPE", "contribution item type is not allowed")
    data = path.read_bytes()
    if len(data) > _MAX_ITEM_BYTES:
        raise FormatError("SOVA-CONTRIBUTE-SIZE", "contribution item exceeds size limit")
    if any(data.startswith(magic) for magic in _EXECUTABLE_MAGIC):
        raise FormatError("SOVA-CONTRIBUTE-MALWARE", "executable payloads are forbidden")
    if _SECRET.search(data):
        raise FormatError("SOVA-CONTRIBUTE-SECRET", "credential-shaped content was detected")
    if path.suffix == ".sova":
        PackageReader(path).verify("sova.capsule")
    return {
        "name": path.name,
        "digest": sha256_digest(data),
        "size": len(data),
        "schemaValidated": path.suffix == ".sova",
        "safetyScanClean": True,
        "malwareScan": "bounded-magic-and-type-screen-clean",
        "secretScan": "bounded-pattern-screen-clean",
    }


def preview_contribution(specification: Mapping[str, Any]) -> dict[str, Any]:
    raw_items = specification.get("items")
    if (
        not isinstance(raw_items, list)
        or not raw_items
        or any(not isinstance(item, str) for item in raw_items)
    ):
        raise FormatError("SOVA-CONTRIBUTE-ITEMS", "items must be a non-empty path array")
    contributor = specification.get("contributor")
    license_expression = specification.get("license")
    if not isinstance(contributor, Mapping) or not isinstance(license_expression, str):
        raise FormatError("SOVA-CONTRIBUTE-METADATA", "contributor and license are required")
    if not isinstance(contributor.get("name"), str) or not isinstance(
        contributor.get("identity"), str
    ):
        raise FormatError("SOVA-CONTRIBUTE-METADATA", "contributor name and identity are required")
    gates = specification.get("gates")
    if not isinstance(gates, Mapping):
        raise FormatError("SOVA-CONTRIBUTE-GATES", "gates must be an object")
    required_gates = (
        "humanReviewed",
        "publicDisclosureAllowed",
        "authorizationRedacted",
        "provenanceComplete",
        "separateCorpusReuseConsent",
    )
    if any(not isinstance(gates.get(name), bool) for name in required_gates):
        raise FormatError("SOVA-CONTRIBUTE-GATES", "all contribution gates must be boolean")
    items = [_review_item(Path(item).resolve()) for item in raw_items]
    accepted = all(bool(gates[name]) for name in required_gates[:-1])
    return {
        "artifactType": "sova.contribution-preview",
        "schemaVersion": "0.1.0",
        "contributor": dict(contributor),
        "license": license_expression,
        "items": items,
        "gates": dict(gates),
        "acceptedForLocalStaging": accepted,
        "privateCorpusReuseConsent": bool(gates["separateCorpusReuseConsent"]),
        "privateCorpusReuse": False,
        "uploadPerformed": False,
        "confirmationRequired": True,
        "humanModerationRequired": True,
    }


def prepare_contribution(
    specification: Mapping[str, Any],
    destination: Path,
    *,
    confirmed: bool,
) -> dict[str, Any]:
    preview = preview_contribution(specification)
    if not confirmed:
        raise FormatError("SOVA-CONTRIBUTE-CONFIRM", "explicit per-item confirmation is required")
    if preview["acceptedForLocalStaging"] is not True:
        raise FormatError("SOVA-CONTRIBUTE-GATE", "contribution gates did not pass")
    destination = destination.resolve()
    if destination.exists():
        raise FormatError("SOVA-CONTRIBUTE-DESTINATION", "destination must not exist")
    destination.mkdir(parents=True)
    item_root = destination / "items" / "sha256"
    item_root.mkdir(parents=True)
    raw_items = specification["items"]
    for source_value, item in zip(raw_items, preview["items"], strict=True):
        source = Path(source_value).resolve()
        (item_root / str(item["digest"])[7:]).write_bytes(source.read_bytes())
    staged = {
        **preview,
        "artifactType": "sova.contribution-staging",
        "confirmed": True,
        "submitted": False,
        "pullRequestCreated": False,
        "externalMessageSent": False,
    }
    (destination / "contribution.json").write_bytes(canonical_json_bytes(staged) + b"\n")
    return staged


__all__ = ["prepare_contribution", "preview_contribution"]
