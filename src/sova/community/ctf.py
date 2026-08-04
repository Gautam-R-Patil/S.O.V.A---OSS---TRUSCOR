# SPDX-License-Identifier: Apache-2.0
"""Reference-only CTF catalog tied to verified local SOVA artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class CTFScenario:
    identifier: str
    title: str
    difficulty: str
    source_project: str
    source_url: str
    source_license: str
    setup_mode: str
    artifact: Path
    explanation: str

    def __post_init__(self) -> None:
        if self.difficulty not in {"beginner", "intermediate", "advanced"}:
            raise FormatError("SOVA-CTF-DIFFICULTY", "CTF difficulty is invalid")
        if self.setup_mode not in {
            "bundled-synthetic",
            "manual-reviewed",
            "external-project-reference",
        }:
            raise FormatError("SOVA-CTF-SETUP", "CTF setup mode is invalid")
        if not all(
            (
                self.identifier,
                self.title,
                self.source_project,
                self.source_url,
                self.source_license,
                self.explanation,
            )
        ):
            raise FormatError("SOVA-CTF-METADATA", "CTF provenance is incomplete")


def build_ctf_catalog(scenarios: Sequence[CTFScenario], destination: Path) -> dict[str, Any]:
    """Create an inert catalog; never clone, install, start, or contact referenced projects."""
    if not scenarios:
        raise FormatError("SOVA-CTF-SCENARIOS", "CTF catalog requires scenarios")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in scenarios:
        if item.identifier in seen:
            raise FormatError("SOVA-CTF-DUPLICATE", "CTF scenario identifier is duplicated")
        seen.add(item.identifier)
        PackageReader(item.artifact).verify("sova.capsule")
        rows.append(
            {
                "id": item.identifier,
                "title": item.title,
                "difficulty": item.difficulty,
                "source": {
                    "project": item.source_project,
                    "url": item.source_url,
                    "license": item.source_license,
                    "reuse": "reference-only-no-assets-copied",
                },
                "safeLocalSetup": {
                    "mode": item.setup_mode,
                    "automaticCommands": [],
                    "freshAuthorizationRequired": True,
                },
                "artifact": {
                    "path": item.artifact.as_posix(),
                    "digest": sha256_digest(item.artifact.read_bytes()),
                    "verified": True,
                },
                "explanation": item.explanation,
                "contributionPath": (
                    "review artifact and licence -> sova registry contribution prepare -> "
                    "local verify -> explicit maintainer review"
                ),
            }
        )
    document = {
        "artifactType": "sova.ctf-catalog",
        "schemaVersion": "0.1.0",
        "scenarios": rows,
        "execution": "inert-catalog-only",
        "telemetry": "none",
        "limitations": [
            "External vulnerable-agent projects retain their own safety and setup requirements.",
            "A reference does not imply endorsement, coordination, or bundled redistribution.",
        ],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(document) + b"\n")
    return document
