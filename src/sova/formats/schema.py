# SPDX-License-Identifier: Apache-2.0
"""Bundled JSON Schema 2020-12 validation."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

import jsonschema_rs
from jsonschema import Draft202012Validator, FormatChecker

from sova.formats.errors import FormatError, ValidationIssue

_SCHEMA_FILES = {
    "sova.capsule": "capsule-manifest-0.1.0.schema.json",
    "sova.scenario": "scenario-0.1.0.schema.json",
    "sova.trace": "trace-manifest-0.1.0.schema.json",
    "sova.event": "event-0.1.0.schema.json",
    "sova.map": "map-report-0.1.0.schema.json",
    "sova.forensic-reconstruction": "forensic-reconstruction-0.1.0.schema.json",
    "sova.evidence": "evidence-0.1.0.schema.json",
    "sova.composition-report": "composition-report-0.1.0.schema.json",
}


@lru_cache(maxsize=len(_SCHEMA_FILES))
def _schema(artifact_type: str) -> dict[str, Any]:
    try:
        filename = _SCHEMA_FILES[artifact_type]
    except KeyError as error:
        raise FormatError(
            "SOVA-SCHEMA-UNSUPPORTED-TYPE",
            f"unsupported artifact type: {artifact_type!r}",
        ) from error
    resource = files("sova.schemas").joinpath(filename)
    schema = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise FormatError(
            "SOVA-SCHEMA-DEFINITION",
            f"bundled schema root is not an object: {filename}",
        )
    Draft202012Validator.check_schema(schema)
    return schema


@lru_cache(maxsize=len(_SCHEMA_FILES))
def _validator(artifact_type: str) -> jsonschema_rs.Draft202012Validator:
    """Compile the high-throughput validator once per immutable schema."""
    return jsonschema_rs.Draft202012Validator(
        _schema(artifact_type),
        validate_formats=True,
        ignore_unknown_formats=False,
    )


@lru_cache(maxsize=len(_SCHEMA_FILES))
def _reference_validator(artifact_type: str) -> Draft202012Validator:
    """Retain the independent pure-Python correctness oracle for parity tests."""
    return Draft202012Validator(_schema(artifact_type), format_checker=FormatChecker())


def validation_issues(document: Any, artifact_type: str | None = None) -> list[ValidationIssue]:
    """Return stable sorted structural validation issues."""
    if not isinstance(document, dict):
        return [
            ValidationIssue(
                "SOVA-SCHEMA-ROOT-TYPE",
                "artifact root must be an object",
            )
        ]
    actual_type = document.get("artifactType")
    selected_type = artifact_type or actual_type
    if not isinstance(selected_type, str):
        return [
            ValidationIssue(
                "SOVA-SCHEMA-MISSING-TYPE",
                "artifactType is required",
                "$.artifactType",
            )
        ]
    errors = sorted(
        _validator(selected_type).iter_errors(document),
        key=lambda item: tuple(str(part) for part in item.instance_path),
    )
    return [
        ValidationIssue(
            "SOVA-SCHEMA-INVALID",
            error.message,
            "$" + "".join(f"[{part!r}]" for part in error.instance_path),
        )
        for error in errors
    ]


def validate_document(document: Any, artifact_type: str | None = None) -> None:
    """Raise the first structural validation issue."""
    issues = validation_issues(document, artifact_type)
    if issues:
        issue = issues[0]
        raise FormatError(issue.code, issue.message, path=issue.path, details=issue.details)


__all__ = ["validate_document", "validation_issues"]
