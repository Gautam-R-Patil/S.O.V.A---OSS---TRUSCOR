# SPDX-License-Identifier: Apache-2.0
"""Emit bounded GitHub workflow annotations from a SOVA CI report."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Sequence

_MAX_ANNOTATIONS = 4096


class AnnotationError(ValueError):
    """A CI report cannot be converted into bounded annotations."""


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_annotations(document: Any) -> list[str]:
    if not isinstance(document, dict) or document.get("artifactType") != "sova.ci-report":
        raise AnnotationError("input is not a SOVA CI report")  # noqa: TRY003
    rows = document.get("annotations")
    if not isinstance(rows, list) or len(rows) > _MAX_ANNOTATIONS:
        raise AnnotationError(  # noqa: TRY003
            "CI annotations are malformed or exceed the limit"
        )
    output: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise AnnotationError("CI annotation must be an object")  # noqa: TRY003
        title = row.get("title")
        message = row.get("message")
        level = row.get("level")
        if not all(isinstance(value, str) and value for value in (title, message, level)):
            raise AnnotationError("CI annotation fields are malformed")  # noqa: TRY003
        command = "error" if level == "failure" else "notice"
        output.append(
            f"::{command} title={_escape(cast('str', title))}::{_escape(cast('str', message))}"
        )
    return output


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if len(values) != 1:
        sys.stderr.write("usage: emit_ci_annotations.py REPORT.json\n")
        return 2
    try:
        document = json.loads(Path(values[0]).read_text(encoding="utf-8"))
        for line in render_annotations(document):
            sys.stdout.write(line + "\n")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        sys.stderr.write(f"SOVA-CI-ANNOTATIONS: {error}\n")
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main
    raise SystemExit(main())


__all__ = ["AnnotationError", "main", "render_annotations"]
