# SPDX-License-Identifier: Apache-2.0
"""Strict JSON and the portable SOVA canonical JSON profile."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

from sova.formats.errors import FormatError

DEFAULT_MAX_JSON_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_ITEMS = 100_000
DEFAULT_MAX_STRING_BYTES = 4 * 1024 * 1024
MAX_IJSON_INTEGER = (1 << 53) - 1


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FormatError(
                "SOVA-FORMAT-DUPLICATE-KEY",
                f"duplicate JSON object member: {key!r}",
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise FormatError(
        "SOVA-FORMAT-NONFINITE-NUMBER",
        f"non-finite JSON number is forbidden: {value}",
    )


def strict_json_loads(
    raw: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> Any:
    """Parse UTF-8 JSON while rejecting ambiguous and resource-hostile input."""
    if len(raw) > max_bytes:
        raise FormatError(
            "SOVA-FORMAT-SIZE-LIMIT",
            "JSON document exceeds the configured byte limit",
            details={"actual": len(raw), "limit": max_bytes},
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FormatError(
            "SOVA-FORMAT-INVALID-UTF8",
            "JSON must be valid UTF-8",
            details={"offset": error.start},
        ) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except FormatError:
        raise
    except json.JSONDecodeError as error:
        raise FormatError(
            "SOVA-FORMAT-INVALID-JSON",
            "invalid JSON document",
            details={"line": error.lineno, "column": error.colno},
        ) from error
    _validate_tree(value, max_depth=max_depth, max_items=max_items)
    return value


def _validate_tree(value: Any, *, max_depth: int, max_items: int) -> None:
    pending: list[tuple[Any, int]] = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > max_items:
            raise FormatError(
                "SOVA-FORMAT-ITEM-LIMIT",
                "JSON document exceeds the configured item limit",
                details={"limit": max_items},
            )
        if depth > max_depth:
            raise FormatError(
                "SOVA-FORMAT-DEPTH-LIMIT",
                "JSON document exceeds the configured nesting limit",
                details={"limit": max_depth},
            )
        if isinstance(current, str):
            try:
                encoded = current.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise FormatError(
                    "SOVA-FORMAT-INVALID-UNICODE",
                    "JSON strings must contain Unicode scalar values, not lone surrogates",
                ) from error
            if len(encoded) > DEFAULT_MAX_STRING_BYTES:
                raise FormatError(
                    "SOVA-FORMAT-STRING-LIMIT",
                    "JSON string exceeds the configured byte limit",
                )
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise FormatError(
                    "SOVA-FORMAT-NONFINITE-NUMBER",
                    "non-finite JSON numbers are forbidden",
                )
        elif isinstance(current, Mapping):
            pending.extend((key, depth + 1) for key in current)
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, Sequence) and not isinstance(current, bytes):
            pending.extend((item, depth + 1) for item in current)


def _reject_float_tree(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise FormatError(
            "SOVA-FORMAT-CANONICAL-FLOAT",
            "canonical SOVA JSON uses integers or decimal strings, not binary floats",
            path=path,
        )
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_float_tree(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _reject_float_tree(child, f"{path}[{index}]")


def _validate_canonical_scalar(value: Any, path: str) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
            value.encode("utf-16-be", errors="strict")
        except UnicodeEncodeError as error:
            raise FormatError(
                "SOVA-FORMAT-INVALID-UNICODE",
                "canonical strings must contain Unicode scalar values, not lone surrogates",
                path=path,
            ) from error
    elif (
        isinstance(value, int)
        and not isinstance(value, bool)
        and not -MAX_IJSON_INTEGER <= value <= MAX_IJSON_INTEGER
    ):
        raise FormatError(
            "SOVA-FORMAT-IJSON-INTEGER",
            "canonical integers must be exactly interoperable in the I-JSON range",
            path=path,
            details={"minimum": -MAX_IJSON_INTEGER, "maximum": MAX_IJSON_INTEGER},
        )


def _utf16_sort_key(value: str) -> bytes:
    try:
        return value.encode("utf-16-be", errors="strict")
    except UnicodeEncodeError as error:
        raise FormatError(
            "SOVA-FORMAT-INVALID-UNICODE",
            "canonical object names must contain Unicode scalar values",
        ) from error


def _canonical_render(value: Any, path: str = "$") -> str:
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        _validate_canonical_scalar(value, path)
        return str(value)
    if isinstance(value, str):
        _validate_canonical_scalar(value, path)
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(
            _canonical_render(child, f"{path}[{index}]")
            for index, child in enumerate(value)
        ) + "]"
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise FormatError(
                "SOVA-FORMAT-NONSTRING-KEY",
                "canonical JSON object member names must be strings",
                path=path,
            )
        ordered = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(
            f"{_canonical_render(key, path)}:{_canonical_render(value[key], f'{path}.{key}')}"
            for key in ordered
        ) + "}"
    raise FormatError(
        "SOVA-FORMAT-NONCANONICAL-VALUE",
        "value cannot be represented as canonical SOVA JSON",
        path=path,
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 bytes for the SOVA JCS/I-JSON subset.

    SOVA forbids binary floating-point values in canonical signed documents.
    Integers are restricted to the exact I-JSON range and decimal quantities
    use normalized strings. Object names use RFC 8785 UTF-16 ordering. This is
    a strict subset of JCS rather than an implementation of its number
    serialization algorithm.
    """
    _validate_tree(value, max_depth=DEFAULT_MAX_DEPTH, max_items=DEFAULT_MAX_ITEMS)
    _reject_float_tree(value)
    try:
        rendered = _canonical_render(value)
        return rendered.encode("utf-8", errors="strict")
    except FormatError:
        raise
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise FormatError(
            "SOVA-FORMAT-NONCANONICAL-VALUE",
            "value cannot be represented as canonical SOVA JSON",
        ) from error


def sha256_digest(data: bytes) -> str:
    """Return the canonical lowercase SHA-256 content identifier."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


__all__ = [
    "MAX_IJSON_INTEGER",
    "canonical_json_bytes",
    "sha256_digest",
    "strict_json_loads",
]
