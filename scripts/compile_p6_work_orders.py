# SPDX-License-Identifier: Apache-2.0
"""Expand a frozen P6 protocol into deterministic, non-executing work orders."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from sova.formats import canonical_json_bytes, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.validation import build_evaluation_work_orders, protocol_from_mapping

_MAX_PROTOCOL_BYTES = 8 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compile the complete frozen P6 run queue.")
    parser.add_argument("protocol", type=Path)
    parser.add_argument("output", type=Path)
    return parser


def _object(raw: bytes) -> dict[str, Any]:
    value = strict_json_loads(raw, max_bytes=_MAX_PROTOCOL_BYTES)
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-P6-WORK-ORDER-TYPE", "evaluation protocol must be an object")
    return value


def _write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise OSError
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        protocol = protocol_from_mapping(_object(args.protocol.read_bytes()))
        work_orders = build_evaluation_work_orders(protocol)
        validate_document(work_orders, "sova.evaluation-work-order-set")
        _write_exclusive(args.output, canonical_json_bytes(work_orders) + b"\n")
    except (FileExistsError, FormatError, OSError) as error:
        sys.stderr.write(f"P6 work-order compilation failed: {error}\n")
        return 2
    sys.stdout.write(str(work_orders["contentDigest"]) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
