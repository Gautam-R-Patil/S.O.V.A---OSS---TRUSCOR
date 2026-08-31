# SPDX-License-Identifier: Apache-2.0
"""Evaluate one frozen P6 observation ledger without executing or changing any run."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from sova.formats import canonical_json_bytes, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.validation import (
    evaluate_blinded_protocol,
    observation_ledger_from_mapping,
    protocol_from_mapping,
)

_MAX_INPUT_BYTES = 32 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile a complete P6 report from a frozen protocol and observation ledger."
    )
    parser.add_argument("protocol", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("output", type=Path)
    return parser


def _object(raw: bytes, role: str) -> dict[str, Any]:
    value = strict_json_loads(raw, max_bytes=_MAX_INPUT_BYTES)
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-P6-EVALUATE-TYPE", f"{role} must be an object")
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


def _require_protocol_binding(observed: str, expected: str) -> None:
    if observed != expected:
        raise FormatError("SOVA-P6-EVALUATE-BINDING", "ledger binds another protocol")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        protocol = protocol_from_mapping(_object(args.protocol.read_bytes(), "protocol"))
        protocol_digest, observations, _ledger_digest = observation_ledger_from_mapping(
            _object(args.ledger.read_bytes(), "observation ledger")
        )
        _require_protocol_binding(protocol_digest, protocol.digest)
        report = evaluate_blinded_protocol(protocol, observations)
        validate_document(report, "sova.blinded-evaluation-report")
        _write_exclusive(args.output, canonical_json_bytes(report) + b"\n")
    except (FileExistsError, FormatError, OSError) as error:
        sys.stderr.write(f"P6 observation evaluation failed: {error}\n")
        return 2
    sys.stdout.write(str(report["contentDigest"]) + "\n")
    return 0 if report["status"] == "conclusive" else 1


if __name__ == "__main__":
    raise SystemExit(main())
