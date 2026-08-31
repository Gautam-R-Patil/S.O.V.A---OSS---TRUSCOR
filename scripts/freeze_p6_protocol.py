# SPDX-License-Identifier: Apache-2.0
"""Canonically freeze a real P6 protocol without executing targets or reading results."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from sova.formats import canonical_json_bytes, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.validation import protocol_from_mapping

_MAX_PROTOCOL_BYTES = 8 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and exclusively freeze one pre-result P6 evaluation protocol."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--expected-release-commit", required=True)
    parser.add_argument("--ack-no-results-observed", action="store_true")
    return parser


def _object(raw: bytes) -> dict[str, Any]:
    value = strict_json_loads(raw, max_bytes=_MAX_PROTOCOL_BYTES)
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-P6-FREEZE-TYPE", "evaluation protocol must be an object")
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


def _require_freeze_acknowledgement(*, value: bool) -> None:
    if not value:
        raise FormatError(
            "SOVA-P6-FREEZE-ACK",
            "freezing requires --ack-no-results-observed",
        )


def _require_commit(observed: str, expected: str) -> None:
    if observed != expected:
        raise FormatError("SOVA-P6-FREEZE-COMMIT", "protocol release commit drifted")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _require_freeze_acknowledgement(value=args.ack_no_results_observed)
        document = _object(args.input.read_bytes())
        protocol = protocol_from_mapping(document)
        _require_commit(protocol.release_commit, args.expected_release_commit)
        validate_document(protocol.to_mapping(), "sova.blinded-evaluation-protocol")
        _write_exclusive(args.output, canonical_json_bytes(protocol.to_mapping()) + b"\n")
    except (FileExistsError, FormatError, OSError) as error:
        sys.stderr.write(f"P6 protocol freeze failed: {error}\n")
        return 2
    result = {
        "status": "frozen-local",
        "protocolDigest": protocol.digest,
        "runCount": protocol.run_count,
        "output": str(args.output),
        "operatorAssertedNoResultsObserved": True,
        "externalTimestampOrCustodyEstablished": False,
        "executionPerformed": False,
    }
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
