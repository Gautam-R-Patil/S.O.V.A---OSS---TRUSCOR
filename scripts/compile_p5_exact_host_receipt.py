# SPDX-License-Identifier: Apache-2.0
"""Compile recorded exact-host cases; this command does not execute or sign them."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from sova.formats import canonical_json_bytes, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.worker.host_acceptance import ExactHostAcceptanceReceipt, ExactHostCaseResult

_MAX_CASES = 11


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile digest-bound observations from an already executed exact-host matrix."
    )
    parser.add_argument("cases", type=Path, help="JSON array of exact-host case results")
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--measured-at", required=True)
    parser.add_argument("--attestation-digest", required=True)
    parser.add_argument("--preflight-receipt-digest", required=True)
    parser.add_argument("--guest-kernel-digest", required=True)
    parser.add_argument("--root-filesystem-digest", required=True)
    parser.add_argument("--worker-policy-digest", required=True)
    return parser


def _case_mappings(raw: bytes) -> list[dict[str, Any]]:
    value = strict_json_loads(raw)
    if not isinstance(value, list) or len(value) > _MAX_CASES:
        raise FormatError("SOVA-WORKER-HOST-CASES", "case input must be an array of at most 11")
    if not all(
        isinstance(item, dict) and all(isinstance(key, str) for key in item) for item in value
    ):
        raise FormatError("SOVA-WORKER-HOST-CASES", "every case must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cases = tuple(
            ExactHostCaseResult.from_mapping(item)
            for item in _case_mappings(args.cases.read_bytes())
        )
        receipt = ExactHostAcceptanceReceipt(
            release_commit=args.release_commit,
            worker_id=args.worker_id,
            measured_at=args.measured_at,
            attestation_digest=args.attestation_digest,
            preflight_receipt_digest=args.preflight_receipt_digest,
            guest_kernel_digest=args.guest_kernel_digest,
            root_filesystem_digest=args.root_filesystem_digest,
            worker_policy_digest=args.worker_policy_digest,
            cases=cases,
        )
        mapping = receipt.to_mapping()
        validate_document(mapping)
    except (FormatError, OSError) as error:
        sys.stderr.write(f"exact-host receipt compilation failed: {error}\n")
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(mapping) + b"\n")
    return 0 if receipt.matrix_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
