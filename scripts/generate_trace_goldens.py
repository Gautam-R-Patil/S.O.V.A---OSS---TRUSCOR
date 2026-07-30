#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate or check deterministic golden events for every registered family."""

from __future__ import annotations

import argparse
from pathlib import Path

from sova.formats import canonical_json_bytes, validate_document
from sova.trace.integrity import event_hash
from sova.trace.kinds import EVENT_FAMILIES

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "tests/fixtures/golden/trace/all-event-families-0.1.0.jsonl"
_WALL_TIME = "2026-07-30T00:00:00Z"
_RUN_ID = "sova:run:018f7f8a-6d1e-7b2a-8d0f-8f0f0f0f0f02"


def golden_bytes() -> bytes:
    """Return fixed canonical JSONL covering every registered event family."""
    rows: list[bytes] = []
    previous_hash: str | None = None
    previous_id: str | None = None
    for sequence, prefix in enumerate(EVENT_FAMILIES):
        event_id = (
            "sova:event:018f7f8a-6d1e-7b2a-8d0f-"
            f"{sequence + 1:012x}"
        )
        event = {
            "artifactType": "sova.event",
            "schemaVersion": "0.1.0",
            "id": event_id,
            "runId": _RUN_ID,
            "sequence": sequence,
            "kind": f"{prefix}fixture",
            "phase": "golden",
            "actor": {
                "id": "fixture:actor",
                "kind": "tester",
                "name": "Golden fixture",
            },
            "target": {
                "id": "fixture:target",
                "kind": "synthetic",
                "name": "Golden target",
            },
            "producer": {
                "id": "fixture:recorder",
                "kind": "recorder",
                "name": "SOVA fixture",
            },
            "wallTime": _WALL_TIME,
            "observedTime": _WALL_TIME,
            "monotonicNs": sequence,
            "clock": {
                "source": "fixture",
                "precision": "exact-fixture",
                "skewEstimateNs": 0,
                "trusted": True,
            },
            "clockDomain": "fixture",
            "parents": [] if previous_id is None else [previous_id],
            "links": [],
            "attempt": None,
            "payload": {
                "family": prefix,
                "synthetic": True,
                "containsLiveTargetData": False,
            },
            "redactions": [],
            "previousHash": previous_hash,
        }
        event["eventHash"] = event_hash(event)
        validate_document(event, "sova.event")
        rows.append(canonical_json_bytes(event) + b"\n")
        previous_hash = str(event["eventHash"])
        previous_id = event_id
    return b"".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the fixture; without this flag, verify exact bytes",
    )
    args = parser.parse_args()
    expected = golden_bytes()
    if args.write:
        DESTINATION.write_bytes(expected)
        print(f"wrote {DESTINATION.relative_to(ROOT)}")
        return 0
    if not DESTINATION.is_file() or DESTINATION.read_bytes() != expected:
        print("golden event-family fixture is missing or stale")
        return 1
    print("golden event-family fixture is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
