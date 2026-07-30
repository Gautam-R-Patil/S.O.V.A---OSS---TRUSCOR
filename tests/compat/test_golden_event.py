# SPDX-License-Identifier: Apache-2.0
"""Stable supported golden-event compatibility contract."""

from __future__ import annotations

from pathlib import Path

from sova.formats import canonical_json_bytes, strict_json_loads, validate_document
from sova.trace.integrity import event_hash
from sova.trace.kinds import EVENT_FAMILIES


def test_supported_golden_event_is_canonical_valid_and_hash_bound() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "tests/fixtures/golden/trace/standard-event-0.1.0.jsonl"
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    line = raw.removesuffix(b"\n")
    event = strict_json_loads(line)
    assert isinstance(event, dict)
    validate_document(event, "sova.event")
    assert canonical_json_bytes(event) == line
    assert event_hash(event) == event["eventHash"]


def test_golden_corpus_covers_every_registered_event_family() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "tests/fixtures/golden/trace/all-event-families-0.1.0.jsonl"
    lines = path.read_bytes().splitlines()
    assert len(lines) == len(EVENT_FAMILIES)
    previous_hash: str | None = None
    previous_id: str | None = None
    seen_prefixes: set[str] = set()
    for sequence, line in enumerate(lines):
        event = strict_json_loads(line)
        assert isinstance(event, dict)
        validate_document(event, "sova.event")
        assert canonical_json_bytes(event) == line
        assert event["sequence"] == sequence
        assert event["previousHash"] == previous_hash
        assert event["parents"] == ([] if previous_id is None else [previous_id])
        assert event_hash(event) == event["eventHash"]
        prefix = next(
            candidate for candidate in EVENT_FAMILIES if event["kind"].startswith(candidate)
        )
        seen_prefixes.add(prefix)
        previous_hash = event["eventHash"]
        previous_id = event["id"]
    assert seen_prefixes == set(EVENT_FAMILIES)
