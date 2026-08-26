# SPDX-License-Identifier: Apache-2.0
"""Typed inter-agent swarm message contract."""

from __future__ import annotations

import pytest

from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.formats.errors import FormatError


def _message(**overrides: object) -> SwarmMessage:
    fields: dict[str, object] = {
        "author_agent_id": "agent-01",
        "seq": 0,
        "kind": SwarmMessageKind.OBSERVATION,
        "refs": (),
        "payload": {"note": "saw a login form"},
        "posted_unix_ms": 1_700_000_000_000,
    }
    fields.update(overrides)
    return SwarmMessage(**fields)  # type: ignore[arg-type]


def test_id_and_digest_are_stable_for_identical_content() -> None:
    first = _message()
    second = _message()
    assert first.id == second.id
    assert first.digest == second.digest


def test_digest_changes_with_any_field() -> None:
    base = _message()
    assert _message(seq=1).digest != base.digest
    assert _message(kind=SwarmMessageKind.FINDING).digest != base.digest
    assert _message(payload={"note": "different"}).digest != base.digest


def test_canonical_mapping_uses_camel_case_keys() -> None:
    mapping = _message().canonical_mapping()
    assert mapping == {
        "authorAgentId": "agent-01",
        "seq": 0,
        "kind": "observation",
        "refs": [],
        "payload": {"note": "saw a login form"},
        "postedUnixMs": 1_700_000_000_000,
    }


def test_payload_over_limit_rejected() -> None:
    with pytest.raises(FormatError, match="256 KiB"):
        _message(payload={"blob": "x" * 300_000})


def test_negative_seq_rejected() -> None:
    with pytest.raises(FormatError, match="non-negative integer"):
        _message(seq=-1)


def test_bool_seq_rejected() -> None:
    with pytest.raises(FormatError, match="non-negative integer"):
        _message(seq=True)


def test_empty_author_rejected() -> None:
    with pytest.raises(FormatError, match="author id"):
        _message(author_agent_id="")


def test_wrong_kind_type_rejected() -> None:
    with pytest.raises(FormatError, match="declared kind"):
        _message(kind="observation")


def test_duplicate_refs_rejected() -> None:
    with pytest.raises(FormatError, match="unique"):
        _message(refs=("a", "a"))


def test_empty_ref_rejected() -> None:
    with pytest.raises(FormatError, match="unique"):
        _message(refs=("",))


def test_non_dict_payload_rejected() -> None:
    with pytest.raises(FormatError, match="payload must be an object"):
        _message(payload="not a dict")
