# SPDX-License-Identifier: Apache-2.0
"""Thread-safe, redacted, hash-chained shared swarm blackboard."""

from __future__ import annotations

import threading

import pytest

from sova.community.swarm.blackboard import SwarmBlackboard
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.formats.errors import FormatError


def _message(
    author: str,
    seq: int,
    *,
    kind: SwarmMessageKind = SwarmMessageKind.OBSERVATION,
    refs: tuple[str, ...] = (),
    payload: dict[str, object] | None = None,
) -> SwarmMessage:
    return SwarmMessage(
        author_agent_id=author,
        seq=seq,
        kind=kind,
        refs=refs,
        payload=payload or {"note": f"{author}-{seq}"},
        posted_unix_ms=1_700_000_000_000 + seq,
    )


def test_post_then_read_returns_the_message() -> None:
    board = SwarmBlackboard()
    message = _message("agent-01", 0)
    board.post(message)
    read = board.read()
    assert len(read) == 1
    assert read[0].id == message.id


def test_read_cursor_excludes_already_seen_messages() -> None:
    board = SwarmBlackboard()
    board.post(_message("agent-01", 0))
    board.post(_message("agent-01", 1))
    board.post(_message("agent-02", 0))
    fresh = board.read(since_seq_by_author={"agent-01": 0, "agent-02": -1})
    assert {(m.author_agent_id, m.seq) for m in fresh} == {("agent-01", 1), ("agent-02", 0)}


def test_read_filters_by_kind() -> None:
    board = SwarmBlackboard()
    board.post(_message("agent-01", 0, kind=SwarmMessageKind.OBSERVATION))
    board.post(_message("agent-01", 1, kind=SwarmMessageKind.FINDING))
    findings = board.read(kinds=(SwarmMessageKind.FINDING,))
    assert len(findings) == 1
    assert findings[0].kind == SwarmMessageKind.FINDING


def test_chain_head_advances_and_is_deterministic_given_the_same_sequence() -> None:
    board_a = SwarmBlackboard()
    board_b = SwarmBlackboard()
    genesis = board_a.chain_head_digest()
    assert genesis == board_b.chain_head_digest()
    for board in (board_a, board_b):
        board.post(_message("agent-01", 0))
        board.post(_message("agent-02", 0))
    assert board_a.chain_head_digest() == board_b.chain_head_digest()
    assert board_a.chain_head_digest() != genesis


def test_redaction_disclosure_rejects_the_post() -> None:
    board = SwarmBlackboard()
    with pytest.raises(FormatError, match="credential-shaped"):
        board.post(
            _message(
                "agent-01",
                0,
                payload={"apiKey": "sk-" + "live-abcdefghijklmnop"},
            )
        )
    assert len(board) == 0


def test_unknown_ref_rejected() -> None:
    board = SwarmBlackboard()
    with pytest.raises(FormatError, match="unknown prior message"):
        board.post(_message("agent-01", 0, refs=("swarm-msg:doesnotexist",)))


def test_known_ref_accepted() -> None:
    board = SwarmBlackboard()
    board.post(_message("agent-01", 0))
    first_id = board.transcript()[0].id
    board.post(_message("agent-02", 0, refs=(first_id,)))
    assert len(board) == 2


def test_message_count_cap_enforced() -> None:
    board = SwarmBlackboard(max_messages=2)
    board.post(_message("agent-01", 0))
    board.post(_message("agent-01", 1))
    with pytest.raises(FormatError, match="message count or byte budget"):
        board.post(_message("agent-01", 2))


def test_byte_budget_cap_enforced() -> None:
    board = SwarmBlackboard(max_bytes=256)
    with pytest.raises(FormatError, match="message count or byte budget"):
        board.post(_message("agent-01", 0, payload={"note": "x" * 512}))


def test_duplicate_message_id_rejected() -> None:
    board = SwarmBlackboard()
    message = _message("agent-01", 0)
    board.post(message)
    with pytest.raises(FormatError, match="already posted"):
        board.post(message)


def test_wrong_type_rejected() -> None:
    board = SwarmBlackboard()
    with pytest.raises(FormatError, match="one exact SwarmMessage"):
        board.post({"not": "a message"})  # type: ignore[arg-type]


def test_concurrent_posts_from_many_threads_preserve_count_and_chain() -> None:
    board = SwarmBlackboard(max_messages=1000)
    agent_count = 8
    per_agent = 20
    barrier = threading.Barrier(agent_count)

    def worker(agent_index: int) -> None:
        agent_id = f"agent-{agent_index:02d}"
        barrier.wait()
        for seq in range(per_agent):
            board.post(_message(agent_id, seq, payload={"agent": agent_id, "seq": seq}))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(agent_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(board) == agent_count * per_agent
    transcript = board.transcript()
    assert len({message.id for message in transcript}) == len(transcript)
    for agent_index in range(agent_count):
        agent_id = f"agent-{agent_index:02d}"
        seqs = sorted(message.seq for message in transcript if message.author_agent_id == agent_id)
        assert seqs == list(range(per_agent))
