# SPDX-License-Identifier: Apache-2.0
"""Check Developer Certificate of Origin sign-offs."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

SIGN_OFF = re.compile(
    r"^Signed-off-by:\s+\S(?:.*\S)?\s+<[^<>\s]+@[^<>\s]+>$",
    re.IGNORECASE | re.MULTILINE,
)


def has_sign_off(message: str) -> bool:
    """Return whether a commit message contains a syntactically valid sign-off."""
    return SIGN_OFF.search(message) is not None


def commit_messages(revision_range: str) -> list[tuple[str, str]]:
    """Return non-merge commit hashes and messages in a Git revision range."""
    revision_result = subprocess.run(
        ["git", "rev-list", "--no-merges", revision_range],
        check=True,
        capture_output=True,
        text=True,
    )
    commits = [line for line in revision_result.stdout.splitlines() if line]
    messages: list[tuple[str, str]] = []
    for commit in commits:
        message_result = subprocess.run(
            ["git", "show", "-s", "--format=%B", commit],
            check=True,
            capture_output=True,
            text=True,
        )
        messages.append((commit, message_result.stdout))
    return messages


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--commit-msg",
        type=Path,
        metavar="PATH",
        help="check one commit-message file (pre-commit commit-msg hook)",
    )
    mode.add_argument(
        "--range",
        dest="revision_range",
        metavar="BASE..HEAD",
        help="check every non-merge commit in a Git revision range",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Check the requested commit message or revision range."""
    args = build_parser().parse_args(argv)
    if args.commit_msg is not None:
        message = args.commit_msg.read_text(encoding="utf-8")
        if not has_sign_off(message):
            print("DCO_CHECK=FAILED: commit message lacks a valid Signed-off-by line")
            return 1
        print("DCO_CHECK=PASS")
        return 0

    failures = [
        commit
        for commit, message in commit_messages(str(args.revision_range))
        if not has_sign_off(message)
    ]
    if failures:
        print("DCO_CHECK=FAILED")
        for commit in failures:
            print(f" - {commit}: missing valid Signed-off-by line")
        return 1
    print("DCO_CHECK=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
