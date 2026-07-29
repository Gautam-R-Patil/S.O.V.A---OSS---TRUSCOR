# SPDX-License-Identifier: Apache-2.0
"""Subprocess worker used to verify crash-safe fixture behavior."""

from __future__ import annotations

import sys
from pathlib import Path

CRASH_EXIT_CODE = 91


def main(argv: list[str]) -> int:
    """Replace a file atomically or crash before replacement."""
    target = Path(argv[0])
    mode = argv[1]
    temporary = target.with_suffix(f"{target.suffix}.pending")
    temporary.write_text("replacement", encoding="utf-8")
    if mode == "crash-before-replace":
        return CRASH_EXIT_CODE
    temporary.replace(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
