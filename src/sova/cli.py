# SPDX-License-Identifier: Apache-2.0
"""The dependency-free SOVA command-line foundation."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

from sova import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Build the public command-line parser without performing side effects."""
    parser = argparse.ArgumentParser(
        prog="sova",
        description=(
            "SOVA OSS is a local-first AI-agent security testing and evidence workbench. "
            "This pre-alpha build currently exposes only the engineering-foundation CLI."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and return a process exit code."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
