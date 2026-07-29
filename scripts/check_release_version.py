# SPDX-License-Identifier: Apache-2.0
"""Require a release tag to match the package version exactly."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT = Path(__file__).resolve().parents[1]


def package_version() -> str:
    """Read the static package version from ``pyproject.toml``."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(project["project"]["version"])


def tag_matches_version(tag: str, version: str) -> bool:
    """Return whether ``tag`` is the canonical tag for ``version``."""
    return tag == f"v{version}"


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="candidate Git tag, including the leading v")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Check the supplied tag against the package version."""
    tag = build_parser().parse_args(argv).tag
    version = package_version()
    if not tag_matches_version(tag, version):
        print(f"RELEASE_VERSION_CHECK=FAILED: tag {tag!r} != 'v{version}'")
        return 1
    print(f"RELEASE_VERSION_CHECK=PASS: {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
