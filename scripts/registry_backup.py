# SPDX-License-Identifier: Apache-2.0
"""Create, verify, or restore a bounded local Registry snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sova.formats import FormatError
from sova.registry import create_registry_backup, restore_registry_backup, verify_registry_backup

if TYPE_CHECKING:
    from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOVA Registry local snapshot utility")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("source", type=Path)
    create.add_argument("destination", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("archive", type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("archive", type=Path)
    restore.add_argument("empty_destination", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result: dict[str, Any]
        if args.command == "create":
            result = create_registry_backup(args.source, args.destination)
        elif args.command == "verify":
            result = verify_registry_backup(args.archive)
        else:
            result = restore_registry_backup(args.archive, args.empty_destination)
    except FormatError as error:
        print(json.dumps({"status": "fail", "code": error.issue.code}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
