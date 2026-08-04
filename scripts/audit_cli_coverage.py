# SPDX-License-Identifier: Apache-2.0
"""Require every registered CLI leaf handler to execute in the complete test suite."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sova.command_audit import AuditError, audit


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    if len(arguments) != 1:
        print("usage: audit_cli_coverage.py COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        report = audit(Path(arguments[0]))
    except (OSError, ValueError, AuditError) as error:
        print(f"CLI_COVERAGE_AUDIT=ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
