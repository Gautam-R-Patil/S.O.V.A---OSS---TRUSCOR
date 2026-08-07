# SPDX-License-Identifier: Apache-2.0
"""Minimal protocol example; it has no target, tool, network, or file authority."""

from __future__ import annotations

import json
import sys


def main() -> int:
    request = json.loads(sys.stdin.buffer.readline())
    operation = request.get("operation")
    response = {
        "protocol": "sova.extension-jsonl/0.1",
        "manifestDigest": request.get("manifestDigest"),
        "operation": operation,
        "accepted": operation in {"describe", "self-test", "invoke"},
        "capabilities": ["oracle.fixture"] if operation == "describe" else [],
    }
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
